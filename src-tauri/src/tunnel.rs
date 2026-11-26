//! 隧道生命周期：拉起特权 helper、盯住它的存活、意外断开后自动重连。
//!
//! helper 是唯一能改动系统网络的进程，因此它一旦消失，隧道就必须视为已断。
//! 这里由主管任务统一负责 helper 的启动、监控与回滚，界面只看到状态与事件。

use std::{
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use happyworking_vpn_core::{ConnectionState, ErrorCode, VpnError};
use happyworking_vpn_sslvpn::{ReconnectBackoff, wait_for_reconnect};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

use crate::AppState;

/// 首次重连前的等待时长。
const RECONNECT_BASE_MILLISECONDS: u64 = 1_000;
/// 重连等待时长上限。
const RECONNECT_MAX_MILLISECONDS: u64 = 30_000;
/// 自动重连的最大尝试次数。
const RECONNECT_MAX_ATTEMPTS: u32 = 5;
/// helper 报告连接成功前的等待上限（要给用户留出确认系统授权的时间）。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(120);
/// helper 响应断开指令的等待上限。
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// 判定网关不可达的连续失败次数。
const LIVENESS_FAILURES: u32 = 3;
/// 网关可达性探测间隔。
const LIVENESS_INTERVAL: Duration = Duration::from_secs(30);

/// 一次隧道尝试的结局。
pub enum Attempt {
    /// 用户主动断开，隧道已按预期回滚。
    Stopped,
    /// 隧道没能保持住；`retryable` 决定是否值得自动重试。
    Failed { reason: String, retryable: bool },
}

/// 隧道断开时通知界面的载荷。
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TunnelLost {
    /// 断开原因。
    pub reason: String,
    /// 已经尝试过的自动重连次数。
    pub attempt: u32,
    /// 是否还会继续自动重连。
    pub will_retry: bool,
}

/// 特权 helper 进程及其三条通道。
struct Helper {
    child: Child,
    input: Option<tokio::process::ChildStdin>,
    stdout: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    stderr: Option<tauri::async_runtime::JoinHandle<String>>,
}

impl Helper {
    /// 取回 helper 的错误输出。
    async fn take_details(&mut self) -> String {
        match self.stderr.take() {
            Some(handle) => handle.await.unwrap_or_default(),
            None => String::new(),
        }
    }
}

/// 隧道主管句柄：取消令牌、任务句柄与回滚结果。
pub struct Supervisor {
    cancel: CancellationToken,
    handle: tauri::async_runtime::JoinHandle<()>,
    cleanup: Arc<Mutex<Option<Result<(), String>>>>,
}

impl Supervisor {
    /// 让主管立刻停下，不再发起新的连接尝试。
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

/// 拉起隧道主管：它会启动 helper，并在意外断开后自动重连。
pub fn start(app: &AppHandle, state: &AppState) {
    let cancel = CancellationToken::new();
    let cleanup = Arc::new(Mutex::new(None));
    let handle =
        tauri::async_runtime::spawn(supervise(app.clone(), cancel.clone(), cleanup.clone()));
    *lock(&state.supervisor) = Some(Supervisor {
        cancel,
        handle,
        cleanup,
    });
}

/// 停止隧道主管，并等待网络配置回滚完成。
pub async fn stop(state: &AppState) -> Option<Result<(), String>> {
    let supervisor = { lock(&state.supervisor).take() }?;
    supervisor.cancel();
    let _ = supervisor.handle.await;
    lock(&supervisor.cleanup).take()
}
/// 主管主循环：维持隧道，意外断开时退避重连。
async fn supervise(
    app: AppHandle,
    cancel: CancellationToken,
    cleanup: Arc<Mutex<Option<Result<(), String>>>>,
) {
    let Ok(mut backoff) =
        ReconnectBackoff::new(RECONNECT_BASE_MILLISECONDS, RECONNECT_MAX_MILLISECONDS)
    else {
        return;
    };
    let mut attempt = 0_u32;
    loop {
        if cancel.is_cancelled() {
            return;
        }
        match run_attempt(&app, &cancel, &cleanup).await {
            Attempt::Stopped => return,
            Attempt::Failed { reason, retryable } => {
                attempt = attempt.saturating_add(1);
                let will_retry = should_retry(retryable, attempt);
                announce(&app, &reason, attempt, will_retry);
                if !will_retry {
                    give_up(&app);
                    return;
                }
                if wait_for_reconnect(&mut backoff, cancel.clone())
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }
}

/// 跑完一次隧道尝试，直到隧道断开或建立失败。
async fn run_attempt(
    app: &AppHandle,
    cancel: &CancellationToken,
    cleanup: &Arc<Mutex<Option<Result<(), String>>>>,
) -> Attempt {
    let state = app.state::<AppState>();
    let request = match tunnel_request(&state) {
        Ok(request) => request,
        Err(error) => {
            return Attempt::Failed {
                reason: error.message().to_owned(),
                retryable: false,
            };
        }
    };
    let mut helper = match spawn_helper(request).await {
        Ok(helper) => helper,
        Err(error) => {
            return Attempt::Failed {
                reason: error.message().to_owned(),
                retryable: false,
            };
        }
    };

    match wait_for_connected(&mut helper, cancel).await {
        ConnectOutcome::Cancelled => {
            shutdown(&mut helper, cleanup).await;
            return Attempt::Stopped;
        }
        ConnectOutcome::Failed { reason, retryable } => {
            let details = terminate(&mut helper).await;
            let reason = join_reason(reason, &details);
            return Attempt::Failed { reason, retryable };
        }
        ConnectOutcome::Connected(event) => announce_connected(app, &event),
    }

    // 隧道已建立，接下来只等它自己结束。
    let (dead_sender, mut dead_receiver) = mpsc::unbounded_channel::<String>();
    let probe =
        tauri::async_runtime::spawn(watch_gateway(app.clone(), cancel.clone(), dead_sender));
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                probe.abort();
                shutdown(&mut helper, cleanup).await;
                return Attempt::Stopped;
            }
            line = helper.stdout.next_line() => {
                match line {
                    Ok(Some(_)) => continue,
                    Ok(None) | Err(_) => break,
                }
            }
            reason = dead_receiver.recv(), if !dead_receiver.is_closed() => {
                let Some(reason) = reason else {
                    // 探测任务自己结束了，继续盯着 helper 就行。
                    continue;
                };
                probe.abort();
                // helper 还活着：走正常断开通道，让它自己回滚网络配置。
                shutdown(&mut helper, cleanup).await;
                return Attempt::Failed { reason, retryable: true };
            }
        }
    }
    probe.abort();

    let status = helper.child.wait().await.ok();
    let details = helper.take_details().await;
    Attempt::Failed {
        reason: describe_exit(status, &details),
        retryable: true,
    }
}

/// 等待 helper 报告连接成功。
enum ConnectOutcome {
    Connected(serde_json::Value),
    Failed { reason: String, retryable: bool },
    Cancelled,
}

async fn wait_for_connected(helper: &mut Helper, cancel: &CancellationToken) -> ConnectOutcome {
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    loop {
        let line = tokio::select! {
            biased;
            () = cancel.cancelled() => return ConnectOutcome::Cancelled,
            () = tokio::time::sleep_until(deadline) => {
                return ConnectOutcome::Failed {
                    reason: "helper 未在超时时间内报告连接成功".to_owned(),
                    retryable: true,
                };
            }
            line = helper.stdout.next_line() => match line {
                Ok(Some(line)) => line,
                Ok(None) => {
                    return ConnectOutcome::Failed {
                        reason: "helper 在隧道建立前退出".to_owned(),
                        retryable: false,
                    };
                }
                Err(_) => {
                    return ConnectOutcome::Failed {
                        reason: "helper 输出通道读取失败".to_owned(),
                        retryable: true,
                    };
                }
            },
        };
        let Some(event) = parse_event(&line) else {
            continue;
        };
        match event.get("kind").and_then(|kind| kind.as_str()) {
            Some("connected") => return ConnectOutcome::Connected(event),
            Some("error") => {
                let reason = event
                    .get("message")
                    .and_then(|message| message.as_str())
                    .unwrap_or("helper 报告隧道建立失败")
                    .to_owned();
                let retryable = event
                    .get("code")
                    .and_then(|code| code.as_str())
                    .map(is_retryable)
                    .unwrap_or(false);
                return ConnectOutcome::Failed { reason, retryable };
            }
            _ => continue,
        }
    }
}

/// 探测网关是否还接得住连接：连不上就说明隧道已经名存实亡。
///
/// 数据通道是长连接，网关假死时它不会报错，界面就会一直假装在线。
/// 这里另开一条短连接确认网关还在，失败到阈值就判定隧道失效。
async fn watch_gateway(
    app: AppHandle,
    cancel: CancellationToken,
    sender: mpsc::UnboundedSender<String>,
) {
    let mut failures = 0_u32;
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(LIVENESS_INTERVAL) => {}
        }
        let state = app.state::<AppState>();
        let Some(gateway) = lock(&state.pending)
            .as_ref()
            .map(|pending| (pending.config.host.clone(), pending.config.port))
        else {
            return;
        };
        let reachable = tokio::time::timeout(
            LIVENESS_INTERVAL,
            tokio::net::TcpStream::connect((gateway.0.as_str(), gateway.1)),
        )
        .await;
        match reachable {
            Ok(Ok(_)) => failures = 0,
            Ok(Err(_)) | Err(_) => {
                failures = failures.saturating_add(1);
                if failures >= LIVENESS_FAILURES {
                    let _ = sender.send("网关长时间无法连接".to_owned());
                    return;
                }
            }
        }
    }
}

/// 按用户要求断开 helper，并记录回滚结果。
async fn shutdown(helper: &mut Helper, cleanup: &Arc<Mutex<Option<Result<(), String>>>>) {
    let disconnect = match helper.input.as_mut() {
        Some(input) => send_disconnect(input)
            .await
            .map_err(|error| error.message().to_owned()),
        None => Ok(()),
    };
    helper.input.take();
    let status = match tokio::time::timeout(SHUTDOWN_TIMEOUT, helper.child.wait()).await {
        Ok(result) => result.map_err(|error| error.to_string()),
        Err(_) => {
            let _ = helper.child.start_kill();
            let _ = helper.child.wait().await;
            *lock(cleanup) = Some(Err("helper 清理超时，请重试；网络回滚尚未完成".to_owned()));
            return;
        }
    };
    let details = helper.take_details().await;
    let result = match (status, disconnect) {
        (Ok(status), Ok(())) if status.success() => Ok(()),
        (Ok(status), Ok(())) => Err(if details.is_empty() {
            format!("helper 断开失败（{status}）")
        } else {
            format!("helper 断开失败：{details}")
        }),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), _) => Err(error),
    };
    *lock(cleanup) = Some(result);
}

/// 通过控制通道通知 helper 断开。
async fn send_disconnect<W: tokio::io::AsyncWrite + Unpin>(input: &mut W) -> Result<(), VpnError> {
    input.write_all(b"disconnect\n").await.map_err(io_error)
}

/// 结束 helper 并取回它的错误输出。
async fn terminate(helper: &mut Helper) -> String {
    let _ = helper.child.start_kill();
    let _ = helper.child.wait().await;
    helper.take_details().await
}

/// 隧道建立成功时通知界面。
fn announce_connected(app: &AppHandle, event: &serde_json::Value) {
    let state = app.state::<AppState>();
    if lock(&state.session).mark_connected().is_ok() {
        let _ = app.emit("vpn-state", ConnectionState::Connected);
        let _ = app.emit("vpn-stage", "connected");
        let _ = app.emit("tunnel-ready", event);
    }
}

/// 隧道断开时通知界面。
fn announce(app: &AppHandle, reason: &str, attempt: u32, will_retry: bool) {
    let state = app.state::<AppState>();
    if lock(&state.session).mark_reconnecting().is_ok() {
        let _ = app.emit("vpn-state", ConnectionState::Reconnecting);
    }
    let _ = app.emit("vpn-stage", "tunnel-lost");
    let _ = app.emit(
        "tunnel-lost",
        TunnelLost {
            reason: reason.to_owned(),
            attempt,
            will_retry,
        },
    );
}

/// 自动重连彻底失败后的收尾。
fn give_up(app: &AppHandle) {
    let state = app.state::<AppState>();
    if lock(&state.session).fail().is_ok() {
        let _ = app.emit("vpn-state", ConnectionState::Failed);
    }
    let _ = app.emit("vpn-stage", "tunnel-lost");
}

/// 组装 helper 请求：网关配置加上认证会话的 cookie。
pub fn tunnel_request(state: &AppState) -> Result<serde_json::Value, VpnError> {
    let (config, certificate) = lock(&state.pending)
        .as_ref()
        .map(|pending| (pending.config.clone(), pending.certificate.clone()))
        .ok_or_else(|| protocol_error("缺少网关配置"))?;
    let session_cookie = lock(&state.auth_session)
        .as_ref()
        .map(|session| session.session_cookie().expose_secret().to_owned())
        .ok_or_else(|| protocol_error("请先完成认证"))?;
    Ok(serde_json::json!({
        "host": config.host,
        "port": config.port,
        "certificate_name": certificate.common_name,
        "certificate_pem": String::from_utf8(certificate.certificate_pem)
            .map_err(|_| protocol_error("证书 PEM 无效"))?,
        "fingerprint": certificate.fingerprint.to_string(),
        "legacy_tls": config.tls_policy == happyworking_vpn_core::TlsPolicy::Legacy,
        "session_cookie": session_cookie,
    }))
}

/// 启动特权 helper。
async fn spawn_helper(request: serde_json::Value) -> Result<Helper, VpnError> {
    let helper = std::env::current_exe()
        .map_err(io_error)?
        .with_file_name("happyworking-vpn-helper");
    let mut child = Command::new("pkexec")
        .arg(helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(io_error)?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| protocol_error("helper 标准输入不可用"))?;
    input
        .write_all(format!("{request}\n").as_bytes())
        .await
        .map_err(io_error)?;
    let stdout = BufReader::new(
        child
            .stdout
            .take()
            .ok_or_else(|| protocol_error("helper 标准输出不可用"))?,
    )
    .lines();
    let stderr = BufReader::new(
        child
            .stderr
            .take()
            .ok_or_else(|| protocol_error("helper 标准错误不可用"))?,
    )
    .lines();
    Ok(Helper {
        child,
        input: Some(input),
        stdout,
        stderr: Some(tauri::async_runtime::spawn(read_helper_stderr(stderr))),
    })
}

/// 读取 helper 的错误输出，只保留最后几行。
async fn read_helper_stderr(
    mut stderr: tokio::io::Lines<BufReader<tokio::process::ChildStderr>>,
) -> String {
    let mut messages = Vec::new();
    while let Ok(Some(line)) = stderr.next_line().await {
        let line = line.trim();
        if !line.is_empty() {
            if messages.len() == 4 {
                messages.remove(0);
            }
            messages.push(line.chars().take(256).collect::<String>());
        }
    }
    messages.join("；")
}

/// 解析 helper 的一行结构化输出。
fn parse_event(line: &str) -> Option<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(line.trim()).ok()
}

/// 只有网络类错误才值得自动重试：证书、配置和认证问题重试也不会变好。
fn is_retryable(code: &str) -> bool {
    matches!(
        code,
        "networkUnavailable" | "protocolError" | "internalError"
    )
}

/// 还能不能再试一次：可重试的错误在用完次数之前一直重试。
fn should_retry(retryable: bool, attempt: u32) -> bool {
    retryable && attempt < RECONNECT_MAX_ATTEMPTS
}

/// 描述 helper 意外退出的原因。
fn describe_exit(status: Option<std::process::ExitStatus>, details: &str) -> String {
    if details.is_empty() {
        match status {
            Some(status) => format!("隧道已中断（helper 退出：{status}）"),
            None => "隧道已中断，helper 退出状态未知".to_owned(),
        }
    } else {
        format!("隧道已中断：{details}")
    }
}

/// 把 helper 的错误输出拼到原因后面。
fn join_reason(reason: String, details: &str) -> String {
    if details.is_empty() {
        reason
    } else {
        format!("{reason}：{details}")
    }
}

fn io_error(error: std::io::Error) -> VpnError {
    VpnError::new(ErrorCode::NetworkUnavailable, error.to_string(), &[])
}

fn protocol_error(message: &str) -> VpnError {
    VpnError::new(ErrorCode::ProtocolError, message, &[])
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disconnect_uses_helper_control_channel() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let request = tokio::spawn(async move { send_disconnect(&mut writer).await });
        let mut command = String::new();
        BufReader::new(reader)
            .read_line(&mut command)
            .await
            .unwrap();

        assert_eq!(command, "disconnect\n");
        request.await.unwrap().unwrap();
    }

    #[test]
    fn only_transient_failures_are_retried() {
        assert!(is_retryable("networkUnavailable"));
        assert!(is_retryable("protocolError"));
        assert!(!is_retryable("authenticationFailed"));
        assert!(!is_retryable("invalidCertificate"));
        assert!(!is_retryable("permissionDenied"));
        assert!(!is_retryable("cancelled"));
    }

    #[test]
    fn an_exit_without_details_still_explains_itself() {
        let reason = describe_exit(None, "");
        assert!(reason.contains("隧道已中断"), "实际：{reason}");
    }

    #[test]
    fn helper_details_are_appended_to_the_reason() {
        let reason = join_reason("隧道建立失败".to_owned(), "会话已过期");
        assert_eq!(reason, "隧道建立失败：会话已过期");
    }

    #[test]
    fn retries_stop_after_the_configured_attempts() {
        assert!(should_retry(true, 1));
        assert!(should_retry(true, RECONNECT_MAX_ATTEMPTS - 1));
        assert!(!should_retry(true, RECONNECT_MAX_ATTEMPTS));
        assert!(!should_retry(false, 1), "会话失效类错误不应重试");
    }
}
