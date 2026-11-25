pub mod credentials;
mod tunnel;

use std::sync::{Mutex, MutexGuard};

use happyworking_vpn_core::{
    ConnectionState, ErrorCode, GatewayConfig, SecretString, Session, VpnError,
};
use happyworking_vpn_sslvpn::{
    AuthOutcome, AuthSession, Challenge, GatewayCapabilities, PeerCertificate, TlsOptions,
    V7SecondAuthInput, challenge_v7, discover, local_mac_address, login_v7, logout_v7,
    probe_certificate,
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, RunEvent};
use tokio_util::sync::CancellationToken;

use crate::credentials::{CredentialKey, CredentialStore, KeyringStore};

struct PendingGateway {
    config: GatewayConfig,
    certificate: PeerCertificate,
}

struct PendingCredentials {
    key: CredentialKey,
    password: SecretString,
    remember: bool,
}

struct AppState {
    session: Mutex<Session>,
    pending: Mutex<Option<PendingGateway>>,
    capabilities: Mutex<Option<GatewayCapabilities>>,
    auth_session: Mutex<Option<AuthSession>>,
    challenge: Mutex<Option<Challenge>>,
    supervisor: Mutex<Option<tunnel::Supervisor>>,
    credentials: KeyringStore,
    pending_credentials: Mutex<Option<PendingCredentials>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            session: Mutex::new(Session::new(32).expect("非零事件通道容量")),
            pending: Mutex::new(None),
            capabilities: Mutex::new(None),
            auth_session: Mutex::new(None),
            challenge: Mutex::new(None),
            supervisor: Mutex::new(None),
            credentials: KeyringStore,
            pending_credentials: Mutex::new(None),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertificateView {
    fingerprint: String,
    subject: String,
    common_name: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthView {
    stage: String,
    message: String,
}

#[derive(Serialize)]
struct SavedCredentialView {
    password: Option<String>,
}

#[tauri::command]
async fn load_saved_credential(
    state: tauri::State<'_, AppState>,
    host: String,
    port: u16,
    username: String,
) -> Result<SavedCredentialView, VpnError> {
    let key = CredentialKey::new(&host, port, &username)?;
    let store = state.credentials;
    let password = tokio::task::spawn_blocking(move || store.load(&key))
        .await
        .map_err(|_| VpnError::new(ErrorCode::InternalError, "读取密钥环任务失败", &[]))??
        .map(|password| password.expose_secret().to_owned());
    Ok(SavedCredentialView { password })
}

#[tauri::command]
fn get_core_state(state: tauri::State<'_, AppState>) -> ConnectionState {
    lock(&state.session).state()
}

#[tauri::command]
async fn probe_gateway(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    config: GatewayConfig,
) -> Result<CertificateView, VpnError> {
    config
        .validate()
        .map_err(|error| VpnError::new(ErrorCode::InvalidConfiguration, error.to_string(), &[]))?;
    {
        let mut session = lock(&state.session);
        if session.is_cancelled() {
            *session = Session::new(32)?;
        }
        session.connect()?;
    }
    emit_state(&app, lock(&state.session).state())?;

    let certificate = probe_certificate(
        &config.host,
        config.port,
        config.tls_policy,
        operation_token(&state),
    )
    .await?;
    let view = CertificateView {
        fingerprint: certificate.fingerprint.to_string(),
        subject: certificate.subject.clone(),
        common_name: certificate.common_name.clone(),
    };
    *lock(&state.pending) = Some(PendingGateway {
        config,
        certificate,
    });
    *lock(&state.capabilities) = None;
    *lock(&state.auth_session) = None;
    *lock(&state.challenge) = None;
    *lock(&state.pending_credentials) = None;
    emit_stage(&app, "certificate")?;
    Ok(view)
}

#[tauri::command]
async fn trust_and_discover(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<AuthView, VpnError> {
    let pending = lock(&state.pending)
        .as_ref()
        .map(|pending| (pending.config.clone(), pending.certificate.clone()))
        .ok_or_else(|| protocol_error("请先读取网关证书"))?;
    let options = tls_options(pending.0, pending.1)?;
    let capabilities = discover(&options, operation_token(&state)).await?;
    *lock(&state.capabilities) = Some(capabilities);
    emit_stage(&app, "ready")?;
    Ok(AuthView {
        stage: "ready".to_owned(),
        message: "网关能力发现完成，可以登录".to_owned(),
    })
}

#[tauri::command]
async fn login_gateway(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    username: String,
    password: SecretString,
    verify_code: String,
    remember: bool,
) -> Result<AuthView, VpnError> {
    let (config, certificate) = lock(&state.pending)
        .as_ref()
        .map(|pending| (pending.config.clone(), pending.certificate.clone()))
        .ok_or_else(|| protocol_error("请先完成证书确认"))?;
    let capabilities = lock(&state.capabilities)
        .clone()
        .ok_or_else(|| protocol_error("请先完成网关发现"))?;
    let options = tls_options(config.clone(), certificate)?;
    let key = CredentialKey::new(&config.host, config.port, &username)?;
    let mac_address = local_mac_address(&config.host, config.port);
    let credentials = happyworking_vpn_sslvpn::V7Credentials {
        username: &username,
        password: password.expose_secret(),
        mac_address: &mac_address,
        language: "CN",
        verify_code: &verify_code,
    };
    let outcome = login_v7(
        &options,
        &capabilities,
        credentials,
        None,
        operation_token(&state),
    )
    .await;
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            *lock(&state.pending_credentials) = None;
            return Err(error);
        }
    };
    *lock(&state.pending_credentials) = Some(PendingCredentials {
        key,
        password,
        remember,
    });
    handle_auth_outcome(&app, &state, outcome).await
}

#[tauri::command]
async fn challenge_gateway(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    code: SecretString,
) -> Result<AuthView, VpnError> {
    let challenge = lock(&state.challenge)
        .take()
        .ok_or_else(|| protocol_error("当前没有待完成的二次认证"))?;
    let (config, certificate) = lock(&state.pending)
        .as_ref()
        .map(|pending| (pending.config.clone(), pending.certificate.clone()))
        .ok_or_else(|| protocol_error("请先完成证书确认"))?;
    let capabilities = lock(&state.capabilities)
        .clone()
        .ok_or_else(|| protocol_error("请先完成网关发现"))?;
    let options = tls_options(config.clone(), certificate)?;
    let mac_address = local_mac_address(&config.host, config.port);
    let input = V7SecondAuthInput {
        username: "",
        password: "",
        kind: &challenge.kind,
        code: code.expose_secret(),
        dynamic_password: challenge
            .dynamic_password
            .as_ref()
            .map(|password| password.expose_secret()),
        verify_code: "",
        mac_address: &mac_address,
        language: "CN",
    };
    let outcome = challenge_v7(
        &options,
        &capabilities,
        &input,
        challenge
            .session_cookie
            .as_ref()
            .map(|cookie| cookie.expose_secret()),
        operation_token(&state),
    )
    .await;
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            *lock(&state.pending_credentials) = None;
            return Err(error);
        }
    };
    handle_auth_outcome(&app, &state, outcome).await
}

#[tauri::command]
async fn logout_gateway(app: AppHandle, state: tauri::State<'_, AppState>) -> Result<(), VpnError> {
    if let Some(Err(message)) = tunnel::stop(&state).await {
        return Err(network_error(message));
    }
    let session = lock(&state.auth_session).take();
    if let Some(session) = session {
        let pending = lock(&state.pending)
            .as_ref()
            .map(|pending| (pending.config.clone(), pending.certificate.clone()))
            .ok_or_else(|| protocol_error("缺少会话网关配置"))?;
        let options = tls_options(pending.0, pending.1)?;
        if let Err(error) = logout_v7(&options, &session, operation_token(&state)).await {
            *lock(&state.auth_session) = Some(session);
            return Err(error);
        }
    }
    *lock(&state.capabilities) = None;
    *lock(&state.challenge) = None;
    *lock(&state.pending_credentials) = None;
    lock(&state.session).disconnect()?;
    emit_state(&app, lock(&state.session).state())?;
    emit_stage(&app, "disconnected")
}

#[tauri::command]
async fn cancel_gateway(app: AppHandle, state: tauri::State<'_, AppState>) -> Result<(), VpnError> {
    lock(&state.session).cancel()?;
    if let Some(Err(message)) = tunnel::stop(&state).await {
        return Err(network_error(message));
    }
    *lock(&state.pending) = None;
    *lock(&state.capabilities) = None;
    *lock(&state.auth_session) = None;
    *lock(&state.challenge) = None;
    *lock(&state.pending_credentials) = None;
    emit_state(&app, lock(&state.session).state())?;
    emit_stage(&app, "disconnected")
}

#[tauri::command]
async fn start_tunnel(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<AuthView, VpnError> {
    if lock(&state.session).state() == ConnectionState::Connected {
        return Err(VpnError::new(ErrorCode::InvalidState, "隧道已在运行", &[]));
    }
    // 先收拾上一轮主管，避免两个 helper 同时改动网络配置。
    if let Some(Err(message)) = tunnel::stop(&state).await {
        return Err(network_error(message));
    }
    tunnel::tunnel_request(&state)?;
    {
        let session = lock(&state.session);
        match session.state() {
            ConnectionState::Disconnected | ConnectionState::Failed => session.connect()?,
            ConnectionState::Reconnecting => {
                session.fail()?;
                session.connect()?;
            }
            ConnectionState::Connecting => {}
            _ => {
                return Err(VpnError::new(
                    ErrorCode::InvalidState,
                    "当前状态不能建立隧道",
                    &[],
                ));
            }
        }
    }
    emit_state(&app, ConnectionState::Connecting)?;
    emit_stage(&app, "tunnel-starting")?;
    tunnel::start(&app, &state);

    Ok(AuthView {
        stage: "tunnel-starting".to_owned(),
        message: "正在请求权限并建立隧道".to_owned(),
    })
}

#[tauri::command]
async fn stop_tunnel(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<AuthView, VpnError> {
    if let Some(Err(message)) = tunnel::stop(&state).await {
        return Err(network_error(message));
    }
    lock(&state.session).disconnect()?;
    emit_state(&app, lock(&state.session).state())?;
    emit_stage(&app, "authenticated")?;
    Ok(AuthView {
        stage: "authenticated".to_owned(),
        message: "隧道已断开，认证会话仍保留".to_owned(),
    })
}

async fn persist_pending_credentials(state: &AppState) -> Result<Option<bool>, VpnError> {
    let Some(pending) = lock(&state.pending_credentials).take() else {
        return Ok(None);
    };
    let store = state.credentials;
    let remember = pending.remember;
    tokio::task::spawn_blocking(move || {
        if remember {
            store.save(&pending.key, &pending.password)
        } else {
            store.delete(&pending.key)
        }
    })
    .await
    .map_err(|_| VpnError::new(ErrorCode::InternalError, "密钥环任务执行失败", &[]))??;
    Ok(Some(remember))
}

async fn handle_auth_outcome(
    app: &AppHandle,
    state: &AppState,
    outcome: AuthOutcome,
) -> Result<AuthView, VpnError> {
    match outcome {
        AuthOutcome::Success(session) => {
            *lock(&state.auth_session) = Some(session);
            *lock(&state.challenge) = None;
            let mut message = "认证成功；隧道尚未建立".to_owned();
            match persist_pending_credentials(state).await {
                Ok(Some(true)) => message.push_str("；密码已保存到系统密钥环"),
                Ok(Some(false)) => message.push_str("；已删除对应的已保存密码"),
                Ok(None) => {}
                Err(_) => message.push_str("；警告：系统密钥环保存或删除失败"),
            }
            emit_stage(app, "authenticated")?;
            Ok(AuthView {
                stage: "authenticated".to_owned(),
                message,
            })
        }
        AuthOutcome::Challenge(challenge) => {
            let view = AuthView {
                stage: "challenge".to_owned(),
                message: challenge.message.clone(),
            };
            *lock(&state.challenge) = Some(challenge);
            emit_stage(app, "challenge")?;
            Ok(view)
        }
    }
}

fn tls_options(
    config: GatewayConfig,
    certificate: PeerCertificate,
) -> Result<TlsOptions, VpnError> {
    Ok(TlsOptions {
        host: config.host.clone(),
        port: config.port,
        server_name: config.host,
        verify_hostname: certificate
            .common_name
            .clone()
            .ok_or_else(|| protocol_error("网关证书缺少 CN，无法执行主机名校验"))?,
        certificate_pem: certificate.certificate_pem,
        fingerprint: certificate.fingerprint,
        policy: config.tls_policy,
        client_identity: None,
    })
}

fn emit_state(app: &AppHandle, state: ConnectionState) -> Result<(), VpnError> {
    update_window_title(app, state);
    app.emit("vpn-state", state)
        .map_err(|error| VpnError::new(ErrorCode::InternalError, error.to_string(), &[]))
}

/// 窗口标题带上连接状态：应用退到后台时，断线也能一眼看见。
fn update_window_title(app: &AppHandle, state: ConnectionState) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let title = match state {
        ConnectionState::Reconnecting => "HappyWorking VPN · 连接中断，正在重连",
        ConnectionState::Failed => "HappyWorking VPN · 连接已断开",
        _ => "HappyWorking VPN",
    };
    let _ = window.set_title(title);
}

fn emit_stage(app: &AppHandle, stage: &str) -> Result<(), VpnError> {
    app.emit("vpn-stage", stage)
        .map_err(|error| VpnError::new(ErrorCode::InternalError, error.to_string(), &[]))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn network_error(message: impl Into<String>) -> VpnError {
    VpnError::new(ErrorCode::NetworkUnavailable, message, &[])
}

fn operation_token(state: &AppState) -> CancellationToken {
    lock(&state.session).cancellation_token()
}

fn protocol_error(message: &str) -> VpnError {
    VpnError::new(ErrorCode::ProtocolError, message, &[])
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            get_core_state,
            load_saved_credential,
            probe_gateway,
            trust_and_discover,
            login_gateway,
            challenge_gateway,
            start_tunnel,
            stop_tunnel,
            logout_gateway,
            cancel_gateway
        ])
        .build(tauri::generate_context!())
        .expect("构建 Tauri 应用失败");

    app.run(|app, event| {
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
            let state = app.state::<AppState>();
            if let Some(supervisor) = lock(&state.supervisor).take() {
                supervisor.cancel();
            }
            let _ = state.session.lock().map(|session| session.cancel());
        }
    });
}
