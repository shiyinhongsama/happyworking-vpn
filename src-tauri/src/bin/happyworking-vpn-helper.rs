use std::{
    io::{Read, Write},
    net::Ipv4Addr,
    os::fd::FromRawFd,
    pin::Pin,
    process::ExitCode,
    task::{Context, Poll, ready},
};

use happyworking_vpn_core::{ErrorCode, TlsPolicy, VpnError};
use happyworking_vpn_netops::{LinuxNetworkBackend, NetworkOperation, NetworkTransaction};
use happyworking_vpn_sslvpn::{TunnelConfig, TunnelRoute, forward_connection, negotiate_v7};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader, ReadBuf};
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
struct HelperRequest {
    host: String,
    port: u16,
    verify_hostname: String,
    certificate_pem: String,
    fingerprint: String,
    legacy_tls: bool,
    session_cookie: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HelperStatus<'a> {
    kind: &'a str,
    interface: &'a str,
    address: Ipv4Addr,
}

struct TunAsyncFd(tokio::io::unix::AsyncFd<std::fs::File>);

impl TunAsyncFd {
    fn new(file: std::fs::File) -> std::io::Result<Self> {
        let fd = std::os::fd::AsRawFd::as_raw_fd(&file);
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(unsafe { tokio::io::unix::AsyncFd::register(file)? }))
    }
}

impl AsyncRead for TunAsyncFd {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            let mut guard = ready!(self.0.poll_read_ready(context))?;
            let unfilled = buffer.initialize_unfilled();
            match guard.try_io(|inner| inner.get_ref().read(unfilled)) {
                Ok(Ok(count)) => {
                    buffer.advance(count);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => continue,
            }
        }
    }
}

impl AsyncWrite for TunAsyncFd {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            let mut guard = ready!(self.0.poll_write_ready(context))?;
            match guard.try_io(|inner| inner.get_ref().write(buffer)) {
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // 结构化错误走标准输出，父进程据此判断是否值得自动重试。
            let status = serde_json::json!({
                "kind": "error",
                "code": error.code(),
                "message": error.message(),
            });
            println!("{status}");
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), VpnError> {
    let mut control = BufReader::new(tokio::io::stdin());
    let mut input = String::new();
    control.read_line(&mut input).await.map_err(io_error)?;
    let request: HelperRequest =
        serde_json::from_str(&input).map_err(|_| network_error("helper 请求格式无效"))?;
    let host_ip = request
        .host
        .parse::<Ipv4Addr>()
        .map_err(|_| network_error("helper 目前要求 IPv4 网关"))?;
    let options = happyworking_vpn_sslvpn::TlsOptions {
        host: request.host.clone(),
        port: request.port,
        server_name: request.host.clone(),
        verify_hostname: request.verify_hostname,
        certificate_pem: request.certificate_pem.into_bytes(),
        fingerprint: request
            .fingerprint
            .parse::<happyworking_vpn_core::CertificateFingerprint>()
            .map_err(|error| network_error(error.to_string()))?,
        policy: if request.legacy_tls {
            TlsPolicy::Legacy
        } else {
            TlsPolicy::Modern
        },
        client_identity: None,
    };
    let cancellation = CancellationToken::new();
    let connection = negotiate_v7(&options, &request.session_cookie, cancellation.clone()).await?;
    let interface = format!("omvpn{}", std::process::id());
    let mut transaction = NetworkTransaction::new(LinuxNetworkBackend::new());
    apply_config(
        &mut transaction,
        &interface,
        host_ip,
        None,
        &connection.config,
    )?;
    let fd = transaction
        .backend_mut()
        .take_tun_fd()
        .ok_or_else(|| network_error("TUN 文件描述符不存在"))?;
    let raw_fd = std::os::fd::AsRawFd::as_raw_fd(&fd);
    let interface_fd = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if interface_fd < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    let interface_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(interface_fd) };
    let tun = TunAsyncFd::new(std::fs::File::from(fd)).map_err(io_error)?;
    let status = HelperStatus {
        kind: "connected",
        interface: &interface,
        address: connection.config.address,
    };
    println!("{}", serde_json::to_string(&status).unwrap());

    let mut current_config = connection.config.clone();
    let forward = forward_connection(connection, tun, cancellation.clone(), |updated| {
        apply_config(
            &mut transaction,
            &interface,
            host_ip,
            Some(&current_config),
            &updated,
        )?;
        current_config = updated;
        Ok(())
    });
    let interrupt = async {
        #[cfg(unix)]
        {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! {
                result = tokio::signal::ctrl_c() => result,
                _ = terminate.recv() => Ok(()),
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await
        }
    };
    let disconnect = wait_for_disconnect(&mut control);

    let result = tokio::select! {
        result = forward => result,
        result = interrupt => result.map_err(io_error),
        result = disconnect => result,
    };
    cancellation.cancel();
    let rollback_result = transaction.rollback();
    drop(interface_fd);
    result?;
    rollback_result?;
    Ok(())
}

async fn wait_for_disconnect<R: tokio::io::AsyncBufRead + Unpin>(
    input: &mut R,
) -> Result<(), VpnError> {
    let mut command = String::new();
    if input.read_line(&mut command).await.map_err(io_error)? == 0 || command.trim() == "disconnect"
    {
        Ok(())
    } else {
        Err(network_error("helper 控制命令无效"))
    }
}

fn apply_config<B: happyworking_vpn_netops::NetworkBackend>(
    transaction: &mut NetworkTransaction<B>,
    interface: &str,
    gateway: Ipv4Addr,
    previous: Option<&TunnelConfig>,
    config: &TunnelConfig,
) -> Result<(), VpnError> {
    if let Some(previous) = previous {
        if previous.gateway != config.gateway {
            return Err(network_error("网关地址在会话中发生变化"));
        }
    }

    if previous.is_none() {
        transaction.apply(NetworkOperation::CreateTun {
            name: interface.to_owned(),
        })?;
    }
    if previous.is_none()
        || previous.is_some_and(|old| old.address != config.address || old.prefix != config.prefix)
    {
        transaction.apply(NetworkOperation::SetAddress {
            interface: interface.to_owned(),
            address: config.address,
            prefix: config.prefix,
        })?;
    }

    if previous.is_none() {
        let physical = physical_route(gateway)?;
        transaction.apply(NetworkOperation::AddRoute {
            network: gateway,
            prefix: 32,
            interface: physical.interface.clone(),
            gateway: physical.gateway,
        })?;
        for route in &config.exclude_routes {
            transaction.apply(route_operation(
                route,
                &physical.interface,
                physical.gateway,
                false,
            ))?;
        }
    }

    let old_routes = previous
        .map(|old| old.routes.as_slice())
        .unwrap_or_default();
    for route in &config.routes {
        if !old_routes.contains(route) {
            transaction.apply(route_operation(route, interface, None, false))?;
        }
    }
    for route in old_routes {
        if !config.routes.contains(route) {
            transaction.apply(route_operation(route, interface, None, true))?;
        }
    }

    if config.restrict && !previous.is_some_and(|old| old.restrict) {
        transaction.apply(NetworkOperation::AddRoute {
            network: Ipv4Addr::UNSPECIFIED,
            prefix: 0,
            interface: interface.to_owned(),
            gateway: None,
        })?;
    }
    if previous.is_some_and(|old| old.restrict) && !config.restrict {
        transaction.apply(NetworkOperation::RemoveRoute {
            network: Ipv4Addr::UNSPECIFIED,
            prefix: 0,
            interface: interface.to_owned(),
            gateway: None,
        })?;
    }

    if previous.is_none() || previous.is_some_and(|old| old.dns != config.dns) {
        transaction.apply(NetworkOperation::SetDns {
            interface: interface.to_owned(),
            servers: config.dns.clone(),
        })?;
    }
    Ok(())
}

struct PhysicalRoute {
    interface: String,
    gateway: Option<Ipv4Addr>,
}

fn physical_route(gateway: Ipv4Addr) -> Result<PhysicalRoute, VpnError> {
    let output = std::process::Command::new("ip")
        .args(["-o", "route", "get", &gateway.to_string()])
        .output()
        .map_err(io_error)?;
    if !output.status.success() {
        return Err(network_error("无法查询 VPN 网关的物理路由"));
    }
    let text =
        String::from_utf8(output.stdout).map_err(|_| network_error("物理路由响应不是 UTF-8"))?;
    let words: Vec<&str> = text.split_whitespace().collect();
    let interface =
        value_after(&words, "dev").ok_or_else(|| network_error("物理路由缺少输出接口"))?;
    let gateway = value_after(&words, "via")
        .map(|value| value.parse())
        .transpose()
        .map_err(|_| network_error("物理路由网关无效"))?;
    Ok(PhysicalRoute {
        interface: interface.to_owned(),
        gateway,
    })
}

fn value_after<'a>(words: &'a [&str], key: &str) -> Option<&'a str> {
    words
        .iter()
        .position(|word| *word == key)
        .and_then(|index| words.get(index + 1))
        .copied()
}

fn route_operation(
    route: &TunnelRoute,
    interface: &str,
    gateway: Option<Ipv4Addr>,
    remove: bool,
) -> NetworkOperation {
    if remove {
        NetworkOperation::RemoveRoute {
            network: route.network,
            prefix: route.prefix,
            interface: interface.to_owned(),
            gateway,
        }
    } else {
        NetworkOperation::AddRoute {
            network: route.network,
            prefix: route.prefix,
            interface: interface.to_owned(),
            gateway,
        }
    }
}

fn io_error(error: std::io::Error) -> VpnError {
    VpnError::new(ErrorCode::NetworkUnavailable, error.to_string(), &[])
}

fn network_error(message: impl Into<String>) -> VpnError {
    VpnError::new(ErrorCode::NetworkUnavailable, message, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeBackend {
        operations: Vec<NetworkOperation>,
    }

    impl happyworking_vpn_netops::NetworkBackend for FakeBackend {
        fn apply(&mut self, operation: &NetworkOperation) -> Result<(), VpnError> {
            self.operations.push(operation.clone());
            Ok(())
        }

        fn rollback(&mut self, _operation: &NetworkOperation) -> Result<(), VpnError> {
            Ok(())
        }
    }

    fn config() -> TunnelConfig {
        TunnelConfig {
            address: "10.1.2.3".parse().unwrap(),
            prefix: 24,
            gateway: "10.1.2.1".parse().unwrap(),
            routes: vec![TunnelRoute {
                network: "10.0.0.0".parse().unwrap(),
                prefix: 8,
            }],
            exclude_routes: Vec::new(),
            dns: vec!["10.1.1.1".parse().unwrap()],
            restrict: false,
            keepalive_seconds: 30,
        }
    }

    #[tokio::test]
    async fn accepts_disconnect_command() {
        let mut input = BufReader::new(&b"disconnect\n"[..]);

        wait_for_disconnect(&mut input).await.unwrap();
    }

    #[tokio::test]
    async fn treats_closed_control_channel_as_disconnect() {
        let mut input = BufReader::new(&b""[..]);

        wait_for_disconnect(&mut input).await.unwrap();
    }

    #[test]
    fn applies_only_dynamic_configuration_changes() {
        let previous = config();
        let mut updated = previous.clone();
        updated.address = "10.1.2.4".parse().unwrap();
        updated.routes = vec![TunnelRoute {
            network: "172.16.0.0".parse().unwrap(),
            prefix: 16,
        }];
        updated.dns = vec!["10.1.1.2".parse().unwrap()];
        updated.restrict = true;
        let mut transaction = NetworkTransaction::new(FakeBackend::default());

        apply_config(
            &mut transaction,
            "omvpn-test",
            "192.0.2.1".parse().unwrap(),
            Some(&previous),
            &updated,
        )
        .unwrap();

        let operations = &transaction.backend().operations;
        assert!(operations.iter().any(|operation| matches!(
            operation,
            NetworkOperation::AddRoute { network, prefix: 16, .. }
                if *network == "172.16.0.0".parse::<Ipv4Addr>().unwrap()
        )));
        assert!(operations.iter().any(|operation| matches!(
            operation,
            NetworkOperation::RemoveRoute { network, prefix: 8, .. }
                if *network == "10.0.0.0".parse::<Ipv4Addr>().unwrap()
        )));
        assert!(
            operations
                .iter()
                .any(|operation| matches!(operation, NetworkOperation::AddRoute { prefix: 0, .. }))
        );
        assert!(operations.iter().any(|operation| matches!(
            operation,
            NetworkOperation::SetDns { servers, .. } if servers == &updated.dns
        )));
        assert!(
            !operations
                .iter()
                .any(|operation| matches!(operation, NetworkOperation::CreateTun { .. }))
        );
    }
}
