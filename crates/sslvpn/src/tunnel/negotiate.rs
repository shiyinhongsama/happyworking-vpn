use happyworking_vpn_core::{ErrorCode, VpnError};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_openssl::SslStream;
use tokio_util::sync::CancellationToken;

use crate::{HttpRequest, TlsOptions, http, tls};

use super::TunnelConfig;

pub struct TunnelConnection {
    pub stream: SslStream<TcpStream>,
    pub config: TunnelConfig,
    pub initial_data: Vec<u8>,
}

pub async fn negotiate_v7(
    options: &TlsOptions,
    session_cookie: &str,
    cancellation: CancellationToken,
) -> Result<TunnelConnection, VpnError> {
    negotiate(options, Some(session_cookie), true, cancellation).await
}

pub async fn negotiate_v3(
    options: &TlsOptions,
    user_id: &str,
    cancellation: CancellationToken,
) -> Result<TunnelConnection, VpnError> {
    negotiate(options, Some(user_id), false, cancellation).await
}

async fn negotiate(
    options: &TlsOptions,
    session: Option<&str>,
    v7: bool,
    cancellation: CancellationToken,
) -> Result<TunnelConnection, VpnError> {
    let operation = async {
        let mut request = HttpRequest::new("NET_EXTEND", "/")?;
        request.omit_connection_header();
        if v7 {
            request.header("User-Agent", "SSLVPN-Client/7.0")?;
        }
        if let Some(session) = session {
            let value = if v7 {
                format!("svpnginfo={session}")
            } else {
                session.to_owned()
            };
            request.header("Cookie", &value)?;
        }

        let mut stream = tls::connect(options).await?;
        stream
            .write_all(&request.to_bytes(&options.host)?)
            .await
            .map_err(|error| {
                VpnError::new(ErrorCode::NetworkUnavailable, error.to_string(), &[])
            })?;
        let result = http::read(&mut stream, cancellation.clone()).await?;
        let config = TunnelConfig::parse(&result.response)?;
        Ok(TunnelConnection {
            stream,
            config,
            initial_data: result.remaining,
        })
    };

    tokio::select! {
        result = operation => result,
        () = cancellation.cancelled() => {
            Err(VpnError::new(ErrorCode::Cancelled, "隧道协商已取消", &[]))
        }
    }
}
