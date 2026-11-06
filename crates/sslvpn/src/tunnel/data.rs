use happyworking_vpn_core::{ErrorCode, VpnError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::{
    FrameDecoder, TunnelConfig, TunnelConnection, TunnelFrame, encode_ip_frame, heartbeat_frame,
};

pub struct DataPlaneOptions {
    pub config: TunnelConfig,
    pub initial_data: Vec<u8>,
}

pub async fn forward_connection<T, F>(
    connection: TunnelConnection,
    tun: T,
    cancellation: CancellationToken,
    on_config: F,
) -> Result<(), VpnError>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(TunnelConfig) -> Result<(), VpnError>,
{
    let TunnelConnection {
        stream,
        config,
        initial_data,
    } = connection;
    forward_streams(
        stream,
        tun,
        DataPlaneOptions {
            config,
            initial_data,
        },
        cancellation,
        on_config,
    )
    .await
}

pub async fn forward_streams<S, T, F>(
    mut tls: S,
    mut tun: T,
    options: DataPlaneOptions,
    cancellation: CancellationToken,
    mut on_config: F,
) -> Result<(), VpnError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(TunnelConfig) -> Result<(), VpnError>,
{
    let mut decoder = FrameDecoder::new(u16::MAX as usize);
    if !options.initial_data.is_empty() {
        let frames = decoder.push(&options.initial_data)?;
        if frames
            .iter()
            .any(|frame| matches!(frame, TunnelFrame::Logoff))
        {
            return Ok(());
        }
        process_frames(frames, &mut tun, &mut on_config).await?;
    }

    let heartbeat_enabled = options.config.keepalive_seconds > 0;
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(
        options.config.keepalive_seconds.max(1) as u64,
    ));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;

    let mut tls_buffer = [0_u8; 8192];
    let mut tun_buffer = vec![0_u8; u16::MAX as usize];
    loop {
        tokio::select! {
            result = tls.read(&mut tls_buffer) => {
                let count = result.map_err(io_error)?;
                if count == 0 {
                    return Err(VpnError::new(ErrorCode::NetworkUnavailable, "TLS 隧道已关闭", &[]));
                }
                let frames = decoder.push(&tls_buffer[..count])?;
                if frames.iter().any(|frame| matches!(frame, TunnelFrame::Logoff)) {
                return Ok(());
            }
            process_frames(frames, &mut tun, &mut on_config).await?;
            }
            result = tun.read(&mut tun_buffer) => {
                let count = result.map_err(io_error)?;
                if count == 0 {
                    return Err(VpnError::new(ErrorCode::NetworkUnavailable, "TUN 接口已关闭", &[]));
                }
                let frame = encode_ip_frame(&tun_buffer[..count])?;
                tls.write_all(&frame).await.map_err(io_error)?;
            }
            _ = heartbeat.tick(), if heartbeat_enabled => {
                tls.write_all(&heartbeat_frame()).await.map_err(io_error)?;
            }
            () = cancellation.cancelled() => {
                return Ok(());
            }
        }
    }
}

async fn process_frames<T, F>(
    frames: Vec<TunnelFrame>,
    tun: &mut T,
    on_config: &mut F,
) -> Result<(), VpnError>
where
    T: AsyncWrite + Unpin,
    F: FnMut(TunnelConfig) -> Result<(), VpnError>,
{
    for frame in frames {
        match frame {
            TunnelFrame::IpPacket(packet) => {
                tun.write_all(&packet).await.map_err(io_error)?;
            }
            TunnelFrame::Heartbeat => {}
            TunnelFrame::NetworkConfig { extension: 2, data } => {
                on_config(TunnelConfig::parse_body(&data)?)?;
            }
            TunnelFrame::NetworkConfig { .. } => {}
            TunnelFrame::Logoff => {}
        }
    }
    Ok(())
}

fn io_error(error: std::io::Error) -> VpnError {
    VpnError::new(ErrorCode::NetworkUnavailable, error.to_string(), &[])
}
