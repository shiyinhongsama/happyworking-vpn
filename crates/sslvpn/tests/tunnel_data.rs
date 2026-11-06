use std::time::Duration;

use happyworking_vpn_sslvpn::{
    DataPlaneOptions, TunnelConfig, encode_ip_frame, forward_streams, heartbeat_frame,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_util::sync::CancellationToken;

fn config(keepalive_seconds: u32) -> TunnelConfig {
    TunnelConfig {
        address: "10.1.2.3".parse().unwrap(),
        prefix: 24,
        gateway: "10.1.2.1".parse().unwrap(),
        routes: Vec::new(),
        exclude_routes: Vec::new(),
        dns: Vec::new(),
        restrict: false,
        keepalive_seconds,
    }
}

fn options(config: &TunnelConfig) -> DataPlaneOptions {
    DataPlaneOptions {
        config: config.clone(),
        initial_data: Vec::new(),
    }
}

fn duplex() -> (DuplexStream, DuplexStream, DuplexStream, DuplexStream) {
    let (tls_client, tls_server) = tokio::io::duplex(64 * 1024);
    let (tun_client, tun_server) = tokio::io::duplex(64 * 1024);
    (tls_client, tls_server, tun_client, tun_server)
}

#[tokio::test]
async fn forwards_packets_in_both_directions() {
    let (tls_client, mut tls_server, tun_client, mut tun_server) = duplex();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(forward_streams(
        tls_client,
        tun_client,
        options(&config(0)),
        cancellation.clone(),
        |_| Ok(()),
    ));

    tls_server
        .write_all(&encode_ip_frame(&[1, 2, 3]).unwrap())
        .await
        .unwrap();
    let mut packet = [0_u8; 3];
    tun_server.read_exact(&mut packet).await.unwrap();
    assert_eq!(packet, [1, 2, 3]);

    tun_server.write_all(&[4, 5, 6]).await.unwrap();
    let mut frame = [0_u8; 7];
    tls_server.read_exact(&mut frame).await.unwrap();
    assert_eq!(frame, [1, 0, 0, 3, 4, 5, 6]);

    cancellation.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn sends_heartbeats_and_applies_configuration_updates() {
    tokio::time::pause();
    let (tls_client, mut tls_server, tun_client, _tun_server) = duplex();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(forward_streams(
        tls_client,
        tun_client,
        options(&config(1)),
        cancellation.clone(),
        |config| {
            assert_eq!(config.keepalive_seconds, 45);
            Ok(())
        },
    ));

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    let mut heartbeat = [0_u8; 4];
    tls_server.read_exact(&mut heartbeat).await.unwrap();
    assert_eq!(heartbeat, heartbeat_frame());

    let body =
        b"IPADDRESS: 10.1.2.4\r\nSUBNETMASK: 24\r\nGATEWAY: 10.1.2.1\r\nKEEPALIVETIME: 45\r\n";
    let mut frame = vec![3, 2];
    frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
    frame.extend_from_slice(body);
    tls_server.write_all(&frame).await.unwrap();
    tokio::task::yield_now().await;

    cancellation.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn stops_cleanly_when_gateway_requests_logoff() {
    let (tls_client, mut tls_server, tun_client, _tun_server) = duplex();
    let task = tokio::spawn(forward_streams(
        tls_client,
        tun_client,
        options(&config(0)),
        CancellationToken::new(),
        |_| Ok(()),
    ));

    tls_server.write_all(&[4, 0, 0, 0]).await.unwrap();
    task.await.unwrap().unwrap();
}

#[test]
fn reconnect_backoff_is_bounded_and_resettable() {
    let mut backoff = happyworking_vpn_sslvpn::ReconnectBackoff::new(100, 350).unwrap();

    assert_eq!(backoff.next_delay(), Duration::from_millis(100));
    assert_eq!(backoff.next_delay(), Duration::from_millis(200));
    assert_eq!(backoff.next_delay(), Duration::from_millis(350));
    assert_eq!(backoff.next_delay(), Duration::from_millis(350));
    backoff.reset();
    assert_eq!(backoff.next_delay(), Duration::from_millis(100));
}

#[tokio::test]
async fn reconnect_wait_can_be_cancelled() {
    tokio::time::pause();
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    let task = tokio::spawn(async move {
        let mut backoff = happyworking_vpn_sslvpn::ReconnectBackoff::new(1000, 2000).unwrap();
        happyworking_vpn_sslvpn::wait_for_reconnect(&mut backoff, task_cancellation).await
    });
    tokio::task::yield_now().await;

    cancellation.cancel();

    assert!(task.await.unwrap().is_err());
}
