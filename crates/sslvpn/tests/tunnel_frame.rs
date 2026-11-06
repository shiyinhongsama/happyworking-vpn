use happyworking_vpn_sslvpn::{FrameDecoder, TunnelFrame, encode_ip_frame, heartbeat_frame};

#[test]
fn encodes_ip_and_heartbeat_frames() {
    assert_eq!(encode_ip_frame(&[1, 2, 3]).unwrap(), [1, 0, 0, 3, 1, 2, 3]);
    assert_eq!(heartbeat_frame(), [2, 1, 0, 0]);
}

#[test]
fn decodes_partial_and_coalesced_frames() {
    let mut decoder = FrameDecoder::new(1500);
    let first = encode_ip_frame(&[10, 11]).unwrap();
    let second = encode_ip_frame(&[20, 21]).unwrap();
    let mut wire = first.clone();
    wire.extend_from_slice(&heartbeat_frame());
    wire.extend_from_slice(&second);

    assert!(decoder.push(&wire[..3]).unwrap().is_empty());
    let frames = decoder.push(&wire[3..]).unwrap();

    assert_eq!(frames.len(), 3);
    assert!(matches!(&frames[0], TunnelFrame::IpPacket(packet) if packet == &[10, 11]));
    assert!(matches!(frames[1], TunnelFrame::Heartbeat));
    assert!(matches!(&frames[2], TunnelFrame::IpPacket(packet) if packet == &[20, 21]));
}

#[test]
fn decodes_network_configuration_frames() {
    let mut decoder = FrameDecoder::new(1500);
    let frames = decoder.push(&[3, 2, 0, 4, b'I', b'P', b'A', b'M']).unwrap();

    assert!(matches!(
        &frames[0],
        TunnelFrame::NetworkConfig { extension: 2, data } if data == b"IPAM"
    ));
}

#[test]
fn accepts_heartbeat_payloads_and_gateway_logoff() {
    let mut decoder = FrameDecoder::new(1500);
    let frames = decoder.push(&[2, 1, 0, 4, 1, 2, 3, 4, 4, 0, 0, 0]).unwrap();

    assert!(matches!(frames[0], TunnelFrame::Heartbeat));
    assert!(matches!(frames[1], TunnelFrame::Logoff));
}

#[test]
fn rejects_invalid_frames_and_oversized_packets() {
    let mut decoder = FrameDecoder::new(1500);
    assert!(decoder.push(&[9, 0, 0, 0]).is_err());
    assert!(encode_ip_frame(&vec![0; 65536]).is_err());
    assert!(encode_ip_frame(&[]).is_err());

    let mut decoder = FrameDecoder::new(2);
    assert!(decoder.push(&encode_ip_frame(&[1, 2, 3]).unwrap()).is_err());
}
