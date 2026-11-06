use bytes::{Buf, BytesMut};
use happyworking_vpn_core::{ErrorCode, VpnError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelFrame {
    IpPacket(Vec<u8>),
    Heartbeat,
    NetworkConfig { extension: u8, data: Vec<u8> },
    Logoff,
}

pub struct FrameDecoder {
    buffer: BytesMut,
    max_frame_size: usize,
}

impl FrameDecoder {
    pub fn new(max_frame_size: usize) -> Self {
        Self {
            buffer: BytesMut::new(),
            max_frame_size,
        }
    }

    pub fn push(&mut self, input: &[u8]) -> Result<Vec<TunnelFrame>, VpnError> {
        self.buffer.extend_from_slice(input);
        let mut frames = Vec::new();
        loop {
            if self.buffer.len() < 4 {
                break;
            }
            let length = u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as usize;
            if length > self.max_frame_size {
                return Err(frame_error("隧道帧超过大小限制"));
            }
            let frame_size = length + 4;
            if self.buffer.len() < frame_size {
                break;
            }

            let packet_type = self.buffer[0];
            let extension = self.buffer[1];
            self.buffer.advance(4);
            let data = self.buffer.split_to(length).to_vec();
            match packet_type {
                1 => frames.push(TunnelFrame::IpPacket(data)),
                2 => frames.push(TunnelFrame::Heartbeat),
                3 => frames.push(TunnelFrame::NetworkConfig { extension, data }),
                4 => frames.push(TunnelFrame::Logoff),
                _ => return Err(frame_error("未知隧道帧类型")),
            }
        }
        Ok(frames)
    }
}

pub fn encode_ip_frame(packet: &[u8]) -> Result<Vec<u8>, VpnError> {
    if packet.is_empty() || packet.len() > u16::MAX as usize {
        return Err(frame_error("IP 数据包长度无效"));
    }
    let mut frame = Vec::with_capacity(packet.len() + 4);
    frame.extend_from_slice(&[1, 0]);
    frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    frame.extend_from_slice(packet);
    Ok(frame)
}

pub fn heartbeat_frame() -> [u8; 4] {
    [2, 1, 0, 0]
}

fn frame_error(message: &str) -> VpnError {
    VpnError::new(ErrorCode::ProtocolError, message, &[])
}
