use std::{
    collections::BTreeMap,
    ffi::CString,
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::Command,
};

use happyworking_vpn_core::{ErrorCode, VpnError};

use crate::{NetworkBackend, NetworkOperation};

#[repr(C)]
struct IfReq {
    name: [i8; 16],
    data: [u8; 24],
}

pub struct LinuxNetworkBackend {
    tun: Option<OwnedFd>,
    previous_flags: BTreeMap<String, i16>,
}

impl Default for LinuxNetworkBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxNetworkBackend {
    pub fn new() -> Self {
        Self {
            tun: None,
            previous_flags: BTreeMap::new(),
        }
    }

    pub fn tun_fd(&self) -> Option<i32> {
        self.tun.as_ref().map(AsRawFd::as_raw_fd)
    }

    pub fn take_tun_fd(&mut self) -> Option<OwnedFd> {
        self.tun.take()
    }
}

impl NetworkBackend for LinuxNetworkBackend {
    fn apply(&mut self, operation: &NetworkOperation) -> Result<(), VpnError> {
        match operation {
            NetworkOperation::CreateTun { name } => {
                self.tun = Some(create_tun(name)?);
                Ok(())
            }
            NetworkOperation::SetAddress {
                interface,
                address,
                prefix,
            } => set_address(interface, *address, *prefix, &mut self.previous_flags),
            NetworkOperation::AddRoute {
                network,
                prefix,
                interface,
                gateway,
            } => change_route(*network, *prefix, interface, *gateway, false),
            NetworkOperation::RemoveRoute {
                network,
                prefix,
                interface,
                gateway,
            } => change_route(*network, *prefix, interface, *gateway, true),
            NetworkOperation::SetDns { interface, servers } => set_dns(Some(interface), servers),
        }
    }

    fn rollback(&mut self, operation: &NetworkOperation) -> Result<(), VpnError> {
        match operation {
            NetworkOperation::CreateTun { .. } => {
                self.tun = None;
                Ok(())
            }
            NetworkOperation::SetAddress { interface, .. } => {
                restore_flags(interface, self.previous_flags.remove(interface))
            }
            NetworkOperation::AddRoute {
                network,
                prefix,
                interface,
                gateway,
            } => change_route(*network, *prefix, interface, *gateway, true),
            NetworkOperation::RemoveRoute {
                network,
                prefix,
                interface,
                gateway,
            } => change_route(*network, *prefix, interface, *gateway, false),
            NetworkOperation::SetDns { interface, .. } => revert_dns(Some(interface)),
        }
    }
}

fn tun_flag_bytes() -> [u8; 2] {
    ((libc::IFF_TUN | libc::IFF_NO_PI) as i16).to_ne_bytes()
}

fn create_tun(name: &str) -> Result<OwnedFd, VpnError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .map_err(io_error)?;
    let fd = file.as_raw_fd();
    let mut request = interface_request(name)?;
    request.data[..2].copy_from_slice(&tun_flag_bytes());
    if unsafe { libc::ioctl(fd, libc::TUNSETIFF, &mut request) } < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    Ok(file.into())
}

fn set_address(
    interface: &str,
    address: Ipv4Addr,
    prefix: u8,
    previous_flags: &mut BTreeMap<String, i16>,
) -> Result<(), VpnError> {
    if prefix > 32 {
        return Err(network_error("IPv4 前缀无效"));
    }
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };

    let flags = interface_flags(socket.as_raw_fd(), interface)?;
    previous_flags.entry(interface.to_owned()).or_insert(flags);
    set_interface_address(socket.as_raw_fd(), interface, address, libc::SIOCSIFADDR)?;
    let mask = if prefix == 0 {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::from(u32::MAX << (32 - prefix))
    };
    set_interface_address(socket.as_raw_fd(), interface, mask, libc::SIOCSIFNETMASK)?;

    let mut request = interface_request(interface)?;
    request.data[..4].copy_from_slice(&1400_i32.to_ne_bytes());
    ioctl_request(socket.as_raw_fd(), libc::SIOCSIFMTU, &mut request)?;

    let mut request = interface_request(interface)?;
    let up = flags | libc::IFF_UP as i16;
    request.data[..2].copy_from_slice(&up.to_ne_bytes());
    ioctl_request(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &mut request)
}

fn restore_flags(interface: &str, flags: Option<i16>) -> Result<(), VpnError> {
    let Some(flags) = flags else {
        return Ok(());
    };
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    let mut request = interface_request(interface)?;
    request.data[..2].copy_from_slice(&flags.to_ne_bytes());
    ioctl_request(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &mut request)
}

fn interface_flags(fd: i32, interface: &str) -> Result<i16, VpnError> {
    let mut request = interface_request(interface)?;
    ioctl_request(fd, libc::SIOCGIFFLAGS, &mut request)?;
    Ok(i16::from_ne_bytes(request.data[..2].try_into().unwrap()))
}

fn set_interface_address(
    fd: i32,
    interface: &str,
    address: Ipv4Addr,
    request_code: libc::c_ulong,
) -> Result<(), VpnError> {
    let mut request = interface_request(interface)?;
    let socket = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.octets()),
        },
        sin_zero: [0; 8],
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &socket as *const libc::sockaddr_in as *const u8,
            std::mem::size_of::<libc::sockaddr_in>(),
        )
    };
    request.data[..bytes.len()].copy_from_slice(bytes);
    ioctl_request(fd, request_code, &mut request)
}

fn interface_request(interface: &str) -> Result<IfReq, VpnError> {
    if interface.is_empty() || interface.len() >= 16 || interface.contains('/') {
        return Err(network_error("网络接口名称无效"));
    }
    let mut request = IfReq {
        name: [0; 16],
        data: [0; 24],
    };
    for (target, source) in request.name.iter_mut().zip(interface.bytes()) {
        *target = source as i8;
    }
    Ok(request)
}

fn ioctl_request(fd: i32, code: libc::c_ulong, request: &mut IfReq) -> Result<(), VpnError> {
    if unsafe { libc::ioctl(fd, code, request) } < 0 {
        Err(io_error(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn change_route(
    network: Ipv4Addr,
    prefix: u8,
    interface: &str,
    gateway: Option<Ipv4Addr>,
    delete: bool,
) -> Result<(), VpnError> {
    let name = CString::new(interface).map_err(|_| network_error("网络接口名称无效"))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    let message = route_message(network, prefix, index, gateway, delete)?;
    let socket = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if socket < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    let mut local: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    local.nl_family = libc::AF_NETLINK as u16;
    if unsafe {
        libc::bind(
            socket.as_raw_fd(),
            &local as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    } < 0
    {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            message.as_ptr() as *const libc::c_void,
            message.len(),
            0,
            &kernel as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if sent < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    let mut response = [0_u8; 4096];
    let received = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            response.as_mut_ptr() as *mut libc::c_void,
            response.len(),
            0,
        )
    };
    if received < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    if received >= 20 {
        let code = i32::from_ne_bytes(response[16..20].try_into().unwrap());
        if code < 0 {
            return Err(io_error(std::io::Error::from_raw_os_error(-code)));
        }
    }
    Ok(())
}

fn route_message(
    network: Ipv4Addr,
    prefix: u8,
    interface_index: u32,
    gateway: Option<Ipv4Addr>,
    delete: bool,
) -> Result<Vec<u8>, VpnError> {
    if prefix > 32 {
        return Err(network_error("IPv4 前缀无效"));
    }
    let mut message = vec![0_u8; 28];
    let kind = if delete {
        libc::RTM_DELROUTE
    } else {
        libc::RTM_NEWROUTE
    };
    let flags = if delete {
        libc::NLM_F_REQUEST | libc::NLM_F_ACK
    } else {
        libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL
    };
    message[4..6].copy_from_slice(&kind.to_ne_bytes());
    message[6..8].copy_from_slice(&(flags as u16).to_ne_bytes());
    message[12..16].copy_from_slice(&1_u32.to_ne_bytes());
    message[16] = libc::AF_INET as u8;
    message[17] = prefix;
    message[20] = libc::RT_TABLE_MAIN;
    message[21] = libc::RTPROT_BOOT;
    message[22] = libc::RT_SCOPE_UNIVERSE;
    message[23] = libc::RTN_UNICAST;
    push_route_attribute(&mut message, libc::RTA_DST, &network.octets());
    if let Some(gateway) = gateway {
        push_route_attribute(&mut message, libc::RTA_GATEWAY, &gateway.octets());
    }
    push_route_attribute(&mut message, libc::RTA_OIF, &interface_index.to_ne_bytes());
    let length = message.len() as u32;
    message[..4].copy_from_slice(&length.to_ne_bytes());
    Ok(message)
}

fn push_route_attribute(message: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = (4 + value.len()) as u16;
    message.extend_from_slice(&length.to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(value);
    while message.len() % 4 != 0 {
        message.push(0);
    }
}

fn set_dns(interface: Option<&str>, servers: &[Ipv4Addr]) -> Result<(), VpnError> {
    let interface = interface.ok_or_else(|| network_error("DNS 配置缺少接口"))?;
    if servers.is_empty() {
        return revert_dns(Some(interface));
    }
    let mut command = Command::new("resolvectl");
    command.arg("dns").arg(interface);
    command.args(servers.iter().map(ToString::to_string));
    run_command(command)
}

fn revert_dns(interface: Option<&str>) -> Result<(), VpnError> {
    let interface = interface.ok_or_else(|| network_error("DNS 回滚缺少接口"))?;
    let mut command = Command::new("resolvectl");
    command.args(["revert", interface]);
    run_command(command)
}

fn run_command(mut command: Command) -> Result<(), VpnError> {
    let status = command.status().map_err(io_error)?;
    if status.success() {
        Ok(())
    } else {
        Err(network_error(format!("系统网络工具返回 {status}")))
    }
}

fn io_error(error: std::io::Error) -> VpnError {
    let code = if error.kind() == std::io::ErrorKind::PermissionDenied {
        ErrorCode::PermissionDenied
    } else {
        ErrorCode::NetworkUnavailable
    };
    VpnError::new(code, error.to_string(), &[])
}

fn network_error(message: impl Into<String>) -> VpnError {
    VpnError::new(ErrorCode::NetworkUnavailable, message, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_message_contains_destination_and_output_interface() {
        let message = route_message(Ipv4Addr::new(172, 16, 0, 0), 16, 7, None, false).unwrap();

        assert_eq!(
            u32::from_ne_bytes(message[..4].try_into().unwrap()) as usize,
            message.len()
        );
        assert_eq!(message[16], libc::AF_INET as u8);
        assert_eq!(message[17], 16);
        assert!(
            message
                .windows(4)
                .any(|window| window == 7_u32.to_ne_bytes())
        );
        assert!(message.windows(4).any(|window| window == [172, 16, 0, 0]));
    }

    #[test]
    fn tun_flags_fit_the_ifreq_field() {
        let bytes = tun_flag_bytes();
        assert_eq!(bytes.len(), 2);
        assert_eq!(
            i16::from_ne_bytes(bytes),
            (libc::IFF_TUN | libc::IFF_NO_PI) as i16
        );
    }

    #[test]
    fn rejects_invalid_interface_names_and_prefixes() {
        assert!(interface_request("bad/name").is_err());
        assert!(route_message(Ipv4Addr::LOCALHOST, 33, 1, None, false).is_err());
    }
}
