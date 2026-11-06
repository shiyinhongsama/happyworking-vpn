use std::net::{IpAddr, UdpSocket};

pub fn local_mac_address(host: &str, port: u16) -> String {
    let local_ip = UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect((host, port))?;
            socket.local_addr()
        })
        .map(|address| address.ip());

    local_ip
        .ok()
        .and_then(interface_for_ip)
        .and_then(|name| std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok())
        .and_then(|address| format_mac(&address))
        .unwrap_or_else(|| "0000-0000-0000".to_owned())
}

fn interface_for_ip(ip: IpAddr) -> Option<String> {
    let IpAddr::V4(expected) = ip else {
        return None;
    };
    let mut current = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut current) } != 0 {
        return None;
    }
    let first = current;
    let mut result = None;
    while let Some(address) = unsafe { current.as_ref() } {
        if !address.ifa_addr.is_null()
            && unsafe { *address.ifa_addr }.sa_family as i32 == libc::AF_INET
        {
            let socket = unsafe { &*(address.ifa_addr as *const libc::sockaddr_in) };
            if socket.sin_addr.s_addr.to_ne_bytes() == expected.octets() {
                result = unsafe { std::ffi::CStr::from_ptr(address.ifa_name) }
                    .to_str()
                    .ok()
                    .map(str::to_owned);
                break;
            }
        }
        current = address.ifa_next;
    }
    unsafe { libc::freeifaddrs(first) };
    result
}

fn format_mac(address: &str) -> Option<String> {
    let compact = address.trim().replace([':', '-'], "").to_lowercase();
    if compact.len() != 12 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!(
        "{}-{}-{}",
        &compact[..4],
        &compact[4..8],
        &compact[8..]
    ))
}

#[cfg(test)]
mod tests {
    use super::format_mac;

    #[test]
    fn formats_the_original_mac_layout() {
        assert_eq!(format_mac("00:11:22:AA:BB:CC").unwrap(), "0011-22aa-bbcc");
        assert!(format_mac("invalid").is_none());
    }
}
