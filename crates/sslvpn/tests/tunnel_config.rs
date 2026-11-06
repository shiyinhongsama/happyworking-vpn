use std::net::Ipv4Addr;

use happyworking_vpn_sslvpn::{HttpResponse, TunnelConfig};

fn response(body: &str) -> HttpResponse {
    let raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    HttpResponse::parse(raw.as_bytes(), 64 * 1024).unwrap()
}

#[test]
fn parses_gateway_network_configuration() {
    let config = TunnelConfig::parse(&response(
        "IPADDRESS: 10.1.2.3\r\nSUBNETMASK: 24\r\nGATEWAY: 10.1.2.1\r\nROUTES: 172.16.0.0/16;10.0.0.0/8\r\nEXCLUDE ROUTES: 192.168.1.0/24\r\nDNS: 10.1.1.1;10.1.1.2\r\nRESTRICT: 1\r\nKEEPALIVETIME: 30\r\n",
    )).unwrap();

    assert_eq!(config.address, Ipv4Addr::new(10, 1, 2, 3));
    assert_eq!(config.prefix, 24);
    assert_eq!(config.gateway, Ipv4Addr::new(10, 1, 2, 1));
    assert_eq!(config.routes.len(), 2);
    assert_eq!(config.routes[0].prefix, 16);
    assert_eq!(
        config.exclude_routes[0].network,
        Ipv4Addr::new(192, 168, 1, 0)
    );
    assert_eq!(config.dns.len(), 2);
    assert!(config.restrict);
    assert_eq!(config.keepalive_seconds, 30);
}

#[test]
fn rejects_missing_or_invalid_required_fields() {
    assert!(TunnelConfig::parse(&response("GATEWAY: 10.1.2.1\r\n")).is_err());
    assert!(
        TunnelConfig::parse(&response(
            "IPADDRESS: 10.1.2.3\r\nSUBNETMASK: 33\r\nGATEWAY: 10.1.2.1\r\n",
        ))
        .is_err()
    );
    assert!(
        TunnelConfig::parse(&response(
            "IPADDRESS: 10.1.2.3\r\nSUBNETMASK: 24\r\nGATEWAY: 10.1.2.1\r\nROUTES: invalid/16\r\n",
        ))
        .is_err()
    );
}

#[test]
fn includes_a_bounded_body_preview_when_address_is_missing() {
    let error = TunnelConfig::parse(&response("Access denied")).unwrap_err();

    assert_eq!(
        error.message(),
        "网络配置缺少 IPADDRESS；响应体 13 字节：Access denied；Content-Length: 13；Transfer-Encoding: <无>；Connection: <无>"
    );
}

#[test]
fn parses_network_configuration_from_http_headers() {
    let raw = "HTTP/1.1 200 OK\r\nIPADDRESS: 10.1.2.3\r\nSUBNETMASK: 24\r\nGATEWAY: 10.1.2.1\r\nROUTES: 172.16.0.0/16\r\nDNS: 10.1.1.1\r\nContent-Length: 0\r\n\r\n";
    let response = HttpResponse::parse(raw.as_bytes(), 4096).unwrap();

    let config = TunnelConfig::parse(&response).unwrap();
    assert_eq!(config.address, Ipv4Addr::new(10, 1, 2, 3));
    assert_eq!(config.prefix, 24);
    assert_eq!(config.gateway, Ipv4Addr::new(10, 1, 2, 1));
    assert_eq!(config.routes[0].network, Ipv4Addr::new(172, 16, 0, 0));
    assert_eq!(config.dns, vec![Ipv4Addr::new(10, 1, 1, 1)]);
}

#[test]
fn accepts_an_ip_only_point_to_point_configuration() {
    let config = TunnelConfig::parse(&response("IPADDRESS: 10.1.2.3\r\n")).unwrap();

    assert_eq!(config.address, Ipv4Addr::new(10, 1, 2, 3));
    assert_eq!(config.prefix, 32);
    assert_eq!(config.gateway, Ipv4Addr::UNSPECIFIED);
}

#[test]
fn accepts_zero_keepalive_as_disabled() {
    let config = TunnelConfig::parse(&response(
        "IPADDRESS: 10.1.2.3\r\nSUBNETMASK: 24\r\nGATEWAY: 10.1.2.1\r\nKEEPALIVETIME: 0\r\n",
    ))
    .unwrap();
    assert_eq!(config.keepalive_seconds, 0);
}
