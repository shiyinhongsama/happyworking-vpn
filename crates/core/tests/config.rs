use happyworking_vpn_core::{ConfigError, GatewayConfig, Protocol, TlsPolicy};

fn gateway() -> GatewayConfig {
    GatewayConfig {
        name: "公司网络".to_owned(),
        host: "vpn.example.com".to_owned(),
        port: 443,
        protocol: Protocol::SslVpn,
        tls_policy: TlsPolicy::Modern,
    }
}

#[test]
fn accepts_a_valid_gateway() {
    assert_eq!(gateway().validate(), Ok(()));
}

#[test]
fn rejects_an_empty_profile_name() {
    let mut config = gateway();
    config.name = "  ".to_owned();

    assert_eq!(config.validate(), Err(ConfigError::Empty { field: "name" }));
}

#[test]
fn rejects_an_empty_host() {
    let mut config = gateway();
    config.host = "".to_owned();

    assert_eq!(config.validate(), Err(ConfigError::Empty { field: "host" }));
}

#[test]
fn rejects_port_zero() {
    let mut config = gateway();
    config.port = 0;

    assert_eq!(config.validate(), Err(ConfigError::InvalidPort { port: 0 }));
}

#[test]
fn rejects_a_host_containing_a_url() {
    let mut config = gateway();
    config.host = "https://vpn.example.com".to_owned();

    assert_eq!(config.validate(), Err(ConfigError::InvalidHost));
}

#[test]
fn accepts_ipv4_ipv6_and_single_label_hosts() {
    for host in ["192.0.2.1", "2001:db8::1", "localhost"] {
        let mut config = gateway();
        config.host = host.to_owned();
        assert_eq!(config.validate(), Ok(()));
    }
}

#[test]
fn rejects_overlong_names() {
    let mut config = gateway();
    config.name = "界".repeat(65);

    assert_eq!(
        config.validate(),
        Err(ConfigError::TooLong {
            field: "name",
            max_chars: 64
        })
    );
}
