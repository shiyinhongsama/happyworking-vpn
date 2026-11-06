use happyworking_vpn_sslvpn::{GatewayCapabilities, validate_gateway_path};

const GATEWAY_RESPONSE: &str = r#"<data>
  <gatewayinfo>
    <auth>
      <supportPassword>true</supportPassword>
      <supportCert>false</supportCert>
      <supportDKey>false</supportDKey>
      <supportvldimg>false</supportvldimg>
    </auth>
    <url>
      <login>/_xml/login.cgi</login>
      <logout>/_xml/logout.cgi</logout>
      <checkonline>/_xml/checkonline.cgi</checkonline>
      <challenge>/_xml/login_challenge.cgi</challenge>
    </url>
  </gatewayinfo>
</data>"#;

#[test]
fn parses_the_observed_v7_gateway_capabilities() {
    let capabilities = GatewayCapabilities::from_xml(GATEWAY_RESPONSE).unwrap();

    assert!(capabilities.support_password);
    assert!(!capabilities.support_cert);
    assert!(!capabilities.support_dkey);
    assert!(!capabilities.support_vldimg);
    assert_eq!(capabilities.login_path, "/_xml/login.cgi");
    assert_eq!(capabilities.logout_path, "/_xml/logout.cgi");
    assert_eq!(capabilities.checkonline_path, "/_xml/checkonline.cgi");
    assert_eq!(capabilities.challenge_path, "/_xml/login_challenge.cgi");
}

#[test]
fn rejects_missing_required_login_path() {
    let xml = GATEWAY_RESPONSE.replace("<login>/_xml/login.cgi</login>", "");
    assert!(GatewayCapabilities::from_xml(&xml).is_err());
}

#[test]
fn only_accepts_local_absolute_gateway_paths() {
    assert_eq!(
        validate_gateway_path("/_xml/login.cgi").unwrap(),
        "/_xml/login.cgi"
    );
    assert!(validate_gateway_path("https://example.com/login").is_err());
    assert!(validate_gateway_path("//example.com/login").is_err());
    assert!(validate_gateway_path("/login\r\nCookie: secret").is_err());
}
