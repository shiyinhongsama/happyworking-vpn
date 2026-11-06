use happyworking_vpn_core::{CertificateFingerprint, ErrorCode, SecretString, VpnError};

#[test]
fn secret_output_is_redacted() {
    let secret = SecretString::new("correct horse battery staple".to_owned());

    assert_eq!(secret.expose_secret(), "correct horse battery staple");
    assert_eq!(format!("{secret}"), "[已隐藏]");
    assert_eq!(format!("{secret:?}"), "SecretString([已隐藏])");
}

#[test]
fn secret_can_enter_through_deserialization() {
    let secret: SecretString = serde_json::from_str("\"top-secret\"").unwrap();
    assert_eq!(secret.expose_secret(), "top-secret");
}

#[test]
fn parses_and_formats_a_certificate_fingerprint() {
    let input = "86:E8:02:E1:EA:E7:17:37:AC:9A:E4:DC:70:F4:7B:8C:33:0E:DD:B2:27:35:25:58:54:AC:1E:F9:99:94:40:B3";
    let fingerprint: CertificateFingerprint = input.parse().unwrap();

    assert_eq!(fingerprint.to_string(), input.to_lowercase());
    let json = serde_json::to_string(&fingerprint).unwrap();
    let decoded: CertificateFingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, fingerprint);
}

#[test]
fn rejects_invalid_certificate_fingerprints() {
    assert!("ab:cd".parse::<CertificateFingerprint>().is_err());
    assert!("g".repeat(64).parse::<CertificateFingerprint>().is_err());
    assert!("0".repeat(64).parse::<CertificateFingerprint>().is_ok());
}

#[test]
fn errors_redact_known_secret_values() {
    let error = VpnError::new(
        ErrorCode::AuthenticationFailed,
        "登录失败，password=top-secret",
        &["top-secret"],
    );

    assert_eq!(error.code(), ErrorCode::AuthenticationFailed);
    assert_eq!(error.message(), "登录失败，password=[已隐藏]");
    assert!(!format!("{error:?}").contains("top-secret"));
}
