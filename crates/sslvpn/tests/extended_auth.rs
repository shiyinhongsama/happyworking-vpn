use happyworking_vpn_sslvpn::{
    AuthOutcome, ClientIdentity, GatewayCapabilities, HttpResponse, V7SecondAuthInput,
    build_v7_image_request, build_v7_second_login_body, parse_v7_login_response,
};
use openssl::{
    asn1::Asn1Time, hash::MessageDigest, pkcs12::Pkcs12, pkey::PKey, rsa::Rsa, x509::X509Builder,
};

fn capabilities() -> GatewayCapabilities {
    GatewayCapabilities {
        support_password: true,
        support_cert: true,
        support_dkey: false,
        support_vldimg: true,
        vldimg_path: Some("/_xml/vldimg.cgi".to_owned()),
        login_path: "/_xml/login.cgi".to_owned(),
        logout_path: "/_xml/logout.cgi".to_owned(),
        checkonline_path: "/_xml/checkonline.cgi".to_owned(),
        challenge_path: "/_xml/login_challenge.cgi".to_owned(),
    }
}

fn key_and_certificate() -> (PKey<openssl::pkey::Private>, openssl::x509::X509) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut builder = X509Builder::new().unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    (key, builder.build())
}

#[test]
fn loads_pem_and_pkcs12_client_identities_without_a_shell() {
    let (key, certificate) = key_and_certificate();
    let mut pem = certificate.to_pem().unwrap();
    pem.extend_from_slice(&key.private_key_to_pem_pkcs8().unwrap());
    if let Err(error) = ClientIdentity::from_pem_bytes(&pem, None) {
        panic!("PEM 客户端身份加载失败：{error}");
    }

    let pkcs12 = Pkcs12::builder()
        .name("identity")
        .pkey(&key)
        .cert(&certificate)
        .build2("secret")
        .unwrap();
    let der = pkcs12.to_der().unwrap();
    assert!(ClientIdentity::from_pkcs12_der(&der, "secret").is_ok());
}

#[test]
fn builds_a_v7_verification_image_request() {
    let request = build_v7_image_request(&capabilities(), Some("session-value")).unwrap();
    let raw = String::from_utf8(request.to_bytes("192.0.2.1").unwrap()).unwrap();

    assert!(raw.starts_with("GET /_xml/vldimg.cgi HTTP/1.1\r\n"));
    assert!(raw.contains("Cookie: svpnginfo=session-value\r\n"));
}

#[test]
fn builds_sms_second_authentication() {
    let body = build_v7_second_login_body(&V7SecondAuthInput {
        username: "alice",
        password: "p@ss",
        kind: "SMS",
        code: "123456",
        dynamic_password: None,
        verify_code: "",
        mac_address: "0011-2233-4455",
        language: "CN",
    })
    .unwrap();
    let text = String::from_utf8(body).unwrap();

    assert!(text.starts_with("request=%3Cdata%3E"));
    assert!(text.contains("SMS"));
    assert!(text.contains("123456"));
}

#[test]
fn builds_sms_imc_binary_password_without_plaintext() {
    let body = build_v7_second_login_body(&V7SecondAuthInput {
        username: "alice",
        password: "p@ss",
        kind: "SMS-IMC",
        code: "123456",
        dynamic_password: Some("dynamic"),
        verify_code: "",
        mac_address: "0011-2233-4455",
        language: "CN",
    })
    .unwrap();
    let text = String::from_utf8(body).unwrap();

    assert!(text.contains("SMS%2DIMC"));
    assert!(text.contains("%B1"));
    assert!(text.contains("%B2"));
    assert!(text.contains("%B3"));
    assert!(!text.contains("p@ss"));
}

#[test]
fn keeps_dynamic_challenge_password_redacted() {
    let xml = "<data><result>Challenge</result><type>SMS-IMC</type><message>Enter code</message><smsDynamicPwdd>dynamic</smsDynamicPwdd></data>";
    let raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{xml}",
        xml.len()
    );
    let response = HttpResponse::parse(raw.as_bytes(), 1024).unwrap();

    let AuthOutcome::Challenge(challenge) =
        parse_v7_login_response(&response, capabilities()).unwrap()
    else {
        panic!("预期二次认证");
    };
    assert_eq!(
        challenge.dynamic_password.as_ref().unwrap().expose_secret(),
        "dynamic"
    );
    assert!(!format!("{challenge:?}").contains("\"dynamic\""));
}
