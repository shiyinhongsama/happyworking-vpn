use base64::{Engine, engine::general_purpose::STANDARD};
use happyworking_vpn_sslvpn::{
    AuthOutcome, GatewayCapabilities, HttpResponse, build_v7_login_body, parse_v7_login_response,
    private_content, url_encode,
};

fn capabilities() -> GatewayCapabilities {
    GatewayCapabilities {
        support_password: true,
        support_cert: false,
        support_dkey: false,
        support_vldimg: false,
        vldimg_path: None,
        login_path: "/_xml/login.cgi".to_owned(),
        logout_path: "/_xml/logout.cgi".to_owned(),
        checkonline_path: "/_xml/checkonline.cgi".to_owned(),
        challenge_path: "/_xml/login_challenge.cgi".to_owned(),
    }
}

fn response(xml: &str, cookie: Option<&str>) -> HttpResponse {
    let mut raw = "HTTP/1.1 200 OK\r\n".to_owned();
    if let Some(cookie) = cookie {
        raw.push_str(&format!("Set-Cookie: {cookie}\r\n"));
    }
    raw.push_str(&format!("Content-Length: {}\r\n\r\n{xml}", xml.len()));
    HttpResponse::parse(raw.as_bytes(), 1024).unwrap()
}

#[test]
fn matches_the_recovered_url_encoding() {
    assert_eq!(url_encode("aZ09"), "aZ09");
    assert_eq!(url_encode("p@ss word"), "p%40ss+word");
    assert_eq!(url_encode("中文"), "%E4%B8%AD%E6%96%87");
}

#[test]
fn builds_a_double_encoded_v7_login_body() {
    let body = build_v7_login_body("alice", "p@ss", "0011-2233-4455", "CN");
    let text = String::from_utf8(body).unwrap();

    assert!(text.starts_with("request=%3Cdata%3E"));
    assert!(text.contains("p%2540ss"));
    assert!(!text.contains("p@ss"));
    assert!(text.contains("0011%2D2233%2D4455"));
}

#[test]
fn private_content_contains_a_bounded_version_tlv() {
    let private = private_content();
    let decoded = STANDARD.decode(private).unwrap();

    assert_eq!(decoded.len(), 22);
    assert_eq!(decoded[0], 1);
    assert_eq!(decoded[1], 22);
}

#[test]
fn parses_a_successful_login_and_cookie() {
    let response = response(
        "<data><result>Success</result><replyMessage>ok</replyMessage></data>",
        Some("svpnginfo=session-value; Path=/"),
    );

    let outcome = parse_v7_login_response(&response, capabilities()).unwrap();
    let AuthOutcome::Success(session) = outcome else {
        panic!("预期登录成功");
    };
    assert_eq!(session.session_cookie().expose_secret(), "session-value");
}

#[test]
fn uses_the_last_session_cookie_like_the_original_client() {
    let xml = "<data><result>Success</result></data>";
    let raw = format!(
        "HTTP/1.1 200 OK\r\nSet-Cookie: svpnginfo=stale-value; Path=/\r\nSet-Cookie: svpnginfo=fresh-value; Path=/\r\nContent-Length: {}\r\n\r\n{xml}",
        xml.len()
    );
    let response = HttpResponse::parse(raw.as_bytes(), 1024).unwrap();

    let outcome = parse_v7_login_response(&response, capabilities()).unwrap();
    let AuthOutcome::Success(session) = outcome else {
        panic!("预期登录成功");
    };
    assert_eq!(session.session_cookie().expose_secret(), "fresh-value");
}

#[test]
fn accepts_a_success_result_with_surrounding_whitespace() {
    let response = response(
        "<data><result>     Success   </result><replyMessage></replyMessage></data>",
        Some("svpnginfo=session-value; Path=/"),
    );

    let outcome = parse_v7_login_response(&response, capabilities()).unwrap();
    assert!(matches!(outcome, AuthOutcome::Success(_)));
}

#[test]
fn parses_a_challenge() {
    let response = response(
        "<data><result>Challenge</result><type>SMS</type><message>Enter code</message><smsDynamicPwdd>123456</smsDynamicPwdd></data>",
        None,
    );

    let AuthOutcome::Challenge(challenge) =
        parse_v7_login_response(&response, capabilities()).unwrap()
    else {
        panic!("预期二次认证");
    };
    assert_eq!(challenge.kind, "SMS");
    assert_eq!(challenge.message, "Enter code");
}

#[test]
fn rejects_an_error_login_without_leaking_secrets() {
    let response = response(
        "<data><result>Failed</result><replyMessage>bad password</replyMessage></data>",
        None,
    );

    let error = parse_v7_login_response(&response, capabilities()).unwrap_err();
    assert_eq!(error.message(), "bad password");
    assert!(!format!("{error:?}").contains("session-value"));
}

#[test]
fn decodes_a_gbk_login_error() {
    let xml = "<data><result>Failed</result><replyMessage>用户名或密码错误</replyMessage></data>";
    let (encoded, _, _) = encoding_rs::GBK.encode(xml);
    let mut raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        encoded.len()
    )
    .into_bytes();
    raw.extend_from_slice(&encoded);
    let response = HttpResponse::parse(&raw, 4096).unwrap();

    let error = parse_v7_login_response(&response, capabilities()).unwrap_err();
    assert_eq!(error.message(), "用户名或密码错误");
}

#[test]
fn reports_the_result_when_gateway_omits_a_failure_reason() {
    let response = response(
        "<data><result>Failed</result><replyMessage></replyMessage></data>",
        None,
    );

    let error = parse_v7_login_response(&response, capabilities()).unwrap_err();
    assert_eq!(
        error.message(),
        "网关拒绝登录（结果：Failed），未提供具体原因"
    );
}

#[test]
fn builds_login_and_logout_http_requests() {
    let login = happyworking_vpn_sslvpn::build_v7_login_request(
        &capabilities(),
        "alice",
        "p@ss",
        "0011-2233-4455",
        "CN",
        Some("session-value"),
    )
    .unwrap();
    let login_raw = String::from_utf8(login.to_bytes("192.0.2.1").unwrap()).unwrap();
    assert!(login_raw.starts_with("POST /_xml/login.cgi HTTP/1.1\r\nHost: 192.0.2.1\r\n"));
    assert!(login_raw.contains("User-Agent: SSLVPN-Client/7.0\r\n"));
    assert!(login_raw.contains("Cookie: svpnginfo=session-value\r\n"));
    assert!(login_raw.contains(&format!("Content-Length: {}\r\n", login.body.len())));
    assert!(
        !login_raw.contains("Connection:"),
        "登录请求应与原客户端一致"
    );

    let response = response(
        "<data><result>Success</result></data>",
        Some("svpnginfo=session-value; Path=/"),
    );
    let AuthOutcome::Success(session) = parse_v7_login_response(&response, capabilities()).unwrap()
    else {
        panic!("预期登录成功");
    };
    let logout = happyworking_vpn_sslvpn::build_v7_logout_request(&session).unwrap();
    let logout_raw = String::from_utf8(logout.to_bytes("192.0.2.1").unwrap()).unwrap();
    assert!(logout_raw.starts_with("GET /_xml/logout.cgi HTTP/1.1\r\n"));
    assert!(logout_raw.contains("Cookie: svpnginfo=session-value\r\n"));
    assert!(logout_raw.ends_with("\r\n\r\n"));
}
