use happyworking_vpn_sslvpn::HttpResponse;
use happyworking_vpn_sslvpn::{
    V3LoginInput, V3LoginOutcome, build_v3_kick_request, build_v3_login_body,
    build_v3_login_request, build_v3_logout_request, build_v3_old_user_request,
    parse_v3_login_response, parse_v3_old_login, parse_v3_parameters,
};

fn input() -> V3LoginInput<'static> {
    V3LoginInput {
        username: "alice",
        password: "p@ss",
        mac_address: "0011-2233-4455",
        language: "cn",
        domain_id: Some(2),
        auth_type: 1,
        verify_code: Some("1234"),
        vpn_id: Some("vld-id"),
        certificate_only: false,
    }
}

fn response(xml: &str, cookie: Option<&str>) -> HttpResponse {
    let mut raw = "HTTP/1.1 200 OK\r\n".to_owned();
    if let Some(cookie) = cookie {
        raw.push_str(&format!("Set-Cookie: {cookie}\r\n"));
    }
    raw.push_str(&format!("Content-Length: {}\r\n\r\n{xml}", xml.len()));
    HttpResponse::parse(raw.as_bytes(), 64 * 1024).unwrap()
}

#[test]
fn parses_v3_auth_domain_and_verification_parameters() {
    let parameters = parse_v3_parameters(
        "var arAuth= new Array(\"Local\",0,\"AD\",1);\nvar arDomain = new Array(\"Default\",0,\"Employees\",2);\nvar defaultAuth=1;\nvar bVldFlag=1;",
    ).unwrap();

    assert_eq!(parameters.auth_types.get(&1).unwrap(), "AD");
    assert_eq!(parameters.domains.get(&2).unwrap(), "Employees");
    assert_eq!(parameters.default_auth_type, 1);
    assert!(parameters.verify_code_required);
}

#[test]
fn builds_the_recovered_v3_form_body() {
    assert_eq!(
        build_v3_login_body(&input()),
        "txtMacAddr=0011-2233-4455&svpnlang=cn&selIdentity=1&txtUsrName=alice&txtPassword=p%40ss&selDomain=2&authmethod=1&vldCode=1234"
    );
}

#[test]
fn builds_v3_login_headers_and_cookies() {
    let request = build_v3_login_request(&input(), "192.0.2.1", 443).unwrap();
    let raw = String::from_utf8(request.to_bytes("192.0.2.1").unwrap()).unwrap();

    assert!(raw.starts_with("POST /svpn/vpnuser/login_submit.cgi HTTP/1.1\r\n"));
    assert!(raw.contains("Referer: https://192.0.2.1:443/svpn/index.cgi\r\n"));
    assert!(raw.contains("Content-Type: application/x-www-form-urlencoded\r\n"));
    assert!(raw.contains(
        "Cookie: domainId=2; authId=1; showOption=0; saveFlag=0; UserName=; vldID=vld-id\r\n"
    ));
}

#[test]
fn distinguishes_success_from_an_existing_login() {
    let success =
        parse_v3_login_response(&response("<html></html>", Some("svpnuid=user-id"))).unwrap();
    assert!(matches!(success, V3LoginOutcome::Success(_)));

    let existing = parse_v3_login_response(&response(
        "<script>location=\"/svpn/olduser_info.cgi\";</script>",
        Some("svpnuid=user-id"),
    ))
    .unwrap();
    assert!(matches!(existing, V3LoginOutcome::ExistingLogin(_)));
}

#[test]
fn parses_old_and_new_user_ids_without_exposing_them_in_debug() {
    let old_login = parse_v3_old_login(
        "var arrOldUserInfo=new Array(\"a\",\"b\",\"c\",\"old-id\",\"new-id\");",
    )
    .unwrap();

    assert_eq!(old_login.old_user_id.expose_secret(), "old-id");
    assert_eq!(old_login.new_user_id.expose_secret(), "new-id");
    assert!(!format!("{old_login:?}").contains("old-id"));
}

#[test]
fn builds_old_user_kick_and_logout_requests_with_dynamic_cookies() {
    let response = response("<html></html>", Some("svpnuid=user-id"));
    let V3LoginOutcome::Success(session) = parse_v3_login_response(&response).unwrap() else {
        panic!("预期成功");
    };
    let old_login = parse_v3_old_login(
        "var arrOldUserInfo=new Array(\"a\",\"b\",\"c\",\"old-id\",\"new-id\");",
    )
    .unwrap();

    let query = build_v3_old_user_request(&session).unwrap();
    assert!(
        String::from_utf8(query.to_bytes("192.0.2.1").unwrap())
            .unwrap()
            .starts_with("GET /svpn/olduser_info.cgi?svpnlang=cn HTTP/1.1\r\n")
    );

    let kick = build_v3_kick_request(&session, &old_login, "192.0.2.1", 443).unwrap();
    let kick_raw = String::from_utf8(kick.to_bytes("192.0.2.1").unwrap()).unwrap();
    assert!(kick_raw.starts_with("GET /svpn/vpnuser/kickolduser.cgi?OldUserID=old%2Did&NewUserID=new%2Did&IsKick=1&svpnlang=cn HTTP/1.1\r\n"));
    assert!(kick_raw.contains("Cookie: user-id\r\n"));
    assert!(!kick_raw.contains("a48eafca8822d45b88f10a2118ec8400"));

    let logout = build_v3_logout_request(&session).unwrap();
    assert!(
        String::from_utf8(logout.to_bytes("192.0.2.1").unwrap())
            .unwrap()
            .starts_with("GET /svpn/logout.cgi HTTP/1.1\r\n")
    );
}
