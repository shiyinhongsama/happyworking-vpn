use happyworking_vpn_sslvpn::HttpResponse;

#[test]
fn parses_a_content_length_response() {
    let response = HttpResponse::parse(
        b"HTTP/1.1 200 OK\r\nServer: SSLVPN-Gateway/7.0\r\nContent-Length: 6\r\n\r\n<data>",
        1024,
    )
    .unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.header("server"), Some("SSLVPN-Gateway/7.0"));
    assert_eq!(response.body, b"<data>");
}

#[test]
fn decodes_a_chunked_response() {
    let response = HttpResponse::parse(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n<da>\r\n5\r\nta></\r\n5\r\ndata>\r\n0\r\n\r\n",
        1024,
    ).unwrap();

    assert_eq!(response.body, b"<da>ta></data>");
}

#[test]
fn rejects_a_response_over_the_limit() {
    let result = HttpResponse::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", 32);

    assert!(result.is_err());
}

#[test]
fn rejects_incomplete_or_invalid_chunks() {
    assert!(
        HttpResponse::parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nz\r\n",
            1024,
        )
        .is_err()
    );
}
