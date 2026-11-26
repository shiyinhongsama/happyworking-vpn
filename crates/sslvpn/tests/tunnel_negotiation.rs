use std::{pin::Pin, time::Duration};

use happyworking_vpn_sslvpn::{TlsOptions, negotiate_v3, negotiate_v7};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    ssl::{SslAcceptor, SslMethod},
    x509::{X509, X509Builder},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_openssl::SslStream;
use tokio_util::sync::CancellationToken;

fn certificate() -> (PKey<openssl::pkey::Private>, X509) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut builder = X509Builder::new().unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder
        .append_extension(
            openssl::x509::extension::BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .unwrap(),
        )
        .unwrap();
    // OpenSSL 3 只拿 SAN 里的 dNSName 做主机名校验，CN 不再算数。
    let context = builder.x509v3_context(None, None);
    let mut alternative = openssl::x509::extension::SubjectAlternativeName::new();
    alternative.dns("localhost");
    builder
        .append_extension(alternative.build(&context).unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    (key, builder.build())
}

fn tls_options(port: u16, certificate: &X509) -> TlsOptions {
    let digest = certificate.digest(MessageDigest::sha256()).unwrap();
    TlsOptions {
        host: "127.0.0.1".to_owned(),
        port,
        server_name: "localhost".to_owned(),
        certificate_name: "localhost".to_owned(),
        certificate_pem: certificate.to_pem().unwrap(),
        fingerprint: digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            .parse()
            .unwrap(),
        policy: happyworking_vpn_core::TlsPolicy::Modern,
        client_identity: None,
    }
}

async fn server(listener: TcpListener, acceptor: SslAcceptor, expected: String) {
    let (tcp, _) = listener.accept().await.unwrap();
    let ssl = acceptor.context();
    let ssl = openssl::ssl::Ssl::new(ssl).unwrap();
    let mut stream = SslStream::new(ssl, tcp).unwrap();
    Pin::new(&mut stream).accept().await.unwrap();
    let mut input = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let count = stream.read(&mut chunk).await.unwrap();
        if count == 0 {
            break;
        }
        input.extend_from_slice(&chunk[..count]);
        if input.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let request = String::from_utf8(input).unwrap();
    assert!(request.starts_with(&expected));
    assert!(!request.contains("Connection:"), "握手请求应与原客户端一致");
    let body =
        "IPADDRESS: 10.1.2.3\r\nSUBNETMASK: 24\r\nGATEWAY: 10.1.2.1\r\nKEEPALIVETIME: 30\r\n";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: Keep-Alive\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn negotiates_v7_without_waiting_for_connection_close() {
    let (key, certificate) = certificate();
    let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls_server()).unwrap();
    acceptor.set_certificate(&certificate).unwrap();
    acceptor.set_private_key(&key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(server(
        listener,
        acceptor.build(),
        "NET_EXTEND / HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: SSLVPN-Client/7.0\r\nCookie: svpnginfo=session-value\r\n".to_owned(),
    ));

    let connection = negotiate_v7(
        &tls_options(port, &certificate),
        "session-value",
        CancellationToken::new(),
    )
    .await
    .unwrap();

    assert_eq!(connection.config.address.to_string(), "10.1.2.3");
    server.await.unwrap();
}

#[tokio::test]
async fn negotiates_v3_with_the_recovered_cookie() {
    let (key, certificate) = certificate();
    let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls_server()).unwrap();
    acceptor.set_certificate(&certificate).unwrap();
    acceptor.set_private_key(&key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(server(
        listener,
        acceptor.build(),
        "NET_EXTEND / HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: user-id\r\n".to_owned(),
    ));

    let connection = negotiate_v3(
        &tls_options(port, &certificate),
        "user-id",
        CancellationToken::new(),
    )
    .await
    .unwrap();

    assert_eq!(connection.config.keepalive_seconds, 30);
    server.await.unwrap();
}
