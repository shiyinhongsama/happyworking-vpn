use std::{pin::Pin, time::Duration};

use happyworking_vpn_core::{CertificateFingerprint, ErrorCode, TlsPolicy, VpnError};
use openssl::{
    hash::MessageDigest,
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

pub struct ClientIdentity {
    certificate: X509,
    private_key: PKey<Private>,
    chain: Vec<X509>,
}

impl ClientIdentity {
    pub fn from_pem_bytes(input: &[u8], password: Option<&str>) -> Result<Self, VpnError> {
        let mut certificates =
            X509::stack_from_pem(input).map_err(|error| certificate_error(error.to_string()))?;
        if certificates.is_empty() {
            return Err(certificate_error("客户端 PEM 中没有证书"));
        }
        let certificate = certificates.remove(0);
        let key_input = [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
        ]
        .iter()
        .find_map(|marker| {
            input
                .windows(marker.len())
                .position(|window| window == marker.as_bytes())
                .map(|position| &input[position..])
        })
        .unwrap_or(input);
        let private_key = match password {
            Some(password) => PKey::private_key_from_pem_passphrase(key_input, password.as_bytes()),
            None => PKey::private_key_from_pem(key_input),
        }
        .map_err(|error| certificate_error(error.to_string()))?;
        Ok(Self {
            certificate,
            private_key,
            chain: certificates,
        })
    }

    pub fn from_pkcs12_der(input: &[u8], password: &str) -> Result<Self, VpnError> {
        let pkcs12 =
            Pkcs12::from_der(input).map_err(|error| certificate_error(error.to_string()))?;
        let parsed = pkcs12
            .parse2(password)
            .map_err(|error| certificate_error(error.to_string()))?;
        Ok(Self {
            certificate: parsed
                .cert
                .ok_or_else(|| certificate_error("PKCS#12 中没有客户端证书"))?,
            private_key: parsed
                .pkey
                .ok_or_else(|| certificate_error("PKCS#12 中没有客户端私钥"))?,
            chain: parsed
                .ca
                .map(|chain| chain.into_iter().collect())
                .unwrap_or_default(),
        })
    }
}

pub struct TlsOptions {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    /// 网关证书声明的名字：用于 SNI 与界面展示。
    ///
    /// 主机名不再靠它校验。这类网关用的是不带 SAN 的自签证书，
    /// 而 OpenSSL 3 的主机名校验只认 SAN，开启就等于拒绝握手；
    /// 真正的信任锚点是用户核对过的 SHA-256 指纹。
    pub certificate_name: String,
    pub certificate_pem: Vec<u8>,
    pub fingerprint: CertificateFingerprint,
    pub policy: TlsPolicy,
    pub client_identity: Option<ClientIdentity>,
}

pub async fn connect(options: &TlsOptions) -> Result<SslStream<TcpStream>, VpnError> {
    let certificate = X509::from_pem(&options.certificate_pem)
        .map_err(|error| certificate_error(error.to_string()))?;
    verify_fingerprint(&certificate, options.fingerprint)?;

    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|error| certificate_error(error.to_string()))?;
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .cert_store_mut()
        .add_cert(certificate)
        .map_err(|error| certificate_error(error.to_string()))?;
    if let Some(identity) = &options.client_identity {
        builder
            .set_certificate(&identity.certificate)
            .map_err(|error| certificate_error(error.to_string()))?;
        builder
            .set_private_key(&identity.private_key)
            .map_err(|error| certificate_error(error.to_string()))?;
        builder
            .check_private_key()
            .map_err(|error| certificate_error(error.to_string()))?;
        for certificate in &identity.chain {
            builder
                .add_extra_chain_cert(certificate.clone())
                .map_err(|error| certificate_error(error.to_string()))?;
        }
    }

    let mut configuration = builder
        .build()
        .configure()
        .map_err(|error| certificate_error(error.to_string()))?;
    // 网关的自签证书没有 SAN，OpenSSL 3 只拿 SAN 做主机名校验，
    // 这里必须关掉，改由握手后按证书实际声明的内容自行把关。
    configuration.set_verify_hostname(false);
    if options.policy == TlsPolicy::Legacy {
        configuration.set_security_level(0);
    }
    let mut ssl = configuration
        .into_ssl(&options.certificate_name)
        .map_err(|error| certificate_error(error.to_string()))?;
    if options.server_name != options.certificate_name {
        ssl.set_hostname(&options.server_name)
            .map_err(|error| certificate_error(error.to_string()))?;
    }

    let connect = async {
        let tcp = TcpStream::connect((options.host.as_str(), options.port))
            .await
            .map_err(|error| network_error(error.to_string()))?;
        let mut stream =
            SslStream::new(ssl, tcp).map_err(|error| certificate_error(error.to_string()))?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|error| network_error(error.to_string()))?;
        let peer = stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| certificate_error("网关未提供证书"))?;
        verify_fingerprint(&peer, options.fingerprint)?;
        if !hostname_matches(&peer, &options.server_name) {
            return Err(certificate_error("网关证书声明的主机名与连接地址不一致"));
        }
        Ok(stream)
    };

    tokio::time::timeout(Duration::from_secs(10), connect)
        .await
        .map_err(|_| network_error("TLS 连接超时"))?
}

#[derive(Clone)]
pub struct PeerCertificate {
    pub certificate_pem: Vec<u8>,
    pub fingerprint: CertificateFingerprint,
    pub subject: String,
    pub common_name: Option<String>,
}

pub async fn probe_certificate(
    host: &str,
    port: u16,
    policy: TlsPolicy,
    cancellation: tokio_util::sync::CancellationToken,
) -> Result<PeerCertificate, VpnError> {
    let operation = async {
        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|error| certificate_error(error.to_string()))?;
        builder.set_verify(SslVerifyMode::NONE);
        let mut configuration = builder
            .build()
            .configure()
            .map_err(|error| certificate_error(error.to_string()))?;
        if policy == TlsPolicy::Legacy {
            configuration.set_security_level(0);
        }
        let ssl = configuration
            .into_ssl(host)
            .map_err(|error| certificate_error(error.to_string()))?;
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|error| network_error(error.to_string()))?;
        let mut stream =
            SslStream::new(ssl, tcp).map_err(|error| certificate_error(error.to_string()))?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|error| network_error(error.to_string()))?;
        let certificate = stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| certificate_error("网关未提供证书"))?;
        if let Some(reason) = policy_rejects(&certificate, policy) {
            return Err(certificate_error(reason));
        }
        peer_certificate(certificate)
    };

    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(10), operation) => {
            result.map_err(|_| network_error("证书读取超时"))?
        }
        () = cancellation.cancelled() => {
            Err(VpnError::new(ErrorCode::Cancelled, "证书读取已取消", &[]))
        }
    }
}

fn peer_certificate(certificate: X509) -> Result<PeerCertificate, VpnError> {
    let digest = certificate
        .digest(MessageDigest::sha256())
        .map_err(|error| certificate_error(error.to_string()))?;
    let fingerprint = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .parse()
        .map_err(|error: happyworking_vpn_core::FingerprintError| {
            certificate_error(error.to_string())
        })?;
    let common_name = certificate
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|entry| entry.data().to_string().ok());
    let subject = certificate
        .subject_name()
        .entries()
        .map(|entry| {
            format!(
                "{}={}",
                entry.object(),
                entry.data().to_string().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok(PeerCertificate {
        certificate_pem: certificate
            .to_pem()
            .map_err(|error| certificate_error(error.to_string()))?,
        fingerprint,
        subject,
        common_name,
    })
}

fn verify_fingerprint(
    certificate: &X509,
    expected: CertificateFingerprint,
) -> Result<(), VpnError> {
    let digest = certificate
        .digest(MessageDigest::sha256())
        .map_err(|error| certificate_error(error.to_string()))?;
    if digest.as_ref() != expected.as_bytes() {
        return Err(certificate_error("网关证书 SHA-256 指纹与已信任值不一致"));
    }
    Ok(())
}

/// 现代安全策略下的网关证书是否已经不够强。
///
/// 这类网关用的是 RSA-1024 自签证书，OpenSSL 会在校验阶段直接拒绝，
/// 与其抛一句天书般的库错误，不如直接说清楚该换哪条策略。
fn policy_rejects(certificate: &X509, policy: TlsPolicy) -> Option<String> {
    if policy != TlsPolicy::Modern {
        return None;
    }
    let key = certificate.public_key().ok()?;
    let bits = match key.rsa() {
        Ok(rsa) => rsa.size() * 8,
        Err(_) => key.bits(),
    };
    if bits < 2048 {
        return Some(format!(
            "网关证书密钥仅 {bits} 位，达不到现代安全策略要求；请改用“旧版 H3C 网关”策略"
        ));
    }
    None
}

/// 证书声明了主机名就必须与连接地址一致；没有声明则以用户核对过的指纹为准。
fn hostname_matches(certificate: &X509, host: &str) -> bool {
    let Some(names) = certificate.subject_alt_names() else {
        return true;
    };
    let mut asserted = false;
    for name in names.iter() {
        if let Some(dns) = name.dnsname() {
            asserted = true;
            if dns.eq_ignore_ascii_case(host) {
                return true;
            }
        }
        if let Some(bytes) = name.ipaddress() {
            asserted = true;
            if ip_bytes_match(bytes, host) {
                return true;
            }
        }
    }
    !asserted
}

/// IP 扩展名里的原始字节与连接地址是否同一个地址。
fn ip_bytes_match(bytes: &[u8], host: &str) -> bool {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => bytes == address.octets(),
        Ok(std::net::IpAddr::V6(address)) => bytes == address.octets(),
        Err(_) => false,
    }
}

fn certificate_error(message: impl Into<String>) -> VpnError {
    VpnError::new(ErrorCode::InvalidCertificate, message, &[])
}

fn network_error(message: impl Into<String>) -> VpnError {
    VpnError::new(ErrorCode::NetworkUnavailable, message, &[])
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use openssl::{
        pkey::PKey,
        rsa::Rsa,
        x509::{X509Builder, extension::SubjectAlternativeName},
    };

    use super::*;

    fn certificate_with_names(names: &[&str]) -> X509 {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut builder = X509Builder::new().unwrap();
        builder.set_pubkey(&key).unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "gateway").unwrap();
        let name = name.build();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        if !names.is_empty() {
            let context = builder.x509v3_context(None, None);
            let mut alternative = SubjectAlternativeName::new();
            for entry in names {
                alternative.dns(entry);
            }
            builder
                .append_extension(alternative.build(&context).unwrap())
                .unwrap();
        }
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    #[test]
    fn a_certificate_without_a_hostname_relies_on_the_fingerprint() {
        let certificate = certificate_with_names(&[]);

        assert!(hostname_matches(&certificate, "122.224.205.114"));
        assert!(hostname_matches(&certificate, "gateway.example"));
    }

    #[test]
    fn a_declared_hostname_must_match() {
        let certificate = certificate_with_names(&["gateway.example"]);

        assert!(hostname_matches(&certificate, "gateway.example"));
        assert!(hostname_matches(&certificate, "GATEWAY.EXAMPLE"));
        assert!(!hostname_matches(&certificate, "other.example"));
    }

    #[test]
    fn a_weak_key_is_refused_by_the_modern_policy_only() {
        let key = PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap();
        let mut builder = X509Builder::new().unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let certificate = builder.build();

        assert!(policy_rejects(&certificate, TlsPolicy::Modern).is_some());
        assert!(policy_rejects(&certificate, TlsPolicy::Legacy).is_none());
    }

    #[test]
    fn a_strong_key_passes_the_modern_policy() {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut builder = X509Builder::new().unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let certificate = builder.build();

        assert!(policy_rejects(&certificate, TlsPolicy::Modern).is_none());
    }

    #[test]
    fn verifies_the_certificate_digest() {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut builder = X509Builder::new().unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let certificate = builder.build();
        let digest = certificate.digest(MessageDigest::sha256()).unwrap();
        let fingerprint = CertificateFingerprint::from_str(
            &digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .unwrap();

        assert!(verify_fingerprint(&certificate, fingerprint).is_ok());
        assert!(
            verify_fingerprint(
                &certificate,
                CertificateFingerprint::from_str(&"00".repeat(32)).unwrap()
            )
            .is_err()
        );
    }
}
