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
    pub verify_hostname: String,
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
    configuration.set_verify_hostname(true);
    if options.policy == TlsPolicy::Legacy {
        configuration.set_security_level(0);
    }
    let mut ssl = configuration
        .into_ssl(&options.verify_hostname)
        .map_err(|error| certificate_error(error.to_string()))?;
    if options.server_name != options.verify_hostname {
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

fn certificate_error(message: impl Into<String>) -> VpnError {
    VpnError::new(ErrorCode::InvalidCertificate, message, &[])
}

fn network_error(message: impl Into<String>) -> VpnError {
    VpnError::new(ErrorCode::NetworkUnavailable, message, &[])
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use openssl::{pkey::PKey, rsa::Rsa, x509::X509Builder};

    use super::*;

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
