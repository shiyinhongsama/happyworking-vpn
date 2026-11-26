use std::{env, fs, net::IpAddr, process::ExitCode};

use happyworking_vpn_core::{CertificateFingerprint, TlsPolicy};
use happyworking_vpn_sslvpn::{TlsOptions, discover};
use tokio_util::sync::CancellationToken;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(capabilities) => {
            println!("{capabilities:#?}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<happyworking_vpn_sslvpn::GatewayCapabilities, String> {
    let mut host = None;
    let mut port = 443;
    let mut ca = None;
    let mut fingerprint = None;
    let mut server_name = None;
    let mut certificate_name = None;
    let mut policy = TlsPolicy::Modern;
    let mut arguments = env::args().skip(1);

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--host" => host = arguments.next(),
            "--port" => {
                port = arguments
                    .next()
                    .ok_or("--port 缺少数值")?
                    .parse()
                    .map_err(|_| "端口无效")?
            }
            "--ca" => ca = arguments.next(),
            "--fingerprint" => fingerprint = arguments.next(),
            "--server-name" => server_name = arguments.next(),
            "--certificate-name" => certificate_name = arguments.next(),
            "--legacy" => policy = TlsPolicy::Legacy,
            _ => return Err(format!("未知参数：{argument}")),
        }
    }

    let host = host.ok_or("需要 --host")?;
    host.parse::<IpAddr>()
        .map_err(|_| "--host 目前要求 IP 地址")?;
    let server_name = server_name.unwrap_or_else(|| host.clone());
    let options = TlsOptions {
        host,
        port,
        server_name,
        certificate_name: certificate_name.ok_or("需要 --certificate-name")?,
        certificate_pem: fs::read(ca.ok_or("需要 --ca")?).map_err(|error| error.to_string())?,
        fingerprint: fingerprint
            .ok_or("需要 --fingerprint")?
            .parse::<CertificateFingerprint>()
            .map_err(|error| error.to_string())?,
        policy,
        client_identity: None,
    };

    discover(&options, CancellationToken::new())
        .await
        .map_err(|error| error.to_string())
}
