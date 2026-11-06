use std::{env, io, process::ExitCode};

use happyworking_vpn_core::{CertificateFingerprint, SecretString, TlsPolicy};
use happyworking_vpn_sslvpn::{
    AuthOutcome, TlsOptions, V7Credentials, discover, local_mac_address, login_v7, logout_v7,
    probe_certificate,
};
use tokio_util::sync::CancellationToken;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<String, String> {
    let mut host = None;
    let mut port = 443;
    let mut username = None;
    let mut fingerprint = None;
    let mut policy = TlsPolicy::Modern;
    let mut tunnel = false;
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
            "--username" => username = arguments.next(),
            "--fingerprint" => fingerprint = arguments.next(),
            "--legacy" => policy = TlsPolicy::Legacy,
            "--tunnel" => tunnel = true,
            _ => return Err(format!("未知参数：{argument}")),
        }
    }

    let host = host.ok_or("需要 --host")?;
    let username = username.ok_or("需要 --username")?;
    let expected = fingerprint
        .ok_or("需要 --fingerprint")?
        .parse::<CertificateFingerprint>()
        .map_err(|error| error.to_string())?;
    let certificate = probe_certificate(&host, port, policy, CancellationToken::new())
        .await
        .map_err(|error| format!("证书读取失败 [{:?}]：{error}", error.code()))?;
    if certificate.fingerprint != expected {
        return Err("网关证书指纹与预期不一致，已停止登录".to_owned());
    }
    let options = TlsOptions {
        host: host.clone(),
        port,
        server_name: host,
        verify_hostname: certificate.common_name.clone().ok_or("网关证书缺少 CN")?,
        certificate_pem: certificate.certificate_pem,
        fingerprint: expected,
        policy,
        client_identity: None,
    };
    let capabilities = discover(&options, CancellationToken::new())
        .await
        .map_err(|error| format!("网关发现失败 [{:?}]：{error}", error.code()))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| format!("读取密码失败：{error}"))?;
    let password = SecretString::new(input.trim_end_matches(['\r', '\n']).to_owned());
    if password.expose_secret().is_empty() {
        return Err("未提供密码".to_owned());
    }
    let mac_address = local_mac_address(&options.host, options.port);
    let outcome = login_v7(
        &options,
        &capabilities,
        V7Credentials {
            username: &username,
            password: password.expose_secret(),
            mac_address: &mac_address,
            language: "CN",
            verify_code: "",
        },
        None,
        CancellationToken::new(),
    )
    .await
    .map_err(|error| format!("登录失败 [{:?}]：{error}", error.code()))?;

    match outcome {
        AuthOutcome::Success(session) => {
            if tunnel {
                let online = happyworking_vpn_sslvpn::check_online_v7(
                    &options,
                    &session,
                    CancellationToken::new(),
                )
                .await
                .map_err(|error| format!("在线检查失败 [{:?}]：{error}", error.code()))?;
                println!("在线检查响应：{}", online.trim());
            }
            let tunnel_result = if tunnel {
                happyworking_vpn_sslvpn::negotiate_v7(
                    &options,
                    session.session_cookie().expose_secret(),
                    CancellationToken::new(),
                )
                .await
                .map(drop)
                .map_err(|error| format!("隧道协商失败 [{:?}]：{error}", error.code()))
            } else {
                Ok(())
            };
            logout_v7(&options, &session, CancellationToken::new())
                .await
                .map_err(|error| format!("认证成功，但诊断会话注销失败：{error}"))?;
            tunnel_result?;
            Ok(if tunnel {
                "认证和隧道协商成功；诊断会话已注销，未创建 TUN".to_owned()
            } else {
                "认证成功；诊断会话已注销，未建立隧道".to_owned()
            })
        }
        AuthOutcome::Challenge(challenge) => Ok(format!(
            "网关要求二次认证（{}）：{}",
            challenge.kind, challenge.message
        )),
    }
}
