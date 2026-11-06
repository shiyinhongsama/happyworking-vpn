use happyworking_vpn_core::{ErrorCode, SecretString, VpnError};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

use crate::{
    GatewayCapabilities, HttpRequest, HttpResponse, TlsOptions,
    codec::{private_content, url_encode, url_encode_bytes},
};

#[derive(Debug)]
pub struct AuthSession {
    capabilities: GatewayCapabilities,
    session_cookie: SecretString,
}

impl AuthSession {
    pub fn session_cookie(&self) -> &SecretString {
        &self.session_cookie
    }

    pub fn capabilities(&self) -> &GatewayCapabilities {
        &self.capabilities
    }
}

#[derive(Debug)]
pub enum AuthOutcome {
    Success(AuthSession),
    Challenge(Challenge),
}

#[derive(Debug)]
pub struct Challenge {
    pub kind: String,
    pub message: String,
    pub dynamic_password: Option<SecretString>,
    pub session_cookie: Option<SecretString>,
}

pub struct V7Credentials<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub mac_address: &'a str,
    pub language: &'a str,
    pub verify_code: &'a str,
}

pub struct V7SecondAuthInput<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub kind: &'a str,
    pub code: &'a str,
    pub dynamic_password: Option<&'a str>,
    pub verify_code: &'a str,
    pub mac_address: &'a str,
    pub language: &'a str,
}

pub fn build_v7_login_body(
    username: &str,
    password: &str,
    mac_address: &str,
    language: &str,
) -> Vec<u8> {
    build_v7_login_body_with_code(username, password, "", mac_address, language)
}

pub fn build_v7_login_body_with_code(
    username: &str,
    password: &str,
    verify_code: &str,
    mac_address: &str,
    language: &str,
) -> Vec<u8> {
    let xml = format!(
        "<data><username>{}</username><password>{}</password><vldCode>{}</vldCode><language>{}</language><OS>Linux</OS><macAddress>{}</macAddress><private>{}</private></data>",
        quick_xml::escape::escape(username),
        quick_xml::escape::escape(url_encode(password)),
        quick_xml::escape::escape(verify_code),
        quick_xml::escape::escape(language),
        quick_xml::escape::escape(mac_address),
        private_content(),
    );
    format!("request={}", url_encode(&xml)).into_bytes()
}

pub fn build_v7_second_login_body(input: &V7SecondAuthInput<'_>) -> Result<Vec<u8>, VpnError> {
    let mut xml = Vec::new();
    xml.extend_from_slice(b"<data><username>");
    xml.extend_from_slice(quick_xml::escape::escape(input.username).as_bytes());
    xml.extend_from_slice(b"</username><type>");
    xml.extend_from_slice(input.kind.as_bytes());
    xml.extend_from_slice(b"</type><code>");
    xml.extend_from_slice(quick_xml::escape::escape(input.code).as_bytes());
    xml.extend_from_slice(b"</code>");

    if input.kind == "SMS-IMC" {
        let dynamic = input.dynamic_password.unwrap_or_default();
        if input.password.len() > 125 || dynamic.len() > 125 || input.code.len() > 125 {
            return Err(protocol_error("SMS-IMC 字段超过协议长度"));
        }
        let mut password = vec![0xb1, (input.password.len() + 2) as u8];
        password.extend_from_slice(input.password.as_bytes());
        password.extend_from_slice(&[0xb2, (dynamic.len() + 2) as u8]);
        password.extend_from_slice(dynamic.as_bytes());
        password.extend_from_slice(&[0xb3, (input.code.len() + 2) as u8]);
        password.extend_from_slice(input.code.as_bytes());

        xml.extend_from_slice(b"<password>");
        xml.extend_from_slice(&password);
        xml.extend_from_slice(b"</password><vldCode>");
        xml.extend_from_slice(quick_xml::escape::escape(input.verify_code).as_bytes());
        xml.extend_from_slice(b"</vldCode><language>");
        xml.extend_from_slice(quick_xml::escape::escape(input.language).as_bytes());
        xml.extend_from_slice(b"</language><OS>Linux</OS><macAddress>");
        xml.extend_from_slice(quick_xml::escape::escape(input.mac_address).as_bytes());
        xml.extend_from_slice(b"</macAddress><private>");
        xml.extend_from_slice(private_content().as_bytes());
        xml.extend_from_slice(b"</private>");
    } else if input.kind != "SMS" {
        return Err(protocol_error("不支持的二次认证类型"));
    }

    xml.extend_from_slice(b"</data>");
    let mut body = b"request=".to_vec();
    body.extend_from_slice(url_encode_bytes(&xml).as_bytes());
    Ok(body)
}

pub fn build_v7_login_request(
    capabilities: &GatewayCapabilities,
    username: &str,
    password: &str,
    mac_address: &str,
    language: &str,
    session_cookie: Option<&str>,
) -> Result<HttpRequest, VpnError> {
    build_v7_login_request_with_code(
        capabilities,
        username,
        password,
        "",
        mac_address,
        language,
        session_cookie,
    )
}

pub fn build_v7_login_request_with_code(
    capabilities: &GatewayCapabilities,
    username: &str,
    password: &str,
    verify_code: &str,
    mac_address: &str,
    language: &str,
    session_cookie: Option<&str>,
) -> Result<HttpRequest, VpnError> {
    let mut request = HttpRequest::new("POST", &capabilities.login_path)?;
    request.omit_connection_header();
    request.header("User-Agent", "SSLVPN-Client/7.0")?;
    if let Some(cookie) = session_cookie {
        request.header("Cookie", &format!("svpnginfo={cookie}"))?;
    }
    request.body =
        build_v7_login_body_with_code(username, password, verify_code, mac_address, language);
    Ok(request)
}

pub fn build_v7_second_login_request(
    capabilities: &GatewayCapabilities,
    input: &V7SecondAuthInput<'_>,
    session_cookie: Option<&str>,
) -> Result<HttpRequest, VpnError> {
    let mut request = HttpRequest::new("POST", &capabilities.challenge_path)?;
    request.omit_connection_header();
    request.header("User-Agent", "SSLVPN-Client/7.0")?;
    if let Some(cookie) = session_cookie {
        request.header("Cookie", &format!("svpnginfo={cookie}"))?;
    }
    request.body = build_v7_second_login_body(input)?;
    Ok(request)
}

pub fn build_v7_image_request(
    capabilities: &GatewayCapabilities,
    session_cookie: Option<&str>,
) -> Result<HttpRequest, VpnError> {
    let path = capabilities
        .vldimg_path
        .as_deref()
        .ok_or_else(|| protocol_error("网关未提供图形验证码地址"))?;
    let mut request = HttpRequest::new("GET", path)?;
    request.header("Connection", "Keep-Alive")?;
    request.header("User-Agent", "SSLVPN-Client/7.0")?;
    if let Some(cookie) = session_cookie {
        request.header("Cookie", &format!("svpnginfo={cookie}"))?;
    }
    Ok(request)
}

pub fn build_v7_logout_request(session: &AuthSession) -> Result<HttpRequest, VpnError> {
    let mut request = HttpRequest::new("GET", &session.capabilities.logout_path)?;
    request.header("Connection", "Keep-Alive")?;
    request.header("Accept-Language", "zh-cn")?;
    request.header("User-Agent", "SSLVPN-Client/7.0")?;
    request.header(
        "Cookie",
        &format!("svpnginfo={}", session.session_cookie.expose_secret()),
    )?;
    Ok(request)
}

pub async fn login_v7(
    options: &TlsOptions,
    capabilities: &GatewayCapabilities,
    credentials: V7Credentials<'_>,
    session_cookie: Option<&str>,
    cancellation: CancellationToken,
) -> Result<AuthOutcome, VpnError> {
    let request = build_v7_login_request_with_code(
        capabilities,
        credentials.username,
        credentials.password,
        credentials.verify_code,
        credentials.mac_address,
        credentials.language,
        session_cookie,
    )?;
    let response = crate::http::send(options, &request, cancellation).await?;
    parse_v7_login_response(&response, capabilities.clone())
}

pub async fn challenge_v7(
    options: &TlsOptions,
    capabilities: &GatewayCapabilities,
    input: &V7SecondAuthInput<'_>,
    session_cookie: Option<&str>,
    cancellation: CancellationToken,
) -> Result<AuthOutcome, VpnError> {
    let request = build_v7_second_login_request(capabilities, input, session_cookie)?;
    let response = crate::http::send(options, &request, cancellation).await?;
    parse_v7_login_response(&response, capabilities.clone())
}

pub async fn get_v7_verify_image(
    options: &TlsOptions,
    capabilities: &GatewayCapabilities,
    session_cookie: Option<&str>,
    cancellation: CancellationToken,
) -> Result<Vec<u8>, VpnError> {
    let request = build_v7_image_request(capabilities, session_cookie)?;
    let response = crate::http::send(options, &request, cancellation).await?;
    if response.status != 200 || response.body.is_empty() {
        return Err(protocol_error("图形验证码响应无效"));
    }
    Ok(response.body)
}

pub async fn check_online_v7(
    options: &TlsOptions,
    session: &AuthSession,
    cancellation: CancellationToken,
) -> Result<String, VpnError> {
    let mut request = HttpRequest::new("GET", &session.capabilities.checkonline_path)?;
    request.header("Connection", "Keep-Alive")?;
    request.header("User-Agent", "SSLVPN-Client/7.0")?;
    request.header(
        "Cookie",
        &format!("svpnginfo={}", session.session_cookie.expose_secret()),
    )?;
    let response = crate::http::send(options, &request, cancellation).await?;
    if response.status != 200 {
        return Err(protocol_error("在线检查返回非成功状态"));
    }
    String::from_utf8(response.body).map_err(|_| protocol_error("在线检查响应不是有效 UTF-8"))
}

pub async fn logout_v7(
    options: &TlsOptions,
    session: &AuthSession,
    cancellation: CancellationToken,
) -> Result<(), VpnError> {
    let request = build_v7_logout_request(session)?;
    let response = crate::http::send(options, &request, cancellation).await?;
    if response.status == 200 {
        Ok(())
    } else {
        Err(protocol_error("注销请求返回非成功状态"))
    }
}

pub fn parse_v7_login_response(
    response: &HttpResponse,
    capabilities: GatewayCapabilities,
) -> Result<AuthOutcome, VpnError> {
    if response.status != 200 {
        return Err(protocol_error("登录请求返回非成功状态"));
    }
    let xml = match std::str::from_utf8(&response.body) {
        Ok(xml) => std::borrow::Cow::Borrowed(xml),
        Err(_) => {
            let (xml, _, had_errors) = encoding_rs::GBK.decode(&response.body);
            if had_errors {
                return Err(protocol_error("登录响应字符编码无效"));
            }
            std::borrow::Cow::Owned(xml.into_owned())
        }
    };
    let document: LoginDocument =
        quick_xml::de::from_str(&xml).map_err(|_| protocol_error("登录响应 XML 无效"))?;

    match document.result.trim() {
        "Success" => {
            let cookie = response_session_cookie(response)
                .ok_or_else(|| protocol_error("登录成功响应缺少 svpnginfo"))?;
            Ok(AuthOutcome::Success(AuthSession {
                capabilities,
                session_cookie: SecretString::new(cookie),
            }))
        }
        "Challenge" => Ok(AuthOutcome::Challenge(Challenge {
            kind: document.challenge_type,
            message: document.message,
            dynamic_password: document.dynamic_password.map(SecretString::new),
            session_cookie: response_session_cookie(response).map(SecretString::new),
        })),
        _ => {
            let message = if document.reply_message.is_empty() {
                if document.message.is_empty() {
                    format!("网关拒绝登录（结果：{}），未提供具体原因", document.result)
                } else {
                    document.message
                }
            } else {
                document.reply_message
            };
            Err(VpnError::new(ErrorCode::AuthenticationFailed, message, &[]))
        }
    }
}

#[derive(Deserialize)]
struct LoginDocument {
    result: String,
    #[serde(default, rename = "replyMessage")]
    reply_message: String,
    #[serde(default, rename = "type")]
    challenge_type: String,
    #[serde(default)]
    message: String,
    #[serde(default, rename = "smsDynamicPwdd")]
    dynamic_password: Option<String>,
}

fn response_session_cookie(response: &HttpResponse) -> Option<String> {
    response
        .headers("set-cookie")
        .filter_map(parse_session_cookie)
        .last()
}

fn parse_session_cookie(header: &str) -> Option<String> {
    let value = header
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("svpnginfo="))?;
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_owned())
}

fn protocol_error(message: &str) -> VpnError {
    VpnError::new(ErrorCode::ProtocolError, message, &[])
}
