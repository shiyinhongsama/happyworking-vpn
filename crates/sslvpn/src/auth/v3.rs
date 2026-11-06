use std::collections::BTreeMap;

use happyworking_vpn_core::{ErrorCode, SecretString, VpnError};
use tokio_util::sync::CancellationToken;

use crate::{HttpRequest, HttpResponse, TlsOptions, codec::url_encode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3Parameters {
    pub auth_types: BTreeMap<i32, String>,
    pub domains: BTreeMap<i32, String>,
    pub default_auth_type: i32,
    pub verify_code_required: bool,
}

pub struct V3LoginInput<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub mac_address: &'a str,
    pub language: &'a str,
    pub domain_id: Option<i32>,
    pub auth_type: i32,
    pub verify_code: Option<&'a str>,
    pub vpn_id: Option<&'a str>,
    pub certificate_only: bool,
}

#[derive(Debug)]
pub struct V3Session {
    user_id: SecretString,
}

impl V3Session {
    pub fn user_id(&self) -> &SecretString {
        &self.user_id
    }
}

#[derive(Debug)]
pub enum V3LoginOutcome {
    Success(V3Session),
    ExistingLogin(V3Session),
}

#[derive(Debug)]
pub struct V3OldLogin {
    pub old_user_id: SecretString,
    pub new_user_id: SecretString,
}

pub fn parse_v3_parameters(input: &str) -> Result<V3Parameters, VpnError> {
    let mut parameters = V3Parameters {
        auth_types: BTreeMap::new(),
        domains: BTreeMap::new(),
        default_auth_type: -1,
        verify_code_required: false,
    };
    let mut verify_code_seen = false;

    for line in input.lines() {
        if line.contains("var arAuth") {
            parse_array(line, &mut parameters.auth_types)?;
        } else if line.contains("var arDomain") {
            parse_array(line, &mut parameters.domains)?;
        } else if let Some(value) = assigned_int(line, "defaultAuth") {
            parameters.default_auth_type = value;
        } else if let Some(value) = assigned_int(line, "bVldFlag") {
            parameters.verify_code_required = value != 0;
            verify_code_seen = true;
        }
    }

    if parameters.auth_types.is_empty()
        || parameters.domains.is_empty()
        || parameters.default_auth_type < 0
        || !verify_code_seen
    {
        return Err(protocol_error("V3 网关参数不完整"));
    }
    Ok(parameters)
}

pub fn build_v3_login_body(input: &V3LoginInput<'_>) -> String {
    let mut body = format!(
        "txtMacAddr={}&svpnlang={}",
        input.mac_address, input.language
    );
    if input.domain_id.is_some() {
        body.push_str("&selIdentity=1");
    }
    if input.certificate_only {
        body.push_str("&txtUsrName=guest&txtPassword=guest");
    } else {
        body.push_str(&format!(
            "&txtUsrName={}&txtPassword={}",
            url_encode(input.username),
            url_encode(input.password)
        ));
    }
    if let Some(domain) = input.domain_id {
        body.push_str(&format!("&selDomain={domain}"));
    }
    body.push_str(&format!("&authmethod={}", input.auth_type));
    if let Some(code) = input.verify_code {
        body.push_str(&format!("&vldCode={code}"));
    }
    body
}

pub fn build_v3_login_request(
    input: &V3LoginInput<'_>,
    host: &str,
    port: u16,
) -> Result<HttpRequest, VpnError> {
    let mut request = HttpRequest::new("POST", "/svpn/vpnuser/login_submit.cgi")?;
    add_v3_headers(&mut request, Some((host, port, "/svpn/index.cgi")))?;
    request.header("Content-Type", "application/x-www-form-urlencoded")?;
    request.header("Cache-Control", "no-cache")?;

    let mut cookie = String::new();
    if let Some(domain) = input.domain_id {
        cookie = format!(
            "domainId={domain}; authId={}; showOption=0; saveFlag=0; UserName=",
            input.auth_type
        );
    }
    if input.verify_code.is_some() {
        let vpn_id = input
            .vpn_id
            .ok_or_else(|| protocol_error("缺少 V3 验证码会话 ID"))?;
        if !cookie.is_empty() {
            cookie.push_str("; ");
        }
        cookie.push_str(&format!("vldID={vpn_id}"));
    }
    if !cookie.is_empty() {
        request.header("Cookie", &cookie)?;
    }
    request.body = build_v3_login_body(input).into_bytes();
    Ok(request)
}

pub fn parse_v3_login_response(response: &HttpResponse) -> Result<V3LoginOutcome, VpnError> {
    if response.status != 200 {
        return Err(protocol_error("V3 登录请求返回非成功状态"));
    }
    let user_id = response
        .header("set-cookie")
        .and_then(|header| parse_cookie(header, "svpnuid"))
        .ok_or_else(|| protocol_error("V3 登录响应缺少 svpnuid"))?;
    let body = String::from_utf8_lossy(&response.body);
    let session = V3Session {
        user_id: SecretString::new(user_id),
    };
    if body.contains("/svpn/olduser_info.cgi") {
        Ok(V3LoginOutcome::ExistingLogin(session))
    } else {
        Ok(V3LoginOutcome::Success(session))
    }
}

pub fn build_v3_old_user_request(session: &V3Session) -> Result<HttpRequest, VpnError> {
    let mut request = HttpRequest::new("GET", "/svpn/olduser_info.cgi?svpnlang=cn")?;
    add_v3_headers(&mut request, None)?;
    request.header("Cookie", session.user_id.expose_secret())?;
    Ok(request)
}

pub fn parse_v3_old_login(input: &str) -> Result<V3OldLogin, VpnError> {
    if !input.contains("var arrOldUserInfo") {
        return Err(protocol_error("V3 旧登录响应缺少用户数组"));
    }
    let mut values = Vec::new();
    let mut remaining = input;
    while let Some(start) = remaining.find('"') {
        remaining = &remaining[start + 1..];
        let end = remaining
            .find('"')
            .ok_or_else(|| protocol_error("V3 旧登录响应引号不完整"))?;
        values.push(remaining[..end].to_owned());
        remaining = &remaining[end + 1..];
    }
    if values.len() < 5 {
        return Err(protocol_error("V3 旧登录响应缺少旧用户或新用户 ID"));
    }
    Ok(V3OldLogin {
        old_user_id: SecretString::new(values[3].clone()),
        new_user_id: SecretString::new(values[4].clone()),
    })
}

pub fn build_v3_kick_request(
    session: &V3Session,
    old_login: &V3OldLogin,
    host: &str,
    port: u16,
) -> Result<HttpRequest, VpnError> {
    let path = format!(
        "/svpn/vpnuser/kickolduser.cgi?OldUserID={}&NewUserID={}&IsKick=1&svpnlang=cn",
        url_encode(old_login.old_user_id.expose_secret()),
        url_encode(old_login.new_user_id.expose_secret())
    );
    let mut request = HttpRequest::new("GET", &path)?;
    add_v3_headers(
        &mut request,
        Some((host, port, "/svpn/olduser_info.cgi?svpnlang=cn")),
    )?;
    request.header("Cookie", session.user_id.expose_secret())?;
    Ok(request)
}

pub fn build_v3_logout_request(session: &V3Session) -> Result<HttpRequest, VpnError> {
    let mut request = HttpRequest::new("GET", "/svpn/logout.cgi")?;
    add_v3_headers(&mut request, None)?;
    request.header("Cookie", session.user_id.expose_secret())?;
    Ok(request)
}

pub async fn login_v3(
    options: &TlsOptions,
    input: &V3LoginInput<'_>,
    cancellation: CancellationToken,
) -> Result<V3LoginOutcome, VpnError> {
    let request = build_v3_login_request(input, &options.host, options.port)?;
    let response = crate::http::send(options, &request, cancellation).await?;
    parse_v3_login_response(&response)
}

pub async fn logout_v3(
    options: &TlsOptions,
    session: &V3Session,
    cancellation: CancellationToken,
) -> Result<(), VpnError> {
    let request = build_v3_logout_request(session)?;
    let response = crate::http::send(options, &request, cancellation).await?;
    if response.status == 200 {
        Ok(())
    } else {
        Err(protocol_error("V3 注销请求返回非成功状态"))
    }
}

fn add_v3_headers(
    request: &mut HttpRequest,
    referer: Option<(&str, u16, &str)>,
) -> Result<(), VpnError> {
    request.header(
        "Accept",
        "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, */*",
    )?;
    if let Some((host, port, path)) = referer {
        request.header("Referer", &format!("https://{host}:{port}{path}"))?;
    }
    request.header("Accept-Language", "zh-cn")?;
    request.header("UA-CPU", "x86")?;
    request.header("Accept-Encoding", "gzip, deflate")?;
    request.header(
        "User-Agent",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
    )?;
    Ok(())
}

fn parse_array(line: &str, output: &mut BTreeMap<i32, String>) -> Result<(), VpnError> {
    let mut remaining = line;
    while let Some(start) = remaining.find('"') {
        remaining = &remaining[start + 1..];
        let end = remaining
            .find('"')
            .ok_or_else(|| protocol_error("V3 参数数组引号不完整"))?;
        let value = remaining[..end].to_owned();
        remaining = &remaining[end + 1..];
        let comma = remaining
            .find(',')
            .ok_or_else(|| protocol_error("V3 参数数组缺少键"))?;
        let key_text = &remaining[comma + 1..];
        let digits: String = key_text
            .trim_start()
            .chars()
            .take_while(|character| character.is_ascii_digit() || *character == '-')
            .collect();
        let key = digits
            .parse::<i32>()
            .map_err(|_| protocol_error("V3 参数数组键无效"))?;
        output.insert(key, value);
        remaining = key_text;
    }
    Ok(())
}

fn assigned_int(line: &str, name: &str) -> Option<i32> {
    let (_, value) = line.split_once(name)?;
    let digits: String = value
        .trim_start()
        .strip_prefix('=')?
        .trim_start()
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '-')
        .collect();
    digits.parse().ok()
}

fn parse_cookie(header: &str, name: &str) -> Option<String> {
    let value = header
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&format!("{name}=")))?;
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_owned())
}

fn protocol_error(message: &str) -> VpnError {
    VpnError::new(ErrorCode::ProtocolError, message, &[])
}
