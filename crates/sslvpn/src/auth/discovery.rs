use happyworking_vpn_core::{ErrorCode, VpnError};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayCapabilities {
    pub support_password: bool,
    pub support_cert: bool,
    pub support_dkey: bool,
    pub support_vldimg: bool,
    pub vldimg_path: Option<String>,
    pub login_path: String,
    pub logout_path: String,
    pub checkonline_path: String,
    pub challenge_path: String,
}

#[derive(Deserialize)]
struct Document {
    gatewayinfo: GatewayInfo,
}

#[derive(Deserialize)]
struct GatewayInfo {
    auth: Authentication,
    url: Urls,
}

#[derive(Deserialize)]
struct Authentication {
    #[serde(rename = "supportPassword")]
    support_password: bool,
    #[serde(rename = "supportCert")]
    support_cert: bool,
    #[serde(rename = "supportDKey")]
    support_dkey: bool,
    supportvldimg: bool,
}

#[derive(Deserialize)]
struct Urls {
    vldimg: Option<String>,
    login: String,
    logout: String,
    checkonline: String,
    challenge: String,
}

impl GatewayCapabilities {
    pub fn from_xml(xml: &str) -> Result<Self, VpnError> {
        let document: Document =
            quick_xml::de::from_str(xml).map_err(|_| protocol_error("V7 网关能力 XML 无效"))?;
        let auth = document.gatewayinfo.auth;
        let urls = document.gatewayinfo.url;

        Ok(Self {
            support_password: auth.support_password,
            support_cert: auth.support_cert,
            support_dkey: auth.support_dkey,
            support_vldimg: auth.supportvldimg,
            vldimg_path: urls
                .vldimg
                .map(|path| validate_gateway_path(&path))
                .transpose()?,
            login_path: validate_gateway_path(&urls.login)?,
            logout_path: validate_gateway_path(&urls.logout)?,
            checkonline_path: validate_gateway_path(&urls.checkonline)?,
            challenge_path: validate_gateway_path(&urls.challenge)?,
        })
    }
}

pub fn validate_gateway_path(path: &str) -> Result<String, VpnError> {
    if path.len() > 2048
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains("://")
        || path.chars().any(char::is_control)
    {
        return Err(protocol_error("网关返回了无效或非本地的 URL 路径"));
    }
    Ok(path.to_owned())
}

use tokio_util::sync::CancellationToken;

use crate::{HttpRequest, HttpResponse, TlsOptions, http};

pub async fn discover(
    options: &TlsOptions,
    cancellation: CancellationToken,
) -> Result<GatewayCapabilities, VpnError> {
    let first = get(options, "/svpn/index.cgi", cancellation.clone()).await?;
    let path = if first.status == 200 {
        None
    } else if matches!(first.status, 301 | 302 | 303 | 307 | 308) {
        let location = first
            .header("location")
            .ok_or_else(|| protocol_error("网关重定向缺少 Location"))?;
        Some(validate_gateway_path(location)?)
    } else {
        return Err(protocol_error("网关参数入口返回非成功状态"));
    };

    let response = match path {
        Some(path) => get(options, &path, cancellation).await?,
        None => first,
    };
    if response.status != 200 {
        return Err(protocol_error("网关参数请求返回非成功状态"));
    }

    let xml = String::from_utf8(response.body)
        .map_err(|_| protocol_error("网关能力响应不是有效 UTF-8"))?;
    GatewayCapabilities::from_xml(&xml)
}

async fn get(
    options: &TlsOptions,
    path: &str,
    cancellation: CancellationToken,
) -> Result<HttpResponse, VpnError> {
    let mut request = HttpRequest::new("GET", path)?;
    request.header("Connection", "Keep-Alive")?;
    request.header("User-Agent", "SSLVPN-Client/7.0")?;
    http::send(options, &request, cancellation).await
}

fn protocol_error(message: &str) -> VpnError {
    VpnError::new(ErrorCode::ProtocolError, message, &[])
}
