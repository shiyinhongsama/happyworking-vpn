use std::net::Ipv4Addr;

use happyworking_vpn_core::{ErrorCode, VpnError};

use crate::HttpResponse;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelRoute {
    pub network: Ipv4Addr,
    pub prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Ipv4Addr,
    pub routes: Vec<TunnelRoute>,
    pub exclude_routes: Vec<TunnelRoute>,
    pub dns: Vec<Ipv4Addr>,
    pub restrict: bool,
    pub keepalive_seconds: u32,
}

impl TunnelConfig {
    pub fn parse_body(body: &[u8]) -> Result<Self, VpnError> {
        Self::parse(&HttpResponse::from_body(body))
    }

    pub fn parse(response: &HttpResponse) -> Result<Self, VpnError> {
        if response.status != 200 {
            return Err(config_error("NET_EXTEND 返回非成功状态"));
        }
        let input = std::str::from_utf8(&response.body)
            .map_err(|_| config_error("网络配置不是有效 UTF-8"))?;
        let mut config = Self {
            address: Ipv4Addr::UNSPECIFIED,
            prefix: 32,
            gateway: Ipv4Addr::UNSPECIFIED,
            routes: Vec::new(),
            exclude_routes: Vec::new(),
            dns: Vec::new(),
            restrict: false,
            keepalive_seconds: 10,
        };
        let mut address_seen = false;
        let header_lines = [
            "IPADDRESS",
            "SUBNETMASK",
            "GATEWAY",
            "EXCLUDE ROUTES",
            "ROUTES",
            "DNS",
            "RESTRICT",
            "KEEPALIVETIME",
        ]
        .into_iter()
        .filter_map(|name| response.header(name).map(|value| format!("{name}:{value}")))
        .collect::<Vec<_>>();

        for line in header_lines
            .iter()
            .map(String::as_str)
            .chain(input.lines())
            .take(2000)
        {
            let line = line.trim();
            if let Some(value) = field(line, "IPADDRESS") {
                config.address = parse_ip(value)?;
                address_seen = true;
            } else if let Some(value) = field(line, "SUBNETMASK") {
                config.prefix = parse_prefix(value)?;
            } else if let Some(value) = field(line, "GATEWAY") {
                config.gateway = parse_ip(value)?;
            } else if let Some(value) = field(line, "EXCLUDE ROUTES") {
                config.exclude_routes = parse_routes(value)?;
            } else if let Some(value) = field(line, "ROUTES") {
                config.routes = parse_routes(value)?;
            } else if let Some(value) = field(line, "DNS") {
                config.dns = parse_ip_list(value)?;
            } else if let Some(value) = field(line, "RESTRICT") {
                config.restrict = parse_integer::<u32>(value)? != 0;
            } else if let Some(value) = field(line, "KEEPALIVETIME") {
                config.keepalive_seconds = parse_integer(value)?;
            }
        }

        if !address_seen {
            let body = String::from_utf8_lossy(&response.body);
            let preview = body.trim().chars().take(512).collect::<String>();
            let preview = if preview.is_empty() {
                "<空>".to_owned()
            } else {
                preview
            };
            return Err(config_error(&format!(
                "网络配置缺少 IPADDRESS；响应体 {} 字节：{preview}；Content-Length: {}；Transfer-Encoding: {}；Connection: {}",
                response.body.len(),
                response.header("content-length").unwrap_or("<无>"),
                response.header("transfer-encoding").unwrap_or("<无>"),
                response.header("connection").unwrap_or("<无>"),
            )));
        }
        Ok(config)
    }
}

fn parse_routes(input: &str) -> Result<Vec<TunnelRoute>, VpnError> {
    input
        .split(';')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let (network, prefix) = value
                .split_once('/')
                .ok_or_else(|| config_error("路由缺少前缀"))?;
            Ok(TunnelRoute {
                network: parse_ip(network)?,
                prefix: parse_prefix(prefix)?,
            })
        })
        .collect()
}

fn parse_ip_list(input: &str) -> Result<Vec<Ipv4Addr>, VpnError> {
    input
        .split(';')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(parse_ip)
        .collect()
}

fn parse_ip(input: &str) -> Result<Ipv4Addr, VpnError> {
    input
        .trim()
        .parse()
        .map_err(|_| config_error("IPv4 地址无效"))
}

fn parse_prefix(input: &str) -> Result<u8, VpnError> {
    let prefix = parse_integer::<u8>(input)?;
    if prefix > 32 {
        return Err(config_error("IPv4 前缀不能超过 32"));
    }
    Ok(prefix)
}

fn parse_integer<T>(input: &str) -> Result<T, VpnError>
where
    T: std::str::FromStr,
{
    input
        .trim()
        .parse()
        .map_err(|_| config_error("网络配置数值无效"))
}

fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.strip_prefix(name)?.strip_prefix(':').map(str::trim)
}

fn config_error(message: &str) -> VpnError {
    VpnError::new(ErrorCode::ProtocolError, message, &[])
}
