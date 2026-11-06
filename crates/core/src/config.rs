use std::{fmt, net::IpAddr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Protocol {
    SslVpn,
    X1,
    Portal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TlsPolicy {
    Modern,
    Legacy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayConfig {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    pub tls_policy: TlsPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Empty {
        field: &'static str,
    },
    TooLong {
        field: &'static str,
        max_chars: usize,
    },
    InvalidPort {
        port: u16,
    },
    InvalidHost,
    InvalidText {
        field: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { field } => write!(formatter, "{field} 不能为空"),
            Self::TooLong { field, max_chars } => {
                write!(formatter, "{field} 不能超过 {max_chars} 个字符")
            }
            Self::InvalidPort { port } => write!(formatter, "端口 {port} 无效"),
            Self::InvalidHost => write!(formatter, "主机地址无效，请输入 IP 或不含协议的主机名"),
            Self::InvalidText { field } => write!(formatter, "{field} 不能包含控制字符"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl GatewayConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_text("name", &self.name, 64)?;
        validate_text("host", &self.host, 253)?;

        if self.port == 0 {
            return Err(ConfigError::InvalidPort { port: self.port });
        }

        if self.host.parse::<IpAddr>().is_ok() {
            return Ok(());
        }

        if is_valid_hostname(&self.host) {
            Ok(())
        } else {
            Err(ConfigError::InvalidHost)
        }
    }
}

fn validate_text(field: &'static str, value: &str, max_chars: usize) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::Empty { field });
    }
    if value.chars().count() > max_chars {
        return Err(ConfigError::TooLong { field, max_chars });
    }
    if value.chars().any(char::is_control) {
        return Err(ConfigError::InvalidText { field });
    }
    Ok(())
}

fn is_valid_hostname(host: &str) -> bool {
    if !host.is_ascii() || host.contains(['/', '@', '#', '?']) {
        return false;
    }

    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}
