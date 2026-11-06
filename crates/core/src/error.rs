use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    InvalidConfiguration,
    InvalidState,
    InvalidCertificate,
    CertificateUntrusted,
    AuthenticationFailed,
    NetworkUnavailable,
    ProtocolError,
    PermissionDenied,
    Cancelled,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnError {
    code: ErrorCode,
    message: String,
}

impl VpnError {
    pub fn new(code: ErrorCode, message: impl Into<String>, secrets: &[&str]) -> Self {
        let mut message = message.into();
        for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
            message = message.replace(secret, "[已隐藏]");
        }
        message = message
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .take(1024)
            .collect();
        Self { code, message }
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for VpnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for VpnError {}
