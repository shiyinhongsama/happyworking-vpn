use std::{fmt, str::FromStr};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertificateFingerprint([u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FingerprintError;

impl CertificateFingerprint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl FromStr for CertificateFingerprint {
    type Err = FingerprintError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let compact: String = input
            .chars()
            .filter(|character| *character != ':' && *character != '-')
            .collect();
        if compact.len() != 64 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(FingerprintError);
        }

        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16)
                .map_err(|_| FingerprintError)?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for CertificateFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str(":")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for CertificateFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl serde::Serialize for CertificateFingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for CertificateFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let input = <String as serde::Deserialize>::deserialize(deserializer)?;
        input.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("证书指纹必须是 32 字节十六进制 SHA-256 值")
    }
}

impl std::error::Error for FingerprintError {}
