use happyworking_vpn_core::{ErrorCode, SecretString, VpnError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialKey {
    account: String,
}

impl CredentialKey {
    pub fn new(host: &str, port: u16, username: &str) -> Result<Self, VpnError> {
        if host.trim().is_empty() || host.chars().count() > 253 || port == 0 {
            return Err(invalid_key());
        }
        if username.trim().is_empty()
            || username.chars().count() > 256
            || username.chars().any(char::is_control)
            || host.chars().any(char::is_control)
        {
            return Err(invalid_key());
        }
        Ok(Self {
            account: format!("{}:{}:{}", host.trim().to_lowercase(), port, username),
        })
    }

    pub fn account(&self) -> &str {
        &self.account
    }
}

pub trait CredentialStore: Send + Sync {
    fn save(&self, key: &CredentialKey, password: &SecretString) -> Result<(), VpnError>;
    fn load(&self, key: &CredentialKey) -> Result<Option<SecretString>, VpnError>;
    fn delete(&self, key: &CredentialKey) -> Result<(), VpnError>;
}

#[derive(Clone, Copy)]
pub struct KeyringStore;

impl CredentialStore for KeyringStore {
    fn save(&self, key: &CredentialKey, password: &SecretString) -> Result<(), VpnError> {
        entry(key)?
            .set_password(password.expose_secret())
            .map_err(keyring_error)
    }

    fn load(&self, key: &CredentialKey) -> Result<Option<SecretString>, VpnError> {
        match entry(key)?.get_password() {
            Ok(password) => Ok(Some(SecretString::new(password))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(keyring_error(error)),
        }
    }

    fn delete(&self, key: &CredentialKey) -> Result<(), VpnError> {
        match entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(keyring_error(error)),
        }
    }
}

fn entry(key: &CredentialKey) -> Result<keyring::Entry, VpnError> {
    keyring::Entry::new("com.happyworking.vpn", key.account()).map_err(keyring_error)
}

fn keyring_error(_error: keyring::Error) -> VpnError {
    VpnError::new(ErrorCode::InternalError, "系统密钥环不可用或操作失败", &[])
}

fn invalid_key() -> VpnError {
    VpnError::new(
        ErrorCode::InvalidConfiguration,
        "凭据的主机、端口或用户名无效",
        &[],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "显式访问本机 Secret Service，并清理虚构测试账号"]
    fn secret_service_round_trip() {
        let key = CredentialKey::new(
            "test.invalid",
            443,
            &format!("happyworking-vpn-test-{}", std::process::id()),
        )
        .unwrap();
        let store = KeyringStore;
        struct Cleanup<'a> {
            store: &'a KeyringStore,
            key: &'a CredentialKey,
        }
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = self.store.delete(self.key);
            }
        }
        let cleanup = Cleanup {
            store: &store,
            key: &key,
        };
        store
            .save(&key, &SecretString::new("dummy-password".to_owned()))
            .unwrap();
        assert_eq!(
            store.load(&key).unwrap().unwrap().expose_secret(),
            "dummy-password"
        );
        store.delete(&key).unwrap();
        assert!(store.load(&key).unwrap().is_none());
        drop(cleanup);
    }
}
