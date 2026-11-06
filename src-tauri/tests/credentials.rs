use std::{collections::HashMap, sync::Mutex};

use happyworking_vpn_app::credentials::{CredentialKey, CredentialStore};
use happyworking_vpn_core::SecretString;

#[derive(Default)]
struct FakeStore {
    values: Mutex<HashMap<String, String>>,
}

impl CredentialStore for FakeStore {
    fn save(
        &self,
        key: &CredentialKey,
        password: &SecretString,
    ) -> Result<(), happyworking_vpn_core::VpnError> {
        self.values.lock().unwrap().insert(
            key.account().to_owned(),
            password.expose_secret().to_owned(),
        );
        Ok(())
    }

    fn load(
        &self,
        key: &CredentialKey,
    ) -> Result<Option<SecretString>, happyworking_vpn_core::VpnError> {
        Ok(self
            .values
            .lock()
            .unwrap()
            .get(key.account())
            .map(|value| SecretString::new(value.clone())))
    }

    fn delete(&self, key: &CredentialKey) -> Result<(), happyworking_vpn_core::VpnError> {
        self.values.lock().unwrap().remove(key.account());
        Ok(())
    }
}

#[test]
fn key_is_scoped_by_host_port_and_username() {
    let key = CredentialKey::new("VPN.Example.com", 443, "alice").unwrap();
    assert_eq!(key.account(), "vpn.example.com:443:alice");
}

#[test]
fn rejects_invalid_credential_keys() {
    assert!(CredentialKey::new("", 443, "alice").is_err());
    assert!(CredentialKey::new("vpn.example.com", 0, "alice").is_err());
    assert!(CredentialKey::new("vpn.example.com", 443, "").is_err());
    assert!(CredentialKey::new("vpn.example.com", 443, "alice\n").is_err());
}

#[test]
fn store_supports_save_load_and_delete() {
    let store = FakeStore::default();
    let key = CredentialKey::new("vpn.example.com", 443, "alice").unwrap();
    let password = SecretString::new("dummy-password".to_owned());

    store.save(&key, &password).unwrap();
    assert_eq!(
        store.load(&key).unwrap().unwrap().expose_secret(),
        "dummy-password"
    );
    store.delete(&key).unwrap();
    assert!(store.load(&key).unwrap().is_none());
}
