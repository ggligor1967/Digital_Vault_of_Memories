//! Windows user-context generic credentials with explicit local persistence.
use dvm_domain::{
    AppError, ErrorCode,
    security::{CredentialStore, SecretValue},
};

/// Native adapter. No ambient keyring default and no renderer-accessible interface.
#[derive(Default)]
pub struct WindowsCredentialStore;

fn failure() -> AppError {
    AppError::new(ErrorCode::ProviderUnavailable)
}
fn validate_reference(reference: &str) -> Result<(), AppError> {
    if reference.len() > 180
        || reference.len() < 12
        || !(reference.starts_with("dvm/device/") || reference.starts_with("dvm/provider/"))
        || !reference
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"/-".contains(&b))
    {
        return Err(failure());
    }
    Ok(())
}

#[cfg(windows)]
mod native {
    use super::{
        AppError, CredentialStore, SecretValue, WindowsCredentialStore, failure, validate_reference,
    };
    use keyring_core::{Entry, api::CredentialStoreApi};
    use std::{collections::HashMap, sync::Mutex};
    use zeroize::Zeroizing;

    // Serialize across adapter instances: Windows does not promise reliable
    // ordering for concurrent reads/writes to the same credential.
    static ACCESS: Mutex<()> = Mutex::new(());
    fn entry(reference: &str) -> Result<Entry, AppError> {
        validate_reference(reference)?;
        let store = windows_native_keyring_store::Store::new().map_err(|_| failure())?;
        store
            .build(
                "dvm",
                "local",
                Some(&HashMap::from([
                    ("target", reference),
                    ("persistence", "Local"),
                ])),
            )
            .map_err(|_| failure())
    }
    fn local(entry: &Entry) -> Result<(), AppError> {
        let attributes = entry.get_attributes().map_err(|_| failure())?;
        if !attributes
            .get("persistence")
            .is_some_and(|p| p.eq_ignore_ascii_case("local"))
        {
            return Err(failure());
        }
        Ok(())
    }
    impl CredentialStore for WindowsCredentialStore {
        fn store(&self, reference: &str, secret: &SecretValue) -> Result<(), AppError> {
            let _guard = ACCESS.lock().map_err(|_| failure())?;
            let entry = entry(reference)?;
            entry.set_secret(secret.as_bytes()).map_err(|_| failure())?;
            local(&entry)
        }
        fn retrieve(&self, reference: &str) -> Result<Option<SecretValue>, AppError> {
            let _guard = ACCESS.lock().map_err(|_| failure())?;
            let entry = entry(reference)?;
            let bytes = match entry.get_secret() {
                Ok(value) => Zeroizing::new(value),
                Err(keyring_core::Error::NoEntry) => return Ok(None),
                Err(_) => return Err(failure()),
            };
            local(&entry)?;
            Ok(Some(SecretValue::new(bytes)?))
        }
        fn delete(&self, reference: &str) -> Result<(), AppError> {
            let _guard = ACCESS.lock().map_err(|_| failure())?;
            match entry(reference)?.delete_credential() {
                Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
                Err(_) => Err(failure()),
            }
        }
    }
}

#[cfg(not(windows))]
impl CredentialStore for WindowsCredentialStore {
    fn store(&self, reference: &str, _: &SecretValue) -> Result<(), AppError> {
        validate_reference(reference)?;
        Err(failure())
    }
    fn retrieve(&self, reference: &str) -> Result<Option<SecretValue>, AppError> {
        validate_reference(reference)?;
        Err(failure())
    }
    fn delete(&self, reference: &str) -> Result<(), AppError> {
        validate_reference(reference)?;
        Err(failure())
    }
}
