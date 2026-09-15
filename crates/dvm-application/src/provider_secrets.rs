//! Provider credential lifecycle only. No provider SDK or network behavior.
use dvm_domain::{
    AppError, ErrorCode,
    security::{CredentialLookup, CredentialStore, SecretValue},
};

/// Backend-only access to OS-held provider credentials.
pub struct ProviderSecretStore<S: CredentialStore> {
    store: S,
}
impl<S: CredentialStore> ProviderSecretStore<S> {
    /// Injects the native store.
    pub const fn new(store: S) -> Self {
        Self { store }
    }
    fn reference(provider: &str, profile: &str) -> Result<String, AppError> {
        for part in [provider, profile] {
            if part.is_empty()
                || part.len() > 64
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(AppError::new(ErrorCode::ProviderAuthFailed));
            }
        }
        Ok(format!("dvm/provider/{provider}/{profile}"))
    }
    /// Writes a synthetic or user-provided credential solely to the OS store.
    /// # Errors
    /// Invalid reference or native store failure.
    pub fn store(
        &self,
        provider: &str,
        profile: &str,
        secret: &SecretValue,
    ) -> Result<(), AppError> {
        self.store
            .store(&Self::reference(provider, profile)?, secret)
    }
    /// Returns only a boolean suitable for a future narrow status command.
    ///
    /// A malformed persisted credential is deliberately not reported as
    /// unconfigured: it is an entry that exists and cannot be used, which is a
    /// different situation from having no credential at all and is repaired
    /// differently. Reporting `false` would invite a silent overwrite of state
    /// the caller never saw; reporting `true` would promise a usable
    /// credential. It fails instead, and never claims configuration.
    /// # Errors
    /// Invalid reference, a malformed persisted credential, or a native store
    /// failure.
    pub fn configured(&self, provider: &str, profile: &str) -> Result<bool, AppError> {
        Ok(self.lookup(provider, profile)?.is_some())
    }
    /// Trusted backend only; never register this method as IPC.
    /// # Errors
    /// Invalid reference, a malformed persisted credential, or a native store
    /// failure.
    pub fn retrieve(&self, provider: &str, profile: &str) -> Result<Option<SecretValue>, AppError> {
        self.lookup(provider, profile)
    }
    /// The single place the three lookup outcomes become provider semantics,
    /// so `configured` and `retrieve` cannot disagree about what is stored.
    ///
    /// An operational failure stays an operational failure; only a value the
    /// store positively reported as unusable becomes an authentication
    /// failure, carrying none of the offending bytes.
    fn lookup(&self, provider: &str, profile: &str) -> Result<Option<SecretValue>, AppError> {
        match self.store.retrieve(&Self::reference(provider, profile)?)? {
            CredentialLookup::Missing => Ok(None),
            CredentialLookup::Present(secret) => Ok(Some(secret)),
            CredentialLookup::InvalidStoredValue => {
                Err(AppError::new(ErrorCode::ProviderAuthFailed))
            }
        }
    }
    /// Removes one provider credential, safely if already absent.
    /// # Errors
    /// Invalid reference or native store failure.
    pub fn delete(&self, provider: &str, profile: &str) -> Result<(), AppError> {
        self.store.delete(&Self::reference(provider, profile)?)
    }
}
