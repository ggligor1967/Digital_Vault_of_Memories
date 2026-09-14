//! Non-secret keyslot envelopes and trusted session ports.
use crate::{AppError, storage::ReconciliationHealth};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Trusted credential value. No Debug or Serialize, and zeroized on drop.
/// ```compile_fail
/// let value: Option<dvm_domain::security::SecretValue> = None;
/// serde_json::to_string(&value).unwrap();
/// ```
/// ```compile_fail
/// let value: Option<dvm_domain::security::SecretValue> = None;
/// format!("{value:?}");
/// ```
pub struct SecretValue(Zeroizing<Vec<u8>>);
impl SecretValue {
    /// Owns bounded OS credential material.
    /// # Errors
    /// Empty or over-2560-byte credentials are rejected.
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Result<Self, AppError> {
        if bytes.is_empty() || bytes.len() > 2560 {
            return Err(AppError::new(crate::ErrorCode::ProviderAuthFailed));
        }
        Ok(Self(bytes))
    }
    /// Borrow only in trusted native code.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Trusted OS credential port; no renderer command implements this interface.
pub trait CredentialStore: Send + Sync {
    /// Stores only in the user-scoped operating-system store.
    /// # Errors
    /// Invalid reference, unsupported platform or native write failure.
    fn store(&self, reference: &str, secret: &SecretValue) -> Result<(), AppError>;
    /// Returns absence distinctly, never creating an entry while reading.
    /// # Errors
    /// Invalid reference or native failure.
    fn retrieve(&self, reference: &str) -> Result<Option<SecretValue>, AppError>;
    /// Idempotently removes one application-owned entry.
    /// # Errors
    /// Invalid reference or native failure.
    fn delete(&self, reference: &str) -> Result<(), AppError>;
}

/// Persisted Argon2id version 0x13 costs, in KiB and iterations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgonProfile {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Number of lanes.
    pub parallelism: u32,
}

impl ArgonProfile {
    /// Lowest accepted production cost. Tests must not bypass it.
    pub const BASELINE: Self = Self {
        memory_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
    };
}

/// Authenticated non-secret envelope. Types and algorithms are checked before use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keyslot {
    /// Exact versioned type: passphrase-v1, recovery-v1 or device-v1.
    pub slot_type: String,
    /// Mandatory slot interpretation version.
    pub version: u32,
    /// Canonical random UUID.
    pub id: String,
    /// Exact wrapping primitive identifier.
    pub wrap_algorithm: String,
    /// Exact derivation identifier; empty for a device KEK.
    pub kdf_algorithm: String,
    /// Present only for a passphrase.
    pub argon: Option<ArgonProfile>,
    /// Sixteen random bytes for a passphrase; empty otherwise.
    pub salt: Vec<u8>,
    /// Fresh 24-byte `XChaCha` nonce.
    pub nonce: Vec<u8>,
    /// Opaque application credential target for a device slot; empty otherwise.
    pub credential_ref: String,
    /// Exactly 32 ciphertext bytes followed by the 16-byte authentication tag.
    pub wrapped_vmk: Vec<u8>,
}

/// User decision at the trusted creation boundary.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPolicy {
    /// Default: generate independent recovery material.
    #[default]
    Generate,
    /// Caller confirms warning: losing the passphrase may permanently lose access.
    DeclinedAfterDataLossWarning,
}

/// Public operational state; contains no private metadata.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VaultState {
    /// No vault selected.
    #[default]
    Closed,
    /// Selected, no live keys.
    Locked,
    /// Authentication in progress.
    Unlocking,
    /// Only state admitting content operations.
    Open,
    /// Admission closed and live owner being released.
    Locking,
    /// Storage health prohibits normal operation.
    DegradedReadOnly,
}

/// Application-owned port implemented by trusted infrastructure.
pub trait SessionBackend: Send {
    /// Nonserializable credential supplied by a trusted caller.
    type Credential;
    /// Single live key/storage owner.
    type Active: Send;
    /// Authenticates before opening or mutating storage.
    /// # Errors
    /// Authentication, format or storage failure; no partial owner is returned.
    fn unlock(&self, credential: &Self::Credential) -> Result<Self::Active, AppError>;
    /// Current storage admission health.
    fn health(active: &Self::Active) -> ReconciliationHealth;
}
