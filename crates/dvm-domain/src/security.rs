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

/// What a credential store found, once raw persisted bytes have been judged
/// against the [`SecretValue`] invariant.
///
/// A stored credential is external input: the operating system will hand back
/// whatever is recorded under a reference, including representations no
/// trusted value can hold. Promoting those bytes directly into a
/// [`SecretValue`] is what erases the distinction this type exists to keep —
/// a rejected conversion becomes an error indistinguishable from the
/// credential service being unreachable, and a caller that could have repaired
/// the entry is told to give up instead.
///
/// Read together with the enclosing `Result`, the four outcomes are distinct:
///
/// * `Ok(Missing)` — the store answered; no entry exists.
/// * `Ok(Present(_))` — the store answered; the stored value satisfies the
///   trusted invariant.
/// * `Ok(InvalidStoredValue)` — the store answered; an entry exists but what
///   it holds is unusable. Repairable by re-enrollment.
/// * `Err(_)` — the credential service itself failed. Nothing is known about
///   the entry, so nothing may be rotated on the strength of it.
///
/// No `Debug` or `Serialize`, for the same reason [`SecretValue`] has neither.
/// ```compile_fail
/// let value: Option<dvm_domain::security::CredentialLookup> = None;
/// serde_json::to_string(&value).unwrap();
/// ```
/// ```compile_fail
/// let value: Option<dvm_domain::security::CredentialLookup> = None;
/// format!("{value:?}");
/// ```
pub enum CredentialLookup {
    /// The store answered and holds no entry under this reference.
    Missing,
    /// The store answered and the persisted value is trusted credential material.
    Present(SecretValue),
    /// The store answered and an entry exists, but its stored representation
    /// is invalid or policy-unusable.
    ///
    /// Carries no payload by construction: the offending bytes are dropped,
    /// and therefore zeroized, at the point of classification. Nothing
    /// downstream can reach them, log them or return them.
    InvalidStoredValue,
}
impl CredentialLookup {
    /// Judges raw persisted bytes an adapter has just read from an entry that
    /// exists.
    ///
    /// This is the only boundary at which untrusted stored bytes become a
    /// trusted value. Bytes the invariant rejects are consumed here and
    /// zeroized on drop rather than travelling any further, so an invalid
    /// persisted credential is classified without ever being handled.
    #[must_use]
    pub fn classify(bytes: Zeroizing<Vec<u8>>) -> Self {
        SecretValue::new(bytes).map_or(Self::InvalidStoredValue, Self::Present)
    }
}

/// Trusted OS credential port; no renderer command implements this interface.
pub trait CredentialStore: Send + Sync {
    /// Stores only in the user-scoped operating-system store.
    /// # Errors
    /// Invalid reference, unsupported platform or native write failure.
    fn store(&self, reference: &str, secret: &SecretValue) -> Result<(), AppError>;
    /// Classifies what is persisted, never creating an entry while reading.
    ///
    /// Absence, an unusable stored value and an operational failure are three
    /// different answers; see [`CredentialLookup`].
    /// # Errors
    /// Invalid reference or native failure. Never a malformed stored value:
    /// that is `Ok(CredentialLookup::InvalidStoredValue)`.
    fn retrieve(&self, reference: &str) -> Result<CredentialLookup, AppError>;
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

/// Canonical prefix of every device credential reference.
pub const DEVICE_REFERENCE_PREFIX: &str = "dvm/device/";
/// Canonical prefix of every provider credential reference.
pub const PROVIDER_REFERENCE_PREFIX: &str = "dvm/provider/";
/// Shortest admissible credential reference: a prefix plus a non-empty suffix.
const REFERENCE_MIN_LEN: usize = 12;
/// Longest admissible credential reference.
const REFERENCE_MAX_LEN: usize = 160;

/// The single canonical credential-reference grammar.
///
/// Persisted keyslot admission and the operating-system credential adapter
/// must accept exactly the same language, otherwise a header can be admitted
/// whose device credential the adapter later refuses, making quick unlock
/// permanently impossible. Both call this function so the two languages cannot
/// drift apart.
///
/// A reference is bounded ASCII: lowercase letters, digits, `/` and `-`,
/// carrying an exact application prefix. Uppercase is rejected rather than
/// normalised, so a malformed reference fails closed at admission.
#[must_use]
pub fn is_canonical_credential_reference(reference: &str) -> bool {
    (REFERENCE_MIN_LEN..=REFERENCE_MAX_LEN).contains(&reference.len())
        && (reference.starts_with(DEVICE_REFERENCE_PREFIX)
            || reference.starts_with(PROVIDER_REFERENCE_PREFIX))
        && reference
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"/-".contains(&b))
}

/// The canonical grammar restricted to the device credential prefix.
///
/// Every reference accepted here is accepted by
/// [`is_canonical_credential_reference`], and therefore by the credential
/// adapter.
#[must_use]
pub fn is_canonical_device_reference(reference: &str) -> bool {
    reference.starts_with(DEVICE_REFERENCE_PREFIX) && is_canonical_credential_reference(reference)
}

/// Durability of a vault header that has already passed its activation point.
///
/// The activation point is the successful atomic replacement of `vault.header`
/// by a validated new header. Before it the old header is authoritative; after
/// it the new header is, and no later failure may be reported as though the old
/// credentials were still valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderDurability {
    /// The activated header was synced and re-read successfully.
    Durable,
    /// The activated header is authoritative, but a post-activation durability
    /// or verification step did not complete. The new credentials are valid and
    /// must be retained; the envelope describes only the secondary failure.
    Uncertain(AppError),
}

impl HeaderDurability {
    /// Whether the activated header was also proven durable.
    #[must_use]
    pub const fn is_durable(&self) -> bool {
        matches!(self, Self::Durable)
    }
    /// The non-secret secondary failure, when durability is uncertain.
    #[must_use]
    pub const fn uncertainty(&self) -> Option<&AppError> {
        match self {
            Self::Durable => None,
            Self::Uncertain(error) => Some(error),
        }
    }
    /// Records a post-activation failure without ever revoking activation.
    ///
    /// The first uncertainty is kept, so a chain of secondary failures cannot
    /// obscure the one that actually broke durability.
    #[must_use]
    pub fn degraded(self, error: AppError) -> Self {
        match self {
            Self::Durable => Self::Uncertain(error),
            uncertain @ Self::Uncertain(_) => uncertain,
        }
    }
}

/// Disposition of best-effort removal of a credential that the authoritative
/// header does not reference.
///
/// Cleanup is always secondary evidence: it never replaces a primary error and
/// never converts a completed activation into a failure. No variant carries
/// credential material; [`AppError`] is the non-secret envelope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CleanupOutcome {
    /// No unreferenced credential needed removal.
    #[default]
    NotRequired,
    /// The unreferenced credential was removed.
    Completed,
    /// The unreferenced credential remains and must be reclaimed later. The
    /// envelope is boxed so that carrying cleanup evidence never inflates the
    /// error arm of a lifecycle result.
    Failed(Box<AppError>),
}

impl CleanupOutcome {
    /// Whether an unreferenced credential is known to remain in the OS store.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
    /// The non-secret envelope of a failed cleanup.
    #[must_use]
    pub fn failure(&self) -> Option<&AppError> {
        match self {
            Self::Failed(error) => Some(error.as_ref()),
            Self::NotRequired | Self::Completed => None,
        }
    }
}

/// A trusted keyslot operation whose header replacement passed the activation
/// point.
///
/// Holding this value means the new credential state is already authoritative:
/// the caller must adopt the new credentials and must not fall back to the
/// previous ones. Any newly generated secret is carried in the value, so
/// activation can never silently destroy recoverable material.
pub struct Activated<T> {
    value: T,
    durability: HeaderDurability,
    cleanup: CleanupOutcome,
}

impl<T> Activated<T> {
    /// Records an activation together with its secondary evidence.
    #[must_use]
    pub const fn new(value: T, durability: HeaderDurability, cleanup: CleanupOutcome) -> Self {
        Self {
            value,
            durability,
            cleanup,
        }
    }
    /// Borrows the newly authoritative material.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }
    /// Takes ownership of the newly authoritative material.
    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }
    /// Post-activation durability of the now authoritative header.
    #[must_use]
    pub const fn durability(&self) -> &HeaderDurability {
        &self.durability
    }
    /// Disposition of any unreferenced predecessor credential.
    #[must_use]
    pub const fn cleanup(&self) -> &CleanupOutcome {
        &self.cleanup
    }
    /// Whether activation was durable and left no unreferenced credential in
    /// the operating-system store.
    ///
    /// A cleanup that *completed* removed the unreferenced credential, so it
    /// leaves no residual work and settles exactly as fully as a cleanup that
    /// was never required. Only [`CleanupOutcome::Failed`] names a credential
    /// that is known to remain and must be reclaimed later, so only it keeps a
    /// durable activation from being fully settled.
    ///
    /// The predicate asks [`CleanupOutcome::is_failed`] rather than repeating
    /// the list of settled variants, so the two cannot drift apart.
    #[must_use]
    pub const fn is_fully_settled(&self) -> bool {
        self.durability.is_durable() && !self.cleanup.is_failed()
    }
    /// Rewrites the carried material, preserving the activation evidence.
    #[must_use]
    pub fn map<U>(self, operation: impl FnOnce(T) -> U) -> Activated<U> {
        Activated {
            value: operation(self.value),
            durability: self.durability,
            cleanup: self.cleanup,
        }
    }
}

/// A trusted keyslot operation that failed strictly before the activation
/// point.
///
/// The previously active credential state remains authoritative, so the caller
/// must keep using the old credentials. The primary failure is always
/// preserved: a failed best-effort cleanup is recorded alongside it and never
/// replaces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotActivated {
    primary: AppError,
    cleanup: CleanupOutcome,
}

impl NotActivated {
    /// Records a pre-activation failure and the disposition of its cleanup.
    #[must_use]
    pub const fn new(primary: AppError, cleanup: CleanupOutcome) -> Self {
        Self { primary, cleanup }
    }
    /// The primary failure. This is the cause the caller must act on.
    #[must_use]
    pub const fn primary(&self) -> &AppError {
        &self.primary
    }
    /// Disposition of the credential the still-active old header does not
    /// reference.
    #[must_use]
    pub const fn cleanup(&self) -> &CleanupOutcome {
        &self.cleanup
    }
    /// Attaches secondary cleanup evidence without disturbing the primary
    /// failure.
    #[must_use]
    pub fn with_cleanup(mut self, cleanup: CleanupOutcome) -> Self {
        self.cleanup = cleanup;
        self
    }
    /// Unwraps to the primary envelope for callers that carry only `AppError`.
    #[must_use]
    pub fn into_primary(self) -> AppError {
        self.primary
    }
}

impl From<AppError> for NotActivated {
    fn from(primary: AppError) -> Self {
        Self::new(primary, CleanupOutcome::NotRequired)
    }
}

impl core::fmt::Display for NotActivated {
    /// Renders the primary envelope first, then a classification of the
    /// secondary cleanup. Neither carries credential material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "not activated: {}", self.primary)?;
        match &self.cleanup {
            CleanupOutcome::NotRequired => Ok(()),
            CleanupOutcome::Completed => write!(f, "; cleanup completed"),
            CleanupOutcome::Failed(error) => write!(f, "; cleanup failed: {error}"),
        }
    }
}

impl core::error::Error for NotActivated {}

/// Outcome of a trusted keyslot lifecycle operation, phase-aware by
/// construction: the success arm can only be built after activation and the
/// failure arm only before it, so no caller can confuse the two states.
pub type Committed<T> = Result<Activated<T>, NotActivated>;
#[cfg(test)]
mod tests {
    use super::{Activated, CleanupOutcome, HeaderDurability};
    use crate::{AppError, ErrorCode};

    /// The complete settlement oracle. Durability and cleanup are independent
    /// axes, so the predicate is pinned over every combination rather than over
    /// the cases that happen to occur in the current lifecycle paths.
    #[test]
    fn settlement_truth_table_is_exhaustive() {
        let secondary = || AppError::new(ErrorCode::DiskFull);
        let table = [
            (true, CleanupOutcome::NotRequired, true),
            (true, CleanupOutcome::Completed, true),
            (true, CleanupOutcome::Failed(Box::new(secondary())), false),
            (false, CleanupOutcome::NotRequired, false),
            (false, CleanupOutcome::Completed, false),
            (false, CleanupOutcome::Failed(Box::new(secondary())), false),
        ];
        for (durable, cleanup, settled) in table {
            let durability = if durable {
                HeaderDurability::Durable
            } else {
                HeaderDurability::Uncertain(AppError::new(ErrorCode::Internal))
            };
            let activated = Activated::new((), durability, cleanup.clone());
            assert_eq!(
                activated.is_fully_settled(),
                settled,
                "settlement is wrong for durable={durable} cleanup={cleanup:?}"
            );
        }
        println!("SETTLEMENT_TRUTH_TABLE=PASS");
    }

    /// A completed cleanup is settled *and* reports no residue, while a failed
    /// one names its non-secret envelope. This keeps the settlement predicate
    /// and the cleanup accessors from disagreeing about the same outcome.
    #[test]
    fn completed_cleanup_reports_no_remaining_credential() {
        assert!(!CleanupOutcome::NotRequired.is_failed());
        assert!(!CleanupOutcome::Completed.is_failed());
        assert!(CleanupOutcome::NotRequired.failure().is_none());
        assert!(CleanupOutcome::Completed.failure().is_none());
        let failed = CleanupOutcome::Failed(Box::new(AppError::new(ErrorCode::DiskFull)));
        assert!(failed.is_failed());
        assert_eq!(failed.failure().map(|e| e.code), Some(ErrorCode::DiskFull));
    }
}
