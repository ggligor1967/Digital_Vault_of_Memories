//! Windows user-context generic credentials with explicit local persistence.
use dvm_domain::{
    AppError, ErrorCode,
    security::{CredentialLookup, CredentialStore, SecretValue, is_canonical_credential_reference},
};

/// Native adapter. No ambient keyring default and no renderer-accessible interface.
#[derive(Default)]
pub struct WindowsCredentialStore;

fn failure() -> AppError {
    AppError::new(ErrorCode::ProviderUnavailable)
}
/// Admission through the one canonical grammar shared with keyslot validation,
/// so the two languages cannot drift apart.
pub(crate) fn validate_reference(reference: &str) -> Result<(), AppError> {
    if is_canonical_credential_reference(reference) {
        Ok(())
    } else {
        Err(failure())
    }
}

/// Disposition of the last compensating removal this adapter performed after a
/// failed post-write persistence verification.
///
/// `set_secret` has already persisted the credential by the time verification
/// runs, so a verification failure is settled by removing exactly what was just
/// written. That removal is secondary evidence in the same sense as the keyslot
/// lifecycle cleanup: the verification failure is always the primary error the
/// store contract returns, and this records only the non-secret classification
/// of the removal. It names no credential, carries no secret bytes, and is
/// never read by production control flow.
#[cfg(windows)]
static POST_WRITE_COMPENSATION: std::sync::Mutex<Option<dvm_domain::security::CleanupOutcome>> =
    std::sync::Mutex::new(None);

/// Deterministic seam for the two steps that follow a successful `set_secret`.
///
/// In a production build both predicates are constant `false`, so the adapter
/// has no switch and cannot be steered from outside this crate. Only the test
/// build carries state, and even then it can never write a forbidden
/// persistence class to the real store: it reports one. The compensation branch
/// the seam exercises lives in the production adapter, so deleting that branch
/// is detectable by the oracles that use this seam.
#[cfg(windows)]
pub(crate) mod post_write_seam {
    /// Post-write persistence verification is never perturbed in production.
    #[cfg(not(test))]
    pub(super) const fn verification_fails(_reference: &str) -> bool {
        false
    }
    /// The compensating removal is never perturbed in production.
    #[cfg(not(test))]
    pub(super) const fn compensation_fails(_reference: &str) -> bool {
        false
    }

    #[cfg(test)]
    pub(crate) use testing::{arm, last_compensation, reset};
    #[cfg(test)]
    pub(super) use testing::{compensation_fails, verification_fails};

    #[cfg(test)]
    mod testing {
        use dvm_domain::security::CleanupOutcome;
        use std::sync::Mutex;

        /// Which credential reference is perturbed, and which of the two
        /// post-write steps must fail for it. Scoping to a single reference
        /// keeps the seam from disturbing any other test that uses the real
        /// store concurrently.
        #[derive(Default)]
        struct Faults {
            reference: Option<String>,
            verification: bool,
            compensation: bool,
        }
        static FAULTS: Mutex<Faults> = Mutex::new(Faults {
            reference: None,
            verification: false,
            compensation: false,
        });

        /// Arms the seam for exactly one credential reference.
        pub(crate) fn arm(reference: &str, verification: bool, compensation: bool) {
            if let Ok(mut faults) = FAULTS.lock() {
                *faults = Faults {
                    reference: Some(reference.to_owned()),
                    verification,
                    compensation,
                };
            }
        }
        /// Disarms the seam and forgets recorded evidence, so an oracle observes
        /// only the calls it made itself.
        pub(crate) fn reset() {
            if let Ok(mut faults) = FAULTS.lock() {
                *faults = Faults::default();
            }
            if let Ok(mut recorded) = crate::credentials::POST_WRITE_COMPENSATION.lock() {
                *recorded = None;
            }
        }
        /// Non-secret classification of the last compensating removal that
        /// production actually performed.
        pub(crate) fn last_compensation() -> Option<CleanupOutcome> {
            crate::credentials::POST_WRITE_COMPENSATION
                .lock()
                .ok()
                .and_then(|recorded| recorded.clone())
        }
        pub(crate) fn verification_fails(reference: &str) -> bool {
            FAULTS
                .lock()
                .is_ok_and(|f| f.verification && f.reference.as_deref() == Some(reference))
        }
        pub(crate) fn compensation_fails(reference: &str) -> bool {
            FAULTS
                .lock()
                .is_ok_and(|f| f.compensation && f.reference.as_deref() == Some(reference))
        }
    }
}

#[cfg(windows)]
mod native {
    use super::{
        AppError, CredentialLookup, CredentialStore, SecretValue, WindowsCredentialStore, failure,
        validate_reference,
    };
    use dvm_domain::security::CleanupOutcome;
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
    /// Whether Windows reports this credential as locally persisted.
    ///
    /// The two failure kinds are deliberately not the same value. Failing to
    /// *query* the attributes is an outage: nothing is known, so nothing may be
    /// concluded. A successful query that reports a persistence class this
    /// adapter forbids is a fact about the stored entry, and the read path
    /// turns it into a classification rather than an error.
    /// # Errors
    /// The attribute query itself failed.
    fn persisted_locally(entry: &Entry) -> Result<bool, AppError> {
        Ok(entry
            .get_attributes()
            .map_err(|_| failure())?
            .get("persistence")
            .is_some_and(|p| p.eq_ignore_ascii_case("local")))
    }
    /// The write path's stricter reading: anything but local persistence is a
    /// failure to be compensated, not a value to be classified.
    fn local(entry: &Entry) -> Result<(), AppError> {
        if persisted_locally(entry)? {
            Ok(())
        } else {
            Err(failure())
        }
    }
    /// Post-write verification of the persistence class Windows actually
    /// assigned to the credential `set_secret` has already stored.
    ///
    /// Kept separate from the read path's check so that a test seam proving the
    /// compensation branch cannot perturb `retrieve`.
    fn verify_persisted(reference: &str, entry: &Entry) -> Result<(), AppError> {
        if super::post_write_seam::verification_fails(reference) {
            return Err(failure());
        }
        local(entry)
    }
    /// Best-effort removal of the credential this call just persisted.
    ///
    /// Returns a classification rather than a `Result` because the caller must
    /// keep the verification failure as primary: this can only be recorded
    /// beside it.
    fn compensate(reference: &str, entry: &Entry) -> CleanupOutcome {
        if super::post_write_seam::compensation_fails(reference) {
            // Distinctly classified, so a masked primary failure is detectable.
            return CleanupOutcome::Failed(Box::new(AppError::new(super::ErrorCode::DiskFull)));
        }
        match entry.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => CleanupOutcome::Completed,
            Err(_) => CleanupOutcome::Failed(Box::new(failure())),
        }
    }
    /// Records the non-secret disposition of a compensating removal. A poisoned
    /// recorder is discarded rather than turned into a failure, because
    /// secondary evidence must never displace the primary error.
    fn record(cleanup: CleanupOutcome) {
        if let Ok(mut recorded) = super::POST_WRITE_COMPENSATION.lock() {
            *recorded = Some(cleanup);
        }
    }
    /// Persists a raw blob the way an external writer or an earlier release
    /// could have left one, including representations no `SecretValue` holds.
    ///
    /// Test-only. The production write path takes a `SecretValue` and so cannot
    /// create an invalid entry at all, which is precisely why staging that
    /// class in the *real* Windows store needs a seam. It writes through the
    /// same entry builder and persistence class as `store`, so what the read
    /// path then classifies is a genuine Windows credential, not a simulation.
    #[cfg(test)]
    pub(crate) fn store_raw(reference: &str, bytes: &[u8]) -> Result<(), AppError> {
        let _guard = ACCESS.lock().map_err(|_| failure())?;
        entry(reference)?.set_secret(bytes).map_err(|_| failure())
    }
    impl CredentialStore for WindowsCredentialStore {
        fn store(&self, reference: &str, secret: &SecretValue) -> Result<(), AppError> {
            let _guard = ACCESS.lock().map_err(|_| failure())?;
            let entry = entry(reference)?;
            entry.set_secret(secret.as_bytes()).map_err(|_| failure())?;
            // `set_secret` has already persisted the credential, so a failed
            // post-write verification must not leave it stored, least of all
            // under a persistence class this adapter forbids. The exact entry
            // just written is removed best effort, the verification failure
            // stays primary, and the removal is recorded beside it.
            if let Err(primary) = verify_persisted(reference, &entry) {
                record(compensate(reference, &entry));
                return Err(primary);
            }
            Ok(())
        }
        /// Classifies what Windows actually holds, before any of it is trusted.
        ///
        /// The raw blob never leaves this function: it is read into zeroizing
        /// storage, judged, and either promoted to a `SecretValue` or dropped.
        /// A blob the invariant rejects — an empty credential is the reachable
        /// case, since Windows both accepts and returns one — is reported as an
        /// unusable stored value, not as a failure of the credential service,
        /// so an authenticated caller can still repair the entry.
        fn retrieve(&self, reference: &str) -> Result<CredentialLookup, AppError> {
            let _guard = ACCESS.lock().map_err(|_| failure())?;
            let entry = entry(reference)?;
            let bytes = match entry.get_secret() {
                Ok(value) => Zeroizing::new(value),
                Err(keyring_core::Error::NoEntry) => return Ok(CredentialLookup::Missing),
                Err(_) => return Err(failure()),
            };
            // An entry exists, so a forbidden persistence class is now a
            // property of that entry rather than a reason to fail the read.
            if !persisted_locally(&entry)? {
                return Ok(CredentialLookup::InvalidStoredValue);
            }
            Ok(CredentialLookup::classify(bytes))
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

/// Test-only staging of raw persisted state; see [`native::store_raw`].
#[cfg(all(windows, test))]
pub(crate) use native::store_raw;

#[cfg(not(windows))]
impl CredentialStore for WindowsCredentialStore {
    fn store(&self, reference: &str, _: &SecretValue) -> Result<(), AppError> {
        validate_reference(reference)?;
        Err(failure())
    }
    fn retrieve(&self, reference: &str) -> Result<CredentialLookup, AppError> {
        validate_reference(reference)?;
        Err(failure())
    }
    fn delete(&self, reference: &str) -> Result<(), AppError> {
        validate_reference(reference)?;
        Err(failure())
    }
}
