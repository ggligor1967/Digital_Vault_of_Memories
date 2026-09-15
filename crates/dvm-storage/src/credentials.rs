//! Windows user-context generic credentials with explicit local persistence.
use dvm_domain::{
    AppError, ErrorCode,
    security::{CredentialStore, SecretValue, is_canonical_credential_reference},
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
        AppError, CredentialStore, SecretValue, WindowsCredentialStore, failure, validate_reference,
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
