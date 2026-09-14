//! Production keyslot lifecycle. All paths and credentials are trusted native inputs.
use crate::{Vault, header, vault::io_error};
use dvm_crypto::{
    DigestReceipt, PlaintextSink, VaultMasterKey,
    keyslots::{self, DeviceKey, Passphrase, RecoverySecret},
};
use dvm_domain::{
    AppError, ErrorCode,
    security::{
        Activated, ArgonProfile, CleanupOutcome, Committed, CredentialStore, HeaderDurability,
        NotActivated, RecoveryPolicy, SecretValue, SessionBackend,
    },
    storage::{ImportReceipt, ImportRepository, ReconciliationHealth, VaultHeader},
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Trusted unlock input. None of these values implement Serialize or Debug.
pub enum UnlockCredential {
    /// Exact UTF-8 passphrase.
    Passphrase(Passphrase),
    /// Independent recovery material.
    Recovery(RecoverySecret),
    /// Ask the trusted OS store for a device KEK.
    Device,
}

/// Locked production backend: contains no VMK or derived storage keys.
pub struct ProtectedVault {
    root: PathBuf,
    credentials: Arc<dyn CredentialStore>,
}

/// Single active owner; application session must guard every content operation.
pub struct OpenVault {
    vault: Vault,
    vmk: VaultMasterKey,
    credentials: Arc<dyn CredentialStore>,
    _keyslot_ownership: File,
}

fn read_header(root: &Path) -> Result<VaultHeader, AppError> {
    let path = root.join("vault.header");
    if fs::symlink_metadata(&path)
        .map_err(|e| io_error(&e))?
        .file_type()
        .is_symlink()
    {
        return Err(AppError::new(ErrorCode::CorruptHeader));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| io_error(&e))?
        .take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error(&e))?;
    header::parse(&bytes)
}

#[cfg(test)]
thread_local! {
    static UPDATE_FAULT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn checkpoint(point: &str) -> Result<(), AppError> {
    tests::crash_point(point);
    if UPDATE_FAULT.with(|f| f.get() == Some(point)) {
        return Err(AppError::new(ErrorCode::Internal));
    }
    Ok(())
}

/// `HEADER_ACTIVATED` is the successful atomic replacement of `vault.header` by
/// the validated new header. It is the single linearization point of the
/// keyslot lifecycle: before it the old header is authoritative, after it the
/// new one is. The return type carries that phase, so a post-activation
/// durability failure can never be mistaken for a pre-activation failure.
fn replace_header(root: &Path, new: &VaultHeader) -> Result<HeaderDurability, NotActivated> {
    let bytes = header::serialize(new)?;
    #[cfg(test)]
    checkpoint("before-temp")?;
    let temp = root.join(format!(".keyslot-{}.tmp", Uuid::new_v4()));
    let staged = (|| -> Result<(), AppError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| io_error(&e))?;
        file.write_all(&bytes).map_err(|e| io_error(&e))?;
        #[cfg(test)]
        checkpoint("after-temp")?;
        file.flush().map_err(|e| io_error(&e))?;
        file.sync_all().map_err(|e| io_error(&e))?;
        #[cfg(test)]
        checkpoint("after-sync")?;
        drop(file);
        #[cfg(test)]
        checkpoint("before-activation")?;
        fs::rename(&temp, root.join("vault.header")).map_err(|e| io_error(&e))
    })();
    if let Err(error) = staged {
        // This name was created by this invocation, and never names user content.
        if temp.exists() {
            let _ = fs::remove_file(&temp);
        }
        return Err(NotActivated::from(error));
    }
    // Past the activation point. Every remaining failure is durability
    // uncertainty about credentials that are already authoritative.
    #[cfg(test)]
    if let Err(error) = checkpoint("after-activation") {
        return Ok(HeaderDurability::Uncertain(error));
    }
    let durable = OpenOptions::new()
        .write(true)
        .open(root.join("vault.header"))
        .and_then(|f| f.sync_all());
    #[cfg(test)]
    if let Err(error) = checkpoint("post-activation-sync") {
        return Ok(HeaderDurability::Uncertain(error));
    }
    match durable {
        Ok(()) => Ok(HeaderDurability::Durable),
        Err(error) => Ok(HeaderDurability::Uncertain(io_error(&error))),
    }
}

/// Everything a caller must receive once vault creation passed the activation
/// point. The recovery credential is persisted as a keyslot the instant the
/// header activates, so it is delivered here even when a later durability step
/// reports uncertainty; dropping it would make that slot unusable forever.
pub struct CreatedVault {
    /// Locked backend for the newly activated vault.
    pub backend: ProtectedVault,
    /// Generated recovery credential, present exactly when the policy asked
    /// for one and the recovery slot is therefore active in `vault.header`.
    pub recovery: Option<RecoverySecret>,
}

impl ProtectedVault {
    /// Default production creation generates recovery and calibrates the KDF.
    ///
    /// A successful return means the header activated, so the generated
    /// recovery credential is already persisted and is always delivered.
    /// # Errors
    /// Refuses existing paths and fails closed on any pre-activation crypto or
    /// storage error; the vault is then not created.
    pub fn create(
        root: &Path,
        passphrase: &Passphrase,
        credentials: Arc<dyn CredentialStore>,
    ) -> Committed<CreatedVault> {
        Self::create_with_policy(
            root,
            passphrase,
            RecoveryPolicy::Generate,
            keyslots::calibrate()?.0,
            credentials,
        )
    }
    /// Explicit trusted policy and validated production costs, including acknowledged decline.
    /// # Errors
    /// Invalid profile, or a pre-activation failure to bootstrap a new vault.
    /// A failure here means no header ever activated.
    pub fn create_with_policy(
        root: &Path,
        passphrase: &Passphrase,
        policy: RecoveryPolicy,
        profile: ArgonProfile,
        credentials: Arc<dyn CredentialStore>,
    ) -> Committed<CreatedVault> {
        keyslots::validate_profile(profile)?;
        let vmk = VaultMasterKey::generate()?;
        let mut envelope = header::injected_key_header();
        envelope.keyslots.push(keyslots::wrap_passphrase(
            &envelope.vault_id,
            &vmk,
            passphrase,
            profile,
        )?);
        let recovery = if policy == RecoveryPolicy::Generate {
            let secret = RecoverySecret::generate()?;
            envelope
                .keyslots
                .push(keyslots::wrap_recovery(&envelope.vault_id, &vmk, &secret)?);
            Some(secret)
        } else {
            None
        };
        // The injected bootstrap remains non-admissible to production until the
        // fully authenticated header has atomically activated.
        let vault = Vault::create_with_injected_key(root, &vmk)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("local-state/keyslots.lock"))
            .and_then(|file| file.sync_all())
            .map_err(|e| io_error(&e))?;
        // Resolved before activation so that nothing fallible stands between
        // the activation point and delivery of the recovery credential.
        let canonical = fs::canonicalize(root).map_err(|e| io_error(&e))?;
        let durability = replace_header(root, &envelope)?;
        drop(vault);
        // Post-activation verification can only downgrade durability. It must
        // never withhold the now-persisted recovery credential.
        let durability = match read_header(&canonical) {
            Ok(_) => durability,
            Err(error) => durability.degraded(error),
        };
        Ok(Activated::new(
            CreatedVault {
                backend: Self {
                    root: canonical,
                    credentials,
                },
                recovery,
            },
            durability,
            CleanupOutcome::NotRequired,
        ))
    }
    /// Selects a production envelope without opening private metadata.
    /// # Errors
    /// Missing, malformed or unsupported production vault.
    pub fn select(root: &Path, credentials: Arc<dyn CredentialStore>) -> Result<Self, AppError> {
        read_header(root)?;
        Ok(Self {
            root: fs::canonicalize(root).map_err(|e| io_error(&e))?,
            credentials,
        })
    }
}

impl SessionBackend for ProtectedVault {
    type Credential = UnlockCredential;
    type Active = OpenVault;
    fn unlock(&self, credential: &UnlockCredential) -> Result<OpenVault, AppError> {
        // Existing lock only: an unsuccessful unlock must not create any file.
        let ownership = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.root.join("local-state/keyslots.lock"))
            .map_err(|e| io_error(&e))?;
        ownership
            .try_lock()
            .map_err(|_| AppError::new(ErrorCode::VaultLocked))?;
        let envelope = read_header(&self.root)?;
        let kind = match credential {
            UnlockCredential::Passphrase(_) => "passphrase-v1",
            UnlockCredential::Recovery(_) => "recovery-v1",
            UnlockCredential::Device => "device-v1",
        };
        let slot = envelope
            .keyslots
            .iter()
            .find(|s| s.slot_type == kind)
            .ok_or_else(|| AppError::new(ErrorCode::BadPassphrase))?;
        let vmk = match credential {
            UnlockCredential::Passphrase(passphrase) => {
                keyslots::unwrap_passphrase(&envelope.vault_id, slot, passphrase)?
            }
            UnlockCredential::Recovery(secret) => {
                keyslots::unwrap_recovery(&envelope.vault_id, slot, secret)?
            }
            UnlockCredential::Device => {
                let secret = self
                    .credentials
                    .retrieve(&slot.credential_ref)?
                    .ok_or_else(|| AppError::new(ErrorCode::ProviderUnavailable))?;
                keyslots::unwrap_device(
                    &envelope.vault_id,
                    slot,
                    &DeviceKey::from_credential(secret.as_bytes())?,
                )?
            }
        };
        // Authentication has succeeded before SQLCipher open or reconciliation.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| AppError::new(ErrorCode::Internal))?
            .as_secs();
        let vault = Vault::open_with_injected_key(&self.root, &vmk, now)?;
        Ok(OpenVault {
            vault,
            vmk,
            credentials: Arc::clone(&self.credentials),
            _keyslot_ownership: ownership,
        })
    }
    fn health(active: &OpenVault) -> ReconciliationHealth {
        active.vault.health()
    }
}

impl OpenVault {
    /// Best-effort removal of a credential no authoritative header references.
    ///
    /// Cleanup is secondary evidence only: the caller keeps the primary
    /// outcome and merely records what this returned.
    fn discard(&self, reference: &str) -> CleanupOutcome {
        match self.credentials.delete(reference) {
            Ok(()) => CleanupOutcome::Completed,
            Err(error) => CleanupOutcome::Failed(Box::new(error)),
        }
    }
    /// Changes only the authenticated header, preserving storage keys and bytes.
    ///
    /// A successful return means the replacement passphrase slot activated and
    /// the new passphrase is authoritative, even when durability is uncertain.
    /// # Errors
    /// Wrong current passphrase, invalid costs, or a pre-activation update
    /// failure that leaves the old passphrase authoritative.
    pub fn change_passphrase(
        &self,
        old: &Passphrase,
        new: &Passphrase,
        profile: ArgonProfile,
    ) -> Committed<()> {
        let mut envelope = read_header(&self.vault.root)?;
        let index = envelope
            .keyslots
            .iter()
            .position(|s| s.slot_type == "passphrase-v1")
            .ok_or_else(|| AppError::new(ErrorCode::CorruptHeader))?;
        let unwrapped =
            keyslots::unwrap_passphrase(&envelope.vault_id, &envelope.keyslots[index], old)?;
        // A trusted-in-memory comparison catches accidental slot/root mismatches.
        if unwrapped.storage_keys()?.0.as_bytes() != self.vmk.storage_keys()?.0.as_bytes() {
            return Err(AppError::new(ErrorCode::CorruptHeader).into());
        }
        envelope.keyslots[index] =
            keyslots::wrap_passphrase(&envelope.vault_id, &self.vmk, new, profile)?;
        Ok(Activated::new(
            (),
            replace_header(&self.vault.root, &envelope)?,
            CleanupOutcome::NotRequired,
        ))
    }
    /// Enrolls quick-unlock, replacing a device slot whose operating-system
    /// credential is genuinely absent. Passphrase and recovery slots and the
    /// VMK are untouched, so every independent path keeps working.
    ///
    /// A device slot whose credential still exists is left alone; a credential
    /// store that fails operationally is never treated as absence, because that
    /// would let an outage destroy a working quick unlock.
    ///
    /// A successful return means the device slot activated and its credential
    /// must be retained even when durability is uncertain.
    /// # Errors
    /// A healthy device slot already exists, the credential store failed, or a
    /// pre-activation header update failed. A failure never leaves the header
    /// referencing a credential that was cleaned up.
    pub fn enable_device(&self) -> Committed<()> {
        let mut envelope = read_header(&self.vault.root)?;
        let stale = match envelope
            .keyslots
            .iter()
            .position(|s| s.slot_type == "device-v1")
        {
            None => None,
            Some(index) => {
                let existing = envelope.keyslots[index].credential_ref.clone();
                // An operational store failure propagates: only proven absence
                // authorizes replacing a persisted slot.
                if self.credentials.retrieve(&existing)?.is_some() {
                    return Err(AppError::new(ErrorCode::CorruptHeader).into());
                }
                Some((index, existing))
            }
        };
        let key = DeviceKey::generate()?;
        let reference = format!("dvm/device/{}/{}", envelope.vault_id, Uuid::new_v4());
        // Admission through the canonical reference grammar happens before any
        // credential reaches the operating-system store.
        let slot = keyslots::wrap_device(&envelope.vault_id, &self.vmk, &key, reference.clone())?;
        if let Err(primary) = self.credentials.store(
            &reference,
            &SecretValue::new(Zeroizing::new(key.credential_bytes().to_vec()))?,
        ) {
            // The store failure stays primary; cleanup is recorded beside it.
            let cleanup = self.discard(&reference);
            return Err(NotActivated::new(primary, cleanup));
        }
        match stale {
            Some((index, _)) => envelope.keyslots[index] = slot,
            None => envelope.keyslots.push(slot),
        }
        let durability = match replace_header(&self.vault.root, &envelope) {
            Ok(durability) => durability,
            Err(failure) => {
                // Strictly pre-activation: the authoritative header cannot
                // reference the new credential, so removing it is safe and the
                // header error remains primary.
                let cleanup = self.discard(&reference);
                return Err(failure.with_cleanup(cleanup));
            }
        };
        // Only now, and only for a predecessor the active header no longer
        // references. A failure here leaves activation standing.
        let cleanup = match stale {
            Some((_, previous)) if previous != reference => self.discard(&previous),
            _ => CleanupOutcome::NotRequired,
        };
        Ok(Activated::new((), durability, cleanup))
    }
    /// Imports through the existing G1 canonical pipeline inside session admission.
    /// # Errors
    /// Source/storage/authentication failure; no fabricated success.
    pub fn import(&self, source: &Path) -> Result<ImportReceipt, AppError> {
        self.vault.commit_import(self.vault.stage_import(source)?)
    }
    /// Authenticated byte recovery through the existing G1 sink contract.
    /// # Errors
    /// Missing, corrupt or unreadable canonical data.
    pub fn recover(
        &self,
        blob_id: &str,
        sink: &mut impl PlaintextSink,
    ) -> Result<DigestReceipt, AppError> {
        self.vault.recover(blob_id, sink)
    }
}

#[cfg(test)]
mod tests;
