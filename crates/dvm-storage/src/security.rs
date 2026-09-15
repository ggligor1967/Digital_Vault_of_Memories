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
        Keyslot, NotActivated, RecoveryPolicy, SecretValue, SessionBackend,
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

/// What the operating-system store actually holds for a persisted device slot.
///
/// Presence of a credential is never proof that a device slot works. A
/// truncated, overwritten or foreign credential leaves quick unlock exactly as
/// broken as a deleted one, and the header alone cannot tell the two apart, so
/// the classification is decided by what the credential can do rather than by
/// whether an entry exists.
enum DeviceSlotHealth {
    /// The stored credential authenticates the slot and unwraps the vault's
    /// active master key. Quick unlock works, so the slot is left untouched.
    Healthy,
    /// No credential exists, or the credential that exists cannot unwrap this
    /// vault's active master key. Quick unlock is broken and an authenticated
    /// session may replace the slot.
    Unusable,
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
        // One selection boundary for every credential kind: the slot type it
        // requires, and the classification for that slot being absent. A vault
        // with no device slot has no configured quick-unlock path at all, which
        // is a provider-availability fact rather than a failed authentication
        // attempt, so it must not be reported as a wrong passphrase. Absent
        // passphrase and recovery slots keep their existing authentication
        // classification.
        let (kind, absent) = match credential {
            UnlockCredential::Passphrase(_) => ("passphrase-v1", ErrorCode::BadPassphrase),
            UnlockCredential::Recovery(_) => ("recovery-v1", ErrorCode::BadPassphrase),
            UnlockCredential::Device => ("device-v1", ErrorCode::ProviderUnavailable),
        };
        let slot = envelope
            .keyslots
            .iter()
            .find(|s| s.slot_type == kind)
            .ok_or_else(|| AppError::new(absent))?;
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
    /// Decides whether a persisted device slot can still perform quick unlock.
    ///
    /// Three facts together prove health, and nothing less does: the stored
    /// credential has the exact device-key length, it authenticates this slot's
    /// envelope, and the root it unwraps is the vault's *active* master key. A
    /// successful authenticated decryption on its own is not enough, because a
    /// slot can authenticate under its own credential and still yield a
    /// superseded root, which would unlock a vault whose storage keys no longer
    /// match.
    ///
    /// Everything after the store read is an in-memory statement about the
    /// credential itself, so a wrong length or a failed authentication
    /// classifies the slot instead of failing the operation.
    ///
    /// # Errors
    /// An operational credential-store failure, propagated unchanged. An outage
    /// is never absence: treating it as one would let a transient fault destroy
    /// a working quick unlock.
    fn device_health(&self, vault_id: &str, slot: &Keyslot) -> Result<DeviceSlotHealth, AppError> {
        let Some(secret) = self.credentials.retrieve(&slot.credential_ref)? else {
            return Ok(DeviceSlotHealth::Unusable);
        };
        let Ok(root) = DeviceKey::from_credential(secret.as_bytes())
            .and_then(|key| keyslots::unwrap_device(vault_id, slot, &key))
        else {
            return Ok(DeviceSlotHealth::Unusable);
        };
        // A trusted-memory comparison of derived roots, the same equality the
        // passphrase rewrap path uses. No root or fingerprint is serialized,
        // logged or returned.
        if root.storage_keys()?.0.as_bytes() == self.vmk.storage_keys()?.0.as_bytes() {
            Ok(DeviceSlotHealth::Healthy)
        } else {
            Ok(DeviceSlotHealth::Unusable)
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
    /// Enrolls quick-unlock, replacing a device slot that can no longer perform
    /// it. Passphrase and recovery slots and the VMK are untouched, so every
    /// independent path keeps working and the same root stays authoritative.
    ///
    /// A slot is replaceable whenever its operating-system credential cannot
    /// unwrap the active master key — whether the credential is absent, the
    /// wrong length, overwritten, or valid for some other vault or a superseded
    /// root. All of those leave quick unlock broken with no other way to restore
    /// it, and an authenticated open session is already an authorized security
    /// boundary, so it may re-enroll. A slot whose credential does unwrap the
    /// active master key is healthy and is deliberately not rotated. A
    /// credential store that fails operationally is never treated as either
    /// case, because that would let an outage destroy a working quick unlock.
    ///
    /// A successful return means the device slot activated and its credential
    /// must be retained even when durability is uncertain.
    /// # Errors
    /// A healthy device slot already exists, the credential store failed, or a
    /// pre-activation header update failed. A failure never leaves the header
    /// referencing a credential that was cleaned up.
    pub fn enable_device(&self) -> Committed<()> {
        let mut envelope = read_header(&self.vault.root)?;
        let replaceable = match envelope
            .keyslots
            .iter()
            .position(|s| s.slot_type == "device-v1")
        {
            None => None,
            Some(index) => {
                // An operational store failure propagates out of the
                // classification: only a credential proven unable to unwrap the
                // active root authorizes replacing a persisted slot.
                let slot = &envelope.keyslots[index];
                match self.device_health(&envelope.vault_id, slot)? {
                    DeviceSlotHealth::Healthy => {
                        return Err(AppError::new(ErrorCode::CorruptHeader).into());
                    }
                    DeviceSlotHealth::Unusable => Some((index, slot.credential_ref.clone())),
                }
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
        match replaceable {
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
        let cleanup = match replaceable {
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
