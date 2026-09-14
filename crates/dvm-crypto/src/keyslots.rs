//! Authenticated VMK wrapping; deterministic AAD is specified in ADR-0006.
use crate::VaultMasterKey;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use dvm_domain::{
    AppError, ErrorCode,
    security::{ArgonProfile, Keyslot, is_canonical_device_reference},
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Exact UTF-8 credential, with no Debug/Serialize implementation.
/// ```compile_fail
/// let value: Option<dvm_crypto::keyslots::Passphrase> = None;
/// serde_json::to_string(&value).unwrap();
/// ```
/// ```compile_fail
/// let value: Option<dvm_crypto::keyslots::Passphrase> = None;
/// format!("{value:?}");
/// ```
pub struct Passphrase(Zeroizing<String>);
/// Independent 256-bit recovery credential. Never persist or send through IPC.
/// ```compile_fail
/// let value: Option<dvm_crypto::keyslots::RecoverySecret> = None;
/// serde_json::to_string(&value).unwrap();
/// ```
/// ```compile_fail
/// let value: Option<dvm_crypto::keyslots::RecoverySecret> = None;
/// format!("{value:?}");
/// ```
pub struct RecoverySecret(Zeroizing<[u8; 32]>);
/// Local user-context protected wrapping key.
/// ```compile_fail
/// let value: Option<dvm_crypto::keyslots::DeviceKey> = None;
/// serde_json::to_string(&value).unwrap();
/// ```
/// ```compile_fail
/// let value: Option<dvm_crypto::keyslots::DeviceKey> = None;
/// format!("{value:?}");
/// ```
pub struct DeviceKey(Zeroizing<[u8; 32]>);
struct PassphraseKek(Zeroizing<[u8; 32]>);
struct RecoveryKek(Zeroizing<[u8; 32]>);

fn bad_header() -> AppError {
    AppError::new(ErrorCode::CorruptHeader)
}
fn random<const N: usize>() -> Result<[u8; N], AppError> {
    let mut value = [0; N];
    getrandom::fill(&mut value).map_err(|_| AppError::new(ErrorCode::Internal))?;
    Ok(value)
}

impl Passphrase {
    /// Takes ownership; no Unicode normalization or whitespace processing.
    /// # Errors
    /// Empty or over-1024-byte credentials are rejected.
    pub fn new(value: Zeroizing<String>) -> Result<Self, AppError> {
        if value.is_empty() || value.len() > 1024 {
            return Err(AppError::new(ErrorCode::BadPassphrase));
        }
        Ok(Self(value))
    }
}

impl RecoverySecret {
    /// Generates 256 independent OS-random bits.
    /// # Errors
    /// OS entropy failure.
    pub fn generate() -> Result<Self, AppError> {
        let mut value = Zeroizing::new([0; 32]);
        getrandom::fill(value.as_mut()).map_err(|_| AppError::new(ErrorCode::Internal))?;
        Ok(Self(value))
    }
    /// Trusted presentation only. The caller must not persist or log this value.
    #[must_use]
    pub fn encode_for_trusted_presentation(&self) -> Zeroizing<String> {
        use std::fmt::Write;
        let mut result = Zeroizing::new(String::with_capacity(64));
        for byte in self.0.iter() {
            let _ = write!(result, "{byte:02x}");
        }
        result
    }
    /// Parses exactly 64 lowercase hex characters without normalization.
    /// # Errors
    /// Invalid credential encoding.
    pub fn decode(value: Zeroizing<String>) -> Result<Self, AppError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(AppError::new(ErrorCode::BadPassphrase));
        }
        let mut bytes = Zeroizing::new([0; 32]);
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| AppError::new(ErrorCode::BadPassphrase))?;
        }
        drop(value);
        Ok(Self(bytes))
    }
}

impl DeviceKey {
    /// Generates an independent device KEK.
    /// # Errors
    /// OS randomness unavailable.
    pub fn generate() -> Result<Self, AppError> {
        let mut value = Zeroizing::new([0; 32]);
        getrandom::fill(value.as_mut()).map_err(|_| AppError::new(ErrorCode::Internal))?;
        Ok(Self(value))
    }
    /// Copies only at the trusted credential-store boundary.
    /// # Errors
    /// Credential has an invalid size.
    pub fn from_credential(value: &[u8]) -> Result<Self, AppError> {
        if value.len() != 32 {
            return Err(AppError::new(ErrorCode::ProviderAuthFailed));
        }
        let mut bytes = Zeroizing::new([0; 32]);
        bytes.copy_from_slice(value);
        Ok(Self(bytes))
    }
    /// Borrow for the trusted OS adapter only.
    #[must_use]
    pub fn credential_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Rejects both weak costs and unbounded attacker-controlled allocation/work.
/// # Errors
/// Invalid persisted or requested production profile.
pub fn validate_profile(profile: ArgonProfile) -> Result<(), AppError> {
    if !(19 * 1024..=256 * 1024).contains(&profile.memory_kib)
        || !(2..=10).contains(&profile.iterations)
        || profile.parallelism != 1
    {
        return Err(bad_header());
    }
    Ok(())
}

fn passphrase_kek(
    passphrase: &Passphrase,
    salt: &[u8],
    profile: ArgonProfile,
) -> Result<PassphraseKek, AppError> {
    Ok(PassphraseKek(crate::sodium::derive(
        passphrase.0.as_bytes(),
        salt,
        profile,
    )?))
}
fn recovery_kek(secret: &RecoverySecret) -> Result<RecoveryKek, AppError> {
    let mut output = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(b"DVM/v2/recovery"), secret.0.as_ref())
        .expand(b"DVM/v2/recovery-kek", output.as_mut())
        .map_err(|_| bad_header())?;
    Ok(RecoveryKek(output))
}

/// Measured production-cost selection; returns only public costs and elapsed time.
/// # Errors
/// OS entropy or KDF failure. Never reduces the baseline.
pub fn calibrate() -> Result<(ArgonProfile, Duration), AppError> {
    let passphrase = Passphrase::new(Zeroizing::new("DVM calibration public input".into()))?;
    let salt = random::<16>()?;
    let mut profile = ArgonProfile::BASELINE;
    loop {
        let start = Instant::now();
        let _key = passphrase_kek(&passphrase, &salt, profile)?;
        let elapsed = start.elapsed();
        if elapsed >= Duration::from_millis(250) || profile.memory_kib == 256 * 1024 {
            return Ok((profile, elapsed));
        }
        profile.memory_kib = (profile.memory_kib * 2).min(256 * 1024);
    }
}

fn canonical_id(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

/// Validates every mandatory metadata field before expensive KDF work.
/// # Errors
/// Unknown format or malformed slot. No unauthenticated plaintext is returned.
pub fn validate_slot(slot: &Keyslot) -> Result<(), AppError> {
    if slot.version != 1
        || slot.wrap_algorithm != "XChaCha20-Poly1305"
        || !canonical_id(&slot.id)
        || slot.nonce.len() != 24
        || slot.wrapped_vmk.len() != 48
    {
        return Err(bad_header());
    }
    match slot.slot_type.as_str() {
        "passphrase-v1"
            if slot.kdf_algorithm == "Argon2id-0x13"
                && slot.salt.len() == 16
                && slot.credential_ref.is_empty() =>
        {
            validate_profile(slot.argon.ok_or_else(bad_header)?)?;
        }
        "recovery-v1"
            if slot.kdf_algorithm == "HKDF-SHA-256/recovery-v1"
                && slot.salt.is_empty()
                && slot.argon.is_none()
                && slot.credential_ref.is_empty() => {}
        // The one canonical grammar, shared with the operating-system
        // credential adapter: a reference this admits is one that adapter
        // accepts, so an unusable device slot can never be persisted.
        "device-v1"
            if slot.kdf_algorithm.is_empty()
                && slot.salt.is_empty()
                && slot.argon.is_none()
                && is_canonical_device_reference(&slot.credential_ref) => {}
        _ => return Err(bad_header()),
    }
    Ok(())
}

fn aad(vault_id: &str, slot: &Keyslot) -> Result<Vec<u8>, AppError> {
    if !canonical_id(vault_id) {
        return Err(bad_header());
    }
    validate_slot(slot)?;
    let mut result = b"DVM/keyslot/aad/v1".to_vec();
    let profile = slot.argon.unwrap_or(ArgonProfile {
        memory_kib: 0,
        iterations: 0,
        parallelism: 0,
    });
    for value in [
        vault_id.as_bytes(),
        slot.slot_type.as_bytes(),
        &slot.version.to_le_bytes(),
        slot.id.as_bytes(),
        slot.wrap_algorithm.as_bytes(),
        slot.kdf_algorithm.as_bytes(),
        &profile.memory_kib.to_le_bytes(),
        &profile.iterations.to_le_bytes(),
        &profile.parallelism.to_le_bytes(),
        &slot.salt,
        &slot.nonce,
        slot.credential_ref.as_bytes(),
    ] {
        result.extend_from_slice(
            &u32::try_from(value.len())
                .map_err(|_| bad_header())?
                .to_le_bytes(),
        );
        result.extend_from_slice(value);
    }
    Ok(result)
}

fn envelope(kind: &str, kdf: &str) -> Result<Keyslot, AppError> {
    Ok(Keyslot {
        slot_type: kind.into(),
        version: 1,
        id: Uuid::new_v4().to_string(),
        wrap_algorithm: "XChaCha20-Poly1305".into(),
        kdf_algorithm: kdf.into(),
        argon: None,
        salt: vec![],
        nonce: random::<24>()?.to_vec(),
        credential_ref: String::new(),
        wrapped_vmk: vec![0; 48],
    })
}
fn wrap(
    vault_id: &str,
    vmk: &VaultMasterKey,
    mut slot: Keyslot,
    kek: &[u8],
) -> Result<Keyslot, AppError> {
    let associated = aad(vault_id, &slot)?;
    slot.wrapped_vmk = XChaCha20Poly1305::new_from_slice(kek)
        .map_err(|_| bad_header())?
        .encrypt(
            &XNonce::try_from(slot.nonce.as_slice()).map_err(|_| bad_header())?,
            Payload {
                msg: vmk.0.as_ref(),
                aad: &associated,
            },
        )
        .map_err(|_| bad_header())?;
    Ok(slot)
}
fn unwrap(vault_id: &str, slot: &Keyslot, kek: &[u8]) -> Result<VaultMasterKey, AppError> {
    let associated = aad(vault_id, slot)?;
    let bytes = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(kek)
            .map_err(|_| bad_header())?
            .decrypt(
                &XNonce::try_from(slot.nonce.as_slice()).map_err(|_| bad_header())?,
                Payload {
                    msg: &slot.wrapped_vmk,
                    aad: &associated,
                },
            )
            .map_err(|_| AppError::new(ErrorCode::BadPassphrase))?,
    );
    if bytes.len() != 32 {
        return Err(bad_header());
    }
    let mut root = Zeroizing::new([0; 32]);
    root.copy_from_slice(&bytes);
    Ok(VaultMasterKey::from_injected_bytes(root))
}

/// Wraps the existing VMK with a fresh salt and nonce.
/// # Errors
/// Invalid profile, randomness or wrapping failure.
pub fn wrap_passphrase(
    vault_id: &str,
    vmk: &VaultMasterKey,
    passphrase: &Passphrase,
    profile: ArgonProfile,
) -> Result<Keyslot, AppError> {
    validate_profile(profile)?;
    let mut slot = envelope("passphrase-v1", "Argon2id-0x13")?;
    slot.argon = Some(profile);
    slot.salt = random::<16>()?.to_vec();
    let key = passphrase_kek(passphrase, &slot.salt, profile)?;
    wrap(vault_id, vmk, slot, key.0.as_ref())
}
/// Unwraps only after validating the passphrase slot metadata.
/// # Errors
/// `BadPassphrase` for authentication failure; `CorruptHeader` for malformed data.
pub fn unwrap_passphrase(
    vault_id: &str,
    slot: &Keyslot,
    passphrase: &Passphrase,
) -> Result<VaultMasterKey, AppError> {
    validate_slot(slot)?;
    if slot.slot_type != "passphrase-v1" {
        return Err(bad_header());
    }
    let key = passphrase_kek(passphrase, &slot.salt, slot.argon.ok_or_else(bad_header)?)?;
    unwrap(vault_id, slot, key.0.as_ref())
}
/// Wraps the same root using independently generated recovery material.
/// # Errors
/// Randomness or wrapping failure.
pub fn wrap_recovery(
    vault_id: &str,
    vmk: &VaultMasterKey,
    secret: &RecoverySecret,
) -> Result<Keyslot, AppError> {
    wrap(
        vault_id,
        vmk,
        envelope("recovery-v1", "HKDF-SHA-256/recovery-v1")?,
        recovery_kek(secret)?.0.as_ref(),
    )
}
/// Authenticates the independent recovery path.
/// # Errors
/// Invalid slot or recovery credential.
pub fn unwrap_recovery(
    vault_id: &str,
    slot: &Keyslot,
    secret: &RecoverySecret,
) -> Result<VaultMasterKey, AppError> {
    if slot.slot_type != "recovery-v1" {
        return Err(bad_header());
    }
    unwrap(vault_id, slot, recovery_kek(secret)?.0.as_ref())
}
/// Binds a device credential reference into the authenticated envelope.
/// # Errors
/// Invalid reference or wrapping failure.
pub fn wrap_device(
    vault_id: &str,
    vmk: &VaultMasterKey,
    key: &DeviceKey,
    reference: String,
) -> Result<Keyslot, AppError> {
    let mut slot = envelope("device-v1", "")?;
    slot.credential_ref = reference;
    wrap(vault_id, vmk, slot, key.0.as_ref())
}
/// Authenticates the device path without changing other slots.
/// # Errors
/// Invalid slot or credential.
pub fn unwrap_device(
    vault_id: &str,
    slot: &Keyslot,
    key: &DeviceKey,
) -> Result<VaultMasterKey, AppError> {
    if slot.slot_type != "device-v1" {
        return Err(bad_header());
    }
    unwrap(vault_id, slot, key.0.as_ref())
}

#[cfg(test)]
mod tests;
