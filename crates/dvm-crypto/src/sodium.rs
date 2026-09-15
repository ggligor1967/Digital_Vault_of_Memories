//! Private, fallible boundary to the pinned libsodium Argon2id implementation.
use dvm_domain::{AppError, ErrorCode, security::ArgonProfile};
use std::ffi::CStr;
use zeroize::Zeroizing;

pub(super) fn derive(
    passphrase: &[u8],
    salt: &[u8],
    profile: ArgonProfile,
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    crate::keyslots::validate_profile(profile)?;
    if salt.len() != 16 || passphrase.is_empty() || passphrase.len() > 1024 {
        return Err(AppError::new(ErrorCode::CorruptHeader));
    }
    let memory_bytes = usize::try_from(profile.memory_kib)
        .ok()
        .and_then(|value| value.checked_mul(1024))
        .ok_or_else(|| AppError::new(ErrorCode::CorruptHeader))?;
    let length =
        u64::try_from(passphrase.len()).map_err(|_| AppError::new(ErrorCode::CorruptHeader))?;
    // SAFETY: sodium_init is thread-safe and idempotent; it takes no pointers.
    if unsafe { libsodium_sys::sodium_init() } < 0 {
        return Err(AppError::new(ErrorCode::Internal));
    }
    // SAFETY: this API returns a static NUL-terminated library-owned version.
    let version = unsafe { libsodium_sys::sodium_version_string() };
    if version.is_null() {
        return Err(AppError::new(ErrorCode::Internal));
    }
    // SAFETY: the non-null pointer above remains valid for the process lifetime.
    if unsafe { CStr::from_ptr(version) }.to_bytes() != b"1.0.22" {
        return Err(AppError::new(ErrorCode::Internal));
    }
    let mut output = Zeroizing::new([0; 32]);
    let algorithm = i32::try_from(libsodium_sys::crypto_pwhash_argon2id_ALG_ARGON2ID13)
        .map_err(|_| AppError::new(ErrorCode::Internal))?;
    // SAFETY: output owns 32 writable bytes, salt has exactly 16 readable bytes,
    // and passphrase is readable for the explicit byte length (including NULs).
    // The disjoint buffers live throughout this synchronous call. Bounds above
    // enforce the supported costs; libsodium Argon2id13 uses exactly one lane.
    let status = unsafe {
        libsodium_sys::crypto_pwhash_argon2id(
            output.as_mut_ptr(),
            32,
            passphrase.as_ptr().cast(),
            length,
            salt.as_ptr(),
            u64::from(profile.iterations),
            memory_bytes,
            algorithm,
        )
    };
    if status != 0 {
        return Err(AppError::new(ErrorCode::Internal));
    }
    Ok(output)
}
