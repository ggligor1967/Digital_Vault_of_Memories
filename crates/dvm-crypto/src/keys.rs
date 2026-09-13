//! Storage key hierarchy. Raw keys intentionally implement neither `Debug` nor `Serde`.
use dvm_domain::{AppError, ErrorCode};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Random 256-bit root, owned only by trusted Rust callers.
///
/// ```compile_fail
/// use dvm_crypto::VaultMasterKey;
/// let key = VaultMasterKey::generate().unwrap();
/// serde_json::to_string(&key).unwrap();
/// ```
/// ```compile_fail
/// use dvm_crypto::VaultMasterKey;
/// println!("{:?}", VaultMasterKey::generate().unwrap());
/// ```
pub struct VaultMasterKey(Zeroizing<[u8; 32]>);
/// `SQLCipher` raw key; never persist or log this value.
/// ```compile_fail
/// let key = dvm_crypto::VaultMasterKey::generate().unwrap().storage_keys().unwrap().0;
/// serde_json::to_string(&key).unwrap();
/// ```
pub struct DbKey(Zeroizing<[u8; 32]>);
/// Independent root for per-blob keys.
/// ```compile_fail
/// let root = dvm_crypto::VaultMasterKey::generate().unwrap().storage_keys().unwrap().1;
/// serde_json::to_string(&root).unwrap();
/// ```
pub struct BlobRootKey(Zeroizing<[u8; 32]>);
/// Key scoped to exactly one random blob identifier.
/// ```compile_fail
/// let root = dvm_crypto::VaultMasterKey::generate().unwrap().storage_keys().unwrap().1;
/// let key = root.for_blob(&[1; 16]).unwrap();
/// serde_json::to_string(&key).unwrap();
/// ```
pub struct BlobKey(pub(crate) Zeroizing<[u8; 32]>);

fn derive(input: &[u8], salt: &[u8], label: &[u8]) -> Result<Zeroizing<[u8; 32]>, AppError> {
    let mut output = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(salt), input)
        .expand(label, output.as_mut())
        .map_err(|_| AppError::new(ErrorCode::Internal))?;
    Ok(output)
}

impl VaultMasterKey {
    /// Generates a root using the OS CSPRNG.
    /// # Errors
    /// Fails closed when operating-system randomness is unavailable.
    pub fn generate() -> Result<Self, AppError> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| AppError::new(ErrorCode::Internal))?;
        Ok(Self(bytes))
    }

    /// Accepts externally supplied key material at the trusted integration boundary.
    /// This does not persist or wrap it. The caller owns any original copies.
    #[must_use]
    pub fn from_injected_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Derives domain-separated storage keys.
    /// # Errors
    /// Returns INTERNAL if the fixed-size HKDF expansion fails.
    pub fn storage_keys(&self) -> Result<(DbKey, BlobRootKey), AppError> {
        Ok((
            DbKey(derive(self.0.as_ref(), b"DVM/v1", b"DVM/v1/db")?),
            BlobRootKey(derive(self.0.as_ref(), b"DVM/v1", b"DVM/v1/blob-root")?),
        ))
    }
}

impl DbKey {
    /// Borrows the raw key for the native adapter. Never cross IPC with this slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl BlobRootKey {
    /// Derives the key for the supplied 16-byte random blob ID.
    /// # Errors
    /// Returns INTERNAL if HKDF fails.
    pub fn for_blob(&self, id: &[u8; 16]) -> Result<BlobKey, AppError> {
        Ok(BlobKey(derive(self.0.as_ref(), id, b"DVM/v1/blob")?))
    }
}

/// Creates an opaque 128-bit identifier without path/content information.
/// # Errors
/// Returns INTERNAL if the OS CSPRNG fails.
pub fn random_id() -> Result<[u8; 16], AppError> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| AppError::new(ErrorCode::Internal))?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separation_and_reproducibility() -> Result<(), AppError> {
        let vmk = VaultMasterKey::from_injected_bytes(Zeroizing::new([42; 32]));
        let (db, root) = vmk.storage_keys()?;
        assert_ne!(db.0.as_ref(), root.0.as_ref());
        let first = root.for_blob(&[1; 16])?;
        assert_ne!(first.0.as_ref(), root.for_blob(&[2; 16])?.0.as_ref());
        let (_, reopened_root) = vmk.storage_keys()?;
        assert_eq!(
            first.0.as_ref(),
            reopened_root.for_blob(&[1; 16])?.0.as_ref()
        );
        Ok(())
    }
}
