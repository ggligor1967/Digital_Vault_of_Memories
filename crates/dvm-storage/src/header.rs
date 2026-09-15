//! Strict versioned vault header parser/serializer; validates slots, wraps no keys.
use dvm_domain::{AppError, ErrorCode, storage::VaultHeader};
use uuid::Uuid;

/// Constructs only an internal injected-key test header, never a production vault.
#[must_use]
pub fn injected_key_header() -> VaultHeader {
    VaultHeader {
        format_version: 1,
        vault_id: Uuid::new_v4().to_string(),
        schema_version: 1,
        database_cipher: "SQLCipher".into(),
        database_cipher_version: 4,
        blob_format: "DVB1".into(),
        aead: "XChaCha20-Poly1305".into(),
        hkdf: "HKDF-SHA-256".into(),
        hash: "SHA-256".into(),
        keyslot_format_version: 1,
        keyslots: vec![],
    }
}

/// Parses a bounded header, failing closed on unsupported mandatory fields.
/// # Errors
/// `CORRUPT_HEADER` for malformed data; unsupported versions fail before any write.
pub fn parse(bytes: &[u8]) -> Result<VaultHeader, AppError> {
    let header = parse_trusted_fixture(bytes)?;
    validate_production(&header)?;
    Ok(header)
}

/// G1 injected-key compatibility boundary. Never use as production admission.
/// # Errors
/// Invalid or unsupported envelope.
pub fn parse_trusted_fixture(bytes: &[u8]) -> Result<VaultHeader, AppError> {
    if bytes.len() > 16_384 {
        return Err(AppError::new(ErrorCode::CorruptHeader));
    }
    let header: VaultHeader =
        serde_json::from_slice(bytes).map_err(|_| AppError::new(ErrorCode::CorruptHeader))?;
    validate(&header)?;
    Ok(header)
}

/// Serializes only a supported, valid header.
/// # Errors
/// Rejects malformed or unsupported envelope data.
pub fn serialize(header: &VaultHeader) -> Result<Vec<u8>, AppError> {
    validate_production(header)?;
    serialize_trusted_fixture(header)
}

/// Preserves closed-G1 empty-slot test fixtures, without production admission.
/// # Errors
/// Invalid or unsupported envelope.
pub fn serialize_trusted_fixture(header: &VaultHeader) -> Result<Vec<u8>, AppError> {
    validate(header)?;
    serde_json::to_vec(header).map_err(|_| AppError::new(ErrorCode::CorruptHeader))
}

fn validate(header: &VaultHeader) -> Result<(), AppError> {
    if Uuid::parse_str(&header.vault_id).is_err() {
        return Err(AppError::new(ErrorCode::CorruptHeader));
    }
    if header.schema_version > 1 {
        return Err(AppError::new(ErrorCode::MigrationRequired));
    }
    if header.format_version != 1
        || header.schema_version != 1
        || header.database_cipher != "SQLCipher"
        || header.database_cipher_version != 4
        || header.blob_format != "DVB1"
        || header.aead != "XChaCha20-Poly1305"
        || header.hkdf != "HKDF-SHA-256"
        || header.hash != "SHA-256"
        || header.keyslot_format_version != 1
    {
        return Err(AppError::new(ErrorCode::UnsupportedVaultVersion));
    }
    if !header.keyslots.is_empty() {
        validate_production(header)?;
    }
    Ok(())
}

/// Production requires one passphrase and at most one independent recovery/device slot.
/// # Errors
/// Empty, duplicate, malformed or unsupported slots.
pub fn validate_production(header: &VaultHeader) -> Result<(), AppError> {
    if header.keyslots.is_empty() || header.keyslots.len() > 3 {
        return Err(AppError::new(ErrorCode::CorruptHeader));
    }
    let mut types = std::collections::HashSet::new();
    let mut ids = std::collections::HashSet::new();
    for slot in &header.keyslots {
        dvm_crypto::keyslots::validate_slot(slot)?;
        if !types.insert(slot.slot_type.as_str()) || !ids.insert(slot.id.as_str()) {
            return Err(AppError::new(ErrorCode::CorruptHeader));
        }
    }
    if !types.contains("passphrase-v1") {
        return Err(AppError::new(ErrorCode::CorruptHeader));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_fail_closed_matrix() -> Result<(), Box<dyn std::error::Error>> {
        let header = injected_key_header();
        let bytes = serialize_trusted_fixture(&header)?;
        assert_eq!(parse_trusted_fixture(&bytes)?, header);
        for field in [
            "format_version",
            "vault_id",
            "schema_version",
            "aead",
            "keyslots",
        ] {
            let mut value = serde_json::to_value(&header)?;
            value.as_object_mut().ok_or("object")?.remove(field);
            assert_eq!(
                parse_trusted_fixture(&serde_json::to_vec(&value)?)
                    .err()
                    .ok_or("must fail")?
                    .code,
                ErrorCode::CorruptHeader
            );
        }
        for field in [
            "format_version",
            "database_cipher_version",
            "keyslot_format_version",
        ] {
            let mut value = serde_json::to_value(&header)?;
            value[field] = 99.into();
            assert_eq!(
                parse_trusted_fixture(&serde_json::to_vec(&value)?)
                    .err()
                    .ok_or("must fail")?
                    .code,
                ErrorCode::UnsupportedVaultVersion
            );
        }
        let mut bad = header.clone();
        bad.aead = "unknown".into();
        assert!(serialize_trusted_fixture(&bad).is_err());
        bad = header.clone();
        bad.vault_id = "../../private".into();
        assert_eq!(
            serialize_trusted_fixture(&bad)
                .err()
                .ok_or("must fail")?
                .code,
            ErrorCode::CorruptHeader
        );
        for length in 0..bytes.len() {
            assert!(parse_trusted_fixture(&bytes[..length]).is_err());
        }
        Ok(())
    }
}
