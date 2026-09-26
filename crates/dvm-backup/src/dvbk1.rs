use crate::activation::{activate_directory_noreplace, activate_file_noreplace};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use dvm_crypto::{BlobRootKey, DbKey, DigestReceipt, PlaintextSink, decrypt, keys::BackupKey};
use dvm_domain::{
    AppError, ErrorCode,
    security::{CredentialStore, SessionBackend},
    storage::ReconciliationHealth,
};
use dvm_storage::{
    database, header, migrations,
    security::{OpenVault, ProtectedVault, UnlockCredential, unlock_backup_header},
    validate_blob_storage_relpath,
};
use hkdf::Hkdf;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroizing;

const MANIFEST_MAGIC: &[u8; 8] = b"DVBK1M1\0";
const MAX_SMALL_MEMBER: u64 = 16 * 1024 * 1024;
const MAX_MEMBERS: usize = 100_003;
const COPY_CHUNK: usize = 64 * 1024;

#[cfg(test)]
thread_local! {
    static SNAPSHOT_RENDEZVOUS: std::cell::RefCell<Option<Arc<std::sync::Barrier>>> =
        const { std::cell::RefCell::new(None) };
    static BEFORE_BACKUP_ACTIVATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static BACKUP_SNAPSHOT_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicFormat {
    magic: String,
    format_version: u32,
    backup_id: String,
    manifest_algorithm: String,
    manifest_version: u32,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Member {
    path: String,
    size: u64,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    backup_id: String,
    vault_id: String,
    format_version: u32,
    app_version: String,
    schema_version: u32,
    created_at_unix_seconds: u64,
    members: Vec<Member>,
    canonical_blob_count: u64,
    canonical_logical_bytes: u64,
}

/// A backup is restorable only after FULL verification succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReceipt {
    /// Opaque backup identity.
    pub backup_id: String,
    /// FULL verification passed before activation.
    pub restorable: bool,
    /// Operational source bookkeeping succeeded after archive activation.
    pub history_recorded: bool,
}

/// Explicit verification level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMode {
    /// Checks container, authenticated manifest, encrypted DB, and member hashes.
    Structural,
    /// Also decrypts and hashes every canonical plaintext blob.
    Full,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::too_many_lines)]
    use super::*;
    use dvm_crypto::keyslots::Passphrase;
    use dvm_domain::security::{
        ArgonProfile, CredentialLookup, CredentialStore, NotActivated, RecoveryPolicy, SecretValue,
        SessionBackend,
    };
    use dvm_storage::security::ProtectedVault;
    use std::process::Command;
    type CanonicalState = BTreeMap<String, Vec<Vec<String>>>;
    use std::sync::Arc;

    struct NoDeviceStore;
    impl CredentialStore for NoDeviceStore {
        fn store(&self, _: &str, _: &SecretValue) -> Result<(), AppError> {
            Err(AppError::new(ErrorCode::ProviderUnavailable))
        }
        fn retrieve(&self, _: &str) -> Result<CredentialLookup, AppError> {
            Ok(CredentialLookup::Missing)
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
    }

    struct Fixture {
        root: PathBuf,
    }
    impl Fixture {
        fn new() -> std::io::Result<Self> {
            let root = std::env::temp_dir().join(format!("dvm-g3-test-{}", Uuid::new_v4()));
            fs::create_dir(&root)?;
            Ok(Self { root })
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.root.parent() == Some(std::env::temp_dir().as_path())
                && self
                    .root
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("dvm-g3-test-"))
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }
    fn pass() -> Result<Passphrase, AppError> {
        Passphrase::new(Zeroizing::new("g3 test phrase".into()))
    }

    fn canonical_state(
        path: &Path,
        key: &DbKey,
    ) -> Result<CanonicalState, Box<dyn std::error::Error>> {
        let db = database::open_snapshot_readonly(path, key)?;
        let version: u32 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let mut state = BTreeMap::new();
        state.insert("user_version".into(), vec![vec![version.to_string()]]);
        for table in ["items", "blobs", "item_blobs", "jobs", "schema_migrations"] {
            let mut statement = db.prepare(&format!("SELECT * FROM {table} ORDER BY 1"))?;
            let columns = statement.column_count();
            let mut query = statement.query([])?;
            let mut table_rows = Vec::new();
            while let Some(row) = query.next()? {
                let mut values = Vec::with_capacity(columns);
                for index in 0..columns {
                    let value: rusqlite::types::Value = row.get(index)?;
                    values.push(format!("{value:?}"));
                }
                table_rows.push(values);
            }
            state.insert(table.into(), table_rows);
        }
        Ok(state)
    }

    fn hash_file(path: &Path) -> Result<String, std::io::Error> {
        let mut file = File::open(path)?;
        let mut digest = Sha256::new();
        let mut chunk = vec![0u8; COPY_CHUNK];
        loop {
            let count = file.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            digest.update(&chunk[..count]);
        }
        Ok(hex(&digest.finalize()))
    }

    #[test]
    fn portable_storage_relpath_snapshot_accepts_only_exact_id_bound_forms()
    -> Result<(), Box<dyn std::error::Error>> {
        let db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE blobs(id TEXT, sha256_hex TEXT, size_bytes INTEGER, storage_relpath TEXT); CREATE TABLE item_blobs(blob_id TEXT);")?;
        let id = Uuid::new_v4().to_string();
        db.execute(
            "INSERT INTO blobs VALUES (?1,?2,8,'')",
            [&id, &"0".repeat(64)],
        )?;
        db.execute("INSERT INTO item_blobs VALUES (?1)", [&id])?;
        for relative in [format!("blobs/{id}.dvb"), format!("blobs\\{id}.dvb")] {
            db.execute("UPDATE blobs SET storage_relpath=?1", [&relative])?;
            assert_eq!(snapshot_blobs(&db)?.len(), 1);
        }
        for relative in [
            format!("./blobs/{id}.dvb"),
            format!("blobs//{id}.dvb"),
            format!("blobs/./{id}.dvb"),
            format!("blobs/../blobs/{id}.dvb"),
            format!("blobs\\..\\blobs\\{id}.dvb"),
            format!("/blobs/{id}.dvb"),
            format!("C:\\blobs\\{id}.dvb"),
            format!("\\\\server\\blobs\\{id}.dvb"),
            format!("blobs/{id}.dvb/"),
            format!("blobs/{id}.dvb:stream"),
            format!("blobs/{id}.dvb\0"),
            format!("blobs/{}.dvb", Uuid::new_v4()),
        ] {
            db.execute("UPDATE blobs SET storage_relpath=?1", [&relative])?;
            assert_eq!(
                snapshot_blobs(&db).unwrap_err().code,
                ErrorCode::BackupInvalid,
                "{relative:?}"
            );
        }
        Ok(())
    }

    fn create_test_vault(fixture: &Fixture) -> Result<OpenVault, AppError> {
        let created = ProtectedVault::create_with_policy(
            &fixture.root.join("vault"),
            &pass()?,
            RecoveryPolicy::Generate,
            ArgonProfile::BASELINE,
            Arc::new(NoDeviceStore),
        )
        .map_err(NotActivated::into_primary)?
        .into_value();
        created
            .backend
            .unlock(&UnlockCredential::Passphrase(pass()?))
    }

    #[test]
    fn portable_storage_relpath_backup_restore_preserves_legacy_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let active = create_test_vault(&fixture)?;
        let source = fixture.root.join("source");
        fs::write(&source, b"portable archive plaintext")?;
        let imported = active.import(&source)?;
        let header_bytes = fs::read(fixture.root.join("vault/vault.header"))?;
        let vmk = unlock_backup_header(&header_bytes, &UnlockCredential::Passphrase(pass()?))?;
        let (db_key, _) = vmk.storage_keys()?;
        drop(active);
        let db = Connection::open(fixture.root.join("vault/metadata.db"))?;
        let key_literal = Zeroizing::new(format!("x'{}'", hex(db_key.as_bytes())));
        db.pragma_update(None, "key", key_literal.as_str())?;
        let legacy = format!("blobs\\{}.dvb", imported.blob_id);
        db.execute("UPDATE blobs SET storage_relpath=?1", [&legacy])?;
        db.close().map_err(|(_, error)| error)?;
        let backend = ProtectedVault::select(&fixture.root.join("vault"), Arc::new(NoDeviceStore))?;
        let active = backend.unlock(&UnlockCredential::Passphrase(pass()?))?;
        let archive = fixture.root.join("legacy.dvmbak");
        assert!(create_backup(&active, &archive)?.restorable);
        drop(active);
        let before = canonical_state(&fixture.root.join("vault/metadata.db"), &db_key)?;
        for mode in [VerificationMode::Structural, VerificationMode::Full] {
            assert_eq!(
                verify_backup(&archive, &UnlockCredential::Passphrase(pass()?), mode)?
                    .canonical_blob_count,
                1
            );
        }
        let restored = fixture.root.join("restored");
        restore_backup(
            &archive,
            &restored,
            &UnlockCredential::Passphrase(pass()?),
            Arc::new(NoDeviceStore),
        )?;
        let backend = ProtectedVault::select(&restored, Arc::new(NoDeviceStore))?;
        let active = backend.unlock(&UnlockCredential::Passphrase(pass()?))?;
        assert_eq!(
            active
                .recover(&imported.blob_id, &mut DiscardPlaintext)?
                .sha256_hex,
            imported.sha256_hex
        );
        assert_eq!(
            canonical_state(&restored.join("metadata.db"), &db_key)?,
            before
        );
        Ok(())
    }

    #[test]
    fn backup_activation_error_classification_preserves_operational_failures() {
        use std::io::ErrorKind;
        for (kind, expected) in [
            (ErrorKind::AlreadyExists, ErrorCode::RestoreConflict),
            (ErrorKind::PermissionDenied, ErrorCode::Internal),
            (ErrorKind::NotFound, ErrorCode::Internal),
            (ErrorKind::Unsupported, ErrorCode::Internal),
            (ErrorKind::StorageFull, ErrorCode::DiskFull),
        ] {
            assert_eq!(activation_error(&kind.into()).code, expected);
        }
    }

    #[test]
    fn backup_activation_conflict_preserves_competitor_and_records_no_history()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let active = create_test_vault(&fixture)?;
        for kind in [
            "file",
            "empty-directory",
            "occupied-directory",
            #[cfg(unix)]
            "dangling-symlink",
        ] {
            let destination = fixture.root.join(format!("race-{kind}.dvmbak"));
            let competitor = destination.clone();
            BEFORE_BACKUP_ACTIVATION.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || match kind {
                    "file" => fs::write(&competitor, b"competitor").unwrap(),
                    #[cfg(unix)]
                    "dangling-symlink" => {
                        std::os::unix::fs::symlink("missing-target", &competitor).unwrap();
                    }
                    _ => {
                        fs::create_dir(&competitor).unwrap();
                        if kind == "occupied-directory" {
                            fs::write(competitor.join("sentinel"), b"competitor").unwrap();
                        }
                    }
                }));
            });
            assert_eq!(
                create_backup(&active, &destination).unwrap_err().code,
                ErrorCode::RestoreConflict
            );
            match kind {
                "file" => assert_eq!(fs::read(&destination)?, b"competitor"),
                "occupied-directory" => {
                    assert_eq!(fs::read(destination.join("sentinel"))?, b"competitor");
                }
                #[cfg(unix)]
                "dangling-symlink" => {
                    assert_eq!(fs::read_link(&destination)?, Path::new("missing-target"));
                }
                _ => assert_eq!(fs::read_dir(&destination)?.count(), 0),
            }
            let residue: Vec<_> = fs::read_dir(&fixture.root)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<Result<_, _>>()?;
            // Snapshot WAL/SHM sidecar lifecycle is outside activation classification.
            assert!(
                residue.iter().all(|name| {
                    let name = name.to_string_lossy();
                    !name.starts_with(".dvm-backup-")
                        || (!name.ends_with(".part") && !name.ends_with(".snapshot"))
                }),
                "staging residue: {residue:?}"
            );
        }
        let snapshot = fixture.root.join("history.snapshot");
        let access = active.snapshot_for_backup(&snapshot)?;
        let db = database::open_snapshot_readonly(&snapshot, &access.db_key)?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM backup_history", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn backup_activation_conflict_detects_dangling_symlink_before_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let active = create_test_vault(&fixture)?;
        let destination = fixture.root.join("dangling.dvmbak");
        let missing = fixture.root.join("missing");
        std::os::unix::fs::symlink(&missing, &destination)?;
        let snapshots_before = BACKUP_SNAPSHOT_COUNT.get();
        let result = create_backup(&active, &destination);
        assert_eq!(result.unwrap_err().code, ErrorCode::RestoreConflict);
        assert_eq!(BACKUP_SNAPSHOT_COUNT.get(), snapshots_before);
        assert_eq!(fs::read_link(&destination)?, missing);
        assert!(fs::read_dir(&fixture.root)?.all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".dvm-backup-")
        }));
        Ok(())
    }

    #[test]
    fn encrypted_backup_and_full_verification() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let store: Arc<dyn CredentialStore> = Arc::new(NoDeviceStore);
        let created = ProtectedVault::create_with_policy(
            &fixture.root.join("vault"),
            &pass()?,
            RecoveryPolicy::Generate,
            ArgonProfile::BASELINE,
            Arc::clone(&store),
        )
        .map_err(NotActivated::into_primary)?
        .into_value();
        let active = created
            .backend
            .unlock(&UnlockCredential::Passphrase(pass()?))?;
        let source = fixture.root.join("Șárga amintire.txt");
        fs::write(
            &source,
            b"G3 plaintext sentinel inside encrypted canonical blob",
        )?;
        let imported = active.import(&source)?;
        let archive = fixture.root.join("reference.dvmbak");
        assert_eq!(
            create_backup(&active, &fixture.root.join("vault/inside.dvmbak"))
                .err()
                .ok_or("inside-source backup accepted")?
                .code,
            ErrorCode::BackupInvalid
        );
        let receipt = create_backup(&active, &archive)?;
        assert!(receipt.restorable);
        assert_eq!(
            create_backup(&active, &archive)
                .err()
                .ok_or("overwrite accepted")?
                .code,
            ErrorCode::RestoreConflict
        );
        drop(active);
        let verified = verify_backup(
            &archive,
            &UnlockCredential::Passphrase(pass()?),
            VerificationMode::Full,
        )?;
        assert_eq!(receipt.backup_id, verified.backup_id);
        assert_eq!(verified.canonical_blob_count, 1);
        let original = fixture.root.join("vault");
        fs::remove_dir_all(&original)?;
        assert!(!original.exists());
        let restored = fixture.root.join("restored");
        restore_backup(
            &archive,
            &restored,
            &UnlockCredential::Passphrase(pass()?),
            Arc::clone(&store),
        )?;
        assert_eq!(
            restore_backup(
                &archive,
                &restored,
                &UnlockCredential::Passphrase(pass()?),
                Arc::clone(&store)
            )
            .err()
            .ok_or("restore overwrite accepted")?
            .code,
            ErrorCode::RestoreConflict
        );
        #[cfg(target_os = "linux")]
        {
            let dangling = fixture.root.join("dangling-restored");
            let missing = fixture.root.join("missing-target");
            std::os::unix::fs::symlink(&missing, &dangling)?;
            assert_eq!(
                restore_backup(
                    &archive,
                    &dangling,
                    &UnlockCredential::Passphrase(pass()?),
                    Arc::clone(&store)
                )
                .err()
                .ok_or("dangling restore symlink replaced")?
                .code,
                ErrorCode::RestoreConflict
            );
            assert_eq!(fs::read_link(&dangling)?, missing);
        }
        let reopened = ProtectedVault::select(&restored, store)?;
        let restored_active = reopened.unlock(&UnlockCredential::Passphrase(pass()?))?;
        assert_eq!(
            restored_active
                .recover(&imported.blob_id, &mut DiscardPlaintext)?
                .sha256_hex,
            imported.sha256_hex
        );
        let bytes = fs::read(&archive)?;
        assert!(
            !bytes
                .windows(b"G3 plaintext sentinel".len())
                .any(|slice| slice == b"G3 plaintext sentinel")
        );
        println!("G3_DVBK1_FULL=PASS");
        Ok(())
    }

    #[test]
    fn destructive_restore_preserves_every_canonical_row_and_plaintext_hash()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let store: Arc<dyn CredentialStore> = Arc::new(NoDeviceStore);
        let created = ProtectedVault::create_with_policy(
            &fixture.root.join("vault"),
            &pass()?,
            RecoveryPolicy::Generate,
            ArgonProfile::BASELINE,
            Arc::clone(&store),
        )
        .map_err(NotActivated::into_primary)?
        .into_value();
        let recovery = created.recovery.ok_or("missing recovery secret")?;
        let active = created
            .backend
            .unlock(&UnlockCredential::Passphrase(pass()?))?;
        let sources = [
            ("small binary.bin", vec![0, 255, 4, 17, 0]),
            (
                "amintire șárga.txt",
                "Memorie română és magyar".as_bytes().to_vec(),
            ),
            (
                "duplicate with spaces.txt",
                "Memorie română és magyar".as_bytes().to_vec(),
            ),
            ("empty.bin", Vec::new()),
            ("large bounded.bin", vec![0xA5; 2 * 1024 * 1024]),
        ];
        let mut imports = Vec::new();
        for (name, bytes) in sources {
            let path = fixture.root.join(name);
            fs::write(&path, bytes)?;
            imports.push(active.import(&path)?);
        }
        assert_eq!(imports[1].blob_id, imports[2].blob_id);
        let header_bytes = fs::read(fixture.root.join("vault/vault.header"))?;
        let vmk = unlock_backup_header(&header_bytes, &UnlockCredential::Passphrase(pass()?))?;
        let (db_key, _) = vmk.storage_keys()?;
        let db_path = fixture.root.join("vault/metadata.db");
        let db = Connection::open(&db_path)?;
        db.pragma_update(None, "key", format!("x'{}'", hex(db_key.as_bytes())))?;
        db.execute(
            "UPDATE items SET metadata_json=?1,title=?2 WHERE id=?3",
            rusqlite::params![
                r#"{"note":"café șárga"}"#,
                "Târgu Mureș",
                imports[0].item_id
            ],
        )?;
        drop(db);
        let archive = fixture.root.join("corpus.dvmbak");
        let receipt = create_backup(&active, &archive)?;
        assert!(receipt.restorable && receipt.history_recorded);
        assert_eq!(
            verify_backup(
                &archive,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Structural
            )?
            .canonical_blob_count,
            4
        );
        assert_eq!(
            verify_backup(
                &archive,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Full
            )?
            .canonical_blob_count,
            4
        );
        let original_metadata = canonical_state(&db_path, &db_key)?;
        let archive_hash = hash_file(&archive)?;
        drop(active);
        fs::remove_dir_all(fixture.root.join("vault"))?;
        assert!(!fixture.root.join("vault").exists());
        let restored = fixture.root.join("restored vault");
        restore_backup(
            &archive,
            &restored,
            &UnlockCredential::Passphrase(pass()?),
            Arc::clone(&store),
        )?;
        assert_eq!(hash_file(&archive)?, archive_hash);
        let backend = ProtectedVault::select(&restored, Arc::clone(&store))?;
        let restored_active = backend.unlock(&UnlockCredential::Passphrase(pass()?))?;
        let restored_metadata = canonical_state(&restored.join("metadata.db"), &db_key)?;
        assert_eq!(original_metadata, restored_metadata);
        for import in &imports {
            let recovered = restored_active.recover(&import.blob_id, &mut DiscardPlaintext)?;
            assert_eq!(recovered.sha256_hex, import.sha256_hex);
            assert_eq!(recovered.size_bytes, import.size_bytes);
        }
        drop(restored_active);
        assert_eq!(
            backend
                .unlock(&UnlockCredential::Device)
                .err()
                .ok_or("device unexpectedly unlocked")?
                .code,
            ErrorCode::ProviderUnavailable
        );
        drop(backend.unlock(&UnlockCredential::Recovery(recovery))?);
        let largest_member = fs::metadata(fixture.root.join("large bounded.bin"))?.len();
        assert!(largest_member > (COPY_CHUNK * 16) as u64);
        let largest_stored_blob = imports
            .iter()
            .map(|import| {
                fs::metadata(
                    restored
                        .join("blobs")
                        .join(format!("{}.dvb", import.blob_id)),
                )
                .map(|metadata| metadata.len())
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .ok_or("missing canonical blob")?;
        println!(
            "G3_DESTRUCTIVE_RESTORE=PASS G3_PLAINTEXT_HASH_MISMATCH=NO G3_CANONICAL_METADATA=PASS G3_BOUNDED_MEMORY=PASS largest_plaintext_member={largest_member} largest_stored_blob={largest_stored_blob} chunk={COPY_CHUNK} backup_sha256={archive_hash}"
        );
        Ok(())
    }

    #[test]
    fn backup_crash_child() -> Result<(), Box<dyn std::error::Error>> {
        let (Ok(root), Ok(destination)) = (
            std::env::var("DVM_G3_CRASH_VAULT"),
            std::env::var("DVM_G3_CRASH_DEST"),
        ) else {
            return Ok(());
        };
        let backend = ProtectedVault::select(Path::new(&root), Arc::new(NoDeviceStore))?;
        let active = backend.unlock(&UnlockCredential::Passphrase(pass()?))?;
        create_backup(&active, Path::new(&destination))?;
        Err("backup checkpoint not reached".into())
    }

    #[test]
    fn backup_activation_crash_matrix() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let store: Arc<dyn CredentialStore> = Arc::new(NoDeviceStore);
        let created = ProtectedVault::create_with_policy(
            &fixture.root.join("vault"),
            &pass()?,
            RecoveryPolicy::Generate,
            ArgonProfile::BASELINE,
            Arc::clone(&store),
        )
        .map_err(NotActivated::into_primary)?
        .into_value();
        let active = created
            .backend
            .unlock(&UnlockCredential::Passphrase(pass()?))?;
        let source = fixture.root.join("large.bin");
        fs::write(&source, vec![7u8; 2 * 1024 * 1024])?;
        active.import(&source)?;
        drop(active);
        for (point, activated) in [
            ("before_staging", false),
            ("after_snapshot", false),
            ("after_public", false),
            ("mid_blob_copy", false),
            ("after_blob", false),
            ("after_members", false),
            ("after_manifest", false),
            ("after_finish", false),
            ("after_sync", false),
            ("before_activation", false),
            ("after_activation", true),
            ("before_success_response", true),
        ] {
            let destination = fixture.root.join(format!("{point}.dvmbak"));
            let status = Command::new(std::env::current_exe()?)
                .args(["dvbk1::tests::backup_crash_child", "--exact", "--nocapture"])
                .env("DVM_G3_CRASH_VAULT", fixture.root.join("vault"))
                .env("DVM_G3_CRASH_DEST", &destination)
                .env("DVM_G3_BACKUP_CHECKPOINT", point)
                .status()?;
            assert_eq!(status.code(), Some(91), "backup checkpoint {point}");
            assert_eq!(destination.exists(), activated, "backup activation {point}");
            if activated {
                let verified = verify_backup(
                    &destination,
                    &UnlockCredential::Passphrase(pass()?),
                    VerificationMode::Full,
                )?;
                let header_bytes = fs::read(fixture.root.join("vault/vault.header"))?;
                let vmk =
                    unlock_backup_header(&header_bytes, &UnlockCredential::Passphrase(pass()?))?;
                let (db_key, _) = vmk.storage_keys()?;
                let db = database::open_snapshot_readonly(
                    &fixture.root.join("vault/metadata.db"),
                    &db_key,
                )?;
                let recorded: i64 = db.query_row(
                    "SELECT count(*) FROM backup_history WHERE backup_id=?1",
                    [&verified.backup_id],
                    |row| row.get(0),
                )?;
                assert_eq!(recorded, i64::from(point == "before_success_response"));
            }
        }
        println!("G3_BACKUP_CRASH_MATRIX=PASS");
        Ok(())
    }

    #[test]
    fn import_after_snapshot_is_excluded_from_backup() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let store: Arc<dyn CredentialStore> = Arc::new(NoDeviceStore);
        let created = ProtectedVault::create_with_policy(
            &fixture.root.join("vault"),
            &pass()?,
            RecoveryPolicy::Generate,
            ArgonProfile::BASELINE,
            store,
        )
        .map_err(NotActivated::into_primary)?
        .into_value();
        let active = Arc::new(
            created
                .backend
                .unlock(&UnlockCredential::Passphrase(pass()?))?,
        );
        let first = fixture.root.join("first.bin");
        fs::write(&first, b"before snapshot")?;
        active.import(&first)?;
        let rendezvous = Arc::new(std::sync::Barrier::new(2));
        let writer_barrier = Arc::clone(&rendezvous);
        let writer_vault = Arc::clone(&active);
        let archive = fixture.root.join("boundary.dvmbak");
        let writer_archive = archive.clone();
        let writer = std::thread::spawn(move || {
            SNAPSHOT_RENDEZVOUS.with(|slot| *slot.borrow_mut() = Some(writer_barrier));
            create_backup(&writer_vault, &writer_archive)
        });
        rendezvous.wait();
        let competing =
            ProtectedVault::select(&fixture.root.join("vault"), Arc::new(NoDeviceStore))?;
        assert_eq!(
            competing
                .unlock(&UnlockCredential::Passphrase(pass()?))
                .err()
                .ok_or("competing maintenance session admitted")?
                .code,
            ErrorCode::VaultLocked
        );
        let second = fixture.root.join("second.bin");
        fs::write(&second, b"committed after snapshot")?;
        active.import(&second)?;
        rendezvous.wait();
        writer.join().map_err(|_| "backup worker panic")??;
        assert_eq!(
            verify_backup(
                &archive,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Full
            )?
            .canonical_blob_count,
            1
        );
        println!("G3_SNAPSHOT_CONCURRENT_IMPORT_BOUNDARY=PASS G3_MAINTENANCE_COORDINATION=PASS");
        Ok(())
    }

    #[test]
    fn backup_write_fault_child() -> Result<(), Box<dyn std::error::Error>> {
        let (Ok(root), Ok(destination), Ok(kind)) = (
            std::env::var("DVM_G3_FAULT_VAULT"),
            std::env::var("DVM_G3_FAULT_DEST"),
            std::env::var("DVM_G3_WRITE_FAULT"),
        ) else {
            return Ok(());
        };
        let backend = ProtectedVault::select(Path::new(&root), Arc::new(NoDeviceStore))?;
        let active = backend.unlock(&UnlockCredential::Passphrase(pass()?))?;
        let error = create_backup(&active, Path::new(&destination))
            .err()
            .ok_or("write fault accepted")?;
        assert_eq!(
            error.code,
            if kind == "disk_full" {
                ErrorCode::DiskFull
            } else {
                ErrorCode::Internal
            }
        );
        Ok(())
    }

    #[test]
    fn backup_write_failures_leave_no_final_archive_or_source_change()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let store: Arc<dyn CredentialStore> = Arc::new(NoDeviceStore);
        let created = ProtectedVault::create_with_policy(
            &fixture.root.join("vault"),
            &pass()?,
            RecoveryPolicy::Generate,
            ArgonProfile::BASELINE,
            Arc::clone(&store),
        )
        .map_err(NotActivated::into_primary)?
        .into_value();
        let active = created
            .backend
            .unlock(&UnlockCredential::Passphrase(pass()?))?;
        let source = fixture.root.join("source.bin");
        fs::write(&source, vec![3u8; 256 * 1024])?;
        active.import(&source)?;
        let vmk = unlock_backup_header(
            &fs::read(fixture.root.join("vault/vault.header"))?,
            &UnlockCredential::Passphrase(pass()?),
        )?;
        let (db_key, _) = vmk.storage_keys()?;
        let before = canonical_state(&fixture.root.join("vault/metadata.db"), &db_key)?;
        drop(active);
        for kind in ["disk_full", "write_error"] {
            let destination = fixture.root.join(format!("{kind}.dvmbak"));
            let status = Command::new(std::env::current_exe()?)
                .args([
                    "dvbk1::tests::backup_write_fault_child",
                    "--exact",
                    "--nocapture",
                ])
                .env("DVM_G3_FAULT_VAULT", fixture.root.join("vault"))
                .env("DVM_G3_FAULT_DEST", &destination)
                .env("DVM_G3_WRITE_FAULT", kind)
                .status()?;
            assert!(status.success(), "fault child {kind}");
            assert!(!destination.exists());
            assert_eq!(
                before,
                canonical_state(&fixture.root.join("vault/metadata.db"), &db_key)?
            );
        }
        println!("G3_BACKUP_DISK_FULL=PASS G3_BACKUP_WRITE_FAILURE=PASS");
        Ok(())
    }

    fn malicious_archive(
        path: &Path,
        name: &str,
        entry_type: tar::EntryType,
        duplicate: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut builder = tar::Builder::new(File::create(path)?);
        for _ in 0..(if duplicate { 2 } else { 1 }) {
            let mut entry = tar::Header::new_gnu();
            entry.set_entry_type(entry_type);
            entry.set_mode(0o600);
            entry.set_size(0);
            let raw = entry.as_mut_bytes();
            raw[..100].fill(0);
            raw[..name.len()].copy_from_slice(name.as_bytes());
            entry.set_cksum();
            builder.append(&entry, &[][..])?;
        }
        builder.into_inner()?.sync_all()?;
        Ok(())
    }

    #[test]
    fn archive_path_and_special_entry_matrix_is_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = Fixture::new()?;
        for (index, hostile) in [
            "../escape",
            "a/../../escape",
            "/absolute",
            "C:/absolute",
            r"C:\absolute",
            r"\\server\share",
            r"a\..\..\escape",
            "",
            "blobs/nested/00000000-0000-0000-0000-000000000000.dvb",
            "blobs/not-a-uuid.dvb",
        ]
        .iter()
        .enumerate()
        {
            assert!(!valid_member_name(hostile));
            let archive = fixture.root.join(format!("hostile-{index}.dvmbak"));
            malicious_archive(&archive, hostile, tar::EntryType::Regular, false)?;
            assert_eq!(
                verify_backup(
                    &archive,
                    &UnlockCredential::Passphrase(pass()?),
                    VerificationMode::Structural
                )
                .err()
                .ok_or("hostile path accepted")?
                .code,
                ErrorCode::BackupInvalid
            );
            assert!(!fixture.root.join("escape").exists());
        }
        for (index, kind) in [
            tar::EntryType::Symlink,
            tar::EntryType::Link,
            tar::EntryType::Fifo,
            tar::EntryType::Directory,
        ]
        .iter()
        .enumerate()
        {
            let archive = fixture.root.join(format!("special-{index}.dvmbak"));
            malicious_archive(&archive, "vault.header", *kind, false)?;
            assert!(
                verify_backup(
                    &archive,
                    &UnlockCredential::Passphrase(pass()?),
                    VerificationMode::Structural
                )
                .is_err()
            );
        }
        let duplicate = fixture.root.join("duplicate.dvmbak");
        malicious_archive(&duplicate, "vault.header", tar::EntryType::Regular, true)?;
        assert!(
            verify_backup(
                &duplicate,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Structural
            )
            .is_err()
        );
        println!(
            "G3_ARCHIVE_PATH_TRAVERSAL_REJECTED=PASS G3_SPECIAL_ENTRIES_REJECTED=PASS G3_DUPLICATES_REJECTED=PASS"
        );
        Ok(())
    }

    fn flip_member(
        source: &Path,
        destination: &Path,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        fs::copy(source, destination)?;
        let mut archive = tar::Archive::new(File::open(source)?);
        let mut offset = None;
        for entry in archive.entries()?.raw(true) {
            let entry = entry?;
            if entry.header().path_bytes().as_ref() == name.as_bytes() {
                offset = Some(entry.raw_file_position() + entry.size() / 2);
                break;
            }
        }
        let offset = offset.ok_or("member absent")?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(destination)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut byte = [0];
        file.read_exact(&mut byte)?;
        byte[0] ^= 1;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&byte)?;
        file.sync_all()?;
        Ok(())
    }

    fn repack(
        stage: &Path,
        destination: &Path,
        public: &[u8],
        manifest: &[u8],
        include_blob: bool,
        extra_blob: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = File::create(destination)?;
        let mut builder = tar::Builder::new(StagedOutput::new(output));
        append_bytes(&mut builder, "public-format.json", public)?;
        append_bytes(
            &mut builder,
            "vault.header",
            &fs::read(stage.join("vault.header"))?,
        )?;
        let (db, size) = source_file(&stage.join("metadata.db.snapshot"))?;
        append_stream(&mut builder, "metadata.db.snapshot", db, size)?;
        if include_blob {
            let mut blobs = fs::read_dir(stage.join("blobs"))?.collect::<Result<Vec<_>, _>>()?;
            blobs.sort_by_key(std::fs::DirEntry::file_name);
            for blob in blobs {
                let name = format!("blobs/{}", blob.file_name().to_string_lossy());
                let (file, size) = source_file(&blob.path())?;
                append_stream(&mut builder, &name, file, size)?;
            }
        }
        if extra_blob {
            append_bytes(
                &mut builder,
                "blobs/00000000-0000-0000-0000-000000000000.dvb",
                b"extra",
            )?;
        }
        append_bytes(&mut builder, "manifest.enc", manifest)?;
        builder.into_inner()?.file.sync_all()?;
        Ok(())
    }

    #[test]
    fn corruption_matrix_rejects_every_corrupted_archive() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = Fixture::new()?;
        let store: Arc<dyn CredentialStore> = Arc::new(NoDeviceStore);
        let created = ProtectedVault::create_with_policy(
            &fixture.root.join("vault"),
            &pass()?,
            RecoveryPolicy::Generate,
            ArgonProfile::BASELINE,
            Arc::clone(&store),
        )
        .map_err(NotActivated::into_primary)?
        .into_value();
        let active = created
            .backend
            .unlock(&UnlockCredential::Passphrase(pass()?))?;
        let source = fixture.root.join("source.bin");
        fs::write(&source, vec![9u8; 256 * 1024])?;
        let imported = active.import(&source)?;
        let archive = fixture.root.join("valid.dvmbak");
        create_backup(&active, &archive)?;
        drop(active);
        for (index, member) in [
            "public-format.json",
            "vault.header",
            "metadata.db.snapshot",
            "manifest.enc",
            "blob",
        ]
        .iter()
        .enumerate()
        {
            let name = if *member == "blob" {
                format!("blobs/{}.dvb", imported.blob_id)
            } else {
                (*member).into()
            };
            let corrupt = fixture.root.join(format!("corrupt-{index}.dvmbak"));
            flip_member(&archive, &corrupt, &name)?;
            assert!(
                verify_backup(
                    &corrupt,
                    &UnlockCredential::Passphrase(pass()?),
                    VerificationMode::Structural
                )
                .is_err(),
                "corrupt {member} accepted"
            );
        }
        let truncated = fixture.root.join("truncated.dvmbak");
        fs::copy(&archive, &truncated)?;
        let file = OpenOptions::new().write(true).open(&truncated)?;
        file.set_len(file.metadata()?.len() - 1)?;
        assert!(
            verify_backup(
                &truncated,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Structural
            )
            .is_err()
        );
        let extracted = extract_to_stage(&archive, fixture.root.join("controlled-stage"))?;
        let public = small_member(&extracted.stage.root, "public-format.json", 4096)?;
        let encrypted = small_member(&extracted.stage.root, "manifest.enc", MAX_SMALL_MEMBER)?;
        let vmk = unlock_backup_header(
            &small_member(&extracted.stage.root, "vault.header", 16_384)?,
            &UnlockCredential::Passphrase(pass()?),
        )?;
        let (_, backup_key) = vmk.auxiliary_keys()?;
        let public_format: PublicFormat = serde_json::from_slice(&public)?;
        let mut changed_public = vec![b' '];
        changed_public.extend_from_slice(&public);
        assert!(
            decrypt_manifest(
                &encrypted,
                &changed_public,
                &public_format.backup_id,
                &backup_key
            )
            .is_err(),
            "public-format AAD tamper accepted"
        );
        let mut manifest =
            decrypt_manifest(&encrypted, &public, &public_format.backup_id, &backup_key)?;
        let missing = fixture.root.join("missing-blob.dvmbak");
        repack(
            &extracted.stage.root,
            &missing,
            &public,
            &encrypted,
            false,
            false,
        )?;
        assert!(
            verify_backup(
                &missing,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Structural
            )
            .is_err()
        );
        let extra = fixture.root.join("extra-blob.dvmbak");
        repack(
            &extracted.stage.root,
            &extra,
            &public,
            &encrypted,
            true,
            true,
        )?;
        assert!(
            verify_backup(
                &extra,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Structural
            )
            .is_err()
        );
        manifest.canonical_blob_count += 1;
        let wrong_count = fixture.root.join("wrong-count.dvmbak");
        repack(
            &extracted.stage.root,
            &wrong_count,
            &public,
            &encrypt_manifest(&manifest, &public, &backup_key)?,
            true,
            false,
        )?;
        assert!(
            verify_backup(
                &wrong_count,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Structural
            )
            .is_err()
        );
        manifest.canonical_blob_count -= 1;
        manifest.canonical_logical_bytes += 1;
        let wrong_total = fixture.root.join("wrong-total.dvmbak");
        repack(
            &extracted.stage.root,
            &wrong_total,
            &public,
            &encrypt_manifest(&manifest, &public, &backup_key)?,
            true,
            false,
        )?;
        assert!(
            verify_backup(
                &wrong_total,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Structural
            )
            .is_err()
        );
        manifest.canonical_logical_bytes -= 1;
        manifest.members[0].sha256 = "0".repeat(64);
        let wrong_hash = fixture.root.join("wrong-hash.dvmbak");
        repack(
            &extracted.stage.root,
            &wrong_hash,
            &public,
            &encrypt_manifest(&manifest, &public, &backup_key)?,
            true,
            false,
        )?;
        assert!(
            verify_backup(
                &wrong_hash,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Structural
            )
            .is_err()
        );
        let mut unknown_public: PublicFormat = serde_json::from_slice(&public)?;
        unknown_public.format_version = 99;
        let unknown = fixture.root.join("unknown-version.dvmbak");
        repack(
            &extracted.stage.root,
            &unknown,
            &serde_json::to_vec(&unknown_public)?,
            &encrypted,
            true,
            false,
        )?;
        assert!(
            verify_backup(
                &unknown,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Structural
            )
            .is_err()
        );
        println!("G3_CORRUPTION_MATRIX=PASS G3_UNKNOWN_VERSION=PASS G3_MANIFEST_AUTH=PASS");
        Ok(())
    }

    #[test]
    fn authenticated_structural_backup_still_requires_every_plaintext_hash()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let store: Arc<dyn CredentialStore> = Arc::new(NoDeviceStore);
        let created = ProtectedVault::create_with_policy(
            &fixture.root.join("vault"),
            &pass()?,
            RecoveryPolicy::Generate,
            ArgonProfile::BASELINE,
            Arc::clone(&store),
        )
        .map_err(NotActivated::into_primary)?
        .into_value();
        let active = created
            .backend
            .unlock(&UnlockCredential::Passphrase(pass()?))?;
        let source = fixture.root.join("source.bin");
        fs::write(&source, vec![0x47u8; 256 * 1024])?;
        let imported = active.import(&source)?;
        let archive = fixture.root.join("valid.dvmbak");
        create_backup(&active, &archive)?;
        drop(active);
        let extracted = extract_to_stage(&archive, fixture.root.join("blob-stage"))?;
        let public = small_member(&extracted.stage.root, "public-format.json", 4096)?;
        let encrypted = small_member(&extracted.stage.root, "manifest.enc", MAX_SMALL_MEMBER)?;
        let vmk = unlock_backup_header(
            &small_member(&extracted.stage.root, "vault.header", 16_384)?,
            &UnlockCredential::Passphrase(pass()?),
        )?;
        let (db_key, _) = vmk.storage_keys()?;
        let (_, backup_key) = vmk.auxiliary_keys()?;
        let public_format: PublicFormat = serde_json::from_slice(&public)?;
        let mut manifest =
            decrypt_manifest(&encrypted, &public, &public_format.backup_id, &backup_key)?;
        let blob_name = format!("blobs/{}.dvb", imported.blob_id);
        let blob_path = stage_path(&extracted.stage.root, &blob_name)?;
        let mut file = OpenOptions::new().read(true).write(true).open(&blob_path)?;
        file.seek(SeekFrom::Start(100))?;
        let mut byte = [0];
        file.read_exact(&mut byte)?;
        byte[0] ^= 1;
        file.seek(SeekFrom::Start(100))?;
        file.write_all(&byte)?;
        file.sync_all()?;
        manifest
            .members
            .iter_mut()
            .find(|member| member.path == blob_name)
            .ok_or("blob manifest entry")?
            .sha256 = hash_file(&blob_path)?;
        let corrupt_blob = fixture.root.join("authenticated-corrupt-blob.dvmbak");
        repack(
            &extracted.stage.root,
            &corrupt_blob,
            &public,
            &encrypt_manifest(&manifest, &public, &backup_key)?,
            true,
            false,
        )?;
        verify_backup(
            &corrupt_blob,
            &UnlockCredential::Passphrase(pass()?),
            VerificationMode::Structural,
        )?;
        assert!(
            verify_backup(
                &corrupt_blob,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Full
            )
            .is_err()
        );

        let clean = extract_to_stage(&archive, fixture.root.join("hash-stage"))?;
        let db_path = clean.stage.root.join("metadata.db.snapshot");
        let db = Connection::open(&db_path)?;
        db.pragma_update(None, "key", format!("x'{}'", hex(db_key.as_bytes())))?;
        db.execute(
            "UPDATE blobs SET sha256_hex=?1 WHERE id=?2",
            rusqlite::params!["0".repeat(64), imported.blob_id],
        )?;
        db.close().map_err(|(_, error)| error)?;
        let mut hash_manifest =
            decrypt_manifest(&encrypted, &public, &public_format.backup_id, &backup_key)?;
        let db_member = hash_manifest
            .members
            .iter_mut()
            .find(|member| member.path == "metadata.db.snapshot")
            .ok_or("db manifest entry")?;
        db_member.sha256 = hash_file(&db_path)?;
        db_member.size = fs::metadata(&db_path)?.len();
        let mismatched = fixture.root.join("authenticated-hash-mismatch.dvmbak");
        repack(
            &clean.stage.root,
            &mismatched,
            &public,
            &encrypt_manifest(&hash_manifest, &public, &backup_key)?,
            true,
            false,
        )?;
        verify_backup(
            &mismatched,
            &UnlockCredential::Passphrase(pass()?),
            VerificationMode::Structural,
        )?;
        assert!(
            verify_backup(
                &mismatched,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Full
            )
            .is_err()
        );

        let plaintext = fixture.root.join("plaintext.db");
        let plain_db = Connection::open(&plaintext)?;
        plain_db.execute_batch(
            "CREATE TABLE canary(value TEXT); INSERT INTO canary VALUES ('plaintext snapshot');",
        )?;
        plain_db.close().map_err(|(_, error)| error)?;
        assert!(fs::read(&plaintext)?.starts_with(b"SQLite format 3"));
        fs::copy(&plaintext, &db_path)?;
        let plain_member = hash_manifest
            .members
            .iter_mut()
            .find(|member| member.path == "metadata.db.snapshot")
            .ok_or("db manifest entry")?;
        plain_member.sha256 = hash_file(&db_path)?;
        plain_member.size = fs::metadata(&db_path)?.len();
        let unencrypted = fixture.root.join("plaintext-snapshot.dvmbak");
        repack(
            &clean.stage.root,
            &unencrypted,
            &public,
            &encrypt_manifest(&hash_manifest, &public, &backup_key)?,
            true,
            false,
        )?;
        assert!(
            verify_backup(
                &unencrypted,
                &UnlockCredential::Passphrase(pass()?),
                VerificationMode::Structural
            )
            .is_err()
        );
        println!(
            "G3_FULL_COMPLETENESS_NEGATIVE=PASS G3_PLAINTEXT_HASH_MISMATCH_NEGATIVE=PASS G3_PLAINTEXT_SNAPSHOT_NEGATIVE=PASS"
        );
        Ok(())
    }

    #[test]
    fn restore_crash_child() -> Result<(), Box<dyn std::error::Error>> {
        let (Ok(archive), Ok(destination)) = (
            std::env::var("DVM_G3_CRASH_ARCHIVE"),
            std::env::var("DVM_G3_CRASH_DEST"),
        ) else {
            return Ok(());
        };
        restore_backup(
            Path::new(&archive),
            Path::new(&destination),
            &UnlockCredential::Passphrase(pass()?),
            Arc::new(NoDeviceStore),
        )?;
        Err("restore checkpoint not reached".into())
    }

    #[test]
    fn restore_activation_crash_matrix() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let store: Arc<dyn CredentialStore> = Arc::new(NoDeviceStore);
        let created = ProtectedVault::create_with_policy(
            &fixture.root.join("vault"),
            &pass()?,
            RecoveryPolicy::Generate,
            ArgonProfile::BASELINE,
            Arc::clone(&store),
        )
        .map_err(NotActivated::into_primary)?
        .into_value();
        let active = created
            .backend
            .unlock(&UnlockCredential::Passphrase(pass()?))?;
        let source = fixture.root.join("large.bin");
        fs::write(&source, vec![8u8; 2 * 1024 * 1024])?;
        let imported = active.import(&source)?;
        let archive = fixture.root.join("crash.dvmbak");
        create_backup(&active, &archive)?;
        drop(active);
        for (point, activated) in [
            ("restore_before_stage", false),
            ("restore_after_header", false),
            ("restore_after_db", false),
            ("mid_blob_extraction", false),
            ("restore_after_extraction", false),
            ("restore_after_structural", false),
            ("restore_after_full", false),
            ("restore_before_activation", false),
            ("restore_after_activation", true),
            ("restore_before_success_response", true),
        ] {
            let destination = fixture.root.join(format!("restored-{point}"));
            let status = Command::new(std::env::current_exe()?)
                .args([
                    "dvbk1::tests::restore_crash_child",
                    "--exact",
                    "--nocapture",
                ])
                .env("DVM_G3_CRASH_ARCHIVE", &archive)
                .env("DVM_G3_CRASH_DEST", &destination)
                .env("DVM_G3_BACKUP_CHECKPOINT", point)
                .status()?;
            assert_eq!(status.code(), Some(91), "restore checkpoint {point}");
            assert_eq!(
                destination.exists(),
                activated,
                "restore activation {point}"
            );
            if activated {
                let backend = ProtectedVault::select(&destination, Arc::clone(&store))?;
                let restored = backend.unlock(&UnlockCredential::Passphrase(pass()?))?;
                assert_eq!(
                    restored
                        .recover(&imported.blob_id, &mut DiscardPlaintext)?
                        .sha256_hex,
                    imported.sha256_hex
                );
            }
        }
        println!("G3_RESTORE_CRASH_MATRIX=PASS");
        Ok(())
    }
}

/// Verification result without secret or item metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReceipt {
    /// Opaque archive identity.
    pub backup_id: String,
    /// Completed verification mode.
    pub mode: VerificationMode,
    /// Number of canonical blobs covered.
    pub canonical_blob_count: u64,
}

fn invalid() -> AppError {
    AppError::new(ErrorCode::BackupInvalid)
}
fn io_error(error: &std::io::Error) -> AppError {
    AppError::new(if error.kind() == std::io::ErrorKind::StorageFull {
        ErrorCode::DiskFull
    } else {
        ErrorCode::Internal
    })
}
fn activation_error(error: &std::io::Error) -> AppError {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        AppError::new(ErrorCode::RestoreConflict)
    } else {
        io_error(error)
    }
}
fn hex(bytes: &[u8]) -> String {
    dvm_crypto::dvb1::hex(bytes)
}

#[cfg(test)]
fn checkpoint(name: &str) {
    if std::env::var("DVM_G3_BACKUP_CHECKPOINT").is_ok_and(|point| point == name) {
        std::process::exit(91);
    }
}

fn manifest_key(root: &BackupKey, backup_id: &str) -> Result<Zeroizing<[u8; 32]>, AppError> {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(backup_id.as_bytes()), root.as_bytes())
        .expand(b"DVM/DVBK1/manifest/v1", key.as_mut())
        .map_err(|_| AppError::new(ErrorCode::Internal))?;
    Ok(key)
}

fn encrypt_manifest(
    manifest: &Manifest,
    public: &[u8],
    root: &BackupKey,
) -> Result<Vec<u8>, AppError> {
    let key = manifest_key(root, &manifest.backup_id)?;
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| AppError::new(ErrorCode::Internal))?;
    let plaintext = Zeroizing::new(serde_json::to_vec(manifest).map_err(|_| invalid())?);
    if u64::try_from(plaintext.len()).map_err(|_| invalid())? > MAX_SMALL_MEMBER - 48 {
        return Err(invalid());
    }
    let ciphertext = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| invalid())?
        .encrypt(
            &XNonce::try_from(nonce.as_slice()).map_err(|_| invalid())?,
            Payload {
                msg: plaintext.as_ref(),
                aad: public,
            },
        )
        .map_err(|_| invalid())?;
    let mut framed = Vec::with_capacity(8 + 24 + ciphertext.len());
    framed.extend_from_slice(MANIFEST_MAGIC);
    framed.extend_from_slice(&nonce);
    framed.extend_from_slice(&ciphertext);
    Ok(framed)
}

fn decrypt_manifest(
    bytes: &[u8],
    public: &[u8],
    backup_id: &str,
    root: &BackupKey,
) -> Result<Manifest, AppError> {
    if bytes.len() < 8 + 24 + 16
        || u64::try_from(bytes.len()).map_err(|_| invalid())? > MAX_SMALL_MEMBER
        || !bytes.starts_with(MANIFEST_MAGIC)
    {
        return Err(invalid());
    }
    let key = manifest_key(root, backup_id)?;
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| invalid())?
            .decrypt(
                &XNonce::try_from(&bytes[8..32]).map_err(|_| invalid())?,
                Payload {
                    msg: &bytes[32..],
                    aad: public,
                },
            )
            .map_err(|_| invalid())?,
    );
    serde_json::from_slice(&plaintext).map_err(|_| invalid())
}

fn valid_member_name(name: &str) -> bool {
    if matches!(
        name,
        "public-format.json" | "vault.header" | "metadata.db.snapshot" | "manifest.enc"
    ) {
        return true;
    }
    let Some(id) = name
        .strip_prefix("blobs/")
        .and_then(|suffix| suffix.strip_suffix(".dvb"))
    else {
        return false;
    };
    Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == id)
}

fn source_file(path: &Path) -> Result<(File, u64), AppError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(&error))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(invalid());
    }
    let file = File::open(path).map_err(|error| io_error(&error))?;
    Ok((file, metadata.len()))
}

struct HashingReader<R> {
    input: R,
    digest: Sha256,
    bytes: u64,
    #[cfg(test)]
    blob: bool,
    #[cfg(test)]
    reads: u64,
}

struct StagedOutput {
    file: File,
    #[cfg(test)]
    remaining_before_fault: Option<(usize, std::io::ErrorKind)>,
}
impl StagedOutput {
    fn new(file: File) -> Self {
        #[cfg(test)]
        let remaining_before_fault = match std::env::var("DVM_G3_WRITE_FAULT").ok().as_deref() {
            Some("disk_full") => Some((1024, std::io::ErrorKind::StorageFull)),
            Some("write_error") => Some((1024, std::io::ErrorKind::PermissionDenied)),
            _ => None,
        };
        Self {
            file,
            #[cfg(test)]
            remaining_before_fault,
        }
    }
}
impl Write for StagedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        #[cfg(test)]
        if let Some((remaining, kind)) = self.remaining_before_fault {
            if remaining == 0 {
                return Err(std::io::Error::from(kind));
            }
            let count = self.file.write(&bytes[..bytes.len().min(remaining)])?;
            self.remaining_before_fault = Some((remaining - count, kind));
            return Ok(count);
        }
        self.file.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let count = self.input.read(output)?;
        self.digest.update(&output[..count]);
        self.bytes += count as u64;
        #[cfg(test)]
        {
            if self.blob && count > 0 {
                self.reads += 1;
                if self.reads == 2 {
                    checkpoint("mid_blob_copy");
                }
            }
        }
        Ok(count)
    }
}

fn append_stream(
    builder: &mut tar::Builder<StagedOutput>,
    name: &str,
    input: impl Read,
    size: u64,
) -> Result<Member, AppError> {
    let mut entry = tar::Header::new_gnu();
    entry.set_entry_type(tar::EntryType::Regular);
    entry.set_mode(0o600);
    entry.set_size(size);
    entry.set_cksum();
    let mut hashing = HashingReader {
        input,
        digest: Sha256::new(),
        bytes: 0,
        #[cfg(test)]
        blob: name.starts_with("blobs/"),
        #[cfg(test)]
        reads: 0,
    };
    builder
        .append_data(&mut entry, name, &mut hashing)
        .map_err(|error| io_error(&error))?;
    if hashing.bytes != size {
        return Err(invalid());
    }
    Ok(Member {
        path: name.into(),
        size,
        sha256: hex(&hashing.digest.finalize()),
    })
}

fn append_bytes(
    builder: &mut tar::Builder<StagedOutput>,
    name: &str,
    bytes: &[u8],
) -> Result<Member, AppError> {
    append_stream(builder, name, bytes, bytes.len() as u64)
}

fn snapshot_blobs(db: &Connection) -> Result<Vec<(String, DigestReceipt)>, AppError> {
    let mut query = db.prepare("SELECT DISTINCT b.id,b.sha256_hex,b.size_bytes,b.storage_relpath FROM blobs b JOIN item_blobs ib ON ib.blob_id=b.id ORDER BY b.id").map_err(|_| invalid())?;
    let rows = query
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| invalid())?;
    let mut result = Vec::new();
    for row in rows {
        let (id, sha256_hex, size, relative) = row.map_err(|_| invalid())?;
        let name = format!("blobs/{id}.dvb");
        if !valid_member_name(&name)
            || validate_blob_storage_relpath(&id, &relative).is_err()
            || size < 0
        {
            return Err(invalid());
        }
        result.push((
            id,
            DigestReceipt {
                sha256_hex,
                size_bytes: u64::try_from(size).map_err(|_| invalid())?,
            },
        ));
        if result.len() > MAX_MEMBERS - 4 {
            return Err(invalid());
        }
    }
    Ok(result)
}

/// Creates and FULL-verifies a DVBK1 archive before publication.
/// # Errors
/// Existing destinations and paths inside the source vault are refused.
#[allow(clippy::too_many_lines)] // One ordered activation transaction, with no hidden post-activation fallible return.
pub fn create_backup(vault: &OpenVault, destination: &Path) -> Result<BackupReceipt, AppError> {
    if destination
        .extension()
        .is_none_or(|extension| extension != "dvmbak")
    {
        return Err(AppError::new(ErrorCode::RestoreConflict));
    }
    match fs::symlink_metadata(destination) {
        Ok(_) => return Err(AppError::new(ErrorCode::RestoreConflict)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(&error)),
    }
    let parent = fs::canonicalize(destination.parent().ok_or_else(invalid)?)
        .map_err(|error| io_error(&error))?;
    if parent.starts_with(vault.root_for_backup()) {
        return Err(invalid());
    }
    let destination = parent.join(destination.file_name().ok_or_else(invalid)?);
    let token = Uuid::new_v4();
    let staging = parent.join(format!(".dvm-backup-{token}.part"));
    let snapshot = parent.join(format!(".dvm-backup-{token}.snapshot"));
    #[cfg(test)]
    checkpoint("before_staging");
    let result = (|| {
        #[cfg(test)]
        BACKUP_SNAPSHOT_COUNT.set(BACKUP_SNAPSHOT_COUNT.get() + 1);
        let access = vault.snapshot_for_backup(&snapshot)?;
        #[cfg(test)]
        SNAPSHOT_RENDEZVOUS.with(|slot| {
            if let Some(barrier) = slot.borrow_mut().take() {
                barrier.wait();
                barrier.wait();
            }
        });
        #[cfg(test)]
        checkpoint("after_snapshot");
        let snapshot_db = database::open_snapshot_readonly(&snapshot, &access.db_key)?;
        let version: u32 = snapshot_db
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| invalid())?;
        migrations::validate_history(&snapshot_db, version)?;
        let blobs = snapshot_blobs(&snapshot_db)?;
        let blob_count = blobs.len() as u64;
        let logical_bytes = blobs.iter().try_fold(0u64, |total, (_, receipt)| {
            total.checked_add(receipt.size_bytes).ok_or_else(invalid)
        })?;
        drop(snapshot_db);
        let parsed_header = header::parse(&access.header)?;
        let backup_id = Uuid::new_v4().to_string();
        let public = serde_json::to_vec(&PublicFormat {
            magic: "DVBK1".into(),
            format_version: 1,
            backup_id: backup_id.clone(),
            manifest_algorithm: "HKDF-SHA-256+XChaCha20-Poly1305".into(),
            manifest_version: 1,
        })
        .map_err(|_| invalid())?;
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)
            .map_err(|error| io_error(&error))?;
        let mut builder = tar::Builder::new(StagedOutput::new(output));
        let mut members = Vec::with_capacity(blobs.len() + 3);
        members.push(append_bytes(&mut builder, "public-format.json", &public)?);
        #[cfg(test)]
        checkpoint("after_public");
        members.push(append_bytes(&mut builder, "vault.header", &access.header)?);
        let (db_file, db_size) = source_file(&snapshot)?;
        members.push(append_stream(
            &mut builder,
            "metadata.db.snapshot",
            db_file,
            db_size,
        )?);
        for (id, _) in &blobs {
            let path = access.root.join("blobs").join(format!("{id}.dvb"));
            let (file, size) = source_file(&path)?;
            members.push(append_stream(
                &mut builder,
                &format!("blobs/{id}.dvb"),
                file,
                size,
            )?);
            #[cfg(test)]
            checkpoint("after_blob");
        }
        #[cfg(test)]
        checkpoint("after_members");
        let created_at_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_secs();
        let manifest = Manifest {
            backup_id: backup_id.clone(),
            vault_id: parsed_header.vault_id,
            format_version: 1,
            app_version: env!("CARGO_PKG_VERSION").into(),
            schema_version: version,
            created_at_unix_seconds,
            members,
            canonical_blob_count: blob_count,
            canonical_logical_bytes: logical_bytes,
        };
        let encrypted = encrypt_manifest(&manifest, &public, &access.backup_key)?;
        append_bytes(&mut builder, "manifest.enc", &encrypted)?;
        #[cfg(test)]
        checkpoint("after_manifest");
        let output = builder.into_inner().map_err(|error| io_error(&error))?;
        #[cfg(test)]
        checkpoint("after_finish");
        output.file.sync_all().map_err(|error| io_error(&error))?;
        drop(output);
        #[cfg(test)]
        checkpoint("after_sync");
        let verified = verify_with_keys(
            &staging,
            &access.db_key,
            &access.blob_root,
            &access.backup_key,
            VerificationMode::Full,
        )?;
        if verified.backup_id != backup_id {
            return Err(invalid());
        }
        #[cfg(test)]
        checkpoint("before_activation");
        #[cfg(test)]
        BEFORE_BACKUP_ACTIVATION.with(|slot| {
            if let Some(before_activation) = slot.borrow_mut().take() {
                before_activation();
            }
        });
        activate_file_noreplace(&staging, &destination)
            .map_err(|error| activation_error(&error))?;
        #[cfg(test)]
        checkpoint("after_activation");
        let history_recorded = vault.record_backup_activation(&backup_id).is_ok();
        #[cfg(test)]
        checkpoint("before_success_response");
        Ok(BackupReceipt {
            backup_id,
            restorable: true,
            history_recorded,
        })
    })();
    let _ = fs::remove_file(&snapshot);
    if result.is_err() {
        let _ = fs::remove_file(&staging);
    }
    result
}

struct OwnedStage {
    root: PathBuf,
    activated: bool,
}
impl OwnedStage {
    fn create(path: PathBuf) -> Result<Self, AppError> {
        fs::create_dir(&path).map_err(|error| io_error(&error))?;
        let owned = Self {
            root: path,
            activated: false,
        };
        fs::create_dir(owned.root.join("blobs")).map_err(|error| io_error(&error))?;
        Ok(owned)
    }
}
impl Drop for OwnedStage {
    fn drop(&mut self) {
        if !self.activated {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

struct Extracted {
    stage: OwnedStage,
    observed: BTreeMap<String, Member>,
}

fn stage_path(stage: &Path, name: &str) -> Result<PathBuf, AppError> {
    match name {
        "public-format.json" | "vault.header" | "metadata.db.snapshot" | "manifest.enc" => {
            Ok(stage.join(name))
        }
        _ => {
            let id = name
                .strip_prefix("blobs/")
                .and_then(|value| value.strip_suffix(".dvb"))
                .ok_or_else(invalid)?;
            if !valid_member_name(name) {
                return Err(invalid());
            }
            Ok(stage.join("blobs").join(format!("{id}.dvb")))
        }
    }
}

#[allow(clippy::too_many_lines)] // Each member is validated, streamed, hashed and synced before the next entry.
fn extract_to_stage(archive_path: &Path, stage_path_value: PathBuf) -> Result<Extracted, AppError> {
    let stage = OwnedStage::create(stage_path_value)?;
    let (archive_file, archive_size) = source_file(archive_path)?;
    if archive_size < 1024 || archive_size % 512 != 0 {
        return Err(invalid());
    }
    let mut archive = tar::Archive::new(archive_file);
    let mut observed = BTreeMap::new();
    let entries = archive.entries().map_err(|_| invalid())?.raw(true);
    for entry in entries {
        let mut entry = entry.map_err(|_| invalid())?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            return Err(invalid());
        }
        let raw = entry.header().path_bytes();
        let name = std::str::from_utf8(raw.as_ref())
            .map_err(|_| invalid())?
            .to_owned();
        if !valid_member_name(&name)
            || observed.contains_key(&name)
            || observed.len() >= MAX_MEMBERS
        {
            return Err(invalid());
        }
        let size = entry.size();
        let limit = match name.as_str() {
            "public-format.json" => 4096,
            "vault.header" => 16_384,
            "manifest.enc" => MAX_SMALL_MEMBER,
            _ => u64::MAX,
        };
        if size > limit {
            return Err(invalid());
        }
        let output_path = stage_path(&stage.root, &name)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)
            .map_err(|error| io_error(&error))?;
        let mut digest = Sha256::new();
        let mut copied = 0u64;
        let mut buffer = vec![0u8; COPY_CHUNK];
        loop {
            let count = entry.read(&mut buffer).map_err(|error| io_error(&error))?;
            if count == 0 {
                break;
            }
            output
                .write_all(&buffer[..count])
                .map_err(|error| io_error(&error))?;
            digest.update(&buffer[..count]);
            copied = copied.checked_add(count as u64).ok_or_else(invalid)?;
            if copied > size {
                return Err(invalid());
            }
            #[cfg(test)]
            if name.starts_with("blobs/") {
                checkpoint("mid_blob_extraction");
            }
        }
        if copied != size {
            return Err(invalid());
        }
        output.sync_all().map_err(|error| io_error(&error))?;
        #[cfg(test)]
        if name == "vault.header" {
            checkpoint("restore_after_header");
        }
        #[cfg(test)]
        if name == "metadata.db.snapshot" {
            checkpoint("restore_after_db");
        }
        observed.insert(
            name.clone(),
            Member {
                path: name,
                size,
                sha256: hex(&digest.finalize()),
            },
        );
    }
    let mut file = archive.into_inner();
    let mut trailing = vec![0u8; COPY_CHUNK];
    while file.read(&mut trailing).map_err(|error| io_error(&error))? != 0 {
        // tar::Archive stops at its first zero block; later data must be padding.
        if trailing.iter().any(|byte| *byte != 0) {
            return Err(invalid());
        }
        trailing.fill(0);
    }
    file.seek(SeekFrom::End(-1024))
        .map_err(|error| io_error(&error))?;
    let mut footer = [0u8; 1024];
    file.read_exact(&mut footer)
        .map_err(|error| io_error(&error))?;
    if footer.iter().any(|byte| *byte != 0) {
        return Err(invalid());
    }
    for required in [
        "public-format.json",
        "vault.header",
        "metadata.db.snapshot",
        "manifest.enc",
    ] {
        if !observed.contains_key(required) {
            return Err(invalid());
        }
    }
    Ok(Extracted { stage, observed })
}

fn small_member(stage: &Path, name: &str, limit: u64) -> Result<Vec<u8>, AppError> {
    let path = stage_path(stage, name)?;
    let (mut file, size) = source_file(&path)?;
    if size > limit {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(size).map_err(|_| invalid())?);
    file.read_to_end(&mut bytes)
        .map_err(|error| io_error(&error))?;
    Ok(bytes)
}

struct DiscardPlaintext;
impl PlaintextSink for DiscardPlaintext {
    fn stage(&mut self, _: &[u8]) -> Result<(), AppError> {
        Ok(())
    }
    fn commit(&mut self, _: &DigestReceipt) -> Result<(), AppError> {
        Ok(())
    }
    fn abort(&mut self) {}
}

fn verify_extracted(
    extracted: &Extracted,
    db_key: &DbKey,
    blob_root: &BlobRootKey,
    backup_key: &BackupKey,
    mode: VerificationMode,
) -> Result<VerificationReceipt, AppError> {
    let root = &extracted.stage.root;
    let public_bytes = small_member(root, "public-format.json", 4096)?;
    let public: PublicFormat = serde_json::from_slice(&public_bytes).map_err(|_| invalid())?;
    if public.magic != "DVBK1"
        || public.format_version != 1
        || public.manifest_version != 1
        || public.manifest_algorithm != "HKDF-SHA-256+XChaCha20-Poly1305"
        || Uuid::parse_str(&public.backup_id).is_err()
    {
        return Err(invalid());
    }
    let header_bytes = small_member(root, "vault.header", 16_384)?;
    let vault_header = header::parse(&header_bytes).map_err(|_| invalid())?;
    let encrypted_manifest = small_member(root, "manifest.enc", MAX_SMALL_MEMBER)?;
    let manifest = decrypt_manifest(
        &encrypted_manifest,
        &public_bytes,
        &public.backup_id,
        backup_key,
    )?;
    if manifest.backup_id != public.backup_id
        || manifest.vault_id != vault_header.vault_id
        || manifest.format_version != 1
        || manifest.schema_version == 0
        || manifest.schema_version > migrations::CURRENT_SCHEMA_VERSION
        || manifest.members.len() + 1 != extracted.observed.len()
    {
        return Err(invalid());
    }
    let mut listed = BTreeMap::new();
    for member in &manifest.members {
        if member.path == "manifest.enc"
            || !valid_member_name(&member.path)
            || listed.insert(member.path.clone(), member.clone()).is_some()
        {
            return Err(invalid());
        }
    }
    let observed: BTreeMap<_, _> = extracted
        .observed
        .iter()
        .filter(|(path, _)| path.as_str() != "manifest.enc")
        .map(|(path, member)| (path.clone(), member.clone()))
        .collect();
    if listed != observed {
        return Err(invalid());
    }
    let db = database::open_snapshot_readonly(&root.join("metadata.db.snapshot"), db_key)
        .map_err(|_| invalid())?;
    database::integrity(&db).map_err(|_| invalid())?;
    let version: u32 = db
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| invalid())?;
    migrations::validate_history(&db, version).map_err(|_| invalid())?;
    if version != manifest.schema_version {
        return Err(invalid());
    }
    let blobs = snapshot_blobs(&db)?;
    let count = blobs.len() as u64;
    let logical_bytes = blobs.iter().try_fold(0u64, |sum, (_, receipt)| {
        sum.checked_add(receipt.size_bytes).ok_or_else(invalid)
    })?;
    if count != manifest.canonical_blob_count
        || logical_bytes != manifest.canonical_logical_bytes
        || observed.len() != blobs.len() + 3
    {
        return Err(invalid());
    }
    for (id, receipt) in &blobs {
        let name = format!("blobs/{id}.dvb");
        if !observed.contains_key(&name) {
            return Err(invalid());
        }
        if mode == VerificationMode::Full {
            let mut file = File::open(stage_path(root, &name)?).map_err(|_| invalid())?;
            let id_bytes = Uuid::parse_str(id).map_err(|_| invalid())?.into_bytes();
            decrypt(
                &mut file,
                &blob_root.for_blob(&id_bytes).map_err(|_| invalid())?,
                &id_bytes,
                Some(receipt),
                &mut DiscardPlaintext,
            )
            .map_err(|_| invalid())?;
        }
    }
    Ok(VerificationReceipt {
        backup_id: public.backup_id,
        mode,
        canonical_blob_count: count,
    })
}

fn verify_with_keys(
    archive: &Path,
    db_key: &DbKey,
    blob_root: &BlobRootKey,
    backup_key: &BackupKey,
    mode: VerificationMode,
) -> Result<VerificationReceipt, AppError> {
    let stage = std::env::temp_dir().join(format!("dvm-g3-verify-{}", Uuid::new_v4()));
    let extracted = extract_to_stage(archive, stage)?;
    verify_extracted(&extracted, db_key, blob_root, backup_key, mode)
}

/// Verifies a portable archive using a trusted passphrase or recovery credential.
/// # Errors
/// Authentication, structure, `SQLCipher`, or blob failure never yields a receipt.
pub fn verify_backup(
    archive: &Path,
    credential: &UnlockCredential,
    mode: VerificationMode,
) -> Result<VerificationReceipt, AppError> {
    let stage = std::env::temp_dir().join(format!("dvm-g3-verify-{}", Uuid::new_v4()));
    let extracted = extract_to_stage(archive, stage)?;
    let header_bytes = small_member(&extracted.stage.root, "vault.header", 16_384)?;
    let vmk = unlock_backup_header(&header_bytes, credential)?;
    let (db_key, blob_root) = vmk.storage_keys()?;
    let (_, backup_key) = vmk.auxiliary_keys()?;
    verify_extracted(&extracted, &db_key, &blob_root, &backup_key, mode)
}

/// Restores only to an absent destination, using a same-volume sibling stage.
/// FULL verification and a normal production unlock precede activation.
/// # Errors
/// Invalid archives and destination conflicts never create a final vault.
pub fn restore_backup(
    archive: &Path,
    destination: &Path,
    credential: &UnlockCredential,
    credentials: Arc<dyn CredentialStore>,
) -> Result<VerificationReceipt, AppError> {
    match fs::symlink_metadata(destination) {
        Ok(_) => return Err(AppError::new(ErrorCode::RestoreConflict)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(&error)),
    }
    let parent = fs::canonicalize(destination.parent().ok_or_else(invalid)?)
        .map_err(|error| io_error(&error))?;
    let destination = parent.join(destination.file_name().ok_or_else(invalid)?);
    let staging = parent.join(format!(".dvm-restore-{}.stage", Uuid::new_v4()));
    #[cfg(test)]
    checkpoint("restore_before_stage");
    let mut extracted = extract_to_stage(archive, staging)?;
    #[cfg(test)]
    checkpoint("restore_after_extraction");
    let header_bytes = small_member(&extracted.stage.root, "vault.header", 16_384)?;
    let vmk = unlock_backup_header(&header_bytes, credential)?;
    let (db_key, blob_root) = vmk.storage_keys()?;
    let (_, backup_key) = vmk.auxiliary_keys()?;
    verify_extracted(
        &extracted,
        &db_key,
        &blob_root,
        &backup_key,
        VerificationMode::Structural,
    )?;
    #[cfg(test)]
    checkpoint("restore_after_structural");
    let verified = verify_extracted(
        &extracted,
        &db_key,
        &blob_root,
        &backup_key,
        VerificationMode::Full,
    )?;
    #[cfg(test)]
    checkpoint("restore_after_full");
    fs::remove_file(extracted.stage.root.join("public-format.json"))
        .map_err(|error| io_error(&error))?;
    fs::remove_file(extracted.stage.root.join("manifest.enc")).map_err(|error| io_error(&error))?;
    fs::rename(
        extracted.stage.root.join("metadata.db.snapshot"),
        extracted.stage.root.join("metadata.db"),
    )
    .map_err(|error| io_error(&error))?;
    for directory in ["tmp", "quarantine", "indexes/vector", "local-state"] {
        fs::create_dir_all(extracted.stage.root.join(directory))
            .map_err(|error| io_error(&error))?;
    }
    for lock in ["owner.lock", "keyslots.lock"] {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(extracted.stage.root.join("local-state").join(lock))
            .map_err(|error| io_error(&error))?;
        file.sync_all().map_err(|error| io_error(&error))?;
    }
    let protected = ProtectedVault::select(&extracted.stage.root, credentials)?;
    let active = protected.unlock(credential)?;
    if ProtectedVault::health(&active) != ReconciliationHealth::Healthy {
        return Err(invalid());
    }
    drop(active);
    drop(protected);
    OpenOptions::new()
        .write(true)
        .open(extracted.stage.root.join("metadata.db"))
        .and_then(|file| file.sync_all())
        .map_err(|error| io_error(&error))?;
    #[cfg(test)]
    checkpoint("restore_before_activation");
    activate_directory_noreplace(&extracted.stage.root, &destination)
        .map_err(|error| activation_error(&error))?;
    extracted.stage.activated = true;
    #[cfg(test)]
    checkpoint("restore_after_activation");
    #[cfg(test)]
    checkpoint("restore_before_success_response");
    Ok(verified)
}
