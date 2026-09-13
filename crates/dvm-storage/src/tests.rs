//! G1 tests, including real child-process termination. Entire module is cfg(test).
#![allow(clippy::too_many_lines)]
use crate::Vault;
use dvm_crypto::{CHUNK_SIZE, DigestReceipt, PlaintextSink, VaultMasterKey, dvb1::sha256};
use dvm_domain::{
    AppError, ErrorCode,
    storage::{ImportRepository, JobRepository, ReconciliationHealth},
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
};
use uuid::Uuid;
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const NOW: u64 = 4_000_000_000;

pub(crate) fn checkpoint(name: &str) {
    if std::env::var("DVM_G1_TEST_CHECKPOINT").is_ok_and(|point| point == name) {
        println!("CHECKPOINT {name}");
        std::process::exit(91); // Real process termination without Rust destructors.
    }
}
pub(crate) struct ChunkCheckpointWriter<'a> {
    output: &'a mut File,
    written: usize,
}
impl<'a> ChunkCheckpointWriter<'a> {
    pub(crate) fn new(output: &'a mut File) -> Self {
        Self { output, written: 0 }
    }
}
impl Write for ChunkCheckpointWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let count = self.output.write(buffer)?;
        self.written += count;
        if self.written >= 68 + 12 + CHUNK_SIZE + 16 {
            checkpoint("C3");
        }
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self, std::io::Error> {
        let root = std::env::temp_dir().join(format!("dvm-g1-test-{}", Uuid::new_v4()));
        fs::create_dir(&root)?;
        Ok(Self { root })
    }
    fn vault_path(&self) -> PathBuf {
        self.root.join("vault")
    }
    fn source(&self, bytes: &[u8]) -> Result<PathBuf, std::io::Error> {
        let path = self.root.join("Private Photos amintire șárga secretă.jpg");
        fs::write(&path, bytes)?;
        Ok(path)
    }
    fn create(&self) -> Result<Vault, AppError> {
        Vault::create_with_injected_key(&self.vault_path(), &key())
    }
    fn reopen(&self) -> Result<Vault, AppError> {
        Vault::open_with_injected_key(&self.vault_path(), &key(), NOW)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Delete only this uniquely generated fixture root, never a caller-supplied path.
        if self.root.parent() == Some(std::env::temp_dir().as_path())
            && self
                .root
                .file_name()
                .is_some_and(|s| s.to_string_lossy().starts_with("dvm-g1-test-"))
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
fn key() -> VaultMasterKey {
    VaultMasterKey::from_injected_bytes(Zeroizing::new([11; 32]))
}
fn count(vault: &Vault, table: &str) -> Result<i64, AppError> {
    vault
        .db()?
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .map_err(|error| crate::database::db_error(&error))
}
fn canonical(vault: &Vault, id: &str) -> PathBuf {
    vault.root.join("blobs").join(format!("{id}.dvb"))
}
fn status(vault: &Vault, id: &str) -> Result<String, AppError> {
    vault
        .db()?
        .query_row("SELECT status FROM jobs WHERE id=?1", [id], |r| r.get(0))
        .map_err(|error| crate::database::db_error(&error))
}

#[derive(Default)]
struct BytesSink {
    staged: Vec<u8>,
    committed: Vec<u8>,
    aborted: bool,
}
impl PlaintextSink for BytesSink {
    fn stage(&mut self, chunk: &[u8]) -> Result<(), AppError> {
        self.staged.extend_from_slice(chunk);
        Ok(())
    }
    fn commit(&mut self, _: &DigestReceipt) -> Result<(), AppError> {
        self.committed = std::mem::take(&mut self.staged);
        Ok(())
    }
    fn abort(&mut self) {
        self.staged.clear();
        self.committed.clear();
        self.aborted = true;
    }
}

#[test]
fn encrypted_sqlcipher_reopen_wrong_key_and_live_wal() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    println!("SQLCIPHER {:?}", vault.cipher);
    // Regression: optional global locking recurses in the Windows warning logger
    // when VirtualLock reaches its quota. Cryptographic allocations still wipe.
    let global_memory_security: String =
        vault
            .db()?
            .pragma_query_value(None, "cipher_memory_security", |row| row.get(0))?;
    assert_eq!(global_memory_security, "0");
    let sentinel = "G1_AT_REST_SENTINEL_UNIQUE_RECOGNIZABLE";
    vault.db()?.execute_batch(
        "PRAGMA wal_autocheckpoint=0; CREATE TABLE g1_sentinel(value TEXT NOT NULL);",
    )?;
    vault.db()?.execute(
        "INSERT INTO g1_sentinel VALUES (?1)",
        [sentinel.repeat(200)],
    )?;
    for path in [
        vault.root.join("metadata.db"),
        vault.root.join("metadata.db-wal"),
    ] {
        let bytes = fs::read(path)?;
        assert!(
            !bytes
                .windows(sentinel.len())
                .any(|w| w == sentinel.as_bytes())
        );
        assert!(!bytes.starts_with(b"SQLite format 3"));
    }
    crate::database::integrity(&*vault.db()?)?;
    drop(vault);
    let wrong = VaultMasterKey::from_injected_bytes(Zeroizing::new([12; 32]));
    let before = fs::read(fixture.vault_path().join("metadata.db"))?;
    assert!(
        !before
            .windows(sentinel.len())
            .any(|window| window == sentinel.as_bytes())
    );
    assert_eq!(
        Vault::open_with_injected_key(&fixture.vault_path(), &wrong, NOW)
            .err()
            .ok_or("wrong key accepted")?
            .code,
        ErrorCode::CorruptDatabase
    );
    assert_eq!(before, fs::read(fixture.vault_path().join("metadata.db"))?);
    let reopened = fixture.reopen()?;
    let value: String = reopened
        .db()?
        .query_row("SELECT value FROM g1_sentinel", [], |r| r.get(0))?;
    assert_eq!(value, sentinel.repeat(200));
    assert_eq!(reopened.cipher.journal_mode, "wal");
    Ok(())
}

#[test]
fn schema_identity_foreign_keys_and_future_version_refusal() -> TestResult {
    // Schema checksum must bind identical bytes in Windows and clean checkouts.
    assert!(!crate::database::SCHEMA.contains('\r'));
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    assert!(vault.db()?.execute("INSERT INTO item_blobs(item_id,blob_id,role) VALUES ('missing','missing','ORIGINAL')",[]).is_err());
    assert_eq!(
        vault
            .db()?
            .pragma_query_value(None, "foreign_keys", |r| r.get::<_, i64>(0))?,
        1
    );
    vault.db()?.pragma_update(None, "user_version", 99)?;
    drop(vault);
    let before = fs::read(fixture.vault_path().join("metadata.db"))?;
    assert_eq!(
        fixture.reopen().err().ok_or("future schema accepted")?.code,
        ErrorCode::MigrationRequired
    );
    assert_eq!(before, fs::read(fixture.vault_path().join("metadata.db"))?);
    Ok(())
}

#[test]
fn restart_recovers_exact_original_and_encrypted_private_metadata() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    let source = vec![31; CHUNK_SIZE + 1];
    let path = fixture.source(&source)?;
    let imported = dvm_application::storage::import(&vault, &path)?;
    assert_eq!(imported.sha256_hex, sha256(&source));
    assert_eq!(count(&vault, "blobs")?, 1);
    assert_eq!(count(&vault, "items")?, 1);
    assert_eq!(count(&vault, "item_blobs")?, 1);
    assert_eq!(count(&vault, "jobs")?, 1);
    let rel = canonical(&vault, &imported.blob_id);
    assert!(!rel.to_string_lossy().contains(&imported.sha256_hex));
    assert!(!rel.to_string_lossy().contains("Private Photos"));
    assert!(fs::read_dir(vault.root.join("tmp"))?.next().is_none());
    drop(vault);
    let vault = fixture.reopen()?;
    let mut sink = BytesSink::default();
    let recovered = vault.recover(&imported.blob_id, &mut sink)?;
    assert_eq!(sink.committed, source);
    assert_eq!(recovered.sha256_hex, imported.sha256_hex);
    assert_eq!(recovered.size_bytes, source.len() as u64);
    println!(
        "RESTART_RECOVERY source=stored=recovered SHA256 {} bytes {}",
        recovered.sha256_hex, recovered.size_bytes
    );
    Ok(())
}

#[test]
fn identical_and_concurrent_imports_share_one_immutable_blob() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = Arc::new(fixture.create()?);
    let path = fixture.source(&[1, 2, 3, 4])?;
    let first = dvm_application::storage::import(vault.as_ref(), &path)?;
    let before = fs::read(canonical(&vault, &first.blob_id))?;
    let second = dvm_application::storage::import(vault.as_ref(), &path)?;
    assert_ne!(first.item_id, second.item_id);
    assert_eq!(first.blob_id, second.blob_id);
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let vault = Arc::clone(&vault);
            let path = path.clone();
            std::thread::spawn(move || dvm_application::storage::import(vault.as_ref(), &path))
        })
        .collect();
    for thread in threads {
        assert_eq!(
            thread.join().map_err(|_| "thread panic")??.blob_id,
            first.blob_id
        );
    }
    assert_eq!(count(&vault, "blobs")?, 1);
    assert_eq!(count(&vault, "items")?, 4);
    assert_eq!(count(&vault, "item_blobs")?, 4);
    assert_eq!(fs::read_dir(vault.root.join("blobs"))?.count(), 1);
    assert_eq!(fs::read(canonical(&vault, &first.blob_id))?, before);
    Ok(())
}

#[test]
fn same_hash_different_size_is_integrity_failure() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    let path = fixture.source(&[4, 5, 6])?;
    let first = dvm_application::storage::import(&vault, &path)?;
    vault.db()?.execute(
        "UPDATE blobs SET size_bytes=size_bytes+1 WHERE id=?1",
        [first.blob_id],
    )?;
    assert_eq!(
        dvm_application::storage::import(&vault, &path)
            .err()
            .ok_or("anomaly accepted")?
            .code,
        ErrorCode::CorruptDatabase
    );
    assert_eq!(count(&vault, "items")?, 1);
    assert_eq!(count(&vault, "blobs")?, 1);
    Ok(())
}

#[test]
fn concurrent_first_imports_commit_only_one_canonical_blob() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = Arc::new(fixture.create()?);
    let source = fixture.source(&[1, 5, 9, 3])?;
    let staged_together = Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let vault = Arc::clone(&vault);
            let barrier = Arc::clone(&staged_together);
            let source = source.clone();
            std::thread::spawn(move || {
                let staged = vault.stage_import(&source);
                barrier.wait();
                vault.commit_import(staged?)
            })
        })
        .collect();
    let receipts = workers
        .into_iter()
        .map(|worker| {
            worker
                .join()
                .map_err(|_| "worker panic")?
                .map_err(Into::into)
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    assert_eq!(receipts[0].blob_id, receipts[1].blob_id);
    assert_ne!(receipts[0].item_id, receipts[1].item_id);
    assert_eq!(count(&vault, "blobs")?, 1);
    assert_eq!(count(&vault, "items")?, 2);
    assert_eq!(count(&vault, "item_blobs")?, 2);
    assert_eq!(fs::read_dir(vault.root.join("blobs"))?.count(), 1);
    assert_eq!(fs::read_dir(vault.root.join("tmp"))?.count(), 0);
    drop(vault);
    let vault = fixture.reopen()?;
    let mut sink = BytesSink::default();
    vault.recover(&receipts[0].blob_id, &mut sink)?;
    assert_eq!(sink.committed, [1, 5, 9, 3]);
    Ok(())
}

#[test]
fn failed_insert_and_deferred_constraint_commit_never_succeed() -> TestResult {
    for failure in [
        "CREATE TRIGGER reject_item BEFORE INSERT ON items BEGIN SELECT RAISE(ABORT,'injected'); END;",
        "CREATE TABLE failure_parent(id TEXT PRIMARY KEY); CREATE TABLE failure_child(id TEXT REFERENCES failure_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_commit AFTER INSERT ON items BEGIN INSERT INTO failure_child VALUES ('missing'); END;",
    ] {
        let fixture = Fixture::new()?;
        let vault = fixture.create()?;
        let path = fixture.source(&[1, 9, 5])?;
        vault.db()?.execute_batch(failure)?;
        assert!(dvm_application::storage::import(&vault, &path).is_err());
        for table in ["items", "blobs", "item_blobs", "jobs"] {
            assert_eq!(count(&vault, table)?, 0);
        }
        drop(vault);
        let vault = fixture.reopen()?;
        assert_eq!(vault.reconciliation.quarantined_orphans, 1);
        assert_eq!(fs::read_dir(vault.root.join("quarantine"))?.count(), 1);
    }
    Ok(())
}

#[test]
fn missing_mutated_truncated_and_substituted_originals_fail_closed() -> TestResult {
    for mutation in ["missing", "flip", "truncate", "swap"] {
        let fixture = Fixture::new()?;
        let vault = fixture.create()?;
        let path = fixture.source(&vec![3; CHUNK_SIZE + 1])?;
        let first = dvm_application::storage::import(&vault, &path)?;
        let stored = canonical(&vault, &first.blob_id);
        match mutation {
            "missing" => fs::remove_file(&stored)?,
            "flip" => {
                let mut bytes = fs::read(&stored)?;
                bytes[80] ^= 1;
                fs::write(&stored, bytes)?;
            }
            "truncate" => {
                fs::OpenOptions::new()
                    .write(true)
                    .open(&stored)?
                    .set_len(90)?;
            }
            _ => {
                let second =
                    dvm_application::storage::import(&vault, &fixture.source(&[7, 8, 9])?)?;
                fs::copy(canonical(&vault, &second.blob_id), &stored)?;
            }
        }
        let mut sink = BytesSink::default();
        let error = vault
            .recover(&first.blob_id, &mut sink)
            .err()
            .ok_or("corruption accepted")?;
        assert_eq!(
            error.code,
            if mutation == "missing" {
                ErrorCode::MissingBlob
            } else {
                ErrorCode::BlobAuthFailed
            }
        );
        assert!(sink.committed.is_empty() && sink.staged.is_empty() && sink.aborted);
        drop(vault);
        let vault = fixture.reopen()?;
        assert_eq!(
            vault.reconciliation.health,
            ReconciliationHealth::RepairRequired
        );
        let item_status: String = vault.db()?.query_row(
            "SELECT status FROM items WHERE id=?1",
            [first.item_id],
            |r| r.get(0),
        )?;
        assert_eq!(item_status, "CORRUPTED");
    }
    Ok(())
}

#[test]
fn durable_jobs_lease_recovery_retries_terminal_and_replay() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    dvm_application::storage::import(&vault, &fixture.source(&[8, 2, 5])?)?;
    drop(vault);
    let vault = fixture.reopen()?;
    let lease = vault.claim_job(NOW, 60)?.ok_or("no job")?;
    assert_eq!(lease.attempt, 1);
    assert_eq!(status(&vault, &lease.id)?, "PROCESSING");
    assert!(vault.claim_job(NOW, 60)?.is_none());
    drop(vault);
    let vault = fixture.reopen()?;
    assert_eq!(status(&vault, &lease.id)?, "PROCESSING");
    drop(vault);
    let vault = Vault::open_with_injected_key(&fixture.vault_path(), &key(), NOW + 61)?;
    assert_eq!(status(&vault, &lease.id)?, "PENDING");
    let second = vault.claim_job(NOW + 61, 60)?.ok_or("no retry")?;
    assert_eq!(second.attempt, 2);
    assert!(vault.complete_job(&lease, NOW + 61).is_err());
    vault.complete_job(&second, NOW + 61)?;
    vault.complete_job(&second, NOW + 62)?;
    assert_eq!(status(&vault, &second.id)?, "DONE");
    assert_eq!(count(&vault, "blobs")?, 1);
    dvm_application::storage::import(&vault, &fixture.source(&[9, 2, 5])?)?;
    let mut now = NOW + 100;
    for attempt in 1..=5 {
        let lease = vault.claim_job(now, 60)?.ok_or("retry missing")?;
        assert_eq!(lease.attempt, attempt);
        vault.fail_job(&lease, now, true)?;
        assert_eq!(
            status(&vault, &lease.id)?,
            if attempt < 5 {
                "PENDING"
            } else {
                "FAILED_TERMINAL"
            }
        );
        assert!(vault.claim_job(now, 60)?.is_none());
        now += 600;
    }
    Ok(())
}

#[test]
fn job_result_commit_failure_is_not_done_and_rolls_back_result() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    let receipt = dvm_application::storage::import(&vault, &fixture.source(&[7, 1, 3])?)?;
    let lease = vault.claim_job(NOW, 60)?.ok_or("no job")?;
    let before: String = vault.db()?.query_row(
        "SELECT verified_at FROM blobs WHERE id=?1",
        [receipt.blob_id.clone()],
        |r| r.get(0),
    )?;
    vault.db()?.execute_batch("CREATE TRIGGER reject_done BEFORE UPDATE OF status ON jobs WHEN NEW.status='DONE' BEGIN SELECT RAISE(ABORT,'injected'); END;")?;
    assert!(vault.complete_job(&lease, NOW).is_err());
    assert_eq!(status(&vault, &lease.id)?, "PROCESSING");
    let after: String = vault.db()?.query_row(
        "SELECT verified_at FROM blobs WHERE id=?1",
        [receipt.blob_id],
        |r| r.get(0),
    )?;
    assert_eq!(before, after);
    Ok(())
}

#[test]
fn payload_idempotency_cancellation_and_exclusive_owner() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    assert_eq!(
        fixture.reopen().err().ok_or("second owner admitted")?.code,
        ErrorCode::VaultLocked
    );
    let receipt = dvm_application::storage::import(&vault, &fixture.source(&[3, 1, 8])?)?;
    assert!(
        crate::jobs::enqueue_verification(&*vault.db()?, &receipt.item_id, &receipt.blob_id)
            .is_err()
    );
    let (id, payload): (String, String) =
        vault
            .db()?
            .query_row("SELECT id,payload_json FROM jobs", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&payload)?
            .as_object()
            .ok_or("not object")?
            .len(),
        2
    );
    assert!(payload.len() < 256);
    assert!(!payload.contains("Private"));
    vault.cancel_pending_job(&id)?;
    assert_eq!(status(&vault, &id)?, "CANCELLED");
    assert!(vault.claim_job(NOW, 60)?.is_none());
    Ok(())
}

#[test]
#[ignore = "only invoked as a named child of the crash matrix"]
fn crash_child() -> TestResult {
    let root = PathBuf::from(std::env::var("DVM_G1_TEST_ROOT")?);
    let source = PathBuf::from(std::env::var("DVM_G1_TEST_SOURCE")?);
    let mut bytes = Zeroizing::new([0; 32]);
    std::io::stdin().read_exact(bytes.as_mut())?;
    let key = VaultMasterKey::from_injected_bytes(bytes);
    let vault = Vault::open_with_injected_key(&root, &key, NOW)?;
    let receipt = dvm_application::storage::import(&vault, &source)?;
    if std::env::var("DVM_G1_TEST_CHECKPOINT")? == "JOB_COMMIT" {
        let lease = vault.claim_job(NOW, 60)?.ok_or("missing child job")?;
        vault.complete_job(&lease, NOW)?;
    }
    println!("IMPORT_SUCCESS {}", receipt.item_id);
    Err("checkpoint not reached".into())
}

#[test]
fn real_process_crash_matrix_c1_through_c8_and_job_commit() -> TestResult {
    for point in ["C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "JOB_COMMIT"] {
        let fixture = Fixture::new()?;
        drop(fixture.create()?);
        let source = vec![13; CHUNK_SIZE + 1];
        let path = fixture.source(&source)?;
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--exact", "tests::crash_child", "--ignored", "--nocapture"])
            .env("DVM_G1_TEST_ROOT", fixture.vault_path())
            .env("DVM_G1_TEST_SOURCE", path)
            .env("DVM_G1_TEST_CHECKPOINT", point)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or("missing child stdin")?
            .write_all(&[11; 32])?;
        let output = child.wait_with_output()?;
        assert_eq!(
            output.status.code(),
            Some(91),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("IMPORT_SUCCESS"));
        assert!(String::from_utf8_lossy(&output.stdout).contains(&format!("CHECKPOINT {point}")));
        let vault = Vault::open_with_injected_key(&fixture.vault_path(), &key(), NOW + 100)?;
        let committed = matches!(point, "C8" | "JOB_COMMIT");
        for table in ["blobs", "items", "item_blobs", "jobs"] {
            assert_eq!(
                count(&vault, table)?,
                i64::from(committed),
                "{point} {table}"
            );
        }
        assert_eq!(
            fs::read_dir(vault.root.join("blobs"))?.count(),
            usize::from(committed)
        );
        assert_eq!(fs::read_dir(vault.root.join("tmp"))?.count(), 0);
        if matches!(point, "C6" | "C7") {
            assert_eq!(vault.reconciliation.quarantined_orphans, 1);
        }
        if matches!(point, "C2" | "C3" | "C4" | "C5") {
            assert_eq!(vault.reconciliation.quarantined_staging, 1);
        }
        if committed {
            let id: String = vault
                .db()?
                .query_row("SELECT id FROM blobs", [], |r| r.get(0))?;
            let mut sink = BytesSink::default();
            vault.recover(&id, &mut sink)?;
            assert_eq!(sink.committed, source);
            if point == "JOB_COMMIT" {
                let job_status: String =
                    vault
                        .db()?
                        .query_row("SELECT status FROM jobs", [], |r| r.get(0))?;
                assert_eq!(job_status, "PENDING");
            }
        }
        println!("CRASH {point} PASS committed={committed} no_false_success=true");
    }
    Ok(())
}

#[test]
fn private_paths_never_cross_storage_error_or_diagnostic_boundary() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    let private = fixture
        .root
        .join("Private Photos")
        .join("amintire șárga secretă.jpg");
    let error = dvm_application::storage::import(&vault, &private)
        .err()
        .ok_or("missing source succeeded")?;
    assert_eq!(error.code, ErrorCode::SourceUnreadable);
    let serialized = serde_json::to_string(&error)?;
    let diagnostic = dvm_observability::storage_failure(&error).to_json_line();
    for output in [&serialized, &diagnostic] {
        assert!(!output.contains("Private"));
        assert!(!output.contains("amintire"));
        assert!(!output.contains("secret"));
    }
    let internal =
        AppError::new(ErrorCode::SourceUnreadable).with_safe_details(private.to_string_lossy());
    assert!(
        !dvm_observability::storage_failure(&internal)
            .to_json_line()
            .contains("Private")
    );
    Ok(())
}

#[test]
fn exhausted_expired_lease_becomes_terminal() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    dvm_application::storage::import(&vault, &fixture.source(&[3])?)?;
    vault.db()?.execute("UPDATE jobs SET max_attempts=1", [])?;
    let lease = vault.claim_job(NOW, 1)?.ok_or("no lease")?;
    drop(vault);
    let vault = Vault::open_with_injected_key(&fixture.vault_path(), &key(), NOW + 2)?;
    assert_eq!(status(&vault, &lease.id)?, "FAILED_TERMINAL");
    assert!(vault.claim_job(NOW + 2, 60)?.is_none());
    Ok(())
}

#[cfg(windows)]
fn windows_measure(expression: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", expression])
        .output()?;
    if !output.status.success() {
        return Err("measurement failed".into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().parse()?)
}

#[test]
#[ignore = "mandatory local heavyweight gate; verify:g1 invokes this explicitly"]
#[cfg(windows)]
fn multi_gb_bounded_memory() -> TestResult {
    use sha2::{Digest, Sha256};
    struct CompareSink {
        source: File,
        buffer: Vec<u8>,
        count: u64,
        committed: bool,
    }
    impl PlaintextSink for CompareSink {
        fn stage(&mut self, chunk: &[u8]) -> Result<(), AppError> {
            self.source
                .read_exact(&mut self.buffer[..chunk.len()])
                .map_err(|_| AppError::new(ErrorCode::SourceUnreadable))?;
            if &self.buffer[..chunk.len()] != chunk {
                return Err(AppError::new(ErrorCode::BlobAuthFailed));
            }
            self.count += chunk.len() as u64;
            Ok(())
        }
        fn commit(&mut self, receipt: &DigestReceipt) -> Result<(), AppError> {
            let mut extra = [0];
            if self.count != receipt.size_bytes
                || self
                    .source
                    .read(&mut extra)
                    .map_err(|_| AppError::new(ErrorCode::SourceUnreadable))?
                    != 0
            {
                return Err(AppError::new(ErrorCode::BlobAuthFailed));
            }
            self.committed = true;
            Ok(())
        }
        fn abort(&mut self) {
            self.count = 0;
            self.committed = false;
        }
    }
    let size = 2 * 1024 * 1024 * 1024_u64 + CHUNK_SIZE as u64;
    let disk_expression = "(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").FreeSpace";
    let free_before = windows_measure(disk_expression)?;
    if free_before < 2 * size + 2 * 1024 * 1024 * 1024 {
        return Err("BLOCKED_BY_DISK_PRESSURE".into());
    }
    let baseline = windows_measure(&format!(
        "(Get-Process -Id {}).WorkingSet64",
        std::process::id()
    ))?;
    let started = std::time::Instant::now();
    let fixture = Fixture::new()?;
    let source_path = fixture.root.join("multi gb source.bin");
    let mut original = File::create(&source_path)?;
    let pattern: Vec<u8> = (0..CHUNK_SIZE).map(|i| i.to_le_bytes()[0]).collect();
    let mut expected_hash = Sha256::new();
    for _ in 0..size / CHUNK_SIZE as u64 {
        original.write_all(&pattern)?;
        expected_hash.update(&pattern);
    }
    original.sync_all()?;
    drop(original);
    drop(pattern);
    let source_hash = dvm_crypto::dvb1::hex(expected_hash.finalize().as_slice());
    let vault = fixture.create()?;
    let imported = dvm_application::storage::import(&vault, &source_path)?;
    assert_eq!(imported.size_bytes, size);
    assert_eq!(imported.sha256_hex, source_hash);
    drop(vault);
    let vault = fixture.reopen()?;
    let mut sink = CompareSink {
        source: File::open(&source_path)?,
        buffer: vec![0; CHUNK_SIZE],
        count: 0,
        committed: false,
    };
    let recovered = vault.recover(&imported.blob_id, &mut sink)?;
    assert!(sink.committed);
    assert_eq!(sink.count, size);
    assert_eq!(recovered.sha256_hex, source_hash);
    let peak = windows_measure(&format!(
        "(Get-Process -Id {}).PeakWorkingSet64",
        std::process::id()
    ))?;
    let free_after = windows_measure(disk_expression)?;
    println!(
        "MULTI_GB size={size} sparse=false chunk={CHUNK_SIZE} largest_buffer={} configured_crypto_buffers={} source_sha256={source_hash} recovered_sha256={} recovered_bytes={} baseline_working_set={baseline} peak_working_set={peak} incremental_estimate={} elapsed_seconds={:.3} disk_before={free_before} disk_after={free_after} BYTE_EQUALITY=PASS BOUNDED_MEMORY=PASS",
        CHUNK_SIZE + 16,
        2 * CHUNK_SIZE + 16,
        recovered.sha256_hex,
        recovered.size_bytes,
        peak.saturating_sub(baseline),
        started.elapsed().as_secs_f64()
    );
    drop(sink);
    drop(vault);
    drop(fixture);
    println!(
        "MULTI_GB fixtures removed disk_after_cleanup={}",
        windows_measure(disk_expression)?
    );
    Ok(())
}

#[test]
fn native_connection_interruption_rolls_back_import() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    let path = fixture.source(&[2, 4, 9])?;
    let staged = vault.stage_import(&path)?;
    vault.db()?.execute_batch("CREATE TRIGGER delay_item BEFORE INSERT ON items BEGIN SELECT sum(n) FROM (WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<1000000000) SELECT n FROM numbers); END;")?;
    let interrupt = vault.db()?.get_interrupt_handle();
    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let finished = Arc::clone(&completed);
    let interrupter = std::thread::spawn(move || {
        while !finished.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(10));
            interrupt.interrupt();
        }
    });
    let result = vault.commit_import(staged);
    completed.store(true, std::sync::atomic::Ordering::Relaxed);
    interrupter.join().map_err(|_| "interrupt thread panic")?;
    assert!(result.is_err());
    for table in ["items", "blobs", "item_blobs", "jobs"] {
        assert_eq!(count(&vault, table)?, 0);
    }
    Ok(())
}

#[test]
fn nonretryable_job_fails_terminal_and_schema_checksum_tampering_is_rejected() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    dvm_application::storage::import(&vault, &fixture.source(&[2, 3, 4])?)?;
    let lease = vault.claim_job(NOW, 60)?.ok_or("missing job")?;
    vault.fail_job(&lease, NOW, false)?;
    assert_eq!(status(&vault, &lease.id)?, "FAILED_TERMINAL");
    vault
        .db()?
        .execute("UPDATE schema_migrations SET checksum='tampered'", [])?;
    drop(vault);
    assert_eq!(
        fixture.reopen().err().ok_or("checksum accepted")?.code,
        ErrorCode::MigrationFailed
    );
    Ok(())
}

#[test]
fn application_job_use_case_commits_one_result() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    assert!(!dvm_application::storage::run_one_job(&vault, NOW)?);
    dvm_application::storage::import(&vault, &fixture.source(&[1, 4, 7])?)?;
    assert!(dvm_application::storage::run_one_job(&vault, NOW)?);
    assert!(!dvm_application::storage::run_one_job(&vault, NOW)?);
    let done: i64 =
        vault
            .db()?
            .query_row("SELECT count(*) FROM jobs WHERE status='DONE'", [], |r| {
                r.get(0)
            })?;
    assert_eq!(done, 1);
    Ok(())
}

#[test]
fn header_and_ciphertext_database_corruption_fail_closed() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    dvm_application::storage::import(&vault, &fixture.source(&[9, 4, 7])?)?;
    drop(vault);
    let database = fixture.vault_path().join("metadata.db");
    let mut bytes = fs::read(&database)?;
    bytes[100] ^= 1;
    fs::write(&database, bytes)?;
    assert_eq!(
        fixture.reopen().err().ok_or("DB corruption accepted")?.code,
        ErrorCode::CorruptDatabase
    );
    fs::write(fixture.vault_path().join("vault.header"), b"{truncated")?;
    assert_eq!(
        fixture
            .reopen()
            .err()
            .ok_or("header corruption accepted")?
            .code,
        ErrorCode::CorruptHeader
    );
    Ok(())
}

#[test]
fn deferred_job_commit_failure_rolls_back_done_and_verified_at() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = fixture.create()?;
    let imported = dvm_application::storage::import(&vault, &fixture.source(&[3, 8, 2])?)?;
    let lease = vault.claim_job(NOW, 60)?.ok_or("no lease")?;
    let before: String = vault.db()?.query_row(
        "SELECT verified_at FROM blobs WHERE id=?1",
        [&imported.blob_id],
        |row| row.get(0),
    )?;
    vault.db()?.execute_batch("CREATE TABLE job_failure_parent(id TEXT PRIMARY KEY); CREATE TABLE job_failure_child(id TEXT REFERENCES job_failure_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_job_commit AFTER UPDATE OF status ON jobs WHEN NEW.status='DONE' BEGIN INSERT INTO job_failure_child VALUES ('missing'); END;")?;
    assert!(vault.complete_job(&lease, NOW).is_err());
    assert_eq!(status(&vault, &lease.id)?, "PROCESSING");
    let after: String = vault.db()?.query_row(
        "SELECT verified_at FROM blobs WHERE id=?1",
        [&imported.blob_id],
        |row| row.get(0),
    )?;
    assert_eq!(before, after);
    assert_eq!(count(&vault, "job_failure_child")?, 0);
    Ok(())
}
