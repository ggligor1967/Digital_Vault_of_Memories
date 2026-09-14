//! Real G2 storage/credential oracles. Only synthetic data and owned test roots.
#![allow(clippy::too_many_lines)]
use super::*;
#[cfg(windows)]
use dvm_application::provider_secrets::ProviderSecretStore;
use dvm_application::session::VaultSession;
use dvm_domain::security::VaultState;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) fn crash_point(point: &str) {
    if std::env::var("DVM_G2_CRASH_POINT").is_ok_and(|p| p == point) {
        std::process::exit(91);
    }
}

#[test]
fn keyslot_crash_child() -> TestResult {
    let Ok(root) = std::env::var("DVM_G2_CRASH_ROOT") else {
        return Ok(());
    };
    let backend = ProtectedVault::select(Path::new(&root), Arc::new(MemoryStore::default()))?;
    let active = backend.unlock(&input("original phrase")?)?;
    active.change_passphrase(
        &pass("original phrase")?,
        &pass("new phrase")?,
        ArgonProfile::BASELINE,
    )?;
    Err("checkpoint was not reached".into())
}

#[test]
fn abrupt_process_crash_header_activation_matrix() -> TestResult {
    for (point, activated) in ACTIVATION_MATRIX {
        let f = Fixture::new()?;
        let (backend, recovery) = create(&f, Arc::new(MemoryStore::default()))?;
        let before = fs::read(f.root().join("vault.header"))?;
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "security::tests::keyslot_crash_child",
                "--exact",
                "--nocapture",
            ])
            .env("DVM_G2_CRASH_ROOT", f.root())
            .env("DVM_G2_CRASH_POINT", point)
            .status()?;
        assert_eq!(status.code(), Some(91));
        if activated {
            drop(backend.unlock(&input("new phrase")?)?);
            assert!(backend.unlock(&input("original phrase")?).is_err());
        } else {
            assert!(before == fs::read(f.root().join("vault.header"))?);
            drop(backend.unlock(&input("original phrase")?)?);
        }
        drop(backend.unlock(&UnlockCredential::Recovery(recovery))?);
    }
    println!("G2_PROCESS_CRASH_HEADER_MATRIX=PASS");
    Ok(())
}

#[derive(Default)]
struct MemoryStore(Mutex<BTreeMap<String, SecretValue>>);
impl CredentialStore for MemoryStore {
    fn store(&self, reference: &str, value: &SecretValue) -> Result<(), AppError> {
        self.0
            .lock()
            .map_err(|_| AppError::new(ErrorCode::Internal))?
            .insert(
                reference.into(),
                SecretValue::new(Zeroizing::new(value.as_bytes().to_vec()))?,
            );
        Ok(())
    }
    fn retrieve(&self, reference: &str) -> Result<Option<SecretValue>, AppError> {
        self.0
            .lock()
            .map_err(|_| AppError::new(ErrorCode::Internal))?
            .get(reference)
            .map(|v| SecretValue::new(Zeroizing::new(v.as_bytes().to_vec())))
            .transpose()
    }
    fn delete(&self, reference: &str) -> Result<(), AppError> {
        self.0
            .lock()
            .map_err(|_| AppError::new(ErrorCode::Internal))?
            .remove(reference);
        Ok(())
    }
}
struct Fixture {
    base: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self, std::io::Error> {
        let base = std::env::temp_dir().join(format!("dvm-g2-{}", Uuid::new_v4()));
        fs::create_dir(&base)?;
        Ok(Self { base })
    }
    fn root(&self) -> PathBuf {
        self.base.join("vault")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.base.parent() == Some(std::env::temp_dir().as_path())
            && self
                .base
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("dvm-g2-"))
        {
            let _ = fs::remove_dir_all(&self.base);
        }
    }
}
fn pass(value: &str) -> Result<Passphrase, AppError> {
    Passphrase::new(Zeroizing::new(value.into()))
}
fn input(value: &str) -> Result<UnlockCredential, AppError> {
    Ok(UnlockCredential::Passphrase(pass(value)?))
}
fn snapshot(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, std::io::Error> {
    fn walk(
        base: &Path,
        path: &Path,
        result: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) -> Result<(), std::io::Error> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                walk(base, &entry.path(), result)?;
            } else {
                result.insert(
                    entry
                        .path()
                        .strip_prefix(base)
                        .map_err(std::io::Error::other)?
                        .to_path_buf(),
                    Sha256::digest(fs::read(entry.path())?).to_vec(),
                );
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result)?;
    Ok(result)
}
#[derive(Default)]
struct Sink {
    bytes: Vec<u8>,
    committed: bool,
}
impl PlaintextSink for Sink {
    fn stage(&mut self, bytes: &[u8]) -> Result<(), AppError> {
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn commit(&mut self, _: &DigestReceipt) -> Result<(), AppError> {
        self.committed = true;
        Ok(())
    }
    fn abort(&mut self) {
        self.bytes.clear();
        self.committed = false;
    }
}
fn create(
    f: &Fixture,
    store: Arc<dyn CredentialStore>,
) -> Result<(ProtectedVault, RecoverySecret), AppError> {
    let activated = ProtectedVault::create_with_policy(
        &f.root(),
        &pass("original phrase")?,
        RecoveryPolicy::default(),
        ArgonProfile::BASELINE,
        store,
    )
    .map_err(NotActivated::into_primary)?;
    assert!(activated.is_fully_settled(), "unexpected creation evidence");
    let created = activated.into_value();
    Ok((
        created.backend,
        created
            .recovery
            .ok_or_else(|| AppError::new(ErrorCode::Internal))?,
    ))
}

#[test]
fn wrong_passphrase_no_durable_mutation_and_locked_guard() -> TestResult {
    let f = Fixture::new()?;
    let store = Arc::new(MemoryStore::default());
    let (backend, _) = create(&f, store.clone())?;
    let session = VaultSession::default();
    assert_eq!(session.state()?, VaultState::Closed);
    session.attach(backend)?;
    assert_eq!(session.state()?, VaultState::Locked);
    session.unlock(&input("original phrase")?)?;
    let source = f.base.join("private name.txt");
    fs::write(&source, b"private canonical original")?;
    let receipt = session.with_open(|v| v.import(&source))?;
    session.lock()?;
    let before = snapshot(&f.root())?;
    assert_eq!(
        session
            .unlock(&input("wrong phrase")?)
            .err()
            .ok_or("must fail")?
            .code,
        ErrorCode::BadPassphrase
    );
    assert_eq!(session.state()?, VaultState::Locked);
    assert_eq!(
        session
            .with_open(|v| v.recover(&receipt.blob_id, &mut Sink::default()))
            .err()
            .ok_or("locked")?
            .code,
        ErrorCode::VaultLocked
    );
    assert!(
        before == snapshot(&f.root())?,
        "failed unlock changed durable bytes or file set"
    );
    assert!(store.0.lock().map_err(|_| "poisoned")?.is_empty());
    session.unlock(&input("original phrase")?)?;
    session.with_open(|v| {
        assert_eq!(v.vault.health(), ReconciliationHealth::Healthy);
        let mut sink = Sink::default();
        v.recover(&receipt.blob_id, &mut sink)?;
        assert!(sink.committed && sink.bytes == b"private canonical original");
        Ok(())
    })?;
    println!("WRONG_PASSPHRASE_NO_MUTATION=PASS LOCKED_ACCESS=PASS");
    Ok(())
}

#[test]
fn rewrap_corpus_preserves_storage_and_independent_slots() -> TestResult {
    let f = Fixture::new()?;
    let store = Arc::new(MemoryStore::default());
    let (backend, recovery) = create(&f, store.clone())?;
    let saved_recovery = recovery.encode_for_trusted_presentation();
    let session = VaultSession::default();
    session.attach(backend)?;
    session.unlock(&input("original phrase")?)?;
    let corpus = [
        vec![],
        b"private unicode bytes \0\xff".to_vec(),
        (0_u8..251).cycle().take(100_000).collect(),
    ];
    let mut receipts = vec![];
    for (i, bytes) in corpus.iter().enumerate() {
        let path = f.base.join(format!("private-{i}.dat"));
        fs::write(&path, bytes)?;
        receipts.push(session.with_open(|v| v.import(&path))?);
    }
    session.with_open(|v| v.enable_device().map_err(NotActivated::into_primary))?;
    let old = read_header(&f.root())?;
    let device_ref = old
        .keyslots
        .iter()
        .find(|s| s.slot_type == "device-v1")
        .ok_or("device")?
        .credential_ref
        .clone();
    session.with_open(|v| {
        let db_key = v.vmk.storage_keys()?.0;
        let blobs = snapshot(&f.root().join("blobs")).map_err(|e| io_error(&e))?;
        let db = Sha256::digest(fs::read(f.root().join("metadata.db")).map_err(|e| io_error(&e))?);
        let activated = v
            .change_passphrase(
                &pass("original phrase")?,
                &pass("changed phrase")?,
                ArgonProfile {
                    iterations: 3,
                    ..ArgonProfile::BASELINE
                },
            )
            .map_err(NotActivated::into_primary)?;
        assert!(activated.is_fully_settled(), "unexpected rewrap evidence");
        assert!(db_key.as_bytes() == v.vmk.storage_keys()?.0.as_bytes());
        assert!(blobs == snapshot(&f.root().join("blobs")).map_err(|e| io_error(&e))?);
        assert!(
            db == Sha256::digest(fs::read(f.root().join("metadata.db")).map_err(|e| io_error(&e))?)
        );
        Ok(())
    })?;
    let new = read_header(&f.root())?;
    assert!(
        old.keyslots[1..] == new.keyslots[1..],
        "independent slots changed"
    );
    session.lock()?;
    assert!(session.unlock(&input("original phrase")?).is_err());
    for credential in [
        input("changed phrase")?,
        UnlockCredential::Recovery(recovery),
        UnlockCredential::Device,
    ] {
        session.unlock(&credential)?;
        for (receipt, bytes) in receipts.iter().zip(&corpus) {
            session.with_open(|v| {
                let mut sink = Sink::default();
                v.recover(&receipt.blob_id, &mut sink)?;
                assert!(sink.committed && &sink.bytes == bytes);
                Ok(())
            })?;
        }
        session.lock()?;
    }
    assert!(
        session
            .unlock(&UnlockCredential::Recovery(RecoverySecret::generate()?))
            .is_err()
    );
    store.delete(&device_ref)?;
    let before = snapshot(&f.root())?;
    assert!(session.unlock(&UnlockCredential::Device).is_err());
    assert!(before == snapshot(&f.root())?);
    session.unlock(&input("changed phrase")?)?;
    session.lock()?;
    session.unlock(&UnlockCredential::Recovery(RecoverySecret::decode(
        saved_recovery,
    )?))?;
    session.lock()?;
    assert!(store.0.lock().map_err(|_| "poisoned")?.is_empty());
    println!("PASSPHRASE_CHANGE_REWRAP_ONLY=PASS SLOT_INDEPENDENCE=PASS KDF_UPGRADE=PASS");
    Ok(())
}

#[test]
fn default_recovery_explicit_decline_and_empty_production_rejection() -> TestResult {
    let f = Fixture::new()?;
    let created = ProtectedVault::create(
        &f.root(),
        &pass("original phrase")?,
        Arc::new(MemoryStore::default()),
    )
    .map_err(NotActivated::into_primary)?
    .into_value();
    assert_eq!(read_header(&f.root())?.keyslots.len(), 2);
    drop(created.backend.unlock(&UnlockCredential::Recovery(
        created.recovery.ok_or("recovery")?,
    ))?);
    let decline = Fixture::new()?;
    let declined = ProtectedVault::create_with_policy(
        &decline.root(),
        &pass("original phrase")?,
        RecoveryPolicy::DeclinedAfterDataLossWarning,
        ArgonProfile::BASELINE,
        Arc::new(MemoryStore::default()),
    )
    .map_err(NotActivated::into_primary)?
    .into_value();
    assert!(declined.recovery.is_none());
    assert_eq!(read_header(&decline.root())?.keyslots.len(), 1);
    let bytes = header::serialize_trusted_fixture(&header::injected_key_header())?;
    assert!(header::parse(&bytes).is_err());
    assert!(header::parse_trusted_fixture(&bytes).is_ok());
    Ok(())
}

#[test]
fn storage_corruption_degrades_session_and_blocks_further_content() -> TestResult {
    let f = Fixture::new()?;
    let (backend, recovery) = create(&f, Arc::new(MemoryStore::default()))?;
    let encoded = recovery.encode_for_trusted_presentation();
    for file in ["vault.header", "metadata.db"] {
        assert!(
            !fs::read(f.root().join(file))?
                .windows(encoded.len())
                .any(|w| w == encoded.as_bytes()),
            "recovery material persisted"
        );
    }
    let session = VaultSession::default();
    session.attach(backend)?;
    session.unlock(&input("original phrase")?)?;
    let source = f.base.join("original.dat");
    fs::write(&source, b"authenticated original")?;
    let receipt = session.with_open(|v| v.import(&source))?;
    let path = f
        .root()
        .join("blobs")
        .join(format!("{}.dvb", receipt.blob_id));
    let mut bytes = fs::read(&path)?;
    let index = bytes.len() - 1;
    bytes[index] ^= 1;
    fs::write(path, bytes)?;
    assert!(
        session
            .with_open(|v| v.recover(&receipt.blob_id, &mut Sink::default()))
            .is_err()
    );
    assert_eq!(session.state()?, VaultState::DegradedReadOnly);
    assert_eq!(
        session
            .with_open(|v| v.import(&source))
            .err()
            .ok_or("degraded")?
            .code,
        ErrorCode::VaultLocked
    );
    session.lock()?;
    assert_eq!(session.state()?, VaultState::Locked);
    Ok(())
}

#[test]
fn closed_g1_injected_fixture_remains_byte_compatible() -> TestResult {
    let f = Fixture::new()?;
    let vmk = VaultMasterKey::from_injected_bytes(Zeroizing::new([17; 32]));
    let vault = Vault::create_with_injected_key(&f.root(), &vmk)?;
    let source = f.base.join("G1 original.bin");
    fs::write(&source, b"G1 canonical compatibility\0\xff")?;
    let receipt = vault.commit_import(vault.stage_import(&source)?)?;
    let blobs = snapshot(&f.root().join("blobs"))?;
    let mut envelope = header::parse_trusted_fixture(&fs::read(f.root().join("vault.header"))?)?;
    envelope.keyslots.push(keyslots::wrap_passphrase(
        &envelope.vault_id,
        &vmk,
        &pass("original phrase")?,
        ArgonProfile::BASELINE,
    )?);
    replace_header(&f.root(), &envelope)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(f.root().join("local-state/keyslots.lock"))?
        .sync_all()?;
    drop(vault);
    let backend = ProtectedVault::select(&f.root(), Arc::new(MemoryStore::default()))?;
    let active = backend.unlock(&input("original phrase")?)?;
    let mut sink = Sink::default();
    active.recover(&receipt.blob_id, &mut sink)?;
    assert!(sink.committed && sink.bytes == fs::read(source)?);
    assert!(blobs == snapshot(&f.root().join("blobs"))?);
    assert!(vmk.storage_keys()?.0.as_bytes() == active.vmk.storage_keys()?.0.as_bytes());
    Ok(())
}

/// Every injected header-update failure, and whether it precedes activation.
const ACTIVATION_MATRIX: [(&str, bool); 6] = [
    ("before-temp", false),
    ("after-temp", false),
    ("after-sync", false),
    ("before-activation", false),
    ("after-activation", true),
    ("post-activation-sync", true),
];

#[test]
fn header_failure_matrix_separates_pre_and_post_activation() -> TestResult {
    for (point, activated) in ACTIVATION_MATRIX {
        let f = Fixture::new()?;
        let (backend, recovery) = create(&f, Arc::new(MemoryStore::default()))?;
        let active = backend.unlock(&input("original phrase")?)?;
        let source = f.base.join("private matrix.dat");
        fs::write(&source, b"private canonical matrix bytes")?;
        let receipt = active.import(&source)?;
        let vmk = active.vmk.storage_keys()?.0;
        let before = fs::read(f.root().join("vault.header"))?;
        let blobs = snapshot(&f.root().join("blobs"))?;
        let db = Sha256::digest(fs::read(f.root().join("metadata.db"))?);
        UPDATE_FAULT.with(|c| c.set(Some(point)));
        let result = active.change_passphrase(
            &pass("original phrase")?,
            &pass("new phrase")?,
            ArgonProfile::BASELINE,
        );
        UPDATE_FAULT.with(|c| c.set(None));
        // Rewrapping a keyslot never touches canonical storage either way.
        // Compared inside the live session, because reopening the vault
        // legitimately rewrites operational database state.
        assert!(blobs == snapshot(&f.root().join("blobs"))?);
        assert!(db == Sha256::digest(fs::read(f.root().join("metadata.db"))?));
        drop(active);
        if activated {
            // The new passphrase is authoritative: reporting an ordinary
            // failure here is exactly the defect this oracle detects.
            let outcome = result
                .map_err(|e| format!("{point}: committed activation reported as failure: {e}"))?;
            assert!(
                outcome.durability().uncertainty().is_some(),
                "{point}: post-activation uncertainty was not reported"
            );
            assert_eq!(*outcome.cleanup(), CleanupOutcome::NotRequired);
            assert!(
                before != fs::read(f.root().join("vault.header"))?,
                "{point}: header did not activate"
            );
            assert!(backend.unlock(&input("original phrase")?).is_err());
            let reopened = backend.unlock(&input("new phrase")?)?;
            assert!(vmk.as_bytes() == reopened.vmk.storage_keys()?.0.as_bytes());
            let mut sink = Sink::default();
            reopened.recover(&receipt.blob_id, &mut sink)?;
            assert!(sink.committed && sink.bytes == b"private canonical matrix bytes");
            drop(reopened);
        } else {
            let failure = result.err().ok_or("pre-activation failure expected")?;
            assert_eq!(failure.primary().code, ErrorCode::Internal);
            assert_eq!(*failure.cleanup(), CleanupOutcome::NotRequired);
            assert!(before == fs::read(f.root().join("vault.header"))?);
            drop(backend.unlock(&input("original phrase")?)?);
            assert!(backend.unlock(&input("new phrase")?).is_err());
        }
        assert!(blobs == snapshot(&f.root().join("blobs"))?);
        drop(backend.unlock(&UnlockCredential::Recovery(recovery))?);
    }
    println!("H1_HEADER_ACTIVATION_MATRIX=PASS H1_PASSPHRASE_COMMIT=PASS");
    Ok(())
}

#[test]
fn creation_delivers_recovery_material_once_the_header_activates() -> TestResult {
    for (point, activated) in ACTIVATION_MATRIX {
        let f = Fixture::new()?;
        UPDATE_FAULT.with(|c| c.set(Some(point)));
        let result = ProtectedVault::create_with_policy(
            &f.root(),
            &pass("original phrase")?,
            RecoveryPolicy::Generate,
            ArgonProfile::BASELINE,
            Arc::new(MemoryStore::default()),
        );
        UPDATE_FAULT.with(|c| c.set(None));
        if activated {
            let outcome = result
                .map_err(|e| format!("{point}: activated creation reported as failure: {e}"))?;
            assert!(outcome.durability().uncertainty().is_some());
            let created = outcome.into_value();
            // The recovery slot is already persisted, so dropping the secret
            // would make it permanently unusable.
            let recovery = created
                .recovery
                .ok_or(format!("{point}: active recovery material was dropped"))?;
            assert_eq!(read_header(&f.root())?.keyslots.len(), 2);
            drop(
                created
                    .backend
                    .unlock(&UnlockCredential::Recovery(recovery))?,
            );
            drop(created.backend.unlock(&input("original phrase")?)?);
        } else {
            // No production header ever activated, so no credential is lost.
            assert!(result.is_err());
            assert!(
                header::parse(&fs::read(f.root().join("vault.header"))?).is_err(),
                "{point}: a production header activated before the failure"
            );
        }
    }
    println!("H1_CREATE_RECOVERY_PRESERVED=PASS");
    Ok(())
}

/// Credential store with independently switchable, distinctly classified
/// failures, so a masked primary error is detectable by code alone.
#[derive(Default)]
struct FaultStore {
    inner: MemoryStore,
    fail_store: AtomicBool,
    fail_retrieve: AtomicBool,
    fail_delete: AtomicBool,
}
impl FaultStore {
    fn set(&self, store: bool, retrieve: bool, delete: bool) {
        self.fail_store.store(store, Ordering::SeqCst);
        self.fail_retrieve.store(retrieve, Ordering::SeqCst);
        self.fail_delete.store(delete, Ordering::SeqCst);
    }
    fn references(&self) -> Result<Vec<String>, AppError> {
        Ok(self
            .inner
            .0
            .lock()
            .map_err(|_| AppError::new(ErrorCode::Internal))?
            .keys()
            .cloned()
            .collect())
    }
}
impl CredentialStore for FaultStore {
    fn store(&self, reference: &str, value: &SecretValue) -> Result<(), AppError> {
        if self.fail_store.load(Ordering::SeqCst) {
            return Err(AppError::new(ErrorCode::ProviderAuthFailed));
        }
        self.inner.store(reference, value)
    }
    fn retrieve(&self, reference: &str) -> Result<Option<SecretValue>, AppError> {
        if self.fail_retrieve.load(Ordering::SeqCst) {
            return Err(AppError::new(ErrorCode::ProviderUnavailable));
        }
        self.inner.retrieve(reference)
    }
    fn delete(&self, reference: &str) -> Result<(), AppError> {
        if self.fail_delete.load(Ordering::SeqCst) {
            return Err(AppError::new(ErrorCode::DiskFull));
        }
        self.inner.delete(reference)
    }
}

fn device_reference(root: &Path) -> Result<Option<String>, AppError> {
    Ok(read_header(root)?
        .keyslots
        .iter()
        .find(|s| s.slot_type == "device-v1")
        .map(|s| s.credential_ref.clone()))
}

#[test]
fn cleanup_failure_is_recorded_without_replacing_the_primary_failure() -> TestResult {
    let f = Fixture::new()?;
    let store = Arc::new(FaultStore::default());
    let (backend, recovery) = create(&f, store.clone())?;
    let active = backend.unlock(&input("original phrase")?)?;
    let before = fs::read(f.root().join("vault.header"))?;

    // A credential-store failure whose cleanup also fails stays the primary
    // cause; the cleanup classification is separate evidence.
    store.set(true, false, true);
    let failure = active
        .enable_device()
        .err()
        .ok_or("store failure expected")?;
    assert_eq!(
        failure.primary().code,
        ErrorCode::ProviderAuthFailed,
        "cleanup failure replaced the primary store error"
    );
    assert_eq!(
        failure.cleanup().failure().map(|e| e.code),
        Some(ErrorCode::DiskFull),
        "secondary cleanup failure was discarded"
    );
    assert!(before == fs::read(f.root().join("vault.header"))?);

    // A pre-activation header failure: the header error stays primary and the
    // unreferenced credential is cleaned up best-effort.
    store.set(false, false, false);
    UPDATE_FAULT.with(|c| c.set(Some("before-activation")));
    let failure = active
        .enable_device()
        .err()
        .ok_or("header failure expected")?;
    UPDATE_FAULT.with(|c| c.set(None));
    assert_eq!(failure.primary().code, ErrorCode::Internal);
    assert_eq!(*failure.cleanup(), CleanupOutcome::Completed);
    assert!(before == fs::read(f.root().join("vault.header"))?);
    assert!(
        store.references()?.is_empty(),
        "unreferenced credential left"
    );

    // The same failure with a failing cleanup keeps the header error primary
    // and names the residue instead of hiding it.
    store.set(false, false, true);
    UPDATE_FAULT.with(|c| c.set(Some("before-activation")));
    let failure = active
        .enable_device()
        .err()
        .ok_or("header failure expected")?;
    UPDATE_FAULT.with(|c| c.set(None));
    assert_eq!(
        failure.primary().code,
        ErrorCode::Internal,
        "cleanup failure replaced the primary header error"
    );
    assert_eq!(
        failure.cleanup().failure().map(|e| e.code),
        Some(ErrorCode::DiskFull)
    );
    assert!(before == fs::read(f.root().join("vault.header"))?);
    let residue = store.references()?;
    assert_eq!(residue.len(), 1, "recorded cleanup failure must be real");
    assert!(device_reference(&f.root())?.is_none());

    // Neither the primary nor the secondary evidence may carry credential
    // material or an operating-system credential reference.
    let rendered = format!("{failure} {failure:?}");
    for leak in &residue {
        assert!(
            !rendered.contains(leak.as_str()),
            "credential reference leaked"
        );
    }
    store.set(false, false, false);
    for reference in residue {
        store.delete(&reference)?;
    }

    // Post-activation: a failing cleanup of the unreferenced predecessor never
    // converts a committed activation into a failure.
    let outcome = active.enable_device().map_err(NotActivated::into_primary)?;
    assert!(outcome.is_fully_settled());
    let first = device_reference(&f.root())?.ok_or("device slot")?;
    store.set(false, false, false);
    store.delete(&first)?;
    store.set(false, false, true);
    let outcome = active.enable_device().map_err(NotActivated::into_primary)?;
    assert!(
        outcome.durability().is_durable(),
        "activation was not durable"
    );
    assert_eq!(
        outcome.cleanup().failure().map(|e| e.code),
        Some(ErrorCode::DiskFull),
        "post-activation cleanup failure was not recorded"
    );
    let second = device_reference(&f.root())?.ok_or("device slot")?;
    assert_ne!(first, second);
    store.set(false, false, false);
    assert_eq!(
        store.references()?,
        vec![second],
        "active credential removed"
    );
    drop(active);
    drop(backend.unlock(&UnlockCredential::Device)?);
    drop(backend.unlock(&UnlockCredential::Recovery(recovery))?);
    println!("D2_PRIMARY_ERROR_PRESERVED=PASS D2_CLEANUP_RECORDED=PASS D2_SECRET_LEAKAGE=NO");
    Ok(())
}

#[test]
fn stale_device_slot_is_re_enrolled_only_on_proven_absence() -> TestResult {
    let f = Fixture::new()?;
    let store = Arc::new(FaultStore::default());
    let (backend, recovery) = create(&f, store.clone())?;
    let saved_recovery = recovery.encode_for_trusted_presentation();
    let active = backend.unlock(&input("original phrase")?)?;
    let source = f.base.join("private device.dat");
    fs::write(&source, b"private canonical device bytes")?;
    let receipt = active.import(&source)?;
    let vmk = active.vmk.storage_keys()?.0;
    assert!(active.enable_device()?.is_fully_settled());
    let first = device_reference(&f.root())?.ok_or("device slot")?;
    let header_before = fs::read(f.root().join("vault.header"))?;
    let blobs = snapshot(&f.root().join("blobs"))?;
    let db = Sha256::digest(fs::read(f.root().join("metadata.db"))?);

    // A healthy device slot is left exactly as it is.
    assert_eq!(
        active
            .enable_device()
            .err()
            .ok_or("healthy slot must be refused")?
            .primary()
            .code,
        ErrorCode::CorruptHeader
    );
    assert!(header_before == fs::read(f.root().join("vault.header"))?);
    assert_eq!(store.references()?, vec![first.clone()]);

    // A credential store that fails operationally is not absence: an outage
    // must never authorize destroying a working quick unlock.
    store.set(false, true, false);
    let failure = active
        .enable_device()
        .err()
        .ok_or("operational failure expected")?;
    store.set(false, false, false);
    assert_eq!(
        failure.primary().code,
        ErrorCode::ProviderUnavailable,
        "an operational credential-store failure was mistaken for absence"
    );
    assert_eq!(*failure.cleanup(), CleanupOutcome::NotRequired);
    assert!(header_before == fs::read(f.root().join("vault.header"))?);
    assert_eq!(
        store.references()?,
        vec![first.clone()],
        "an outage created or destroyed a credential"
    );

    // Proven absence: an authenticated session replaces the stale slot in place.
    store.inner.delete(&first)?;
    let outcome = active
        .enable_device()
        .map_err(|e| format!("a stale device slot could not be re-enrolled: {e}"))?;
    assert!(outcome.durability().is_durable());
    assert_eq!(
        *outcome.cleanup(),
        CleanupOutcome::Completed,
        "the unreferenced predecessor was not reclaimed"
    );
    let header = read_header(&f.root())?;
    assert_eq!(
        header
            .keyslots
            .iter()
            .filter(|s| s.slot_type == "device-v1")
            .count(),
        1,
        "exactly one device slot must remain"
    );
    let second = device_reference(&f.root())?.ok_or("device slot")?;
    assert_ne!(first, second);
    assert_eq!(store.references()?, vec![second.clone()]);
    assert_eq!(header.keyslots.len(), 3);
    // Re-enrollment rewraps the same VMK and touches no other slot.
    let original = header::parse(&header_before)?;
    for kind in ["passphrase-v1", "recovery-v1"] {
        assert!(
            original.keyslots.iter().find(|s| s.slot_type == kind)
                == header.keyslots.iter().find(|s| s.slot_type == kind),
            "re-enrollment changed the {kind} slot"
        );
    }
    assert!(blobs == snapshot(&f.root().join("blobs"))?);
    assert!(db == Sha256::digest(fs::read(f.root().join("metadata.db"))?));

    // Failure matrix over a second stale round; the stale header stays
    // authoritative until a replacement actually activates.
    store.inner.delete(&second)?;
    let stale_header = fs::read(f.root().join("vault.header"))?;
    store.set(true, false, false);
    assert_eq!(
        active
            .enable_device()
            .err()
            .ok_or("store failure expected")?
            .primary()
            .code,
        ErrorCode::ProviderAuthFailed
    );
    store.set(false, false, false);
    assert!(stale_header == fs::read(f.root().join("vault.header"))?);
    assert!(store.references()?.is_empty());

    UPDATE_FAULT.with(|c| c.set(Some("before-activation")));
    let failure = active
        .enable_device()
        .err()
        .ok_or("header failure expected")?;
    UPDATE_FAULT.with(|c| c.set(None));
    assert_eq!(failure.primary().code, ErrorCode::Internal);
    assert_eq!(*failure.cleanup(), CleanupOutcome::Completed);
    assert!(stale_header == fs::read(f.root().join("vault.header"))?);
    assert!(store.references()?.is_empty());

    store.set(false, false, true);
    UPDATE_FAULT.with(|c| c.set(Some("before-activation")));
    let failure = active
        .enable_device()
        .err()
        .ok_or("header failure expected")?;
    UPDATE_FAULT.with(|c| c.set(None));
    store.set(false, false, false);
    assert_eq!(
        failure.primary().code,
        ErrorCode::Internal,
        "cleanup failure replaced the primary header error"
    );
    assert_eq!(
        failure.cleanup().failure().map(|e| e.code),
        Some(ErrorCode::DiskFull)
    );
    assert!(stale_header == fs::read(f.root().join("vault.header"))?);
    for reference in store.references()? {
        store.delete(&reference)?;
    }

    let outcome = active.enable_device()?;
    assert!(outcome.durability().is_durable());
    let third = device_reference(&f.root())?.ok_or("device slot")?;
    assert_ne!(second, third);
    assert_eq!(store.references()?, vec![third.clone()]);
    drop(active);

    // Every independent path still unwraps the same VMK and the same bytes.
    for credential in [
        input("original phrase")?,
        UnlockCredential::Recovery(RecoverySecret::decode(saved_recovery)?),
        UnlockCredential::Device,
    ] {
        let reopened = backend.unlock(&credential)?;
        assert!(vmk.as_bytes() == reopened.vmk.storage_keys()?.0.as_bytes());
        let mut sink = Sink::default();
        reopened.recover(&receipt.blob_id, &mut sink)?;
        assert!(sink.committed && sink.bytes == b"private canonical device bytes");
        drop(reopened);
    }

    // Removing the enrolled device credential degrades only quick unlock.
    let before = snapshot(&f.root())?;
    store.delete(&third)?;
    assert!(backend.unlock(&UnlockCredential::Device).is_err());
    assert!(before == snapshot(&f.root())?);
    drop(backend.unlock(&input("original phrase")?)?);
    drop(backend.unlock(&UnlockCredential::Recovery(recovery))?);
    assert!(store.references()?.is_empty(), "credential residue remains");
    println!("D3_STALE_DEVICE_RE_ENROLLMENT=PASS D3_SLOT_INDEPENDENCE=PASS D3_RESIDUE=NONE");
    Ok(())
}

#[test]
fn device_enrollment_retains_the_credential_it_activated() -> TestResult {
    for (point, activated) in ACTIVATION_MATRIX {
        let f = Fixture::new()?;
        let store = Arc::new(FaultStore::default());
        let (backend, recovery) = create(&f, store.clone())?;
        let active = backend.unlock(&input("original phrase")?)?;
        let before = fs::read(f.root().join("vault.header"))?;
        UPDATE_FAULT.with(|c| c.set(Some(point)));
        let result = active.enable_device();
        UPDATE_FAULT.with(|c| c.set(None));
        drop(active);
        if activated {
            // The device slot is active, so deleting its operating-system
            // credential over a durability error would strand the header.
            let outcome = result
                .map_err(|e| format!("{point}: activated enrollment reported as failure: {e}"))?;
            assert!(
                outcome.durability().uncertainty().is_some(),
                "{point}: post-activation uncertainty was not reported"
            );
            assert_eq!(*outcome.cleanup(), CleanupOutcome::NotRequired);
            let reference = device_reference(&f.root())?.ok_or("device slot")?;
            assert_eq!(
                store.references()?,
                vec![reference],
                "{point}: the activated credential was deleted"
            );
            drop(backend.unlock(&UnlockCredential::Device)?);
        } else {
            let failure = result.err().ok_or("pre-activation failure expected")?;
            assert_eq!(failure.primary().code, ErrorCode::Internal);
            assert_eq!(*failure.cleanup(), CleanupOutcome::Completed);
            assert!(before == fs::read(f.root().join("vault.header"))?);
            assert!(device_reference(&f.root())?.is_none());
            assert!(
                store.references()?.is_empty(),
                "{point}: an unreferenced credential was left behind"
            );
            assert!(backend.unlock(&UnlockCredential::Device).is_err());
        }
        drop(backend.unlock(&input("original phrase")?)?);
        drop(backend.unlock(&UnlockCredential::Recovery(recovery))?);
    }
    println!("H1_DEVICE_ACTIVATION_MATRIX=PASS");
    Ok(())
}

#[test]
fn credential_reference_language_is_shared_by_keyslot_and_adapter() -> TestResult {
    let id = Uuid::new_v4().to_string();
    let vmk = VaultMasterKey::generate()?;
    let key = DeviceKey::generate()?;
    // The exact shape production generates, plus the malformed classes that
    // previously diverged between the two validators.
    let overlong = format!("dvm/device/{}", "a".repeat(200));
    let candidates = [
        format!("dvm/device/{id}/{}", Uuid::new_v4()),
        format!("dvm/device/{id}/UPPER"),
        format!("dvm/device/{id}/A"),
        format!("dvm/device/{id}/under_score"),
        format!("dvm/device/{id}/back\\slash"),
        format!("dvm/device/{id}/with space"),
        format!("dvm/device/{id}/uni\u{e9}code"),
        "dvm/device/".into(),
        "dvm/device".into(),
        overlong,
        format!("dvm/devices/{id}"),
        format!("/dvm/device/{id}"),
        format!("dvm/provider/synthetic/{id}"),
        String::new(),
    ];
    let mut accepted = 0;
    for reference in &candidates {
        let slot = keyslots::wrap_device(&id, &vmk, &key, reference.clone()).is_ok();
        let adapter = crate::credentials::validate_reference(reference).is_ok();
        assert!(
            !slot || adapter,
            "keyslot admitted a reference the credential adapter refuses"
        );
        if reference.starts_with("dvm/device/") {
            assert_eq!(
                slot, adapter,
                "device reference languages disagree for a persisted slot"
            );
        }
        accepted += usize::from(slot);
    }
    assert_eq!(
        accepted, 1,
        "exactly the canonical generated form is admitted"
    );
    // Every adapter-generated device reference is admissible as a slot.
    for _ in 0..64 {
        let reference = format!("dvm/device/{}/{}", Uuid::new_v4(), Uuid::new_v4());
        assert!(crate::credentials::validate_reference(&reference).is_ok());
        assert!(keyslots::wrap_device(&id, &vmk, &key, reference).is_ok());
    }

    // A persisted reference outside the grammar fails closed at admission.
    let f = Fixture::new()?;
    let store = Arc::new(MemoryStore::default());
    let (backend, _recovery) = create(&f, store.clone())?;
    let active = backend.unlock(&input("original phrase")?)?;
    active.enable_device()?;
    drop(active);
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(f.root().join("vault.header"))?)?;
    let slots = value["keyslots"].as_array_mut().ok_or("keyslots")?;
    let slot = slots
        .iter_mut()
        .find(|s| s["slot_type"] == "device-v1")
        .ok_or("device slot")?;
    slot["credential_ref"] = serde_json::Value::String(format!("dvm/device/{id}/UPPER"));
    fs::write(f.root().join("vault.header"), serde_json::to_vec(&value)?)?;
    assert_eq!(
        read_header(&f.root()).err().ok_or("must fail closed")?.code,
        ErrorCode::CorruptHeader
    );
    assert!(backend.unlock(&input("original phrase")?).is_err());
    println!("D1_CREDENTIAL_REFERENCE_LANGUAGE_EQUAL=PASS");
    Ok(())
}

#[cfg(windows)]
#[test]
fn real_windows_provider_and_device_credential_lifecycle() -> TestResult {
    use crate::credentials::WindowsCredentialStore;
    struct Cleanup {
        references: Mutex<Vec<String>>,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Ok(references) = self.references.lock() {
                for r in references.iter() {
                    let _ = WindowsCredentialStore.delete(r);
                }
            }
        }
    }
    struct TrackedNative {
        cleanup: Arc<Cleanup>,
    }
    impl CredentialStore for TrackedNative {
        fn store(&self, reference: &str, secret: &SecretValue) -> Result<(), AppError> {
            self.cleanup
                .references
                .lock()
                .map_err(|_| AppError::new(ErrorCode::Internal))?
                .push(reference.to_owned());
            WindowsCredentialStore.store(reference, secret)
        }
        fn retrieve(&self, reference: &str) -> Result<Option<SecretValue>, AppError> {
            WindowsCredentialStore.retrieve(reference)
        }
        fn delete(&self, reference: &str) -> Result<(), AppError> {
            WindowsCredentialStore.delete(reference)
        }
    }
    let cleanup = Arc::new(Cleanup {
        references: Mutex::new(vec![]),
    });
    let profile = format!("g2-test-{}", Uuid::new_v4());
    let reference = format!("dvm/provider/synthetic/{profile}");
    cleanup
        .references
        .lock()
        .map_err(|_| "poisoned")?
        .push(reference.clone());
    let canary = Zeroizing::new(format!("DVM_G2_PROVIDER_SECRET_{}", Uuid::new_v4()));
    let secret = SecretValue::new(Zeroizing::new(canary.as_bytes().to_vec()))?;
    let provider = ProviderSecretStore::new(WindowsCredentialStore);
    assert!(!provider.configured("synthetic", &profile)?);
    provider.store("synthetic", &profile, &secret)?;
    assert!(provider.configured("synthetic", &profile)?);
    assert!(
        provider
            .retrieve("synthetic", &profile)?
            .ok_or("missing credential")?
            .as_bytes()
            == secret.as_bytes(),
        "credential mismatch; redacted"
    );
    let f = Fixture::new()?;
    let (backend, recovery) = create(
        &f,
        Arc::new(TrackedNative {
            cleanup: cleanup.clone(),
        }),
    )?;
    let active = backend.unlock(&input("original phrase")?)?;
    active.enable_device()?;
    let h = read_header(&f.root())?;
    let reference_device = h
        .keyslots
        .iter()
        .find(|s| s.slot_type == "device-v1")
        .ok_or("device slot")?
        .credential_ref
        .clone();
    cleanup
        .references
        .lock()
        .map_err(|_| "poisoned")?
        .push(reference_device.clone());
    let device = WindowsCredentialStore
        .retrieve(&reference_device)?
        .ok_or("missing device credential")?;
    assert_eq!(device.as_bytes().len(), 32);
    drop(active);
    drop(backend.unlock(&UnlockCredential::Device)?);
    WindowsCredentialStore.delete(&reference_device)?;
    let before = snapshot(&f.root())?;
    assert!(backend.unlock(&UnlockCredential::Device).is_err());
    assert!(before == snapshot(&f.root())?);
    drop(backend.unlock(&input("original phrase")?)?);
    drop(backend.unlock(&UnlockCredential::Recovery(recovery))?);
    for entry in [f.root().join("vault.header"), f.root().join("metadata.db")] {
        let bytes = fs::read(entry)?;
        assert!(
            !bytes
                .windows(secret.as_bytes().len())
                .any(|w| w == secret.as_bytes()),
            "provider secret leaked"
        );
        assert!(
            !bytes
                .windows(device.as_bytes().len())
                .any(|w| w == device.as_bytes()),
            "device KEK leaked"
        );
    }
    let error = AppError::new(ErrorCode::ProviderUnavailable).with_safe_details(canary.as_str());
    let log = dvm_observability::DiagnosticEvent::new("security_test")
        .with_field("secret", canary.as_str())
        .to_json_line();
    let ipc = serde_json::to_string(&error)?;
    assert!(
        !log.contains(canary.as_str()) && !ipc.contains(canary.as_str()),
        "secret leakage; value redacted"
    );
    provider.delete("synthetic", &profile)?;
    assert!(!provider.configured("synthetic", &profile)?);
    assert!(
        WindowsCredentialStore
            .retrieve(&reference_device)?
            .is_none()
    );
    // Error-path cleanup uses the same RAII mechanism and is independently read back.
    let cleanup_ref = format!("dvm/provider/synthetic/g2-failure-{}", Uuid::new_v4());
    {
        let _failure_cleanup = Cleanup {
            references: Mutex::new(vec![cleanup_ref.clone()]),
        };
        WindowsCredentialStore.store(&cleanup_ref, &secret)?;
    }
    assert!(WindowsCredentialStore.retrieve(&cleanup_ref)?.is_none());
    println!(
        "WINDOWS_CREDENTIAL_INTEGRATION=PASS PROVIDER_SECRET_ORACLE=PASS G2_TEST_CREDENTIAL_RESIDUE=NONE"
    );
    Ok(())
}
