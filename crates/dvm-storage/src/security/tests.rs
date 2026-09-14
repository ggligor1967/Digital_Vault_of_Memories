//! Real G2 storage/credential oracles. Only synthetic data and owned test roots.
#![allow(clippy::too_many_lines)]
use super::*;
#[cfg(windows)]
use dvm_application::provider_secrets::ProviderSecretStore;
use dvm_application::session::VaultSession;
use dvm_domain::security::VaultState;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Mutex};
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
    for point in [
        "before-temp",
        "after-temp",
        "after-sync",
        "before-activation",
        "after-activation",
    ] {
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
        if point == "after-activation" {
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
    let (backend, recovery) = ProtectedVault::create_with_policy(
        &f.root(),
        &pass("original phrase")?,
        RecoveryPolicy::default(),
        ArgonProfile::BASELINE,
        store,
    )?;
    Ok((
        backend,
        recovery.ok_or_else(|| AppError::new(ErrorCode::Internal))?,
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
    session.with_open(OpenVault::enable_device)?;
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
        v.change_passphrase(
            &pass("original phrase")?,
            &pass("changed phrase")?,
            ArgonProfile {
                iterations: 3,
                ..ArgonProfile::BASELINE
            },
        )?;
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
    let (backend, recovery) = ProtectedVault::create(
        &f.root(),
        &pass("original phrase")?,
        Arc::new(MemoryStore::default()),
    )?;
    assert_eq!(read_header(&f.root())?.keyslots.len(), 2);
    drop(backend.unlock(&UnlockCredential::Recovery(recovery))?);
    let decline = Fixture::new()?;
    let (_, recovery) = ProtectedVault::create_with_policy(
        &decline.root(),
        &pass("original phrase")?,
        RecoveryPolicy::DeclinedAfterDataLossWarning,
        ArgonProfile::BASELINE,
        Arc::new(MemoryStore::default()),
    )?;
    assert!(recovery.is_none());
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

#[test]
fn header_failure_matrix_preserves_old_or_new_activation() -> TestResult {
    for point in [
        "before-temp",
        "after-temp",
        "after-sync",
        "before-activation",
        "after-activation",
    ] {
        let f = Fixture::new()?;
        let (backend, recovery) = create(&f, Arc::new(MemoryStore::default()))?;
        let active = backend.unlock(&input("original phrase")?)?;
        let before = fs::read(f.root().join("vault.header"))?;
        UPDATE_FAULT.with(|f| f.set(Some(point)));
        let result = active.change_passphrase(
            &pass("original phrase")?,
            &pass("new phrase")?,
            ArgonProfile::BASELINE,
        );
        UPDATE_FAULT.with(|f| f.set(None));
        assert!(result.is_err());
        drop(active);
        if point == "after-activation" {
            assert!(backend.unlock(&input("original phrase")?).is_err());
            drop(backend.unlock(&input("new phrase")?)?);
        } else {
            assert!(before == fs::read(f.root().join("vault.header"))?);
            drop(backend.unlock(&input("original phrase")?)?);
            assert!(backend.unlock(&input("new phrase")?).is_err());
        }
        drop(backend.unlock(&UnlockCredential::Recovery(recovery))?);
    }
    println!("HEADER_FAILURE_MATRIX=PASS");
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
