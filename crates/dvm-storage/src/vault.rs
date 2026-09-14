//! Vault-owned encrypted staging, immutable canonicalization and startup recovery.
use crate::database::{self, CipherEvidence, db_error};
use dvm_crypto::{
    BlobRootKey, DigestReceipt, PlaintextSink, VaultMasterKey, decrypt, encrypt, random_id,
};
use dvm_domain::{
    AppError, ErrorCode,
    storage::{
        ImportReceipt, ImportRepository, ReconciliationHealth, ReconciliationReport, StagedImport,
    },
};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

/// Exclusive trusted vault owner. Share it through `Arc` for concurrent imports.
/// The OS lock blocks competing processes and concurrent startup reconciliation.
pub struct Vault {
    pub(crate) root: PathBuf,
    pub(crate) database: Mutex<Connection>,
    pub(crate) blob_root: BlobRootKey,
    _ownership: File,
    /// Safe native cipher initialization evidence.
    pub cipher: CipherEvidence,
    /// Reconciliation performed before this instance admits writes.
    pub reconciliation: ReconciliationReport,
    /// Sticky repair state latched when this instance observes a canonical
    /// integrity failure at runtime. G1 implements no repair operation, so the
    /// vault stays non-writable for the rest of its lifetime (fail closed).
    repair_required: AtomicBool,
}

pub(crate) fn io_error(error: &std::io::Error) -> AppError {
    AppError::new(if error.kind() == std::io::ErrorKind::StorageFull {
        ErrorCode::DiskFull
    } else {
        ErrorCode::Internal
    })
}
/// Classifies a failure to reach a canonical blob.
///
/// Only a genuinely absent file is `MissingBlob`: that code asserts canonical
/// data loss and makes `recover` persist `CORRUPTED`. Every other filesystem
/// failure (sharing violation, permission denied, transient fault) is merely
/// operational, so it stays an operational error and never accuses intact
/// bytes of being lost.
pub(crate) fn blob_io_error(error: &std::io::Error) -> AppError {
    if error.kind() == std::io::ErrorKind::NotFound {
        AppError::new(ErrorCode::MissingBlob)
    } else {
        io_error(error)
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only canonical-open fault seam for deterministic, cross-platform
    /// operational-error injection. One-shot, thread-local and absent from
    /// production builds, so it is never a runtime fault-injection surface.
    pub(crate) static OPEN_FAULT: std::cell::Cell<Option<std::io::ErrorKind>> =
        const { std::cell::Cell::new(None) };
}

fn open_canonical(path: &Path) -> std::io::Result<File> {
    #[cfg(test)]
    if let Some(kind) = OPEN_FAULT.with(std::cell::Cell::take) {
        return Err(std::io::Error::from(kind));
    }
    File::open(path)
}

#[cfg(test)]
thread_local! {
    /// Test-only canonical-read fault seam: serve a chosen number of valid
    /// bytes from the canonical original, then fail the next read with a chosen
    /// kind. One-shot, thread-local and absent from production builds, so the
    /// operational-versus-authentication classification of canonical reads can
    /// be proven against the real `Vault::recover` path without damaging real
    /// storage and without creating any runtime fault-injection surface.
    pub(crate) static READ_FAULT: std::cell::Cell<Option<(usize, std::io::ErrorKind)>> =
        const { std::cell::Cell::new(None) };

    /// Test-only write-admission rendezvous, armed by the deterministic race
    /// regression. It runs immediately before a canonical mutator acquires its
    /// admission guard, so an interleaving can be driven by a barrier instead
    /// of by sleeps. Thread-local and absent from production builds.
    pub(crate) static ADMISSION_RENDEZVOUS: std::cell::Cell<Option<std::sync::Arc<std::sync::Barrier>>> =
        const { std::cell::Cell::new(None) };
}

/// The canonical original's reader.
///
/// In production this is a transparent pass-through to the open file. Test
/// builds can additionally arm a one-shot read fault (see [`READ_FAULT`]);
/// normal DVB1 and vault API semantics are identical either way.
pub(crate) struct CanonicalRead {
    file: File,
    #[cfg(test)]
    fault: Option<(usize, std::io::ErrorKind)>,
}

impl CanonicalRead {
    fn new(file: File) -> Self {
        Self {
            file,
            #[cfg(test)]
            fault: READ_FAULT.with(std::cell::Cell::take),
        }
    }
}

impl Read for CanonicalRead {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(test)]
        if let Some((remaining, kind)) = self.fault {
            if remaining == 0 {
                return Err(std::io::Error::from(kind));
            }
            let limit = remaining.min(buffer.len());
            let count = self.file.read(&mut buffer[..limit])?;
            self.fault = Some((remaining - count, kind));
            return Ok(count);
        }
        self.file.read(buffer)
    }
}

/// Orphan classification for one `blobs/` directory entry.
///
/// Takes a membership set built once by the caller: the directory scan must
/// stay `O(files)`, never rescan every database row per file.
pub(crate) fn referenced(known: &HashSet<&str>, name: &OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_suffix(".dvb"))
        .is_some_and(|id| known.contains(id))
}

pub(crate) fn uuid_bytes(id: &str) -> Result<[u8; 16], AppError> {
    let parsed = Uuid::parse_str(id).map_err(|_| AppError::new(ErrorCode::CorruptDatabase))?;
    if parsed.to_string() != id {
        return Err(AppError::new(ErrorCode::CorruptDatabase));
    }
    Ok(*parsed.as_bytes())
}
pub(crate) fn blob_relative(id: &str) -> Result<PathBuf, AppError> {
    uuid_bytes(id)?;
    Ok(PathBuf::from("blobs").join(format!("{id}.dvb")))
}

/// A verification-only sink. Plaintext never escapes or becomes a filesystem copy.
pub(crate) struct VerifyOnly;
impl PlaintextSink for VerifyOnly {
    fn stage(&mut self, _: &[u8]) -> Result<(), AppError> {
        Ok(())
    }
    fn commit(&mut self, _: &DigestReceipt) -> Result<(), AppError> {
        Ok(())
    }
    fn abort(&mut self) {}
}

impl Vault {
    /// Creates only a trusted injected-key integration vault with no usable keyslot.
    /// No production UI/IPC calls this API. G2 must supply durable wrapped keys.
    /// # Errors
    /// Refuses any existing root; any failed bootstrap must be preserved for diagnosis.
    pub fn create_with_injected_key(root: &Path, key: &VaultMasterKey) -> Result<Self, AppError> {
        fs::create_dir(root).map_err(|error| io_error(&error))?;
        for directory in [
            "blobs",
            "indexes/vector",
            "tmp",
            "quarantine",
            "local-state",
        ] {
            fs::create_dir_all(root.join(directory)).map_err(|error| io_error(&error))?;
        }
        let ownership = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(root.join("local-state/owner.lock"))
            .map_err(|error| io_error(&error))?;
        ownership
            .try_lock()
            .map_err(|_| AppError::new(ErrorCode::VaultLocked))?;
        let mut header = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("vault.header"))
            .map_err(|error| io_error(&error))?;
        header
            .write_all(&crate::header::serialize(
                &crate::header::injected_key_header(),
            )?)
            .map_err(|error| io_error(&error))?;
        header.sync_all().map_err(|error| io_error(&error))?;
        drop(header);
        let (db_key, blob_root) = key.storage_keys()?;
        let (db, cipher) = database::open(&root.join("metadata.db"), &db_key, true)?;
        let root = fs::canonicalize(root).map_err(|error| io_error(&error))?;
        Ok(Self {
            root,
            database: Mutex::new(db),
            blob_root,
            _ownership: ownership,
            cipher,
            reconciliation: healthy_report(),
            repair_required: AtomicBool::new(false),
        })
    }

    /// Opens an existing injected-key vault and reconciles before admitting writes.
    /// # Errors
    /// Wrong key, unknown header/schema/reader and database corruption fail closed.
    pub fn open_with_injected_key(
        root: &Path,
        key: &VaultMasterKey,
        now: u64,
    ) -> Result<Self, AppError> {
        let root = fs::canonicalize(root).map_err(|error| io_error(&error))?;
        for name in [
            "vault.header",
            "metadata.db",
            "blobs",
            "tmp",
            "quarantine",
            "local-state",
        ] {
            if fs::symlink_metadata(root.join(name))
                .map_err(|error| io_error(&error))?
                .file_type()
                .is_symlink()
            {
                return Err(AppError::new(ErrorCode::CorruptHeader));
            }
        }
        let header_file =
            File::open(root.join("vault.header")).map_err(|error| io_error(&error))?;
        let mut bytes = Vec::new();
        header_file
            .take(16_385)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error(&error))?;
        crate::header::parse(&bytes)?;
        let ownership = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("local-state/owner.lock"))
            .map_err(|error| io_error(&error))?;
        ownership
            .try_lock()
            .map_err(|_| AppError::new(ErrorCode::VaultLocked))?;
        let (db_key, blob_root) = key.storage_keys()?;
        let (db, cipher) = database::open(&root.join("metadata.db"), &db_key, false)?;
        let mut vault = Self {
            root,
            database: Mutex::new(db),
            blob_root,
            _ownership: ownership,
            cipher,
            reconciliation: healthy_report(),
            repair_required: AtomicBool::new(false),
        };
        vault.reconciliation = vault.reconcile(now)?;
        Ok(vault)
    }

    pub(crate) fn db(&self) -> Result<MutexGuard<'_, Connection>, AppError> {
        self.database
            .lock()
            .map_err(|_| AppError::new(ErrorCode::Internal))
    }

    /// Live write-admission health.
    ///
    /// Starts at the startup reconciliation verdict and latches permanently to
    /// `RepairRequired` once this instance observes a canonical integrity
    /// failure, so a corruption discovered after startup is not masked by a
    /// stale healthy snapshot.
    #[must_use]
    pub fn health(&self) -> ReconciliationHealth {
        if self.repair_required.load(Ordering::Acquire) {
            return ReconciliationHealth::RepairRequired;
        }
        self.reconciliation.health
    }

    /// Latches sticky repair state for a canonical integrity failure, and
    /// reports whether the observed code was one. Operational errors are not
    /// integrity failures and must leave both health and item status alone.
    fn note_canonical_integrity_failure(&self, code: ErrorCode) -> bool {
        if matches!(code, ErrorCode::MissingBlob | ErrorCode::BlobAuthFailed) {
            self.repair_required.store(true, Ordering::Release);
            return true;
        }
        false
    }

    /// Authenticates canonical bytes on behalf of a mutating caller, latching
    /// sticky repair state if the canonical original turns out to be unusable.
    pub(crate) fn verify_canonical(&self, db: &Connection, id: &str) -> Result<(), AppError> {
        self.recover_locked(db, id, &mut VerifyOnly)
            .map(|_| ())
            .inspect_err(|error| {
                self.note_canonical_integrity_failure(error.code);
            })
    }

    pub(crate) fn require_writable(&self) -> Result<(), AppError> {
        if self.health() != ReconciliationHealth::Healthy {
            return Err(AppError::new(ErrorCode::MissingBlob));
        }
        Ok(())
    }

    /// Acquires the canonical database mutex and admits the write only while
    /// holding it. Every canonical mutator that requires a healthy vault must
    /// take its guard from here.
    ///
    /// Write admission and integrity discovery have to be ordered by one
    /// synchronization boundary. Reading health *before* taking this lock is a
    /// TOCTOU: while the caller waits for the mutex, another caller can hold
    /// it, discover a canonical integrity failure and latch `RepairRequired`;
    /// the waiting caller then proceeds on a verdict it took before that
    /// discovery and mutates a vault already known to be unusable. Reading the
    /// live repair state under the same guard the mutation will use leaves
    /// exactly two orders — mutation strictly before discovery, or refusal
    /// strictly after it — and no third one in which a mutation follows a
    /// discovery that already happened.
    pub(crate) fn writable_db(&self) -> Result<MutexGuard<'_, Connection>, AppError> {
        #[cfg(test)]
        if let Some(barrier) = ADMISSION_RENDEZVOUS.with(std::cell::Cell::take) {
            barrier.wait();
        }
        let db = self.db()?;
        self.require_writable()?;
        Ok(db)
    }

    /// Recovers an original through a transactional sink, bound to the encrypted DB identity.
    /// # Errors
    /// Missing/corrupt originals mark affected items CORRUPTED and never return success.
    pub fn recover(
        &self,
        id: &str,
        sink: &mut impl PlaintextSink,
    ) -> Result<DigestReceipt, AppError> {
        let db = self.db()?;
        let result = self.recover_locked(&db, id, sink);
        if let Err(error) = &result {
            sink.abort();
            // Only a canonical integrity failure condemns the data. An
            // operational error leaves item status and write admission intact.
            if self.note_canonical_integrity_failure(error.code) {
                db.execute("UPDATE items SET status='CORRUPTED' WHERE id IN (SELECT item_id FROM item_blobs WHERE blob_id=?1)", [id]).map_err(|error| db_error(&error))?;
            }
        }
        result
    }

    pub(crate) fn recover_locked(
        &self,
        db: &Connection,
        id: &str,
        sink: &mut impl PlaintextSink,
    ) -> Result<DigestReceipt, AppError> {
        let (hash, size, relative, version): (String, i64, String, u32) = db.query_row(
            "SELECT sha256_hex,size_bytes,storage_relpath,crypto_format_version FROM blobs WHERE id=?1", [id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(|error| db_error(&error))?;
        let expected_path = blob_relative(id)?;
        if Path::new(&relative) != expected_path || version != 1 {
            return Err(AppError::new(ErrorCode::UnsupportedVaultVersion));
        }
        let path = self.root.join(expected_path);
        let metadata = fs::symlink_metadata(&path).map_err(|error| blob_io_error(&error))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(AppError::new(ErrorCode::BlobAuthFailed));
        }
        let mut file =
            CanonicalRead::new(open_canonical(&path).map_err(|error| blob_io_error(&error))?);
        let id = uuid_bytes(id)?;
        decrypt(
            &mut file,
            &self.blob_root.for_blob(&id)?,
            &id,
            Some(&DigestReceipt {
                sha256_hex: hash,
                size_bytes: u64::try_from(size)
                    .map_err(|_| AppError::new(ErrorCode::CorruptDatabase))?,
            }),
            sink,
        )
    }

    fn reconcile(&self, now: u64) -> Result<ReconciliationReport, AppError> {
        let mut report = healthy_report();
        let db = self.db()?;
        // Reject unsupported mandatory reader metadata before any repair mutation.
        let unsupported: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM blobs WHERE crypto_format_version!=1)",
                [],
                |r| r.get(0),
            )
            .map_err(|error| db_error(&error))?;
        if unsupported {
            return Err(AppError::new(ErrorCode::UnsupportedVaultVersion));
        }
        let mut statement = db
            .prepare("SELECT id FROM blobs")
            .map_err(|error| db_error(&error))?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| db_error(&error))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| db_error(&error))?;
        for id in &ids {
            match self.recover_locked(&db, id, &mut VerifyOnly) {
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.code,
                        ErrorCode::MissingBlob | ErrorCode::BlobAuthFailed
                    ) =>
                {
                    db.execute("UPDATE items SET status='CORRUPTED' WHERE id IN (SELECT item_id FROM item_blobs WHERE blob_id=?1)", [id]).map_err(|error| db_error(&error))?;
                    if error.code == ErrorCode::MissingBlob {
                        report.missing_blobs += 1;
                    }
                    report.health = ReconciliationHealth::RepairRequired;
                }
                Err(error) => return Err(error),
            }
        }
        // Built once, before the scan: a per-file rescan of every row makes
        // startup O(files x rows) and unbounded on a large vault.
        let known: HashSet<&str> = ids.iter().map(String::as_str).collect();
        for entry in fs::read_dir(self.root.join("blobs")).map_err(|error| io_error(&error))? {
            let entry = entry.map_err(|error| io_error(&error))?;
            if !referenced(&known, &entry.file_name()) {
                self.quarantine(&entry.path())?;
                report.quarantined_orphans += 1;
                report.health = ReconciliationHealth::RepairRequired;
            }
        }
        // Exclusive ownership proves no live importer can own these candidates.
        // Preserve even complete/ambiguous staging; never silently delete it.
        for entry in fs::read_dir(self.root.join("tmp")).map_err(|error| io_error(&error))? {
            let entry = entry.map_err(|error| io_error(&error))?;
            self.quarantine(&entry.path())?;
            report.quarantined_staging += 1;
        }
        report.expired_leases = db.execute(
            "UPDATE jobs SET status=CASE WHEN attempts>=max_attempts THEN 'FAILED_TERMINAL' ELSE 'PENDING' END, leased_by=NULL, lease_until=NULL, available_at=?1, updated_at=?1 WHERE status='PROCESSING' AND lease_until<=?1", [crate::jobs::timestamp(now)?]).map_err(|error| db_error(&error))?;
        Ok(report)
    }

    fn quarantine(&self, source: &Path) -> Result<(), AppError> {
        let destination = self
            .root
            .join("quarantine")
            .join(Uuid::new_v4().to_string());
        if destination.exists() {
            return Err(AppError::new(ErrorCode::Internal));
        }
        fs::rename(source, destination).map_err(|error| io_error(&error))
    }
}

fn healthy_report() -> ReconciliationReport {
    ReconciliationReport {
        health: ReconciliationHealth::Healthy,
        quarantined_staging: 0,
        quarantined_orphans: 0,
        missing_blobs: 0,
        expired_leases: 0,
    }
}

impl ImportRepository for Vault {
    fn stage_import(&self, source: &Path) -> Result<StagedImport, AppError> {
        // Best-effort only, and deliberately not the authoritative admission:
        // staging streams and encrypts the whole source, which for a multi-GB
        // original runs for minutes. Holding the database mutex across that
        // would serialize every unrelated database operation behind one import.
        // Admission is therefore decided by `commit_import` under the database
        // guard; this check merely avoids expensive staging that is already
        // known to be pointless. If the repair state changes during staging,
        // the commit refuses and the encrypted `.part` stays reconcilable
        // temporary state — which is recoverable, whereas a false canonical
        // success is not.
        self.require_writable()?;
        let source_meta =
            fs::symlink_metadata(source).map_err(|_| AppError::new(ErrorCode::SourceUnreadable))?;
        if !source_meta.is_file() || source_meta.file_type().is_symlink() {
            return Err(AppError::new(ErrorCode::SourceUnreadable));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(1); // Deny source mutation/deletion while preserving bytes.
        }
        let mut source_file = options
            .open(source)
            .map_err(|_| AppError::new(ErrorCode::SourceUnreadable))?;
        let size = source_file
            .metadata()
            .map_err(|_| AppError::new(ErrorCode::SourceUnreadable))?
            .len();
        if size > i64::MAX as u64 {
            return Err(AppError::new(ErrorCode::SourceUnreadable));
        }
        let blob_id = random_id()?;
        let staging_path = self
            .root
            .join("tmp")
            .join(format!("{}.part", Uuid::from_bytes(blob_id)));
        #[cfg(test)]
        crate::tests::checkpoint("C1");
        let mut candidate = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging_path)
            .map_err(|error| io_error(&error))?;
        #[cfg(test)]
        crate::tests::checkpoint("C2");
        #[cfg(test)]
        let writer = crate::tests::ChunkCheckpointWriter::new(&mut candidate);
        #[cfg(not(test))]
        let writer = &mut candidate;
        let identity = encrypt(
            &mut source_file,
            &mut { writer },
            &self.blob_root.for_blob(&blob_id)?,
            &blob_id,
            size,
        )?;
        #[cfg(test)]
        crate::tests::checkpoint("C4");
        candidate.flush().map_err(|error| io_error(&error))?;
        candidate.sync_all().map_err(|error| io_error(&error))?;
        drop(candidate);
        #[cfg(test)]
        crate::tests::checkpoint("C5");
        decrypt(
            &mut File::open(&staging_path).map_err(|error| io_error(&error))?,
            &self.blob_root.for_blob(&blob_id)?,
            &blob_id,
            Some(&identity),
            &mut VerifyOnly,
        )?;
        Ok(StagedImport {
            blob_id,
            staging_path,
            sha256_hex: identity.sha256_hex,
            size_bytes: size,
            source_name: source
                .file_name()
                .ok_or_else(|| AppError::new(ErrorCode::SourceUnreadable))?
                .to_string_lossy()
                .into_owned(),
            source_path_hint: source.to_string_lossy().into_owned(),
        })
    }

    fn commit_import(&self, staged: StagedImport) -> Result<ImportReceipt, AppError> {
        // Authoritative write admission: taken under the database guard, and
        // held across every canonical mutation below.
        let mut db = self.writable_db()?;
        let candidate_id = Uuid::from_bytes(staged.blob_id).to_string();
        if staged.staging_path != self.root.join("tmp").join(format!("{candidate_id}.part")) {
            return Err(AppError::new(ErrorCode::Internal));
        }
        let identity = DigestReceipt {
            sha256_hex: staged.sha256_hex.clone(),
            size_bytes: staged.size_bytes,
        };
        decrypt(
            &mut File::open(&staged.staging_path).map_err(|error| io_error(&error))?,
            &self.blob_root.for_blob(&staged.blob_id)?,
            &staged.blob_id,
            Some(&identity),
            &mut VerifyOnly,
        )?;
        let existing: Option<(String, i64)> = db
            .query_row(
                "SELECT id,size_bytes FROM blobs WHERE sha256_hex=?1",
                [&staged.sha256_hex],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| db_error(&error))?;
        let (blob_id, new_blob) = if let Some((id, size)) = existing {
            if u64::try_from(size).ok() != Some(staged.size_bytes) {
                return Err(AppError::new(ErrorCode::CorruptDatabase));
            }
            self.verify_canonical(&db, &id)?;
            fs::remove_file(&staged.staging_path).map_err(|error| io_error(&error))?;
            (id, false)
        } else {
            let canonical = self.root.join(blob_relative(&candidate_id)?);
            if canonical.exists() {
                return Err(AppError::new(ErrorCode::Internal));
            }
            fs::rename(&staged.staging_path, &canonical).map_err(|error| io_error(&error))?;
            #[cfg(test)]
            crate::tests::checkpoint("C6");
            OpenOptions::new()
                .write(true)
                .open(&canonical)
                .map_err(|error| io_error(&error))?
                .sync_all()
                .map_err(|error| io_error(&error))?;
            #[cfg(unix)]
            File::open(self.root.join("blobs"))
                .map_err(|error| io_error(&error))?
                .sync_all()
                .map_err(|error| io_error(&error))?;
            (candidate_id, true)
        };
        let tx = db.transaction().map_err(|error| db_error(&error))?;
        if new_blob {
            tx.execute("INSERT INTO blobs(id,sha256_hex,size_bytes,storage_relpath,crypto_format_version,created_at,verified_at) VALUES (?1,?2,?3,?4,1,strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                params![blob_id, staged.sha256_hex, i64::try_from(staged.size_bytes).map_err(|_| AppError::new(ErrorCode::Internal))?, blob_relative(&blob_id)?.to_string_lossy()]).map_err(|error| db_error(&error))?;
        }
        let item_id = Uuid::new_v4().to_string();
        tx.execute("INSERT INTO items(id,kind,source_name,source_path_hint,created_at,updated_at,status) VALUES (?1,'FILE',?2,?3,strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now'),'IMPORTED')", params![item_id, staged.source_name, staged.source_path_hint]).map_err(|error| db_error(&error))?;
        tx.execute(
            "INSERT INTO item_blobs(item_id,blob_id,role) VALUES (?1,?2,'ORIGINAL')",
            params![item_id, blob_id],
        )
        .map_err(|error| db_error(&error))?;
        crate::jobs::enqueue_verification(&tx, &item_id, &blob_id)?;
        #[cfg(test)]
        crate::tests::checkpoint("C7");
        tx.commit().map_err(|error| db_error(&error))?;
        #[cfg(test)]
        crate::tests::checkpoint("C8");
        Ok(ImportReceipt {
            item_id,
            blob_id,
            sha256_hex: staged.sha256_hex,
            size_bytes: staged.size_bytes,
        })
    }
}
