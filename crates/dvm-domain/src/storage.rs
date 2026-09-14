//! Trusted G1 storage contracts. None of these types cross renderer IPC.
use crate::AppError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Versioned non-secret envelope. Empty keyslots are internal test state only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultHeader {
    /// Mandatory envelope version.
    pub format_version: u32,
    /// Opaque random vault identifier.
    pub vault_id: String,
    /// Required database schema.
    pub schema_version: u32,
    /// Native database cipher family.
    pub database_cipher: String,
    /// Required cipher compatibility major version.
    pub database_cipher_version: u32,
    /// Required blob framing identifier.
    pub blob_format: String,
    /// Required AEAD algorithm.
    pub aead: String,
    /// Required subkey derivation algorithm.
    pub hkdf: String,
    /// Required content hash.
    pub hash: String,
    /// Future G2 container format, not a wrapping implementation.
    pub keyslot_format_version: u32,
    /// Reserved, always empty at the G1 internal test boundary.
    pub keyslots: Vec<crate::security::Keyslot>,
}

/// A staged encrypted import awaiting canonical commit. Trusted-only metadata.
pub struct StagedImport {
    /// Random candidate blob identifier.
    pub blob_id: [u8; 16],
    /// Vault-owned candidate, never a user-named temp path.
    pub staging_path: PathBuf,
    /// Streamed plaintext SHA-256.
    pub sha256_hex: String,
    /// Streamed plaintext length.
    pub size_bytes: u64,
    /// Source name to persist solely inside the encrypted DB.
    pub source_name: String,
    /// Source hint to persist solely inside the encrypted DB.
    pub source_path_hint: String,
}

/// Committed durable import, not a READY claim for future processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportReceipt {
    /// Newly created logical item.
    pub item_id: String,
    /// Reused or newly activated canonical blob.
    pub blob_id: String,
    /// Canonical plaintext identity.
    pub sha256_hex: String,
    /// Canonical plaintext byte count.
    pub size_bytes: u64,
}

/// Startup disposition before further writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationHealth {
    /// Canonical references and supported readers are intact.
    Healthy,
    /// Ambiguous files were preserved or referenced data needs repair.
    RepairRequired,
    /// Writes cannot safely proceed.
    DegradedReadOnly,
}

/// Bounded reconciliation counters; no user names or host paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationReport {
    /// Whether normal writes may begin.
    pub health: ReconciliationHealth,
    /// Staging candidates preserved for review.
    pub quarantined_staging: usize,
    /// Physical files without committed references preserved for review.
    pub quarantined_orphans: usize,
    /// Canonical DB rows whose bytes are missing.
    pub missing_blobs: usize,
    /// Expired leases made retryable or terminal at the attempt limit.
    pub expired_leases: usize,
}

/// Storage ports keep application orchestration independent of `SQLCipher`.
pub trait ImportRepository {
    /// Streams, hashes, encrypts, syncs and authenticates a vault-owned candidate.
    /// # Errors
    /// Typed source, storage or authentication failure; never success on partial data.
    fn stage_import(&self, source: &Path) -> Result<StagedImport, AppError>;
    /// Deduplicates/activates and commits all relational effects atomically.
    /// # Errors
    /// Any failure forbids a successful import receipt.
    fn commit_import(&self, staged: StagedImport) -> Result<ImportReceipt, AppError>;
}

/// A durable, bounded synthetic verification job payload. G1 has no media/AI worker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationPayload {
    /// Existing random blob ID, never a host path or secret.
    pub blob_id: String,
    /// Fixed worker contract version.
    pub processor_version: u32,
}

/// Opaque lease generation; stale workers cannot ACK a re-leased job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobLease {
    /// Job identity.
    pub id: String,
    /// Worker identity generated internally by the repository.
    pub worker_id: String,
    /// Monotonic attempt generation.
    pub attempt: u32,
    /// Stable typed work reference.
    pub payload: VerificationPayload,
}

/// Durable job use cases, with result publication owned by the adapter transaction.
pub trait JobRepository {
    /// Claims one runnable job transactionally.
    /// # Errors
    /// Storage failure never yields a lease.
    fn claim_job(&self, now: u64, lease_seconds: u64) -> Result<Option<JobLease>, AppError>;
    /// Verifies original bytes and commits `verified_at` and DONE together.
    /// # Errors
    /// Stale lease, corruption or failed result commit leaves job not DONE.
    fn complete_job(&self, lease: &JobLease, now: u64) -> Result<(), AppError>;
    /// Records a bounded retry or terminal result.
    /// # Errors
    /// Rejects a stale lease or failed durable update.
    fn fail_job(&self, lease: &JobLease, now: u64, retryable: bool) -> Result<(), AppError>;
}
