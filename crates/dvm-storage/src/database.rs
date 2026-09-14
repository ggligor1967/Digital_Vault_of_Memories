//! Native `SQLCipher` connection bootstrap; all error envelopes exclude source strings.
use dvm_crypto::{DbKey, dvb1::hex};
use dvm_domain::{AppError, ErrorCode};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) const SCHEMA: &str = include_str!("schema.sql");

/// Safe cryptographic provider evidence; no key material or user metadata.
#[derive(Debug, Clone)]
pub struct CipherEvidence {
    /// Bundled `SQLCipher` version.
    pub version: String,
    /// Compiled crypto provider.
    pub provider: String,
    /// Version reported by the compiled crypto provider.
    pub provider_version: String,
    /// Verified `cipher_status` from the pinned provider (supported since 4.12).
    pub status: i64,
    /// Active journal mode.
    pub journal_mode: String,
}

pub(crate) fn db_error(error: &rusqlite::Error) -> AppError {
    AppError::new(
        if matches!(error, rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::DiskFull)
        {
            ErrorCode::DiskFull
        } else {
            ErrorCode::CorruptDatabase
        },
    )
}

pub(crate) fn open(
    path: &Path,
    key: &DbKey,
    create: bool,
) -> Result<(Connection, CipherEvidence), AppError> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let mut db = Connection::open_with_flags(path, flags).map_err(|error| db_error(&error))?;
    {
        let key_hex = Zeroizing::new(hex(key.as_bytes()));
        let key_literal = Zeroizing::new(format!("x'{}'", key_hex.as_str()));
        db.pragma_update(None, "key", key_literal.as_str())
            .map_err(|error| db_error(&error))?;
    }
    // Keep SQLCipher's default cryptographic allocation wiping. Its optional global
    // allocator locking recurses through logging when Windows VirtualLock fails.
    let version: String = db
        .pragma_query_value(None, "cipher_version", |row| row.get(0))
        .map_err(|error| db_error(&error))?;
    if !version.starts_with("4.") {
        return Err(AppError::new(ErrorCode::CorruptDatabase));
    }
    // An actual page read is essential: PRAGMA key alone cannot detect a wrong key.
    let tables: i64 = db
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .map_err(|error| db_error(&error))?;
    let schema: u32 = db
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| db_error(&error))?;
    if schema > 1 {
        return Err(AppError::new(ErrorCode::MigrationRequired));
    }
    if (schema == 0 && !create) || (create && tables != 0) {
        return Err(AppError::new(ErrorCode::CorruptDatabase));
    }
    let hmac: String = db
        .pragma_query_value(None, "cipher_use_hmac", |row| row.get(0))
        .map_err(|error| db_error(&error))?;
    let plain_header: String = db
        .pragma_query_value(None, "cipher_plaintext_header_size", |row| row.get(0))
        .map_err(|error| db_error(&error))?;
    if hmac != "1" || plain_header != "0" {
        return Err(AppError::new(ErrorCode::CorruptDatabase));
    }
    let status: String = db
        .pragma_query_value(None, "cipher_status", |row| row.get(0))
        .map_err(|error| db_error(&error))?;
    if status != "1" {
        return Err(AppError::new(ErrorCode::CorruptDatabase));
    }
    integrity(&db)?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY; PRAGMA secure_delete=ON; PRAGMA synchronous=FULL;").map_err(|error| db_error(&error))?;
    let journal_mode: String = db
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| db_error(&error))?;
    if journal_mode != "wal" {
        db.pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| db_error(&error))?;
    }
    let journal_mode: String = db
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| db_error(&error))?;
    if journal_mode != "wal" {
        return Err(AppError::new(ErrorCode::CorruptDatabase));
    }
    if schema == 0 {
        let tx = db.transaction().map_err(|error| db_error(&error))?;
        tx.execute_batch(SCHEMA).map_err(|error| db_error(&error))?;
        tx.execute("INSERT INTO schema_migrations VALUES (1, 'g1-bootstrap', ?1, strftime('%Y-%m-%dT%H:%M:%fZ','now'))", [schema_checksum()]).map_err(|error| db_error(&error))?;
        tx.pragma_update(None, "user_version", 1)
            .map_err(|error| db_error(&error))?;
        tx.commit().map_err(|error| db_error(&error))?;
    }
    let checksum: String = db
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE version=1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| db_error(&error))?;
    if checksum != schema_checksum() {
        return Err(AppError::new(ErrorCode::MigrationFailed));
    }
    // Test compiled capability only; no G4 search implementation or persistent tables.
    db.execute_batch(
        "CREATE VIRTUAL TABLE temp.g1_fts_probe USING fts5(body); DROP TABLE temp.g1_fts_probe;",
    )
    .map_err(|error| db_error(&error))?;
    let provider = db
        .pragma_query_value(None, "cipher_provider", |row| row.get(0))
        .map_err(|error| db_error(&error))?;
    let provider_version = db
        .pragma_query_value(None, "cipher_provider_version", |row| row.get(0))
        .map_err(|error| db_error(&error))?;
    Ok((
        db,
        CipherEvidence {
            version,
            provider,
            provider_version,
            status: 1,
            journal_mode,
        },
    ))
}

pub(crate) fn integrity(db: &Connection) -> Result<(), AppError> {
    let mut stmt = db
        .prepare("PRAGMA cipher_integrity_check")
        .map_err(|error| db_error(&error))?;
    if stmt
        .query([])
        .map_err(|error| db_error(&error))?
        .next()
        .map_err(|error| db_error(&error))?
        .is_some()
    {
        return Err(AppError::new(ErrorCode::CorruptDatabase));
    }
    let result: String = db
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|error| db_error(&error))?;
    if result != "ok" {
        return Err(AppError::new(ErrorCode::CorruptDatabase));
    }
    Ok(())
}

fn schema_checksum() -> String {
    dvm_crypto::dvb1::sha256(SCHEMA.as_bytes())
}
