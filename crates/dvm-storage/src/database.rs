//! Native `SQLCipher` connection bootstrap; all error envelopes exclude source strings.
use crate::migrations::{self, CURRENT_SCHEMA_VERSION};
use dvm_crypto::{DbKey, dvb1::hex};
use dvm_domain::{AppError, ErrorCode};
use rusqlite::{Connection, OpenFlags};
use std::fs::OpenOptions;
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
    if schema > CURRENT_SCHEMA_VERSION {
        return Err(AppError::new(ErrorCode::MigrationRequired));
    }
    if (schema == 0 && !create) || (create && tables != 0) {
        return Err(AppError::new(ErrorCode::CorruptDatabase));
    }
    if schema != 0 {
        migrations::validate_history(&db, schema)?;
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
    migrations::apply_pending(&mut db, schema.max(1), false)?;
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

/// Runs both `SQLCipher` page authentication and `SQLite` logical integrity.
/// # Errors
/// A failed check is classified as a corrupt database.
pub fn integrity(db: &Connection) -> Result<(), AppError> {
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

/// Copies one live `SQLCipher` state to a newly keyed encrypted database.
/// The caller holds the canonical DB mutex, serializing application writes.
pub(crate) fn snapshot_encrypted(
    source: &Connection,
    path: &Path,
    key: &DbKey,
) -> Result<(), AppError> {
    let reserved = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| crate::vault::io_error(&error))?;
    drop(reserved);
    let result = (|| {
        let mut destination = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| db_error(&error))?;
        {
            let key_hex = Zeroizing::new(hex(key.as_bytes()));
            let key_literal = Zeroizing::new(format!("x'{}'", key_hex.as_str()));
            destination
                .pragma_update(None, "key", key_literal.as_str())
                .map_err(|error| db_error(&error))?;
        }
        let status: String = destination
            .pragma_query_value(None, "cipher_status", |row| row.get(0))
            .map_err(|error| db_error(&error))?;
        if status != "1" {
            return Err(AppError::new(ErrorCode::CorruptDatabase));
        }
        {
            let backup = rusqlite::backup::Backup::new(source, &mut destination)
                .map_err(|error| db_error(&error))?;
            backup
                .run_to_completion(64, std::time::Duration::ZERO, None)
                .map_err(|error| db_error(&error))?;
        }
        destination.close().map_err(|(_, error)| db_error(&error))?;
        let snapshot = open_snapshot_readonly(path, key)?;
        integrity(&snapshot)?;
        let version: u32 = snapshot
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|error| db_error(&error))?;
        migrations::validate_history(&snapshot, version)?;
        OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|file| file.sync_all())
            .map_err(|error| crate::vault::io_error(&error))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

/// Opens an existing encrypted snapshot without migration or journal-mode changes.
/// # Errors
/// Wrong keys and corrupt pages fail closed.
pub fn open_snapshot_readonly(path: &Path, key: &DbKey) -> Result<Connection, AppError> {
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| db_error(&error))?;
    {
        let key_hex = Zeroizing::new(hex(key.as_bytes()));
        let key_literal = Zeroizing::new(format!("x'{}'", key_hex.as_str()));
        db.pragma_update(None, "key", key_literal.as_str())
            .map_err(|error| db_error(&error))?;
    }
    db.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })
    .map_err(|error| db_error(&error))?;
    Ok(db)
}

fn schema_checksum() -> String {
    dvm_crypto::dvb1::sha256(SCHEMA.as_bytes())
}
