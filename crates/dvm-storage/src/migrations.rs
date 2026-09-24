//! Immutable ordered schema migrations. Version one is the historical G1 schema bytes.
use crate::database::{SCHEMA, db_error};
use dvm_crypto::dvb1::sha256;
use dvm_domain::{AppError, ErrorCode};
use rusqlite::{Connection, params};

/// Highest schema this binary may mutate.
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

/// Recovery-point policy for a migration.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Additive migration without rewriting canonical rows.
    Low,
    /// Requires an independently verified recovery point.
    High,
}

struct Migration {
    version: u32,
    name: &'static str,
    sql: &'static str,
    risk: Risk,
}

const BACKUP_HISTORY: Migration = Migration {
    version: 2,
    name: "0002_g3_backup_history",
    sql: include_str!("../../../migrations/0002_g3_backup_history.sql"),
    risk: Risk::Low,
};

fn failed() -> AppError {
    AppError::new(ErrorCode::MigrationFailed)
}

/// Checks the complete applied prefix before any migration write.
/// # Errors
/// Mismatched, missing, non-contiguous, or future history fails closed.
pub fn validate_history(db: &Connection, version: u32) -> Result<(), AppError> {
    if version > CURRENT_SCHEMA_VERSION {
        return Err(AppError::new(ErrorCode::MigrationRequired));
    }
    if version == 0 {
        return Ok(());
    }
    let mut statement = db
        .prepare("SELECT version,name,checksum FROM schema_migrations ORDER BY version")
        .map_err(|_| failed())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|_| failed())?;
    let mut observed = 0;
    for row in rows {
        let (applied, name, checksum) = row.map_err(|_| failed())?;
        observed += 1;
        let expected = match observed {
            1 => ("g1-bootstrap", sha256(SCHEMA.as_bytes())),
            2 => (BACKUP_HISTORY.name, sha256(BACKUP_HISTORY.sql.as_bytes())),
            _ => return Err(failed()),
        };
        if applied != observed || name != expected.0 || checksum != expected.1 {
            return Err(failed());
        }
    }
    if observed != version {
        return Err(failed());
    }
    Ok(())
}

/// Refuses high-risk work without independently verified recovery.
/// # Errors
/// Returns `MIGRATION_FAILED` if the risk policy is not met.
pub fn require_recovery_point(risk: Risk, verified: bool) -> Result<(), AppError> {
    if risk == Risk::High && !verified {
        return Err(failed());
    }
    Ok(())
}

/// Applies each pending migration as one `SQLite` transaction.
/// # Errors
/// Failure rolls back all effects of the active migration.
pub fn apply_pending(
    db: &mut Connection,
    version: u32,
    verified_recovery: bool,
) -> Result<(), AppError> {
    validate_history(db, version)?;
    for migration in [BACKUP_HISTORY]
        .iter()
        .filter(|migration| migration.version > version)
    {
        require_recovery_point(migration.risk, verified_recovery)?;
        #[cfg(test)]
        crate::tests::g3_migration_checkpoint("before_transaction");
        let transaction = db.transaction().map_err(|error| db_error(&error))?;
        #[cfg(test)]
        crate::tests::g3_migration_checkpoint("after_begin");
        transaction
            .execute_batch(migration.sql)
            .map_err(|_| failed())?;
        #[cfg(test)]
        crate::tests::g3_migration_checkpoint("after_sql");
        transaction.execute(
            "INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES (?1,?2,?3,strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
            params![migration.version, migration.name, sha256(migration.sql.as_bytes())],
        ).map_err(|_| failed())?;
        #[cfg(test)]
        crate::tests::g3_migration_checkpoint("after_bookkeeping");
        #[cfg(test)]
        crate::tests::g3_migration_checkpoint("before_user_version");
        transaction
            .pragma_update(None, "user_version", migration.version)
            .map_err(|_| failed())?;
        #[cfg(test)]
        crate::tests::g3_migration_checkpoint("before_commit");
        transaction.commit().map_err(|error| db_error(&error))?;
        #[cfg(test)]
        crate::tests::g3_migration_checkpoint("after_commit");
    }
    validate_history(db, CURRENT_SCHEMA_VERSION)
}
