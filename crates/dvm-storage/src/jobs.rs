//! Transactional leases and verification result commits. No future processing worker.
use crate::{
    database::db_error,
    vault::{Vault, uuid_bytes},
};
use dvm_crypto::random_id;
use dvm_domain::{
    AppError, ErrorCode,
    storage::{JobLease, JobRepository, VerificationPayload},
};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

// Fixed-width decimal Unix seconds: UTC, lexicographically sortable and
// unambiguous. Job scheduling columns (available_at, lease_until, created_at,
// updated_at) are ordered and compared as text, so they keep this form.
pub(crate) fn timestamp(seconds: u64) -> Result<String, AppError> {
    if seconds > i64::MAX as u64 {
        return Err(AppError::new(ErrorCode::Internal));
    }
    Ok(format!("{seconds:020}"))
}

// Blob metadata timestamps are a different convention from job scheduling: they
// are UTC ISO-8601 text. Binding Unix seconds and letting SQLite render them
// keeps one grammar across every `blobs.verified_at` writer, using the same
// strftime format as the insertion in `Vault::commit_import`.
fn unix_seconds(seconds: u64) -> Result<i64, AppError> {
    i64::try_from(seconds).map_err(|_| AppError::new(ErrorCode::Internal))
}

pub(crate) fn enqueue_verification(
    db: &Connection,
    item_id: &str,
    blob_id: &str,
) -> Result<(), AppError> {
    uuid_bytes(item_id)?;
    uuid_bytes(blob_id)?;
    let payload = serde_json::to_string(&VerificationPayload {
        blob_id: blob_id.into(),
        processor_version: 1,
    })
    .map_err(|_| AppError::new(ErrorCode::Internal))?;
    db.execute("INSERT INTO jobs(id,kind,item_id,payload_json,status,available_at,idempotency_key,created_at,updated_at) VALUES (?1,'VERIFY_ORIGINAL',?2,?3,'PENDING',printf('%020d',unixepoch()),?4,printf('%020d',unixepoch()),printf('%020d',unixepoch()))", params![Uuid::new_v4().to_string(),item_id,payload,format!("verify-original:{item_id}:1")]).map_err(|error| db_error(&error))?;
    Ok(())
}

impl JobRepository for Vault {
    fn claim_job(&self, now: u64, lease_seconds: u64) -> Result<Option<JobLease>, AppError> {
        if !(1..=3600).contains(&lease_seconds) {
            return Err(AppError::new(ErrorCode::JobTerminal));
        }
        let deadline = timestamp(
            now.checked_add(lease_seconds)
                .ok_or_else(|| AppError::new(ErrorCode::Internal))?,
        )?;
        let now = timestamp(now)?;
        // Admission is read under the same guard that carries the lease
        // mutation, so a repair state latched by a concurrent integrity
        // discovery can never be missed by a claim that was already waiting.
        let mut db = self.writable_db()?;
        let tx = db.transaction().map_err(|error| db_error(&error))?;
        let row: Option<(String,String,u32)> = tx.query_row("SELECT id,payload_json,attempts FROM jobs WHERE status='PENDING' AND available_at<=?1 AND attempts<max_attempts ORDER BY priority,created_at,id LIMIT 1", [&now], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional().map_err(|error| db_error(&error))?;
        let Some((id, payload, attempts)) = row else {
            return Ok(None);
        };
        if payload.len() > 256 {
            return Err(AppError::new(ErrorCode::JobTerminal));
        }
        let payload: VerificationPayload =
            serde_json::from_str(&payload).map_err(|_| AppError::new(ErrorCode::JobTerminal))?;
        uuid_bytes(&payload.blob_id)?;
        if payload.processor_version != 1 {
            return Err(AppError::new(ErrorCode::JobTerminal));
        }
        let worker_id = Uuid::new_v4().to_string();
        tx.execute("UPDATE jobs SET status='PROCESSING',attempts=attempts+1,leased_by=?1,lease_until=?2,updated_at=?3 WHERE id=?4 AND status='PENDING'", params![worker_id,deadline,now,id]).map_err(|error| db_error(&error))?;
        tx.commit().map_err(|error| db_error(&error))?;
        Ok(Some(JobLease {
            id,
            worker_id,
            attempt: attempts + 1,
            payload,
        }))
    }

    fn complete_job(&self, lease: &JobLease, now: u64) -> Result<(), AppError> {
        // Same boundary as `claim_job`: the guard admits the write and then
        // carries the verification result commit.
        let mut db = self.writable_db()?;
        let status = validate_lease(&db, lease, now)?;
        if status == "DONE" {
            return Ok(());
        }
        self.verify_canonical(&db, &lease.payload.blob_id)?;
        let tx = db.transaction().map_err(|error| db_error(&error))?;
        tx.execute(
            "UPDATE blobs SET verified_at=strftime('%Y-%m-%dT%H:%M:%fZ',?1,'unixepoch') WHERE id=?2",
            params![unix_seconds(now)?, lease.payload.blob_id],
        )
        .map_err(|error| db_error(&error))?;
        tx.execute(
            "UPDATE jobs SET status='DONE',lease_until=NULL,updated_at=?1 WHERE id=?2",
            params![timestamp(now)?, lease.id],
        )
        .map_err(|error| db_error(&error))?;
        #[cfg(test)]
        crate::tests::checkpoint("JOB_COMMIT");
        tx.commit().map_err(|error| db_error(&error))
    }

    fn fail_job(&self, lease: &JobLease, now: u64, retryable: bool) -> Result<(), AppError> {
        let mut db = self.db()?;
        if validate_lease(&db, lease, now)? == "DONE" {
            return Err(AppError::new(ErrorCode::JobTerminal));
        }
        let tx = db.transaction().map_err(|error| db_error(&error))?;
        let max_attempts: u32 = tx
            .query_row(
                "SELECT max_attempts FROM jobs WHERE id=?1",
                [&lease.id],
                |r| r.get(0),
            )
            .map_err(|error| db_error(&error))?;
        let should_retry = retryable && lease.attempt < max_attempts;
        let base = 1_u64 << lease.attempt.min(8);
        let delay = base + u64::from(random_id()?[0]) % (base + 1);
        let available = timestamp(
            now.checked_add(delay)
                .ok_or_else(|| AppError::new(ErrorCode::Internal))?,
        )?;
        let status = if should_retry {
            "PENDING"
        } else {
            "FAILED_TERMINAL"
        };
        let code = if should_retry {
            "JOB_RETRYABLE"
        } else {
            "JOB_TERMINAL"
        };
        tx.execute("UPDATE jobs SET status=?1,leased_by=NULL,lease_until=NULL,available_at=?2,updated_at=?3,last_error_code=?4,last_error_message=?4 WHERE id=?5", params![status,available,timestamp(now)?,code,lease.id]).map_err(|error| db_error(&error))?;
        tx.commit().map_err(|error| db_error(&error))
    }
}

fn validate_lease(db: &Connection, lease: &JobLease, now: u64) -> Result<String, AppError> {
    let (status, worker, attempt, deadline, payload): (
        String,
        Option<String>,
        u32,
        Option<String>,
        String,
    ) = db
        .query_row(
            "SELECT status,leased_by,attempts,lease_until,payload_json FROM jobs WHERE id=?1",
            [&lease.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .map_err(|error| db_error(&error))?;
    let now = timestamp(now)?;
    if worker.as_deref() != Some(&lease.worker_id)
        || attempt != lease.attempt
        || serde_json::from_str::<VerificationPayload>(&payload)
            .map_err(|_| AppError::new(ErrorCode::JobTerminal))?
            != lease.payload
        || !matches!(status.as_str(), "PROCESSING" | "DONE")
        || (status == "PROCESSING" && deadline.as_deref().is_none_or(|d| d <= now.as_str()))
    {
        return Err(AppError::new(ErrorCode::JobTerminal));
    }
    Ok(status)
}

impl Vault {
    /// Cancels only an unclaimed PENDING job.
    /// # Errors
    /// Returns `JOB_TERMINAL` when the job is already leased/finished or missing.
    pub fn cancel_pending_job(&self, id: &str) -> Result<(), AppError> {
        let changed = self.db()?.execute("UPDATE jobs SET status='CANCELLED',updated_at=printf('%020d',unixepoch()) WHERE id=?1 AND status='PENDING'", [id]).map_err(|error| db_error(&error))?;
        if changed != 1 {
            return Err(AppError::new(ErrorCode::JobTerminal));
        }
        Ok(())
    }
}
