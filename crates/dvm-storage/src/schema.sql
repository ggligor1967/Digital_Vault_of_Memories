CREATE TABLE schema_migrations (
 version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TEXT NOT NULL
);
CREATE TABLE blobs (
 id TEXT PRIMARY KEY, sha256_hex TEXT NOT NULL CHECK(length(sha256_hex)=64),
 size_bytes INTEGER NOT NULL CHECK(size_bytes>=0), mime_type TEXT,
 storage_relpath TEXT NOT NULL UNIQUE, crypto_format_version INTEGER NOT NULL CHECK(crypto_format_version=1),
 created_at TEXT NOT NULL, verified_at TEXT, UNIQUE(sha256_hex,size_bytes)
);
CREATE UNIQUE INDEX blobs_hash_integrity ON blobs(sha256_hex);
CREATE TABLE items (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, title TEXT, source_name TEXT, source_path_hint TEXT,
 captured_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 favorite INTEGER NOT NULL DEFAULT 0 CHECK(favorite IN (0,1)),
 status TEXT NOT NULL CHECK(status IN ('IMPORTING','IMPORTED','PROCESSING','READY','PARTIAL','FAILED','CORRUPTED','DELETING')),
 metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE item_blobs (
 item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
 blob_id TEXT NOT NULL REFERENCES blobs(id) ON DELETE RESTRICT,
 role TEXT NOT NULL, ordinal INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(item_id,role,ordinal)
);
CREATE TABLE jobs (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind='VERIFY_ORIGINAL'),
 item_id TEXT REFERENCES items(id) ON DELETE CASCADE,
 payload_json TEXT NOT NULL CHECK(length(payload_json)<=256),
 status TEXT NOT NULL CHECK(status IN ('PENDING','PROCESSING','DONE','FAILED_TERMINAL','CANCELLED')),
 priority INTEGER NOT NULL DEFAULT 100, attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
 max_attempts INTEGER NOT NULL DEFAULT 5 CHECK(max_attempts>0), leased_by TEXT, lease_until TEXT,
 available_at TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE,
 last_error_code TEXT, last_error_message TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX jobs_runnable_idx ON jobs(status,available_at,priority,created_at);
