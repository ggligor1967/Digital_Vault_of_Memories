CREATE TABLE backup_history (
 backup_id TEXT PRIMARY KEY,
 format_version INTEGER NOT NULL,
 schema_version INTEGER NOT NULL,
 destination_hint TEXT,
 verification_mode TEXT NOT NULL,
 status TEXT NOT NULL,
 created_at TEXT NOT NULL,
 verified_at TEXT
);
