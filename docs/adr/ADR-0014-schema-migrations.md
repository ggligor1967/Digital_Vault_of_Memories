# ADR-0014: Ordered checksummed migrations

Status: accepted G3 design; G3 CLOSED. Existing ADR identifiers are unchanged.

The historical G1 `crates/dvm-storage/src/schema.sql` remains byte-for-byte unchanged and retains its version-1 `g1-bootstrap` checksum interpretation. New migrations are immutable numbered files under `migrations/`. Version 2 is `0002_g3_backup_history.sql`, an additive LOW-risk table. Its exact bytes are SHA-256 hashed at application time and recorded in `schema_migrations`.

On open, the binary reads `user_version` and refuses a newer schema before migration writes or journal-mode changes. It checks that every committed migration version, name, and checksum matches the bundled ordered prefix. Missing, duplicate, non-contiguous, and modified history fails. New vaults create historical v1 and then apply v2 through the same machinery. The G2 header's `schema_version: 1` remains the header format's historical value; DB `user_version` is 2. The header format is not silently rewritten by a DB migration.

Each migration executes DDL, history insertion, and `user_version` update in one SQLite transaction. LOW-risk additive v2 needs no prior backup. The framework refuses a HIGH-risk migration without an independently verified recovery point; no destructive production migration is introduced. Child-process termination tests prove restart reaches only complete v1 or complete v2. A vault's single-owner lock and DB mutex coordinate migration, snapshot, and writes. Opening a future encrypted WAL database may rebuild its transient `-shm` index; the DB, WAL, and canonical blobs remain unchanged.
