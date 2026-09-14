# ADR-0002: Native encrypted SQLite and journal policy

Status: G1 implementation decision; verification is recorded in the G1 evidence file.

Use exactly rusqlite 0.40.2 with default features disabled and
bundled-sqlcipher-vendored-openssl. SQLCipher and OpenSSL compile from Cargo-locked
source, with the Windows MSVC C toolchain and Perl needed by OpenSSL. No system
SQLCipher library or precompiled crypto artifact is accepted. Clean-room proof is
mandatory before acceptance. FTS5 build capability is checked in an in-memory
temporary table; G4 search is not implemented.

Apply the HKDF-derived raw 32-byte DB key before any page/schema operation using
the documented SQLCipher raw-key hex syntax. The temporary key encoding is
zeroized; it is never logged or stored. Check cipher_version/provider, actual
schema read, HMAC enabled, encrypted header, cipher_integrity_check and SQLite
integrity_check. Require cipher_status=1 from the pinned provider (introduced in 4.12.0).
Wrong key must fail an actual page read before any writes. SQLCipher defaults
remain intact; no KDF/security cost reduction.

Keep the documented default for optional cipher_memory_security. Enabling global
allocation locking caused STATUS_STACK_OVERFLOW in the optimized Windows test:
VirtualLock quota error 1453 logs through sqlcipher_fprintf, which allocates through
the same locked allocator and recursively logs another lock failure (bundled
SQLCipher 4.14.0 source inspected). The isolated test passes with the default;
a regression asserts that policy. SQLCipher still sanitizes cryptographic
allocations, and Rust key buffers use Zeroizing. This does not claim that every
SQLite metadata allocation or OS page is locked/wiped. Page HMAC, encrypted
headers, default cipher parameters and integrity checks remain enabled.

Select WAL, synchronous FULL, foreign_keys ON, temp_store MEMORY and secure_delete
ON. WAL contains encrypted page data; test sentinel absence in both DB and live
WAL. Check supported schema before changing persistent pragmas or bootstrapping.
No attached plaintext databases, exports, or plaintext temporary copies.

An exclusive OS file lock lives for the open vault lifetime. This prevents two
independent vault owners/reconciliation runs. Imports on a shared owner may stage
concurrently; the canonical decision and SQL commit run under a mutex. Random
canonical names are never reused or replaced. File contents are synced before
same-volume rename. Restart/crash durability is tested; simulated process death
is not a hardware power-loss certification.

On Windows, std::fs::rename maps to MoveFileExW; both candidate and canonical
are children of the same vault root, so activation does not use a copy/delete
fallback. The standard operation can replace a destination, so the adapter checks
destination absence while holding its finalization mutex and the exclusive vault
owner lock; random IDs are not recycled. The supported cooperating-writer model
therefore cannot overwrite an existing canonical name. A separate sync_all on
the activated file requests FlushFileBuffers before the DB commit. Unix also
syncs the blobs directory. Windows process-crash tests exercise this actual path;
hostile external filesystem mutation and controller power-loss guarantees are
outside this G1 test boundary.

Rejected: sql.js/browser storage (trust/durability), system SQLCipher (hidden build
dependency), plaintext SQLite (confidentiality), ORM (unnecessary abstraction),
G3 migration engine (out of scope).

Sources checked during G1:

- https://www.zetetic.net/sqlcipher/sqlcipher-api/
- https://github.com/rusqlite/rusqlite
- https://docs.rs/crate/rusqlite/0.40.2/features
- https://sqlite.org/wal.html
- https://sqlite.org/pragma.html#pragma_synchronous
- https://doc.rust-lang.org/std/fs/struct.File.html
- https://doc.rust-lang.org/std/fs/fn.rename.html
