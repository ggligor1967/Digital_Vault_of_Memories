# Digital Vault of Memories — Blueprint v2

**Document class:** Normative implementation blueprint  
**Version:** 2.0.0  
**Status:** APPROVED DESIGN BASELINE / NOT YET AN IMPLEMENTATION  
**Date:** 2026-09-13  
**Primary target:** Desktop, Windows-first, cross-platform-capable  
**Reference stack:** React + TypeScript + Vite renderer; Tauri 2 + Rust trusted backend; native encrypted SQLite; encrypted blob store  

---

## 0. Executive decision

Blueprint v2 replaces the original architecture rather than patching it in place.

The product concept is retained:

> **Bucket → Funnel → Sieve → Cabinet → Robot → Lab**

The implementation model is changed so that the application can make and prove the following claims:

1. an accepted memory is recoverable byte-for-byte;
2. a process crash cannot silently discard an accepted job;
3. sensitive vault content is encrypted at rest with a versioned key hierarchy;
4. the React renderer never owns vault keys, provider secrets, arbitrary filesystem access, or arbitrary shell access;
5. lexical search is real SQLite FTS5 search over the unlocked encrypted database;
6. semantic search uses actual persisted embeddings and an actual vector index;
7. remote AI is optional, explicit, scoped, and observable;
8. backup/restore is a release gate, not an auxiliary feature;
9. every migration, index and derived artifact is versioned and recoverable;
10. the project cannot be called production-ready until all mandatory gates in this document pass.

This document is the single normative source of truth. Older Blueprint documents are historical input only and MUST NOT override this specification.

---

## 1. Normative language

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

Priority classes:

- **P0** — data loss, secret exposure, cryptographic failure, unrecoverable corruption, false security claim, or inability to build/run deterministically.
- **P1** — major correctness, privacy, availability, compatibility or maintainability defect.
- **P2** — UX/performance/operational improvement that does not invalidate vault correctness.

A gate marked **MANDATORY** blocks all later feature work until it passes.

---

## 2. Product definition

Digital Vault of Memories (DVM) is a local-first desktop application for importing, preserving, organizing, searching, enriching and exporting personal digital memories such as photographs, videos, audio, documents and text.

### 2.1 Product principles

DVM MUST follow these principles:

1. **Preservation before intelligence.** Original bytes are more important than derived metadata.
2. **Local core.** Import, storage, browse, lexical search, backup and restore MUST work without Internet access.
3. **Explicit egress.** Remote AI or remote synchronization never happens implicitly.
4. **Zero silent loss.** No successful operation may be reported unless its durable postconditions hold.
5. **Derived data is disposable.** Thumbnails, OCR, embeddings and vector indexes may be rebuilt from canonical data.
6. **Secrets stay behind the trust boundary.** The renderer receives capability results, never root secrets.
7. **Version everything that affects interpretation.** Schema, blob format, crypto format, embeddings and backup formats are versioned.
8. **Recovery is a first-class path.** Destructive restore testing is mandatory before production release.
9. **Least privilege.** Frontend capabilities are explicit and minimal.
10. **No aspirational labels.** Features are documented as implemented, experimental, planned or unsupported.

### 2.2 MVP scope

The desktop MVP MUST include:

- create/open/lock/unlock vault;
- passphrase-based key protection;
- optional device quick-unlock using OS credential storage;
- generated recovery key/keyslot;
- file and folder import;
- streaming SHA-256 hashing;
- encrypted preservation of original bytes;
- duplicate detection;
- durable SQLite-backed processing queue;
- metadata extraction and thumbnails for supported types;
- browse/filter/sort;
- SQLite FTS5 lexical search;
- real embedding storage and vector retrieval;
- hybrid lexical + semantic search;
- local AI provider support when installed;
- optional remote AI providers with explicit egress consent;
- backup creation, validation and restore;
- migration framework;
- local diagnostics and redacted support bundle;
- Windows installer/package and signed updater path;
- automated tests and CI gates defined below.

### 2.3 Explicit non-goals for MVP

The following MUST NOT block the MVP and MUST NOT be implemented before gates G0-G6 pass:

- third-party plugin marketplace;
- arbitrary third-party code execution;
- multi-user collaboration;
- peer-to-peer sync;
- cloud account requirement;
- AR/VR interfaces;
- IPFS storage;
- zero-knowledge proof features;
- social sharing network;
- React Native application;
- cross-device E2E synchronization.

These remain post-MVP tracks with explicit prerequisites in Sections 31-33.

---

## 3. Preserved UX model

The original mental model remains, but each stage maps to a concrete technical contract.

| Product stage | Meaning in v2 | Canonical subsystem |
|---|---|---|
| **Bucket** | Receive files/folders and validate source paths | ImportService |
| **Funnel** | Stream, hash, encrypt, persist and enqueue | BlobStore + Import transaction |
| **Sieve** | Deduplicate, classify, extract and validate | JobService + processors |
| **Cabinet** | Browse and deterministic lexical retrieval | MetadataRepository + FTS5 |
| **Robot** | Semantic retrieval and optional AI reasoning | EmbeddingService + VectorIndex + AI gateway |
| **Lab** | Derived outputs without mutating originals | Export/Transform services |

UI labels MAY keep the friendly terminology; code and tests MUST use the explicit subsystem contracts.

---

## 4. Threat model

Security claims are valid only against the threat model below.

### 4.1 Assets

Protected assets include:

- original imported bytes;
- titles, tags, extracted text, OCR and notes;
- thumbnails and derived media;
- embeddings;
- vault master key material;
- remote-provider API credentials;
- backup contents;
- audit/support logs that may reveal metadata.

### 4.2 Threats in scope

The system MUST address:

- theft or copying of the vault directory while the application is locked;
- theft of backup files;
- accidental file deletion/corruption;
- process termination during import, processing, migration or backup;
- malformed/corrupt media input;
- renderer compromise attempting to invoke excessive native capabilities;
- accidental cloud data egress;
- compromised or malformed AI/provider responses;
- tampering with stored ciphertext;
- replay/duplication of durable jobs;
- malicious archive contents during restore;
- downgrade to incompatible/unsafe database or blob formats;
- leaked logs or support bundles;
- update artifact tampering.

### 4.3 Threats not fully solved by the application

DVM MUST document that it cannot guarantee confidentiality when:

- malware executes with equivalent or higher privileges while the vault is unlocked;
- the operating system itself is compromised;
- an attacker can read process memory during active use;
- the user voluntarily sends content to a remote provider;
- the user loses both the passphrase and all recovery key material.

The product MUST NOT market itself as resistant to a fully compromised host.

### 4.4 Trust boundaries

```text
UNTRUSTED / LESS TRUSTED
┌──────────────────────────────────────────┐
│ React renderer / WebView                 │
│ UI state, typed DTOs, no vault secrets   │
└───────────────────┬──────────────────────┘
                    │ allowlisted typed IPC
TRUST BOUNDARY      ▼
┌──────────────────────────────────────────┐
│ Tauri/Rust application backend           │
│ domain/application services              │
├──────────────────────────────────────────┤
│ Crypto / SQLite / blob / jobs / search   │
│ provider gateway / media processors      │
└───────┬───────────────┬──────────────────┘
        │               │
        ▼               ▼
  Local filesystem   OS credential store
        │
        ▼
 Encrypted vault data

OPTIONAL REMOTE TRUST BOUNDARY
Rust ProviderGateway → explicitly approved HTTPS provider
```

---

## 5. System invariants

Every implementation MUST encode these invariants as tests where feasible.

### Core data invariants

- **INV-001 — Recoverable original:** if import reports `SUCCESS`, the original plaintext bytes MUST be recoverable byte-for-byte.
- **INV-002 — Hash identity:** every canonical blob MUST have a plaintext SHA-256 and size recorded in the encrypted database.
- **INV-003 — No orphan success:** an item MUST NOT become `READY` unless its required canonical blob exists and its DB references are committed.
- **INV-004 — No silent corruption:** authenticated decryption failure MUST surface as corruption and MUST NOT return partial plaintext as valid content.
- **INV-005 — Immutable originals:** processing MUST NOT modify canonical imported bytes.

### Queue invariants

- **INV-006 — Durable job:** a persisted job MUST survive application/process restart.
- **INV-007 — Stable payload:** durable jobs MUST reference stable IDs/paths owned by the vault, never browser `File` objects or ephemeral handles.
- **INV-008 — ACK-after-success:** a job MUST NOT become `DONE` before all required durable writes commit.
- **INV-009 — Crash recovery:** an expired processing lease MUST become eligible for retry without creating duplicate canonical results.
- **INV-010 — Idempotency:** retrying a completed idempotent job MUST not duplicate canonical artifacts.

### Security invariants

- **INV-011 — Renderer isolation:** the renderer MUST NOT receive the Vault Master Key, raw DB key, blob root key or cloud-provider secret.
- **INV-012 — No generic shell:** the renderer MUST NOT have arbitrary shell execution.
- **INV-013 — No generic filesystem:** the renderer MUST NOT have arbitrary read/write access to the host filesystem.
- **INV-014 — Explicit remote egress:** any remote processing operation MUST map to a visible approved egress scope.
- **INV-015 — Locked means inaccessible:** while locked, vault metadata/content MUST not be queryable through application IPC.

### Search/AI invariants

- **INV-016 — Search IDs are real:** lexical or semantic results MUST reference existing item IDs returned by deterministic retrieval, not hallucinated IDs.
- **INV-017 — Compatible embeddings:** a vector query MUST only compare embeddings with compatible model identity, revision and dimension.
- **INV-018 — Index is derived:** deletion of the vector index MUST NOT destroy canonical embeddings or originals.
- **INV-019 — AI is optional:** vault browse, lexical search, backup and restore MUST work with all AI providers disabled.
- **INV-020 — AI provenance:** generated metadata MUST record provider/model/capability/schema provenance.

### Recovery and evolution invariants

- **INV-021 — Restore verification:** a backup cannot be declared restorable until structural and cryptographic validation passes.
- **INV-022 — Schema monotonicity:** a binary MUST refuse to mutate a vault with a schema version newer than it supports.
- **INV-023 — Migration atomicity:** a failed schema migration MUST leave either the pre-migration or post-migration state, never an undocumented hybrid.
- **INV-024 — Format readability:** blob and backup format versions MUST be explicit; readers MUST reject unknown mandatory versions.
- **INV-025 — Release proof:** production release MUST include evidence for all mandatory gates in Section 36.

---

## 6. Canonical architecture

### 6.1 Logical architecture

```text
┌─────────────────────────────────────────────┐
│ Presentation — React/TypeScript/Vite        │
│                                             │
│ Routes / views / forms / progress / a11y    │
│ No SQL, no crypto, no provider credentials  │
└────────────────────┬────────────────────────┘
                     │ generated typed IPC
┌────────────────────▼────────────────────────┐
│ Application layer — Rust                    │
│                                             │
│ VaultService       ImportService            │
│ SearchService      JobService               │
│ BackupService      SettingsService          │
│ AIService          ExportService            │
└─────────────┬──────────┬──────────┬─────────┘
              │          │          │
┌─────────────▼──┐ ┌────▼──────┐ ┌─▼────────────┐
│ Domain/core    │ │ Ports      │ │ Event model   │
│ entities       │ │ traits     │ │ typed errors  │
│ invariants     │ │ contracts  │ │ progress      │
└─────────────┬──┘ └────┬──────┘ └───────────────┘
              │         │ adapters
┌─────────────▼─────────▼──────────────────────┐
│ Trusted infrastructure — Rust               │
│                                             │
│ SQLCipher/SQLite  Encrypted BlobStore        │
│ FTS5             VectorIndex                │
│ OS keychain      Crypto                     │
│ Media            Local/remote provider I/O  │
│ Backup/restore   Structured logging         │
└─────────────────────────────────────────────┘
```

### 6.2 Dependency rule

Dependencies MUST point inward:

```text
presentation → application → domain/ports ← infrastructure
```

React components MUST NOT import database, crypto, filesystem or AI SDK modules.

Infrastructure adapters MUST implement domain/application ports and MUST be replaceable in tests.

---

## 7. Repository topology

The reference repository MUST use one frontend lockfile and one Rust lockfile committed to source control.

```text
digital-vault-of-memories/
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── pnpm-workspace.yaml
├── pnpm-lock.yaml
├── package.json
├── Cargo.toml
├── Cargo.lock
├── apps/
│   └── desktop/
│       ├── index.html
│       ├── package.json
│       ├── vite.config.ts
│       ├── tsconfig.json
│       ├── src/
│       │   ├── app/
│       │   ├── features/
│       │   ├── components/
│       │   ├── ipc/
│       │   └── styles/
│       └── src-tauri/
│           ├── Cargo.toml
│           ├── tauri.conf.json
│           ├── capabilities/
│           └── src/
├── crates/
│   ├── dvm-domain/
│   ├── dvm-application/
│   ├── dvm-crypto/
│   ├── dvm-storage/
│   ├── dvm-search/
│   ├── dvm-ai/
│   ├── dvm-media/
│   ├── dvm-backup/
│   └── dvm-observability/
├── packages/
│   ├── contracts/
│   └── test-fixtures/
├── migrations/
├── tests/
│   ├── integration/
│   ├── crash/
│   ├── e2e/
│   ├── security/
│   └── performance/
├── docs/
│   ├── architecture/
│   ├── threat-model/
│   ├── adr/
│   └── release-evidence/
└── scripts/
```

### 7.1 Build reproducibility rules

- `pnpm-lock.yaml` MUST be committed.
- `Cargo.lock` MUST be committed for the application workspace.
- CI MUST use `pnpm install --frozen-lockfile`.
- CI MUST use `cargo ... --locked` where supported.
- Node/pnpm/Rust versions MUST be pinned through repository-supported version metadata.
- Dependency updates MUST arrive through reviewed PRs; no floating production dependency installation.
- The project MUST NOT claim “copy-and-paste-ready” unless a clean-room clone gate passes.

---

## 8. Filesystem layout of one vault

Reference layout:

```text
<vault-root>/
├── vault.header
├── metadata.db
├── blobs/
│   ├── 00/
│   ├── 01/
│   └── ...
├── indexes/
│   └── vector/
├── tmp/
├── quarantine/
└── local-state/
```

Rules:

- `vault.header` contains versioned non-secret KDF metadata plus encrypted keyslots.
- `metadata.db` is an encrypted native SQLite/SQLCipher database.
- blob filenames MUST be random vault identifiers, not plaintext filenames.
- plaintext original filenames and source path hints MUST be stored only inside the encrypted database.
- `tmp/` may contain only application-owned transient encrypted or non-sensitive staging data; plaintext temp files SHOULD be avoided.
- vector indexes are derived and MAY be deleted/rebuilt.
- logs MUST live outside the vault data set and MUST be redacted.

---

## 9. Cryptographic architecture

### 9.1 Non-negotiable rule

DVM MUST NOT invent a new primitive. It MAY define a file framing format, but cryptographic primitives MUST come from maintained, audited libraries.

### 9.2 Key hierarchy

```text
User passphrase
     │
     ▼
Argon2id(passphrase, random salt, versioned calibrated parameters)
     │
     ▼
Passphrase KEK ───────────────┐
                              │ unwrap
Recovery key → Recovery KEK ──┼──────► random 256-bit Vault Master Key (VMK)
                              │
OS device key → Device KEK ───┘
                                      │
                                      ▼ HKDF-SHA-256 domain separation
                          ┌───────────┼────────────┬──────────────┐
                          ▼           ▼            ▼              ▼
                        DB key    Blob root key  Audit key    Backup key
```

### 9.3 Passphrase KDF

- Default KDF MUST be Argon2id.
- `vault.header` MUST persist algorithm identifier, salt and parameters.
- Parameters MUST never fall below the project security baseline.
- Baseline for initial implementation: at least the current OWASP minimum-equivalent Argon2id profile (19 MiB memory, 2 iterations, parallelism 1).
- Setup SHOULD benchmark the device and increase cost toward an interactive target while preserving the minimum.
- KDF parameters MUST be upgradeable without re-encrypting all content: only a keyslot rewrap is required.

### 9.4 Vault Master Key

- VMK MUST be generated from an OS CSPRNG.
- VMK MUST NOT be derived directly from the passphrase.
- Passphrase changes MUST rewrap the same VMK unless an explicit full key rotation is requested.
- Sensitive key buffers SHOULD use memory-zeroization facilities when released.

### 9.5 Keyslots

`vault.header` MUST support multiple independent keyslots:

1. `passphrase-v1` — mandatory;
2. `recovery-v1` — mandatory at vault creation unless the user explicitly declines after warning;
3. `device-v1` — optional, backed by the operating system credential manager.

Each slot MUST use authenticated encryption and MUST bind the slot metadata as AAD.

### 9.6 Database encryption

The reference implementation MUST use native SQLite with SQLCipher as the canonical encrypted-database layer. Any departure from SQLCipher requires a dedicated ADR, equivalent confidentiality/integrity evidence, FTS5 compatibility proof, migration impact analysis and explicit approval before implementation.

Requirements:

- the database key MUST be a random/HKDF-derived raw key, not a human passphrase;
- FTS5 support MUST be compiled/enabled and tested;
- integrity/authentication support MUST remain enabled;
- plaintext DB copies MUST NOT be created as a normal operating path;
- SQLite WAL/journal behavior MUST be verified under the chosen encrypted implementation;
- temporary SQLite files MUST inherit equivalent protection.

### 9.7 Blob encryption

Reference format: **DVB1**.

- Primitive for DVB1 MUST be XChaCha20-Poly1305. A different AEAD requires a new blob-format version, dedicated ADR, migration/read-compatibility plan and cryptographic review; it MUST NOT be substituted silently.
- Every blob receives a random `blob_id`.
- A blob-specific key is derived with HKDF from `BlobRootKey` and `blob_id`.
- Large files MUST be encrypted in bounded chunks; whole-file buffering is forbidden.
- Reference chunk size: 4 MiB, configurable only through versioned format rules.
- Every chunk MUST use a unique nonce.
- For XChaCha20-Poly1305, a valid construction is a per-blob random nonce prefix plus monotonically increasing chunk index.
- Chunk index, format version, blob ID and plaintext length MUST be authenticated as AAD.
- Truncation, reordering, duplication or substitution of chunks MUST be detectable.

Conceptual framing:

```text
[DVB1 header]
  magic
  format_version
  blob_id
  chunk_size
  original_size
  algorithm_id
  nonce_prefix
  authenticated header fields

[chunk 0]
  plaintext_length
  ciphertext
  authentication_tag

[chunk 1]
  ...
```

### 9.8 Hashing and deduplication

- SHA-256 MUST be computed over plaintext bytes while streaming the import.
- A complete file MUST NOT be loaded into RAM solely to compute a hash.
- Dedup canonical identity is `(sha256, size_bytes)`.
- A same-hash/different-size condition MUST be treated as integrity failure, not normal deduplication.
- Blob path MUST NOT expose the plaintext SHA-256.

### 9.9 Cryptographic agility

All encrypted formats MUST persist an algorithm/version identifier. New writes use the current format; old formats remain readable until an explicit migration lifecycle removes them.

Unknown mandatory crypto formats MUST fail closed.

---

## 10. Secrets and credential storage

### 10.1 Rules

Provider API keys MUST NOT be stored in:

- `localStorage`;
- renderer memory longer than a single secure handoff;
- plaintext config files;
- logs;
- crash reports;
- the encrypted database unless there is a documented reason and equivalent key separation.

### 10.2 OS credential manager

Desktop provider credentials SHOULD use the OS credential manager through a Rust adapter.

The database stores only a non-secret reference:

```text
secret_ref = "provider/openai/default"
```

The renderer may ask `providerConfigured(providerId)` but MUST NOT receive the secret value.

### 10.3 Secret redaction

All logging/tracing layers MUST support field-level redaction. Values matching configured credential sources MUST never be rendered in normal logs.

---

## 11. Canonical data model

All sensitive metadata resides inside the encrypted database.

### 11.1 Core schema

The SQL below is normative in shape; exact naming MAY evolve only through a recorded migration/ADR.

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE schema_migrations (
  version          INTEGER PRIMARY KEY,
  name             TEXT NOT NULL,
  checksum         TEXT NOT NULL,
  applied_at       TEXT NOT NULL
);

CREATE TABLE blobs (
  id                    TEXT PRIMARY KEY,
  sha256_hex            TEXT NOT NULL,
  size_bytes            INTEGER NOT NULL CHECK(size_bytes >= 0),
  mime_type             TEXT,
  storage_relpath       TEXT NOT NULL UNIQUE,
  crypto_format_version INTEGER NOT NULL,
  created_at            TEXT NOT NULL,
  verified_at           TEXT,
  UNIQUE(sha256_hex, size_bytes)
);

CREATE TABLE items (
  id               TEXT PRIMARY KEY,
  kind             TEXT NOT NULL,
  title            TEXT,
  source_name      TEXT,
  source_path_hint TEXT,
  captured_at      TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL,
  favorite         INTEGER NOT NULL DEFAULT 0 CHECK(favorite IN (0,1)),
  status           TEXT NOT NULL,
  metadata_json    TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE item_blobs (
  item_id     TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  blob_id     TEXT NOT NULL REFERENCES blobs(id) ON DELETE RESTRICT,
  role        TEXT NOT NULL,
  ordinal     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(item_id, role, ordinal)
);

CREATE TABLE tags (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  normalized_name TEXT NOT NULL UNIQUE
);

CREATE TABLE item_tags (
  item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  tag_id  TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  source  TEXT NOT NULL,
  PRIMARY KEY(item_id, tag_id, source)
);

CREATE TABLE search_documents (
  rowid          INTEGER PRIMARY KEY,
  item_id        TEXT NOT NULL UNIQUE REFERENCES items(id) ON DELETE CASCADE,
  title          TEXT NOT NULL DEFAULT '',
  body           TEXT NOT NULL DEFAULT '',
  tags           TEXT NOT NULL DEFAULT '',
  source_hash    TEXT NOT NULL
);

CREATE VIRTUAL TABLE search_fts USING fts5(
  title,
  body,
  tags,
  content='search_documents',
  content_rowid='rowid',
  tokenize='unicode61 remove_diacritics 2'
);

CREATE TABLE embeddings (
  item_id         TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  field           TEXT NOT NULL,
  provider_id     TEXT NOT NULL,
  model_id        TEXT NOT NULL,
  model_revision  TEXT NOT NULL,
  dimension       INTEGER NOT NULL CHECK(dimension > 0),
  vector_f32_le   BLOB NOT NULL,
  source_hash     TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  PRIMARY KEY(item_id, field, provider_id, model_id, model_revision)
);

CREATE TABLE jobs (
  id                 TEXT PRIMARY KEY,
  kind               TEXT NOT NULL,
  item_id            TEXT REFERENCES items(id) ON DELETE CASCADE,
  payload_json       TEXT NOT NULL DEFAULT '{}',
  status             TEXT NOT NULL CHECK(status IN ('PENDING','PROCESSING','DONE','FAILED_TERMINAL','CANCELLED')),
  priority           INTEGER NOT NULL DEFAULT 100,
  attempts           INTEGER NOT NULL DEFAULT 0,
  max_attempts       INTEGER NOT NULL DEFAULT 5,
  leased_by          TEXT,
  lease_until        TEXT,
  available_at       TEXT NOT NULL,
  idempotency_key    TEXT NOT NULL UNIQUE,
  last_error_code    TEXT,
  last_error_message TEXT,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL
);

CREATE INDEX jobs_runnable_idx
ON jobs(status, available_at, priority, created_at);

CREATE TABLE ai_runs (
  id               TEXT PRIMARY KEY,
  item_id          TEXT REFERENCES items(id) ON DELETE SET NULL,
  capability       TEXT NOT NULL,
  provider_id      TEXT NOT NULL,
  model_id         TEXT NOT NULL,
  model_revision   TEXT,
  is_remote        INTEGER NOT NULL CHECK(is_remote IN (0,1)),
  egress_scope     TEXT NOT NULL,
  request_hash     TEXT NOT NULL,
  output_schema    TEXT NOT NULL,
  output_json      TEXT,
  status           TEXT NOT NULL,
  created_at       TEXT NOT NULL
);

CREATE TABLE settings (
  key         TEXT PRIMARY KEY,
  value_json  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE secret_refs (
  name             TEXT PRIMARY KEY,
  credential_store TEXT NOT NULL,
  account_ref      TEXT NOT NULL,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);

CREATE TABLE audit_events (
  sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
  event_time     TEXT NOT NULL,
  event_type     TEXT NOT NULL,
  subject_id     TEXT,
  payload_json   TEXT NOT NULL,
  previous_hash  TEXT,
  event_hash     TEXT NOT NULL,
  mac_hex        TEXT NOT NULL
);

CREATE TABLE backup_history (
  backup_id          TEXT PRIMARY KEY,
  format_version     INTEGER NOT NULL,
  schema_version     INTEGER NOT NULL,
  destination_hint  TEXT,
  verification_mode TEXT NOT NULL,
  status             TEXT NOT NULL,
  created_at         TEXT NOT NULL,
  verified_at        TEXT
);
```

### 11.2 FTS synchronization

FTS synchronization MUST be deterministic. The implementation MAY use triggers or an application-managed indexing transaction, but tests MUST prove that insert/update/delete operations keep `search_documents` and `search_fts` consistent.

### 11.3 Canonical versus derived data

Canonical:

- encrypted originals;
- item metadata explicitly created/accepted by the user;
- tags/notes;
- canonical extracted text if designated as user-visible data;
- job history needed for correctness;
- provider provenance records.

Derived/rebuildable:

- thumbnails;
- cached previews;
- FTS table if reconstructable from canonical search documents;
- vector HNSW index;
- temporary transcodes;
- UI caches.

---

## 12. Import pipeline — zero-loss vertical slice

### 12.1 Input contract

The renderer provides only user-selected/dropped path descriptors to the trusted backend. It does not read the entire source file into JavaScript memory.

### 12.2 Pipeline

```text
SELECT/DROP SOURCE
      │
      ▼
validate path/type/access
      │
      ▼
create import session
      │
      ▼
stream source once
 ┌────┼──────────────┐
 ▼    ▼              ▼
SHA256 encrypt chunks metadata probe
      │
      ▼
write <vault>/tmp/<uuid>.part
      │
      ▼
flush + fsync + close
      │
      ▼
verify final AEAD framing
      │
      ▼
atomic rename into blobs/
      │
      ▼
BEGIN DB TRANSACTION
  upsert/reuse blob by sha256+size
  create item
  create item_blob reference
  enqueue required jobs
COMMIT
      │
      ▼
report SUCCESS
```

### 12.3 Failure rules

- Before atomic blob rename: remove stale `.part` on recovery.
- After blob rename but before DB commit: startup reconciliation detects an unreferenced blob and moves it to quarantine or safely reconciles it.
- DB row referencing missing blob: mark affected item `CORRUPTED`, block READY state and surface repair guidance.
- UI MUST distinguish `IMPORTED`, `PROCESSING`, `READY`, `PARTIAL`, `FAILED`, `CORRUPTED`.

### 12.4 Duplicate behavior

If a blob with the same `(sha256,size)` already exists:

- do not write duplicate canonical encrypted bytes;
- create a new item reference only when the user workflow expects a distinct logical item;
- otherwise offer/perform metadata merge according to an explicit dedup policy;
- never silently discard user metadata associated with an incoming logical item.

### 12.5 Large-file requirement

No normal import path may require memory proportional to file size. A multi-GB file MUST import using bounded memory.

---

## 13. Durable job engine

### 13.1 State machine

```text
                 ┌──────────────────────┐
                 │                      │
                 ▼                      │ retry/backoff
PENDING ──lease──► PROCESSING ──error───┘
  │                   │
  │ cancel            │ durable success
  ▼                   ▼
CANCELLED            DONE
                      
PROCESSING ──non-retryable/max attempts──► FAILED_TERMINAL

PROCESSING with expired lease ──startup/worker recovery──► PENDING
```

### 13.2 Lease rules

A worker claims work in one transaction:

1. select an eligible `PENDING` job;
2. set `PROCESSING`;
3. set `leased_by` and `lease_until`;
4. increment `attempts`;
5. commit;
6. perform work;
7. atomically persist result and set `DONE`.

### 13.3 Payload rules

`payload_json` MAY contain:

- item IDs;
- blob IDs;
- processor version;
- user options;
- stable derived artifact IDs.

It MUST NOT contain:

- browser `File` objects;
- live file handles;
- VMK/DB/blob keys;
- provider secrets;
- large binary payloads.

### 13.4 Retry policy

Retryable failures use exponential backoff with bounded jitter. Non-retryable conditions (unsupported format, deterministic schema failure, auth denied) transition to `FAILED_TERMINAL` with a typed error code.

### 13.5 Idempotency

Every job kind MUST document its idempotency key and its replay behavior.

Example:

```text
thumbnail:<item_id>:<processor_version>:<profile>
embedding:<item_id>:<source_hash>:<provider>:<model>:<revision>
ocr:<item_id>:<source_hash>:<processor_version>
```

---

## 14. Startup reconciliation

Unlock MUST perform a bounded reconciliation before normal writes begin.

Checks:

1. remove or quarantine stale `tmp/*.part` according to age/state;
2. reset expired job leases;
3. detect DB blob rows whose physical files are missing;
4. detect physical blob files with no DB reference;
5. validate schema version compatibility;
6. validate required crypto format readers;
7. validate FTS availability;
8. validate vector-index metadata and mark stale indexes for rebuild;
9. never auto-delete ambiguous data without an audit event.

Reconciliation result is one of:

- `HEALTHY`;
- `HEALTHY_WITH_REBUILD_REQUIRED`;
- `DEGRADED_READ_ONLY`;
- `REPAIR_REQUIRED`.

---

## 15. Search architecture

Search has two independent deterministic foundations and one optional reasoning layer.

### 15.1 Lexical search

SQLite FTS5 is the canonical lexical engine.

Indexed fields SHOULD include:

- title;
- tags;
- user notes;
- extracted/OCR text approved for indexing;
- normalized date/location labels when appropriate.

FTS data lives inside the encrypted database.

### 15.2 Embeddings

Embeddings are canonical derived records with explicit compatibility metadata:

```text
provider_id
model_id
model_revision
dimension
source_hash
field
created_at
```

The source hash MUST change when indexed content changes.

### 15.3 Vector index

The reference strategy is an in-process HNSW-class approximate-nearest-neighbor index behind a `VectorIndex` port.

Rules:

- the index is derived from the `embeddings` table;
- index metadata MUST include model identity, revision, dimension, algorithm version and build timestamp;
- incompatible embeddings MUST never share one index;
- index files MUST be encrypted at rest or rebuilt on startup instead of being persisted plaintext;
- deletion of the index MUST trigger a rebuild, not data loss;
- exact/brute-force cosine search MAY exist as a correctness oracle for tests/small datasets but MUST NOT be mislabeled as an ANN index.

### 15.4 Hybrid retrieval

Default hybrid retrieval SHOULD use rank fusion rather than combining incomparable raw BM25/cosine values.

Reference flow:

```text
query
 ├─► FTS5 top N
 └─► embedding → vector top N
          │
          ▼
 reciprocal-rank fusion
          │
          ▼
 filters / permissions
          │
          ▼
 deterministic item IDs + scores
```

### 15.5 AI answer layer

If the user asks for an AI-generated answer:

1. deterministic retrieval runs first;
2. only retrieved snippets/items are placed into the model context;
3. model output MUST cite/reference the provided item IDs;
4. unknown/unretrieved IDs are rejected;
5. AI answer generation is optional and MUST NOT replace basic search.

---

## 16. AI provider architecture

### 16.1 No hardcoded model assumptions

Providers and models change independently of DVM releases. The application MUST not embed business logic tied to a single hardcoded model string.

### 16.2 Capability model

```rust
pub enum AiCapability {
    Chat,
    Embedding,
    Vision,
    Transcription,
    StructuredGeneration,
}

pub struct ModelDescriptor {
    pub provider_id: String,
    pub model_id: String,
    pub revision: Option<String>,
    pub capabilities: Vec<AiCapability>,
    pub embedding_dimension: Option<usize>,
    pub is_remote: bool,
}
```

Provider ports MUST expose capability discovery or an explicitly maintained registry.

### 16.3 Provider contract

Conceptual Rust port:

```rust
#[async_trait]
pub trait AiProvider: Send + Sync {
    async fn health(&self) -> Result<ProviderHealth, AiError>;
    async fn list_models(&self) -> Result<Vec<ModelDescriptor>, AiError>;
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, AiError>;
    async fn embed(&self, request: EmbedRequest) -> Result<EmbedResponse, AiError>;
}
```

A provider that does not support a capability MUST return a typed `CapabilityUnsupported` error before starting the operation.

### 16.4 Local AI

Ollama or another local runtime MAY be supported through the same provider interface.

Local-provider integration MUST:

- perform a health check;
- discover/validate installed models;
- validate embedding dimension;
- fail gracefully when the runtime is absent;
- never auto-download multi-GB models without explicit user confirmation and disk-space disclosure.

### 16.5 Remote AI

Remote providers are disabled by default until configured.

All provider HTTP calls MUST originate in the Rust backend, never directly from renderer JavaScript.

### 16.6 Structured outputs

AI-created tags, summaries or metadata MUST be validated against a versioned schema before entering canonical metadata.

Invalid responses MAY be retried within a bounded policy. Raw unvalidated output MUST NOT mutate canonical metadata.

### 16.7 Provenance

Every persisted AI result records:

- provider;
- model ID/revision;
- capability;
- remote/local flag;
- egress scope;
- source hash;
- output schema version;
- timestamp.

---

## 17. Data-egress and privacy model

“Local-first” does not mean “no data ever leaves the device.” DVM MUST distinguish local storage from optional remote processing.

### 17.1 Egress scopes

Remote operations declare one or more scopes:

- `QUERY_ONLY` — only user query/instruction;
- `METADATA` — selected title/tags/non-binary metadata;
- `EXTRACTED_TEXT` — OCR/transcript/document text;
- `THUMBNAIL` — reduced visual derivative;
- `ORIGINAL_FILE` — canonical original bytes;
- `AUDIO_DERIVATIVE` — generated audio excerpt;
- `LOCATION_METADATA` — location-related fields.

Default policy MUST deny `ORIGINAL_FILE` and `LOCATION_METADATA` remote egress until explicitly enabled for that capability/provider.

### 17.2 Consent UI

Before first use of a remote capability, UI MUST show:

```text
Provider: <name>
Operation: <capability>
Data sent: <egress scopes>
Retention/policy: provider-dependent link/reference
Remember this choice: yes/no
```

The active screen MUST visibly distinguish `LOCAL` versus `REMOTE` processing.

### 17.3 Network-off mode

A global `Offline / Local only` mode MUST prevent remote provider calls at the backend policy layer, not merely hide UI buttons.

---

## 18. Settings architecture

There is exactly one authoritative SettingsRepository.

### 18.1 Non-secret settings

Non-secret settings live in the encrypted database or in a small versioned application config when needed before unlock.

Examples:

- theme;
- language;
- auto-lock interval;
- concurrency limits;
- default search mode;
- enabled local provider;
- remote provider IDs (not secrets);
- egress consent policies.

### 18.2 Secrets

Secrets are represented by `secret_refs` and resolved only in trusted backend code.

### 18.3 Reactive updates

Settings changes MUST publish typed application events so that services and UI update from the same authoritative value. Static `config.json` plus independent `localStorage` copies are forbidden.

---

## 19. Media-processing architecture

### 19.1 General rule

Large media MUST be processed outside the renderer and with explicit resource limits.

### 19.2 Native processors

Preferred order:

1. maintained Rust-native libraries for metadata/thumbnail work;
2. tightly-scoped bundled sidecar when native libraries are insufficient;
3. remote processing only with explicit consent.

### 19.3 FFmpeg sidecar

If FFmpeg is required:

- bundle a known compatible binary through the Tauri sidecar mechanism;
- verify provenance/hash during release construction;
- expose no arbitrary shell command to the renderer;
- construct arguments in trusted Rust code from validated types;
- restrict execution permissions to the exact sidecar;
- apply CPU/time/output-size limits where feasible;
- never interpolate an untrusted free-form shell string.

### 19.4 Derived artifacts

Thumbnails, previews, transcodes and waveforms MUST be associated with:

```text
source_blob_id
source_hash
processor_name
processor_version
profile
created_at
```

A processor-version change MAY invalidate/rebuild derivatives.

---

## 20. Tauri security model

### 20.1 Tauri version

Desktop implementation MUST target Tauri 2 security/capability concepts. Old global `allowlist.all` patterns are prohibited.

### 20.2 Renderer permissions

The main window MUST receive only the permissions required for typed application commands.

Forbidden by default:

- generic filesystem plugin access;
- generic `shell:allow-execute`;
- generic `shell:allow-spawn`;
- arbitrary URL opening without validation;
- broad remote API exposure.

### 20.3 Capability example

Illustrative shape:

```json
{
  "$schema": "../gen/schemas/desktop-schema.json",
  "identifier": "main-window",
  "description": "Minimal main UI permissions",
  "windows": ["main"],
  "permissions": [
    "core:default"
  ]
}
```

Application-specific vault operations SHOULD be custom Tauri commands rather than broad filesystem permissions.

### 20.4 Typed command surface

Reference command families:

```text
vault_create
vault_unlock
vault_lock
vault_status
import_paths
import_cancel
item_get
item_list
item_update_metadata
search_query
jobs_list
jobs_retry
backup_create
backup_validate
restore_preview
restore_execute
settings_get
settings_set
provider_status
provider_models
provider_configure_secret
ai_run
export_item
```

Every command MUST validate inputs in Rust.

### 20.5 CSP

Production CSP SHOULD begin from a restrictive default such as:

```text
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' asset: data: blob:;
font-src 'self';
connect-src 'self' ipc: http://ipc.localhost;
object-src 'none';
base-uri 'none';
frame-ancestors 'none';
```

Exact Tauri-required schemes MUST be validated against the final build.

Remote AI networking occurs in Rust, so provider domains do not need to be broadly exposed through renderer `connect-src`.

`'unsafe-eval'` MUST NOT be enabled in production.

---

## 21. Backup architecture

Backup is mandatory for MVP production readiness.

### 21.1 Backup format

Reference format: `.dvmbak`, version **DVBK1**.

Logical contents:

```text
DVBK1 archive
├── public-format.json        # minimal format/version information
├── vault.header
├── metadata.db.snapshot
├── blobs/...
└── manifest.enc
```

Derived vector indexes, caches and ordinary logs SHOULD be excluded because they can be rebuilt.

### 21.2 Snapshot consistency

Backup creation MUST:

1. obtain a consistent encrypted SQLite snapshot using the supported backup mechanism;
2. enumerate referenced canonical blobs from that snapshot;
3. copy encrypted blob files without decrypting them;
4. generate an encrypted/authenticated manifest;
5. compute hashes over backup members for transport-integrity verification;
6. fsync/close the destination before reporting success.

### 21.3 Backup metadata

Encrypted manifest SHOULD contain:

```text
backup_id
vault_id
format_version
app_version
schema_version
created_at
member path
member size
member SHA-256 (of stored encrypted bytes)
canonical blob count
canonical logical byte count
```

### 21.4 Backup verification

Two modes MAY exist:

- `STRUCTURAL` — archive/member hashes/header/database-open checks;
- `FULL` — decrypt every canonical blob and recompute plaintext SHA-256.

A production release test MUST perform `FULL` verification.

### 21.5 Restore safety

Restore MUST:

- reject path traversal and absolute archive members;
- restore into a new temporary destination first;
- validate format and integrity before activation;
- never silently overwrite an existing vault;
- allow user to choose a new destination;
- preserve the backup unchanged;
- rebuild derived indexes after successful activation.

### 21.6 Destructive restore release test

Mandatory test:

```text
create vault
→ import reference corpus
→ wait for required canonical state
→ create backup
→ record all plaintext SHA-256 values and metadata fixtures
→ delete the original vault directory
→ restore from backup into a clean location
→ unlock
→ FULL verify every canonical blob
→ compare item/tag/metadata fixtures
→ PASS only when all expected values match
```

---

## 22. Migration strategy

### 22.1 Database migrations

- migrations are ordered, checksummed and committed to source control;
- each migration records its checksum in `schema_migrations`;
- migration execution is transactional when SQLite permits;
- app MUST refuse unexpected checksum changes for already-applied migrations;
- app MUST refuse write access to a vault whose schema is newer than supported.

### 22.2 Pre-migration protection

Before a migration classified `HIGH_RISK`, the application MUST create or require a verified recovery point/snapshot.

### 22.3 Blob-format migrations

Blob formats are not mass-rewritten automatically at startup.

Policy:

- readers support known historical versions;
- new imports use current version;
- background migration is explicit, resumable and job-based;
- both versions may coexist during migration;
- the old blob is removed only after the new blob is verified and DB reference transition commits.

### 22.4 Index migrations

Search/vector indexes are derived. Incompatible index versions are deleted/rebuilt rather than migrated in place unless a tested migration exists.

---

## 23. Error model and user-visible state

### 23.1 Typed error envelope

```rust
pub struct AppError {
    pub code: ErrorCode,
    pub message_key: String,
    pub retryable: bool,
    pub correlation_id: String,
    pub safe_details: Option<String>,
}
```

Secret/internal stack data MUST not cross to the UI unless explicitly sanitized.

### 23.2 Required error classes

At minimum:

```text
VAULT_LOCKED
BAD_PASSPHRASE
UNSUPPORTED_VAULT_VERSION
CORRUPT_HEADER
CORRUPT_DATABASE
MISSING_BLOB
BLOB_AUTH_FAILED
SOURCE_UNREADABLE
UNSUPPORTED_MEDIA
DISK_FULL
JOB_RETRYABLE
JOB_TERMINAL
PROVIDER_UNAVAILABLE
PROVIDER_AUTH_FAILED
PROVIDER_CAPABILITY_UNSUPPORTED
REMOTE_EGRESS_DENIED
BACKUP_INVALID
RESTORE_CONFLICT
MIGRATION_REQUIRED
MIGRATION_FAILED
```

### 23.3 No false success

Counters and success banners update only after durable success. `finally` blocks MUST NOT convert failed operations into processed/success states.

---

## 24. Audit and observability

### 24.1 Local diagnostics

DVM SHOULD use structured local tracing with:

- timestamp;
- severity;
- component;
- event code;
- correlation ID;
- safe object IDs;
- duration;
- error code.

Provider prompts, original filenames, extracted text and secrets MUST NOT be logged by default.

### 24.2 Audit events

Security/correctness-sensitive events MAY be written to the encrypted DB:

- vault created;
- keyslot changed;
- backup created/verified/restored;
- remote egress policy changed;
- provider secret configured/removed;
- corruption detected;
- migration applied;
- canonical item deleted.

Audit rows SHOULD be hash-chained and MACed using a key derived from VMK, making unauthorized modification detectable while the vault can be opened.

The product MUST describe this as **tamper-evident under the threat model**, not immutable or tamper-proof.

### 24.3 Support bundle

Support bundle generation is explicit opt-in and MUST:

- redact paths, content, credentials and prompt text by default;
- include app/build versions, platform, schema version, error codes and sanitized diagnostics;
- preview the categories included before export.

Telemetry is disabled by default unless a future explicit product decision changes this policy.

---

## 25. Deletion model

DVM MUST distinguish:

- delete logical item reference;
- delete derived artifacts;
- delete an unreferenced canonical blob;
- delete from backups (not automatically possible).

A blob MAY be physically removed only when no canonical item references it and retention policy permits.

The UI MUST NOT claim secure erasure across SSD wear-leveling or existing backups. It may state that the application removed its active references/files.

---

## 26. Export model

Exports are explicit user actions.

Rules:

- original export decrypts into a user-selected destination;
- application-generated temporary plaintext MUST be minimized and cleaned up;
- export filenames are sanitized for platform rules;
- existing files require explicit overwrite policy;
- export failures MUST not alter canonical originals;
- provenance/metadata sidecar export MAY be offered.

---

## 27. Performance and resource budgets

These are engineering targets and release measurements, not marketing promises.

### 27.1 Memory

- single multi-GB import MUST use bounded memory;
- normal import target SHOULD remain below 256 MiB incremental working memory attributable to one job;
- concurrent jobs MUST be bounded by configured worker pools.

### 27.2 Import corpus

Release performance corpus SHOULD include:

- at least 10,000 mixed small/medium files;
- a multi-GB single video file;
- duplicate sets;
- Unicode paths including Romanian/Hungarian diacritics and spaces;
- malformed/corrupt media;
- deeply nested folders within OS-safe limits.

### 27.3 Search targets

On the project reference machine/corpus:

- FTS query p95 target: under 200 ms for 100k search documents;
- local vector retrieval p95 target: under 500 ms excluding first-time query embedding;
- UI MUST remain responsive while indexing occurs.

If targets are missed, release evidence MUST report actual values rather than hiding them.

### 27.4 Disk pressure

Before large import/backup/model download, DVM SHOULD estimate required disk space and surface a warning before a predictable disk-full failure.

---

## 28. Accessibility and UX requirements

### 28.1 Baseline

Desktop UI SHOULD target WCAG 2.2 AA-relevant behavior where applicable.

Required checks include:

- full keyboard navigation;
- visible focus;
- semantic labels;
- screen-reader status updates for long-running import/backup tasks;
- no color-only error/status meaning;
- scalable text;
- predictable dialogs;
- cancel/retry actions reachable without mouse.

### 28.2 Import UX

Bucket MUST support:

- file picker;
- folder picker;
- desktop drag-and-drop paths;
- progress by item and aggregate;
- duplicate notification/policy;
- cancellation that leaves canonical vault state valid.

Clipboard/paste import MAY be added after core path import is proven.

### 28.3 Privacy UX

Remote operations display a visible remote/provider indicator. Local operations display a local indicator. The distinction MUST not rely on a hidden settings page.

### 28.4 Recovery UX

Vault creation MUST require the user to acknowledge the consequence of losing all unlock/recovery material.

Recovery key generation SHOULD include:

- one-time display;
- copy/save/print options;
- confirmation challenge;
- no automatic cloud upload by DVM.

---

## 29. Desktop update and release security

### 29.1 Application signing

Production installers SHOULD be code-signed for the target platform.

### 29.2 Tauri updater

If automatic update is enabled:

- use Tauri updater signature verification;
- updater signature verification MUST NOT be disabled;
- release private signing keys MUST never enter source control;
- production update transport MUST use HTTPS;
- dangerous invalid-certificate/hostname options MUST remain disabled;
- rollback/downgrade policy MUST consider vault-schema compatibility.

### 29.3 Release evidence

Every released build MUST retain:

- source commit/tag;
- dependency lockfiles;
- build environment metadata;
- test/gate results;
- artifact SHA-256;
- SBOM;
- code-signing/update-signing evidence appropriate to platform.

---

## 30. Dependency and supply-chain policy

- dependency count SHOULD be minimized, especially in crypto/storage/security paths;
- crypto implementations MUST use maintained primitives/libraries;
- `cargo audit` or equivalent Rust advisory scanning runs in CI;
- JS dependency vulnerability scanning runs in CI;
- license policy SHOULD be enforced with a tool such as `cargo-deny` plus JS-license checks;
- release SHOULD emit CycloneDX or SPDX SBOM;
- sidecar binaries MUST have pinned versions and verified release hashes/provenance;
- no runtime download of executable code without an explicit signed update/plugin design.

---

## 31. Plugin architecture — deferred track

Third-party plugins are **not part of MVP**.

A future plugin system MUST NOT execute arbitrary JavaScript with `eval` as its security boundary.

Minimum prerequisites:

- signed manifest;
- publisher identity;
- plugin API version;
- explicit declared permissions;
- user approval of permissions;
- network permission separated from vault-read permission;
- scoped item access;
- CPU/memory/time limits;
- revocation/disable path;
- provenance/audit;
- sandbox such as WebAssembly/WASI or a separate restricted process;
- no access to VMK/provider secrets.

Plugin work begins only after G0-G6 are green.

---

## 32. Mobile architecture — deferred track

The original assumption that web React components can be reused unchanged in React Native is rejected.

Shared assets MAY include:

- domain models;
- schema definitions;
- validation logic;
- sync protocol;
- cryptographic format specification;
- provider contracts;
- generated API types.

Presentation layers remain platform-specific.

Before starting mobile, evaluate two paths:

1. Tauri mobile using shared web presentation where UX/performance is acceptable;
2. React Native/native UI consuming the same domain/sync contracts.

No mobile project starts until desktop vault format and sync protocol are stable.

---

## 33. Sync/collaboration — deferred track

Sync is a separate security product surface and MUST not be bolted directly onto local tables.

Prerequisites:

- stable vault IDs and item/blob identities;
- explicit multi-device key-management design;
- E2E encryption protocol;
- conflict semantics;
- tombstone/deletion rules;
- device enrollment/revocation;
- protocol versioning;
- replay protection;
- recovery story.

Server-side plaintext access is not permitted if the future feature is marketed as E2E encrypted.

---

## 34. Testing architecture

### 34.1 Unit tests

Required domains:

- crypto framing parser/serializer;
- keyslot operations;
- blob chunk nonce uniqueness;
- state machines;
- job retry/backoff/idempotency;
- path sanitization;
- search ranking fusion;
- provider capability selection;
- egress-policy evaluation;
- migration planning;
- typed error mapping.

### 34.2 Property/fuzz tests

Security-sensitive parsers SHOULD receive property/fuzz testing:

- corrupted `vault.header`;
- malformed DVB1 chunks;
- truncated blobs;
- archive traversal paths;
- malformed backup manifests;
- malformed provider JSON;
- migration fixtures.

### 34.3 Integration tests

Must use real components for:

- encrypted SQLite open/close/reopen;
- FTS5 insert/update/delete;
- encrypted blob import/decrypt;
- durable queue restart;
- backup snapshot/restore;
- OS credential adapter via test abstraction;
- vector index build/reopen/rebuild;
- local-provider mock HTTP protocol.

### 34.4 Crash tests

Inject termination after each import boundary:

```text
before temp creation
after first encrypted chunk
after full temp write
before fsync
after fsync
before rename
after rename
before DB transaction
during DB transaction
after DB commit
before UI success response
```

After restart, invariant checks MUST pass.

Repeat equivalent crash-injection for:

- job result commit;
- migration;
- backup creation;
- restore activation.

### 34.5 Security tests

Tests MUST prove:

- locked IPC refuses content access;
- renderer cannot invoke arbitrary filesystem commands;
- renderer cannot invoke arbitrary shell;
- provider secret never appears in IPC responses;
- local-only mode blocks network provider calls at backend;
- archive path traversal is rejected;
- corrupted ciphertext is rejected;
- wrong passphrase does not mutate the vault;
- unsupported future schema opens read-blocked/fails safely.

### 34.6 E2E tests

Desktop E2E MUST cover at least:

```text
create vault
unlock/lock
import file
import folder
duplicate import
browse
FTS search
semantic search
local AI unavailable path
remote egress denied path
backup
restore
export
wrong password
corrupt blob notification
```

---

## 35. CI/CD pipeline

Reference CI stages:

```text
01 checkout
02 toolchain pin verification
03 pnpm install --frozen-lockfile
04 cargo metadata --locked
05 frontend formatting/lint
06 frontend typecheck
07 Rust fmt --check
08 Rust clippy --locked -- -D warnings
09 unit tests
10 integration tests
11 security/advisory/license scans
12 production frontend build
13 Tauri build smoke
14 selected crash/recovery tests
15 SBOM generation
16 evidence summary
```

Windows MUST be a first-class CI target because the MVP is Windows-first.

Cross-platform builds MAY be added incrementally, but a platform MUST NOT be advertised as supported until its packaging and recovery gates pass.

---

## 36. Mandatory implementation gates

The sequence below replaces feature-first roadmap ordering.

### G0 — REPOSITORY FOUNDATION — MANDATORY

**Goal:** prove a deterministic project foundation.

Required outputs:

- Tauri 2 + React/Vite app boots;
- `index.html` at Vite project root;
- committed `pnpm-lock.yaml` and `Cargo.lock`;
- no missing imported dependencies;
- frozen-lockfile install passes in clean environment;
- lint/typecheck/Rust fmt/clippy/unit smoke pass;
- capability configuration contains no arbitrary filesystem/shell grants;
- CI executes the same commands.

**STOP:** any clean install/build error.

**DONE:** clean clone can reproduce green foundation using documented commands.

---

### G1 — ZERO-LOSS VAULT STORAGE — MANDATORY

**Goal:** preserve original bytes durably.

Required outputs:

- native encrypted SQLite open/close/reopen;
- vault header/key hierarchy;
- streaming hash + DVB1 encrypted blob write;
- atomic blob activation;
- `items/blobs/item_blobs` transaction;
- dedup;
- startup reconciliation;
- multi-GB bounded-memory import test.

**STOP:** any case where `SUCCESS` can be emitted without recoverable original bytes.

**DONE:** import/decrypt SHA-256 equality passes across restart and injected crashes.

---

### G2 — SECURITY AND KEY LIFECYCLE — MANDATORY

**Goal:** make security claims defensible.

Required outputs:

- documented threat model;
- Argon2id passphrase keyslot;
- recovery keyslot;
- optional OS quick-unlock slot;
- VMK/subkey hierarchy;
- renderer secret isolation tests;
- restrictive Tauri capabilities;
- production CSP;
- typed lock/unlock state;
- provider secrets in OS credential store;
- redaction tests.

**STOP:** renderer can read secret key material or arbitrary host files/shell.

**DONE:** security test suite passes and threat model matches implementation.

---

### G3 — RECOVERY / BACKUP / MIGRATION — MANDATORY

**Goal:** prove the vault is recoverable and evolvable.

Required outputs:

- DVBK1 backup writer;
- consistent DB snapshot;
- encrypted manifest;
- structural + full verification;
- safe restore to new destination;
- migration framework/checksums;
- newer-schema refusal;
- destructive restore test.

**STOP:** restore cannot reproduce exact plaintext SHA-256 corpus.

**DONE:** delete-original → restore → full hash/metadata comparison = PASS.

---

### G4 — DETERMINISTIC SEARCH — MANDATORY

**Goal:** deliver real lexical and semantic retrieval.

Required outputs:

- FTS5 search;
- deterministic FTS synchronization tests;
- embeddings table with compatibility metadata;
- actual vector index adapter;
- vector rebuild path;
- hybrid rank fusion;
- no-hallucinated-ID test;
- offline operation.

**STOP:** semantic query does not consult actual stored embeddings/index.

**DONE:** benchmark fixtures return expected lexical/vector/hybrid neighbors.

---

### G5 — AI PROVIDER LAYER — MANDATORY FOR AI FEATURES

**Goal:** make AI optional, replaceable and privacy-scoped.

Required outputs:

- capability-based provider interface;
- local provider adapter;
- remote provider adapter(s) only behind backend;
- provider/model discovery/validation;
- egress policy engine;
- explicit consent UI;
- structured-output validation;
- provenance records;
- graceful provider-unavailable behavior.

**STOP:** a cloud call can occur without backend egress authorization.

**DONE:** local-only mode proves zero remote calls while core app remains functional.

---

### G6 — PRODUCT HARDENING / RELEASE CANDIDATE — MANDATORY

**Goal:** prove operational readiness.

Required outputs:

- media processing limits;
- accessibility pass;
- large corpus performance report;
- local diagnostics/support bundle;
- signed build/update path;
- dependency/advisory/license scans;
- SBOM;
- installer test on clean Windows VM;
- complete release evidence pack.

**STOP:** any open P0; any unresolved data-loss/security/recovery P1.

**DONE:** all MVP Definition of Done checks in Section 37 pass.

---

### G7 — MOBILE DESIGN/PROTOTYPE — POST-MVP

Requires G0-G6 green and stable vault/sync contracts.

---

### G8 — PLUGIN SYSTEM — POST-MVP

Requires G0-G6 green plus a separate sandbox/security review.

---

### G9 — SYNC/COLLABORATION — POST-MVP

Requires G0-G6 green plus an independently reviewed E2E synchronization protocol.

---

## 37. MVP Definition of Done

MVP is `DONE` only when every required line is PASS.

| Gate | Acceptance criterion |
|---|---|
| Install | clean checkout + frozen dependency install passes |
| Static | frontend lint/typecheck and Rust fmt/clippy pass |
| Build | production React and Tauri build pass |
| Vault | create/lock/unlock/reopen passes |
| Original preservation | imported corpus decrypts byte-for-byte |
| Large files | multi-GB file import does not whole-buffer/OOM |
| Dedup | duplicate content obeys documented policy |
| Crash safety | injected import crashes reconcile without silent loss |
| Queue | jobs survive restart and expired leases retry safely |
| Crypto integrity | bit-flipped ciphertext is rejected |
| Wrong passphrase | fails closed and makes no mutation |
| Secret isolation | renderer cannot obtain VMK/provider secret |
| Tauri least privilege | no arbitrary shell/filesystem from renderer |
| FTS | expected lexical fixtures pass |
| Vector | expected nearest-neighbor fixtures pass |
| Hybrid | deterministic hybrid fixtures pass |
| AI optionality | core works with all providers disabled |
| Egress | local-only mode proves no remote provider traffic |
| Backup | backup structural/full verification passes |
| Restore | destruction + restore reproduces all canonical hashes |
| Migration | old fixture upgrades; future schema refuses mutation |
| Offline | create/import/browse/FTS/backup/restore work with network disabled |
| Accessibility | required keyboard/focus/screen-reader checks pass |
| Security scans | no unaccepted critical/high production findings |
| Installer | clean Windows install/uninstall/relaunch test passes |
| Release | version, evidence, SBOM and SHA-256 artifacts produced |

Production labeling is prohibited while any required row is FAIL or NOT RUN.

---

## 38. Acceptance test matrix for prior audit findings

This section proves that Blueprint v2 explicitly resolves every major finding from the v1 audit.

| v1 finding | v2 resolution | Proof gate |
|---|---|---|
| `npm ci` without lockfile | pnpm frozen lockfile + Cargo.lock mandatory | G0 |
| undeclared dependencies | clean dependency graph/install gate | G0 |
| Vite `public/index.html` misuse | root `index.html` specified | G0 |
| originals not stored | encrypted canonical BlobStore | G1 |
| browser `File` persisted via JSON | stable blob/item IDs only in durable jobs | G1 |
| dequeue before successful processing | lease + ACK-after-durable-success | G1 |
| constant `vault_passphrase` | Argon2id KEK + random VMK/keyslots | G2 |
| broken CryptoJS WordArray persistence | CryptoJS removed from canonical storage/crypto | G1/G2 |
| SQL `LIKE` on ciphertext | whole encrypted DB unlocked locally + FTS5 | G4 |
| fake semantic search | embeddings + vector index + hybrid retrieval | G4 |
| FAISS described but absent | concrete VectorIndex contract/implementation gate | G4 |
| `CryptoJS.mode.GCM` assumption | maintained AEAD library + versioned format | G2 |
| secrets in `localStorage` | OS credential manager + secret refs | G2 |
| broad Tauri `fs.all` / `shell.all` | Tauri 2 granular capabilities/custom commands | G2 |
| stale ffmpeg.wasm API | renderer ffmpeg removed; native/sidecar contract | G6 |
| web UI reused unchanged in React Native | mobile explicitly separate presentation | G7 |
| hardcoded retired AI models | capability/model registry/discovery | G5 |
| settings split between localStorage/config | single SettingsRepository | G2/G5 |
| online sql.js WASM contradicts offline | native SQLite, no runtime DB WASM CDN | G1 |
| documentation claims missing behavior | normative gates/evidence required | All |
| whole-file hashing | streaming hash/encryption | G1 |
| false success counters | typed durable state and postcondition success | G1/G6 |
| backup as secondary feature | backup/restore is mandatory G3 | G3 |
| immutable-log overclaim | tamper-evident hash/MAC chain wording | G2/G6 |
| plugin `eval` sandbox | plugins deferred; WASM/process capability model required | G8 |
| roadmap feature-first | foundation→storage→security→recovery→search→AI→hardening | G0-G6 |

---

## 39. Reference application ports

These ports are architectural contracts, not mandatory exact syntax.

```rust
#[async_trait]
pub trait BlobStore {
    async fn import_path(&self, source: &Path) -> Result<ImportedBlob, BlobError>;
    async fn open_plaintext(&self, blob_id: &BlobId) -> Result<Box<dyn AsyncRead + Unpin + Send>, BlobError>;
    async fn verify(&self, blob_id: &BlobId, mode: VerifyMode) -> Result<BlobVerification, BlobError>;
    async fn delete_unreferenced(&self, blob_id: &BlobId) -> Result<(), BlobError>;
}

#[async_trait]
pub trait ItemRepository {
    async fn create_from_blob(&self, input: NewItem) -> Result<Item, RepositoryError>;
    async fn get(&self, id: &ItemId) -> Result<Option<Item>, RepositoryError>;
    async fn update_metadata(&self, update: ItemMetadataUpdate) -> Result<Item, RepositoryError>;
}

#[async_trait]
pub trait JobQueue {
    async fn enqueue(&self, job: NewJob) -> Result<JobId, JobError>;
    async fn lease_next(&self, worker: &WorkerId, ttl: Duration) -> Result<Option<LeasedJob>, JobError>;
    async fn complete(&self, lease: JobLease, result: JobResult) -> Result<(), JobError>;
    async fn fail(&self, lease: JobLease, error: JobFailure) -> Result<(), JobError>;
}

#[async_trait]
pub trait SearchIndex {
    async fn lexical(&self, query: LexicalQuery) -> Result<Vec<SearchHit>, SearchError>;
    async fn semantic(&self, query: SemanticQuery) -> Result<Vec<SearchHit>, SearchError>;
    async fn hybrid(&self, query: HybridQuery) -> Result<Vec<SearchHit>, SearchError>;
}

#[async_trait]
pub trait BackupStore {
    async fn create(&self, destination: &Path, options: BackupOptions) -> Result<BackupReceipt, BackupError>;
    async fn validate(&self, source: &Path, mode: VerifyMode) -> Result<BackupValidation, BackupError>;
    async fn restore(&self, source: &Path, destination: &Path) -> Result<RestoreReceipt, BackupError>;
}
```

Application services orchestrate these ports; UI never orchestrates storage primitives directly.

---

## 40. Frontend contract

### 40.1 Renderer responsibilities

Renderer owns:

- visual state;
- route/view composition;
- keyboard/accessibility behavior;
- progress presentation;
- sanitized user input;
- invocation of typed application commands.

Renderer does not own:

- vault unlock keys;
- DB connections;
- original file streams;
- cloud credentials;
- arbitrary host paths beyond user-selected descriptors returned by trusted APIs;
- provider SDKs that require secrets.

### 40.2 Typed DTOs

Rust↔TypeScript DTOs SHOULD be generated or validated from a shared schema to prevent drift.

All IPC requests and responses MUST have explicit versioned shapes for operations that persist data.

---

## 41. Degraded/read-only operation

When possible, corruption or migration uncertainty SHOULD prefer a safe read-only mode over destructive automatic repair.

Examples:

- future schema version → refuse write, show upgrade requirement;
- stale vector index → lexical search remains available while rebuild is scheduled;
- remote AI unavailable → local vault remains fully usable;
- one corrupt derived thumbnail → regenerate;
- missing canonical blob → mark affected item corrupt; do not hide it.

---

## 42. Data classification

Internal classification:

| Class | Examples | Default handling |
|---|---|---|
| S0 Secret | VMK, DB key, provider API key | trusted memory/OS credential store only |
| S1 Private content | originals, OCR, notes, location | encrypted at rest; remote deny by default |
| S2 Private metadata | filenames, tags, timestamps | encrypted DB |
| S3 Derived private | embeddings, thumbnails | encrypted or rebuildable protected storage |
| S4 Operational | version, generic error code | may appear in redacted diagnostics |

Any new feature MUST declare which classes it reads, writes, transmits and logs.

---

## 43. Remote-provider failure and policy behavior

Provider calls MUST have:

- connect timeout;
- total request timeout;
- bounded retries only for safe/retryable failures;
- cancellation;
- rate-limit handling;
- typed auth/configuration errors;
- schema validation;
- no endless autonomous retry loops.

A failed AI enrichment MUST leave the canonical imported memory intact and usable.

---

## 44. Vector model lifecycle

When the selected embedding model changes:

1. existing embeddings remain associated with their original model identity;
2. new model gets its own index namespace;
3. background re-embedding is an explicit durable job set;
4. mixed-dimension vectors are never compared;
5. old model embeddings may be retired only after replacement completeness is verified;
6. the UI may report indexing completeness.

This prevents silent semantic-index corruption when provider models evolve.

---

## 45. Canonical state machines

### 45.1 Item state

```text
IMPORTING
  │
  ▼
IMPORTED ──required jobs──► PROCESSING ──all required complete──► READY
                               │
                               ├─optional/derived failure──► PARTIAL
                               ├─canonical corruption──────► CORRUPTED
                               └─user delete───────────────► DELETING
```

`READY` means canonical blob and required metadata are durable. It does not mean every optional AI enrichment exists.

### 45.2 Vault state

```text
CLOSED → LOCKED → UNLOCKING → OPEN
                    │           │
                    └─failure──► LOCKED
OPEN → LOCKING → LOCKED
OPEN → DEGRADED_READ_ONLY
```

Any secret-dependent backend command MUST check `OPEN` state.

---

## 46. Concurrency rules

- DB writes MUST use a controlled transaction layer.
- Worker concurrency MUST be bounded by job kind.
- Only one destructive migration runs at a time.
- Backup snapshot and migrations MUST coordinate through an application-level maintenance lock.
- Import may continue during derived indexing only if correctness tests prove the chosen SQLite/WAL policy.
- Delete versus processing races MUST resolve through item/blob reference checks in transactions.

---

## 47. Input validation and hostile files

Imported content is untrusted.

Requirements:

- do not trust extension alone; sniff supported magic/type where practical;
- cap parser resource usage;
- subprocess/sidecar timeouts;
- path canonicalization;
- reject device/special files unless explicitly supported;
- symbolic-link behavior is explicit and defaults to not following unexpected links during folder import;
- archive extraction is not performed implicitly;
- parser crashes MUST not corrupt canonical storage.

Canonical storage can preserve an unsupported file even when enrichment is impossible.

---

## 48. Folder import semantics

Folder import MUST define:

- whether symlinks are followed: default `NO`;
- hidden files: configurable, default platform-consistent exclusion;
- permission-denied files: record skip/error without aborting unrelated files;
- deterministic traversal ordering for reproducible tests;
- cancellation behavior;
- per-file result summary;
- source folder hierarchy MAY be captured as encrypted metadata but is not required to mirror storage layout.

---

## 49. Provenance model

Every derived value that can influence user interpretation SHOULD carry provenance.

Examples:

```text
tag
  source = USER | EXIF | OCR | AI
  producer = <processor/provider>
  producer_version/model
  source_hash
  created_at
```

User-entered values MUST be distinguishable from AI-generated suggestions.

AI suggestions MAY require acceptance before replacing user-authored canonical fields.

---

## 50. Documentation architecture

Blueprint v2 eliminates duplicated documentation suites.

Normative hierarchy:

1. `Blueprint_v2.md` — architecture and gates;
2. ADRs — intentional deviations/major decisions;
3. API/format specs — exact binary/IPC formats;
4. operational guides — install/backup/recovery;
5. generated API reference.

If a lower-level document conflicts with the Blueprint, implementation MUST stop and create an ADR/reconciliation change rather than silently choosing one.

Documentation tests SHOULD check:

- commands shown in README execute in CI;
- referenced scripts/files exist;
- current schema/version numbers match code;
- no retired provider model is presented as a mandatory default.

---

## 51. Architecture Decision Records required before implementation closure

At least these ADRs MUST exist:

- **ADR-0001:** Tauri 2 + Rust trusted backend / React renderer boundary.
- **ADR-0002:** native encrypted SQLite choice and FTS5 build configuration.
- **ADR-0003:** VMK/keyslot hierarchy and KDF baseline.
- **ADR-0004:** DVB1 encrypted blob format and streaming semantics.
- **ADR-0005:** SQLite durable job queue/lease semantics.
- **ADR-0006:** lexical + HNSW-class vector retrieval and hybrid rank fusion.
- **ADR-0007:** AI provider capability and egress model.
- **ADR-0008:** DVBK1 backup/restore format.
- **ADR-0009:** Tauri capabilities/CSP/secret boundary.
- **ADR-0010:** plugins excluded from MVP.
- **ADR-0011:** mobile presentation is not shared unchanged with web renderer.
- **ADR-0012:** update signing and schema downgrade policy.

An ADR may refine a decision but MUST not weaken an invariant without explicitly updating the Blueprint and associated tests.

---

## 52. Required engineering evidence per gate

Each gate closure MUST produce a concise evidence record containing:

```text
gate_id
source_commit
platform/toolchain
commands executed
exit codes
unit/integration/e2e counts
relevant benchmark results
security scan summary
known accepted risks
artifact hashes when applicable
verdict: PASS | FAIL | BLOCKED
```

Screenshots alone are not sufficient proof for storage/security/recovery correctness.

---

## 53. Implementation protocol for autonomous coding agents

When Blueprint v2 is handed to Codex/Claude/another implementation agent, the following protocol applies:

1. work only on the current gate;
2. inspect current official dependency/framework documentation before introducing version-sensitive APIs;
3. do not preserve v1 code merely for compatibility if it violates a v2 invariant;
4. never weaken tests to make a gate pass;
5. add tests before/with fixes for every P0/P1 correctness condition;
6. no feature from a later gate may be used to mask failure of an earlier gate;
7. never claim PASS from static inspection when runtime evidence is required;
8. record exact commands and exit codes;
9. stop the gate on an unresolved P0;
10. update documentation in the same change as behavior/contract changes.

---

## 54. Concrete implementation order inside G0-G6

Recommended bounded sequence:

```text
G0.1 workspace + lockfiles
G0.2 Tauri 2 shell + React renderer
G0.3 typed IPC + error envelope
G0.4 CI foundation

G1.1 vault directory/header skeleton
G1.2 encrypted SQLite adapter
G1.3 DVB1 crypto streaming
G1.4 import transaction
G1.5 dedup
G1.6 durable jobs
G1.7 startup reconciliation/crash suite

G2.1 passphrase Argon2id slot
G2.2 recovery slot
G2.3 device keychain slot
G2.4 capability/CSP lockdown
G2.5 secret store/provider secret boundary
G2.6 audit/redaction tests

G3.1 migration framework
G3.2 consistent snapshot
G3.3 DVBK1 archive/manifest
G3.4 restore staging/activation
G3.5 destructive restore gate

G4.1 search_documents + FTS5
G4.2 extraction indexing
G4.3 embeddings canonical store
G4.4 vector index
G4.5 hybrid search
G4.6 search correctness/perf corpus

G5.1 provider contracts
G5.2 local provider
G5.3 egress policy
G5.4 remote adapter(s)
G5.5 structured outputs/provenance
G5.6 AI-assisted retrieval

G6.1 native media processors/sidecars
G6.2 UX/accessibility
G6.3 performance hardening
G6.4 support/diagnostics
G6.5 signing/updater/SBOM
G6.6 clean Windows release rehearsal
```

---

## 55. STOP conditions

Development MUST stop and reconcile before proceeding if any of the following occurs:

- accepted import cannot prove recoverable original bytes;
- any cryptographic primitive/format is improvised without review/test vectors;
- renderer obtains a root secret;
- arbitrary shell/filesystem capability is introduced to solve a convenience issue;
- migration mutates data without a recovery path;
- backup cannot be restored in a clean environment;
- search returns IDs that do not exist;
- semantic retrieval ignores stored embeddings/index;
- cloud egress bypasses policy/consent;
- a later feature requires violating an earlier invariant;
- documentation and running behavior diverge on a security/recovery claim;
- a P0 remains unresolved.

---

## 56. Product status vocabulary

Use only these labels:

- `DESIGN` — specified but not implemented;
- `IMPLEMENTED` — code exists;
- `VERIFIED` — required automated/manual evidence passed;
- `EXPERIMENTAL` — available but excluded from production guarantees;
- `DEPRECATED` — retained temporarily with removal path;
- `UNSUPPORTED` — intentionally unavailable.

The project MUST NOT use `production-ready`, `secure`, `offline-first`, `zero-loss` or equivalent as unqualified labels before corresponding gates have passed.

---

## 57. Reference security checklist

Before each production release:

- [ ] all P0 findings closed;
- [ ] no provider secret in repository/history/build output;
- [ ] Tauri capabilities reviewed for permission creep;
- [ ] CSP reviewed;
- [ ] crypto format/version unchanged or reviewed;
- [ ] KDF baseline still meets current project minimum;
- [ ] dependency advisories reviewed;
- [ ] sidecar provenance verified;
- [ ] corrupted-blob test passes;
- [ ] wrong-passphrase test passes;
- [ ] local-only network-denial test passes;
- [ ] backup full verification passes;
- [ ] destructive restore passes;
- [ ] update signatures verify;
- [ ] support bundle redaction test passes.

---

## 58. Reference recovery checklist

User-facing operational recovery documentation MUST cover:

1. forgotten passphrase with recovery key;
2. lost device with external backup;
3. corrupt derived index;
4. missing/corrupt canonical blob;
5. interrupted application upgrade;
6. interrupted restore;
7. provider outage;
8. OS credential-store entry lost while passphrase still available;
9. backup verification failure;
10. disk-full condition.

---

## 59. Privacy statement requirements

The product privacy documentation MUST accurately state:

- what stays local by default;
- what optional operations contact external providers;
- which data scopes each operation may send;
- where provider credentials are stored;
- whether any telemetry exists;
- backup behavior;
- that an unlocked compromised machine is outside full protection guarantees.

“Nothing leaves your device” MUST NOT be used while remote AI/sync features are enabled or available without qualification.

---

## 60. Future synchronization compatibility hooks

Without implementing sync, v2 MUST avoid choices that make future sync impossible.

Therefore:

- item IDs and blob IDs are globally unique random IDs;
- timestamps are stored in a normalized unambiguous format;
- user edits carry `updated_at` and MAY later gain logical clocks;
- original plaintext hash remains canonical for content identity;
- deletion is routed through a service rather than raw SQL so future tombstones can be introduced;
- schema exposes stable opaque IDs rather than path-based identity.

These hooks do not authorize sync implementation in MVP.

---

## 61. Recommended implementation technologies

These are reference choices, not unconditional dependency mandates. Exact versions MUST be selected from current maintained releases at implementation time and pinned in lockfiles.

| Area | Reference choice |
|---|---|
| Desktop shell | Tauri 2 |
| Trusted backend | Rust |
| Renderer | React + TypeScript + Vite |
| Metadata DB | SQLite with SQLCipher + FTS5 |
| Async runtime | Tokio where required |
| Passphrase KDF | Argon2id |
| Subkey derivation | HKDF-SHA-256 |
| Blob AEAD | XChaCha20-Poly1305 (DVB1) |
| Hash | SHA-256 |
| Secret storage | OS credential/keyring adapter |
| Vector index | in-process HNSW-class implementation behind port |
| Local AI | provider adapter such as Ollama when installed |
| Packaging/update | Tauri bundler/updater with signing |
| JS package manager | pnpm, frozen lockfile |
| Rust dependency lock | Cargo.lock committed |

No choice in this table bypasses gate testing.

---

## 62. Official references to consult during implementation

Version-sensitive implementation MUST re-check current official documentation. Baseline references used for Blueprint v2 include:

- Tauri capabilities/security: https://tauri.app/security/capabilities/
- Tauri 2 updater/signing: https://v2.tauri.app/plugin/updater/
- Tauri sidecars: https://v2.tauri.app/develop/sidecar/
- Tauri configuration/CSP: https://v2.tauri.app/reference/config/
- SQLite FTS5: https://www.sqlite.org/fts5.html
- OWASP Password Storage Cheat Sheet / Argon2id baseline: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

These links are references, not authorization to copy sample configuration without validating the current project version.

---

## 63. Final architecture verdict

Blueprint v2 intentionally removes the v1 shortcuts that caused false guarantees:

```text
sql.js/localStorage DB             → native encrypted SQLite
field AES + SQL LIKE               → encrypted DB + FTS5 after unlock
constant passphrase                → Argon2id keyslot + random VMK
browser File in JSON queue         → durable IDs in SQLite job queue
whole-file ArrayBuffer hashing     → streaming hash/encryption
fake semantic search               → persisted embeddings + vector index
renderer provider secrets          → Rust gateway + OS credential store
broad Tauri fs/shell               → least-privilege typed commands
renderer ffmpeg.wasm               → trusted native/sidecar processing
backup as extra feature            → mandatory recovery gate
shared RN/web UI assumption        → shared domain contracts, separate presentation
plugin eval sandbox                → deferred capability sandbox design
feature-first roadmap              → correctness/security/recovery gates first
```

The resulting system is intentionally less flashy at the beginning and substantially more defensible.

---

# FINAL BLUEPRINT v2 VERDICT

```text
DESIGN BASELINE                  COMPLETE
V1 AUDIT FINDINGS RECONCILED     COMPLETE
ZERO-LOSS ARCHITECTURE           SPECIFIED
CRYPTO/KEY LIFECYCLE             SPECIFIED
DURABLE QUEUE                    SPECIFIED
REAL FTS + VECTOR SEARCH         SPECIFIED
AI PROVIDER/EGRESS MODEL         SPECIFIED
BACKUP/RESTORE                   SPECIFIED
MIGRATIONS                       SPECIFIED
TAURI LEAST-PRIVILEGE MODEL      SPECIFIED
TEST/CI/RELEASE GATES            SPECIFIED
PLUGIN/MOBILE/SYNC BOUNDARIES    SPECIFIED

IMPLEMENTATION STATUS            NOT YET IMPLEMENTED
NEXT AUTHORIZED UNIT             G0 — REPOSITORY FOUNDATION
PRODUCTION STATUS                NO-GO UNTIL G0-G6 PASS
```

Blueprint v2 is now suitable to serve as the normative source for bounded implementation transactions. The first implementation transaction MUST be **G0 — Repository Foundation**; implementation agents MUST NOT begin AI, plugin, mobile, sync or visual-polish work before the foundational gates permit it.
