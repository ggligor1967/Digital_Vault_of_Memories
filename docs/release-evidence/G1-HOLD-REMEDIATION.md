# DVM-V2 / G1 — Material correctness and Windows CI bounded remediation

Transaction: `DVM-V2 / G1 — MATERIAL CORRECTNESS + WINDOWS CI BOUNDED REMEDIATION`.

This document records the remediation of the five open review findings that put
the published G1 candidate on HOLD. It supplements, and does not replace,
`G1-ZERO-LOSS-VAULT-STORAGE.md`.

> **This document now covers two bounded remediations.** Everything up to the
> "Part II" heading is the original record of the first one and is preserved
> unchanged. Part II records a separate, later remediation (T1/T2) and
> reconciles this branch's full publication history. See
> "Publication history reconciliation" in Part II before relying on the
> identity table below, which describes only the first remediation.

## Identity

| Field                        | Value                                      |
| ---------------------------- | ------------------------------------------ |
| Base (`main`)                | `08a6b3d7159566b13c122164862465e539f7d3b5` |
| Starting G1 head             | `8f2b85a4f3aa3cdbb0229f9efe4097fb004c66a1` |
| Branch                       | `feat/dvm-v2-g1-zero-loss-vault-storage`   |
| Pull request                 | #1, OPEN, non-draft, unmerged, base `main` |
| `verified_source_commit`     | `f11ce57fa9fe9da12e89cb34db50bedb829301a8` |
| Verified source tree         | `e6fbba643f5ecdd34d162e15e44cf8a059a7fc17` |
| Parent of remediation commit | `8f2b85a4f3aa3cdbb0229f9efe4097fb004c66a1` |

`verified_source_commit` is the pre-amend candidate that local and clean-room
validation actually executed. This document was then added and folded into that
same commit with `git commit --amend --no-edit`, so the final published SHA
differs and is reported externally. No published commit was rewritten: the
original G1 commit `8f2b85a4` is untouched and remains the parent.

Working tree and index were clean at start and at finish. `origin/main` was
unchanged throughout. Exactly one commit was added to the branch.

Platform: Windows 11 Home 10.0.26200 x64, Rust 1.94.1 x86_64-pc-windows-msvc,
Node 22.22.2, pnpm 10.27.0. Native Strawberry Perl 5.42.3.1 portable was
restored as the documented Windows prerequisite for the vendored OpenSSL build;
the upstream archive SHA-256
`6a081a811781c30aca51dbc036afd93092af91e3297901f02c17043795a10690` was verified
before extraction and matches the value recorded for the original G1 run.

## Findings addressed

| Ref | Thread                                     | Path                              | Classification           |
| --- | ------------------------------------------ | --------------------------------- | ------------------------ |
| R1  | `PRRT_kwDOUZSIRc6h8uBe`                    | `crates/dvm-storage/src/vault.rs` | Material correctness     |
| R2  | `PRRT_kwDOUZSIRc6h8uBf`                    | `crates/dvm-storage/src/vault.rs` | Material correctness     |
| R3  | `PRRT_kwDOUZSIRc6h8uBh`                    | `crates/dvm-storage/src/jobs.rs`  | Material correctness     |
| R4  | `PRRT_kwDOUZSIRc6h8s-y` (Copilot)          | `crates/dvm-storage/src/vault.rs` | Non-material performance |
| R4  | `PRRT_kwDOUZSIRc6h8uBb` (Codex, duplicate) | `crates/dvm-storage/src/vault.rs` | Non-material performance |

The live review surface was re-read before implementation and contained exactly
these five unresolved threads (`reviewThreads.totalCount = 5`). No additional
threads existed.

### R1 — operational I/O is not canonical data loss

Before: `recover_locked` mapped every `symlink_metadata` and `File::open`
failure to `ErrorCode::MissingBlob`. Because `recover` persists `CORRUPTED` for
`MissingBlob`, a sharing violation or permission denial permanently condemned an
intact canonical original.

After: `blob_io_error` reserves `MissingBlob` for
`std::io::ErrorKind::NotFound` and delegates every other filesystem failure to
the existing `io_error` classifier (`StorageFull` to `DiskFull`, otherwise
`Internal`). No new public error code was introduced; the Blueprint error model
is unchanged. `AppError::new` leaves `safe_details` empty, so no path, errno or
OS message can cross the boundary.

### R2 — runtime corruption leaves the writable state

Before: `Vault.reconciliation` was a startup snapshot. A canonical integrity
failure discovered after startup marked the item `CORRUPTED` but left
`require_writable` admitting imports and job mutations.

After: the vault carries a sticky `AtomicBool` latched the moment this instance
observes `MissingBlob` or `BlobAuthFailed`. `health()` reports
`RepairRequired` once latched, `require_writable` consults `health()` rather
than the snapshot, and the latch is one-way because G1 implements no repair
operation. Operational errors never set it. The latch is also applied to the
dedup verification in `commit_import` and to job completion via
`verify_canonical`, so discovery through any path fails closed. There is no
setter reachable from the renderer and no silent reset.

### R3 — one representation for `blobs.verified_at`

Before: blob insertion wrote UTC ISO-8601 via SQLite `strftime`, while
verification job completion overwrote the same column with zero-padded Unix
seconds, so the column alternated format and text ordering stopped being
chronological.

After: the job writer emits the same grammar as the insertion writer by binding
Unix seconds and letting SQLite render them with the identical `strftime`
format. Job scheduling columns (`available_at`, `lease_until`, `created_at`,
`updated_at`) keep the sortable fixed-width form, which is their documented
ordering contract. No schema change, no new dependency, no datetime crate.

### R4 — reconciliation membership

Before: the orphan scan tested each `blobs/` entry with `ids.iter().any(...)`,
giving O(files x rows).

After: a `HashSet<&str>` is built once before the directory scan and each entry
costs one average-O(1) lookup, so the scan is O(files + rows). The set borrows
from the existing id vector, and the verification loop keeps its deterministic
database order. Semantics are unchanged by construction; both duplicate threads
describe the same defect and are addressed by the same change.

## Tests added

All in `crates/dvm-storage/src/tests.rs`.

| Test                                                                         | Covers           |
| ---------------------------------------------------------------------------- | ---------------- |
| `operational_canonical_io_is_never_reported_as_a_missing_blob`               | R1-A, R1-B, R1-D |
| `runtime_canonical_corruption_latches_repair_required_and_blocks_writes`     | R1-C, R2         |
| `verified_at_uses_one_canonical_utc_representation_for_every_writer`         | R3               |
| `reconciliation_orphan_membership_is_constant_time_and_semantics_preserving` | R4               |

R1 uses a one-shot, thread-local `cfg(test)` open seam so an operational error
is injected deterministically on every platform. It is compiled out of
production builds and is not a runtime fault-injection surface. The oracle
exercises the public `recover` path, not a standalone helper.

R2 follows the required sequence: healthy vault, valid import, writes allowed,
post-startup damage, `recover`, expected `MissingBlob` or `BlobAuthFailed`, item
`CORRUPTED`, live health `RepairRequired` while the startup snapshot is still
`Healthy`, import rejected, job claim rejected, job completion rejected, job
still `PROCESSING`, blob count unchanged, cross-thread visibility of the latch
from four concurrent readers, then close and reopen proving startup
reconciliation reaches the same verdict independently.

R3 asserts a single grammar for both writers, decodes the job value with
SQLite's independent `unixepoch()` to prove it encodes exactly the injected
`now`, asserts that plain text ordering is chronological across writers, and
asserts that job scheduling columns retain the fixed-width form.

### Negative control

The three behavioural defects were deliberately re-introduced while keeping the
new API surface, so the tests fail on assertions rather than compile errors:

```
cargo test --locked -p dvm-storage --lib (R1..R4 selection) -> EXIT 101
  runtime_canonical_corruption_latches_repair_required_and_blocks_writes FAILED
    left: Healthy   right: RepairRequired
  operational_canonical_io_is_never_reported_as_a_missing_blob          FAILED
    left: MissingBlob  right: MissingBlob   (assert_ne)
  verified_at_uses_one_canonical_utc_representation_for_every_writer    FAILED
    verification: 00000000004000000000
  reconciliation_orphan_membership_is_constant_time_..                  ok
```

R4 passes against the defective source and this is expected and reported as
such: the fix is complexity-only and its semantics are intentionally identical,
so no behavioural assertion can distinguish the two implementations. Its guard
is structural — the `referenced(&HashSet<&str>, &OsStr)` signature plus a
50,000-id membership test — not a before/after failure. This is stated plainly
rather than presented as a passing behavioural oracle.

## CI1 — Windows native Perl root cause

Reproduced from the exact failed run at the starting head.

| Field             | Value                                                          |
| ----------------- | -------------------------------------------------------------- |
| Failed run        | `34787884208`, head `8f2b85a4f3aa3cdbb0229f9efe4097fb004c66a1` |
| Windows job       | `103806583862`, conclusion `failure`                           |
| Ubuntu job        | `103806583760`, conclusion `success`                           |
| Failing gate step | `rust-clippy`, exit 101                                        |

The vendored OpenSSL `./Configure` aborted with:

```
Can't locate Locale/Maketext/Simple.pm in @INC ... (@INC entries checked:
  ... /usr/lib/perl5/site_perl /usr/share/perl5/site_perl
  /usr/lib/perl5/vendor_perl /usr/share/perl5/vendor_perl
  /usr/lib/perl5/core_perl /usr/share/perl5/core_perl ...)
  at /usr/share/perl5/core_perl/Params/Check.pm line 6.
```

The POSIX `@INC` entries identify the MSYS/Git Perl, not
`C:\Strawberry\perl\bin\perl.exe`. That interpreter ships `Params::Check` but
not `Locale::Maketext::Simple`, which `IPC::Cmd` and therefore
`OpenSSL/config.pm` require.

Cause: the workflow preflighted native Perl and appended it to `GITHUB_PATH`,
but the gate step declared `shell: bash`. Git Bash prepends its own MSYS
`/usr/bin` ahead of anything added to `GITHUB_PATH`, so `perl` resolved to the
MSYS interpreter. The already-green G1 workflow declares no `shell:` for its
gate step and therefore runs under the `windows-latest` default, `pwsh`, which
honours native Windows PATH order — which is exactly why G1 passed while G0
failed at the same commit with the same preflight.

Independently corroborated locally: invoking the same Cargo build from Git Bash
reproduced the identical `@INC` failure, and invoking it with native Perl first
on PATH compiled successfully.

Remediation: the Windows gate runs under `pwsh` and, in the same process that
invokes the gate, asserts the resolved interpreter is
`C:\Strawberry\perl\bin\perl.exe`, prints its version and runs a
`Locale::Maketext::Simple` probe before calling
`node scripts/verify-g0.mjs --no-runtime`. Because the gate script spawns its
children through `cmd.exe` on Windows, those children inherit this selection.
Linux keeps its native bash path. No Perl distribution is installed from the
network, `scripts/verify-g0.mjs` remains the single gate implementation, and no
step uses `continue-on-error`.

## Commands and exit codes

Targeted validation, remediated source:

| Command                                                                         | Exit                               |
| ------------------------------------------------------------------------------- | ---------------------------------- |
| `cargo fmt --all -- --check`                                                    | 0                                  |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 0                                  |
| `cargo test --locked -p dvm-storage -- --nocapture`                             | 0 (24 passed, 0 failed, 2 ignored) |
| `pnpm --filter @dvm/security-tests run test`                                    | 0 (130 passed)                     |
| `pnpm lint`                                                                     | 0                                  |
| `pnpm typecheck`                                                                | 0                                  |
| `git diff --check`                                                              | 0                                  |
| `git diff --cached --check`                                                     | 0                                  |
| Negative control, defects restored                                              | 101 (3 of 4 fail as designed)      |

Release-profile storage tests run inside the G1 gate as
`cargo test --locked --release -p dvm-crypto -p dvm-storage -- --nocapture`,
which is a superset of the required release run for `dvm-storage`.

## Full local G1 acceptance

`pnpm verify:g1` -> EXIT 0, `G1 LOCAL ACCEPTANCE: PASS`.

G0 sub-gate: `15 run, 0 skipped, 0 failed, 0 not reached`,
`G0 VERDICT: PASS`. No mandatory step was skipped; the interactive `runtime`
step executed and passed.

```
MULTI_GB size=2151677952 sparse=false chunk=4194304
  largest_buffer=4194320 configured_crypto_buffers=8388624
  source_sha256=db5700bafac53992293386a224c6d460eaeaef8c1084e1ad909b846dbab8c130
  recovered_sha256=db5700bafac53992293386a224c6d460eaeaef8c1084e1ad909b846dbab8c130
  recovered_bytes=2151677952 baseline_working_set=7143424
  peak_working_set=22908928 incremental_estimate=15765504
  elapsed_seconds=155.977 BYTE_EQUALITY=PASS BOUNDED_MEMORY=PASS
```

Real-process crash matrix C1-C8 passed in both debug and release profiles.
Corruption matrix (`missing`, `flip`, `truncate`, `swap`) passed.

## Clean-room revalidation

Fresh short-path checkout at `C:\dvm-g1-remediation-cr`, cloned with no
checkout and set to `f11ce57fa9fe9da12e89cb34db50bedb829301a8`. Checkout tree
hash `e6fbba643f5ecdd34d162e15e44cf8a059a7fc17` equals the candidate tree. No
`target`, `node_modules`, `dist`, local evidence directory or compiled
SQLCipher/OpenSSL artifact was copied in.

| Gate                                                | Result                              |
| --------------------------------------------------- | ----------------------------------- |
| `pnpm install --frozen-lockfile`                    | EXIT 0                              |
| `git diff --exit-code -- pnpm-lock.yaml Cargo.lock` | EXIT 0, lockfiles unchanged         |
| `pnpm verify:g1 --cleanroom`                        | EXIT 0, `G1 LOCAL ACCEPTANCE: PASS` |
| G0 sub-gate                                         | 15 run, 0 skipped, 0 failed         |
| Crash matrix C1-C8                                  | PASS, debug and release             |
| R1 / R2 / R3 / R4 tests                             | PASS                                |
| Working tree at finish                              | clean                               |

```
MULTI_GB size=2151677952 sparse=false
  source_sha256=db5700bafac53992293386a224c6d460eaeaef8c1084e1ad909b846dbab8c130
  recovered_sha256=db5700bafac53992293386a224c6d460eaeaef8c1084e1ad909b846dbab8c130
  recovered_bytes=2151677952 peak_working_set=22921216
  elapsed_seconds=89.762 BYTE_EQUALITY=PASS BOUNDED_MEMORY=PASS
```

The clean-room reproduced the same plaintext digest as the local run on a corpus
of the same full size. The corpus was not reduced.

### Clean-room infrastructure observations

Two earlier clean-room attempts on this host were terminated by the operating
environment for memory exhaustion before producing any gate verdict, each
failing a compiler invocation with `STATUS_DLL_INIT_FAILED (0xc0000142)`:
attempt 1 during debug dependency compilation, attempt 2 during the release
Tauri dependency build. Host total RAM is 15.72 GiB. Neither attempt produced a
gate result, and neither is recorded as a gate outcome. The successful run
resumed the deterministic incremental build with compiler parallelism bounded to
two jobs; no gate, command or corpus size was changed to obtain it.

Disk observations: the transaction began with roughly 14.6 GiB free. Build
output was reclaimed with `cargo clean` only (11.9 GiB across a superseded
clean-room tree and the main tree after local acceptance had already passed and
been recorded). The multi-GB gate reports its own free space before and after
and removes its fixtures; clean-room free space after fixture cleanup was
9,270,886,400 bytes. No source, lockfile or corpus was reduced to fit.

## Scope

Changed paths in the remediation commit:

```
.github/workflows/g0-foundation.yml
crates/dvm-storage/src/jobs.rs
crates/dvm-storage/src/tests.rs
crates/dvm-storage/src/vault.rs
```

plus this evidence document, folded in by the evidence-only amend.

`scripts/verify-g0.mjs` was deliberately **not** modified: it already spawns
child processes through `cmd.exe` on Windows and inherits the parent PATH, so
running the gate under `pwsh` is sufficient and the single-source gate rule is
preserved without touching the implementation.

Not modified: `Cargo.toml`, `Cargo.lock`, `package.json`, `pnpm-lock.yaml`,
DVB1 framing, key derivation, SQLCipher schema and parameters, schema version,
blob path scheme, renderer IPC, Tauri capabilities, the G1 workflow. No
dependency was added, removed or re-pinned.

## Invariant regression

INV-001 through INV-010 remain covered by the pre-existing G1 suite, which
passed unchanged in both the local and clean-room runs. The two tests most
exposed to the R3 change — `job_result_commit_failure_is_not_done_and_rolls_back_result`
and `deferred_job_commit_failure_rolls_back_done_and_verified_at`, both of which
compare `verified_at` before and after a failed commit — pass unchanged,
confirming the new writer still rolls back atomically.

The remediation strengthens failure classification (R1) and write admission
(R2). It weakens no storage invariant.

## Known remaining non-material findings

- Standalone `chacha20` dependency-guard hardening: carried as a policy
  hardening follow-up, not a G1 correctness or supply-chain defect.
- The G0 workflow header comment still describes Ubuntu as independently
  allowed to fail, while the evidence job fails on any matrix failure. Stale
  prose only, outside this transaction's change allowlist.

## Governance

PR #1 remains OPEN and unmerged. No merge, no auto-merge, no rebase, no force
push, no tag, no release. `main` is unchanged at
`08a6b3d7159566b13c122164862465e539f7d3b5`. G2 remains NOT STARTED. No subagent
was used.

---

# Part II — Write-admission serialization and DVB1 read-error bounded remediation

Transaction:
`DVM-V2 / G1 — WRITE-ADMISSION SERIALIZATION + DVB1 READ-ERROR BOUNDED REMEDIATION`.

Everything above this line is the record of the **first** bounded remediation and
is preserved unchanged. This part records a **second, separate** bounded
remediation of two material findings raised by a fresh exact-head Codex review
of the published branch. It supplements, and does not replace, Part I or
`G1-ZERO-LOSS-VAULT-STORAGE.md`.

## Publication history reconciliation

Part I's identity table states that "exactly one commit was added to the
branch". That was true at the moment Part I was written, and it is no longer a
complete description of the branch. The branch's actual publication sequence is:

| #   | SHA                                                                                                                                                          | Kind        | Summary                                                                                                                                                                                                  |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `8f2b85a4f3aa3cdbb0229f9efe4097fb004c66a1`                                                                                                                   | Feature     | Original G1 implementation.                                                                                                                                                                              |
| 2   | `c1d7f6383ecdb87092b647633a94bb7ff7127b8c`                                                                                                                   | Remediation | Material correctness (R1–R4) plus the initial Windows CI remediation. This is the published SHA of the commit Part I describes; Part I's `verified_source_commit` `f11ce57f` is its pre-amend candidate. |
| 3   | `72c31a030ba1ec5d876b09bdc6a34b513bab7338`                                                                                                                   | CI only     | Explicitly authorized follow-up: the G0 Windows gate selects the **first** native Perl match returned by `Get-Command`.                                                                                  |
| 4   | ``597d2ec2d09391613e4a08a27931748c59957d61` (verified source candidate; the published SHA differs after the evidence-only amend and is reported externally)` | Remediation | This part: T1 write-admission serialization and T2 DVB1 read-error classification.                                                                                                                       |

Reconciliation of the wording gap:

- **Why commit 3 was authorized.** After commit 2 was published, the G0 Windows
  gate still failed. `Get-Command perl -CommandType Application` returns every
  match on PATH, and the assertion compared the whole collection rather than the
  interpreter the process would actually invoke. Selecting index `[0]` — the
  match the process resolves — was authorized as a separate, bounded, CI-only
  change.
- **It was CI only.** Commit 3 touched `.github/workflows/g0-foundation.yml`
  and nothing else. No crate, test, dependency, lockfile or schema changed, so
  the source tree that Part I's local and clean-room evidence executed was not
  altered by it.
- **No force push occurred.** Commits 2, 3 and 4 are ordinary fast-forward
  additions. `8f2b85a4` and `c1d7f638` are byte-identical to their published
  form; no published commit has been amended, rebased or reset at any point.
- **Prior evidence stays attached to the right tree.** Part I's local and
  clean-room results belong to source tree
  `e6fbba643f5ecdd34d162e15e44cf8a059a7fc17` (candidate `f11ce57f`, published as
  `c1d7f638`). They are not claimed as evidence for commit 3 or commit 4.
- **This is a separate bounded remediation.** Commit 4 carries its own
  negative controls, its own full local acceptance, its own clean-room run and
  its own exact-head CI. No earlier result is reused as evidence for it.

No historical timestamp, exit code or measurement recorded in Part I has been
altered.

## Findings addressed

The live review surface was re-read in full before implementation and contained
exactly nine threads (`reviewThreads.totalCount = 9`). No unclassified thread
existed.

| Ref | Thread                                                     | Path                                                                | Classification        |
| --- | ---------------------------------------------------------- | ------------------------------------------------------------------- | --------------------- |
| T1  | `PRRT_kwDOUZSIRc6iDhfl`                                    | `crates/dvm-storage/src/vault.rs`                                   | Material correctness  |
| T2  | `PRRT_kwDOUZSIRc6iDhfs`                                    | `crates/dvm-storage/src/vault.rs` → `crates/dvm-crypto/src/dvb1.rs` | Material correctness  |
| —   | `PRRT_kwDOUZSIRc6iDgeJ` (Copilot, `scripts/verify-g0.mjs`) | —                                                                   | Refuted, non-material |
| —   | `PRRT_kwDOUZSIRc6iDgeg` (Copilot, `scripts/verify-g1.mjs`) | —                                                                   | Refuted, non-material |

The five Part I threads (R1, R2, R3, R4 Codex, R4 Copilot) were re-read and are
regression surfaces only; none was reimplemented.

### T1 — write admission serialized with integrity discovery

Before: every canonical mutator read `require_writable()` **before** acquiring
the database mutex:

```rust
self.require_writable()?;   // health read here
let mut db = self.db()?;    // mutex acquired here
```

Between those two lines another caller can hold the mutex, discover a canonical
integrity failure, latch `RepairRequired` and release. The waiting caller then
proceeds on a verdict taken before that discovery and mutates a vault already
known to be unusable.

After: one central boundary, `Vault::writable_db`, acquires the mutex and reads
the live repair state **while holding it**, returning the guard only when the
vault is `Healthy`. The guard that admits the write is the same guard that
carries the mutation, so exactly two orders remain — mutation strictly before
discovery, or refusal strictly after it — and there is no third order in which a
mutation follows a discovery that already happened.

Mutator audit. Every database-guard acquisition in the crate was inspected:

| Entry point          | Before         | After           | Rationale                                                                                                                          |
| -------------------- | -------------- | --------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `commit_import`      | check → lock   | `writable_db()` | Canonical mutation requiring health.                                                                                               |
| `claim_job`          | check → lock   | `writable_db()` | Canonical mutation requiring health.                                                                                               |
| `complete_job`       | check → lock   | `writable_db()` | Canonical mutation requiring health.                                                                                               |
| `stage_import`       | check, no lock | unchanged       | Best-effort pre-check only; see below.                                                                                             |
| `recover`            | lock           | unchanged       | Integrity **discovery**, not an admitted write. Its `CORRUPTED` update is the discovery itself.                                    |
| `reconcile`          | lock           | unchanged       | Startup, before the instance admits anything.                                                                                      |
| `fail_job`           | lock, no check | unchanged       | Recording a failure must succeed on an unhealthy vault, or a leased job could never be released. Semantics deliberately preserved. |
| `cancel_pending_job` | lock, no check | unchanged       | Cancels an unclaimed `PENDING` job; not admission-gated before this change either.                                                 |

Read-only and non-admitted paths were not mechanically rewritten.

**The database mutex is not held across staging.** `stage_import` streams and
encrypts the entire source, which for a multi-GB original runs for minutes. It
takes no database guard at all, before or after this change; its
`require_writable()` call is documented in the source as a best-effort check
that only avoids expensive staging already known to be pointless. Authoritative
admission belongs to `commit_import`. If the repair state changes during
staging, the commit refuses and the encrypted `.part` survives as reconcilable
temporary state — recoverable, whereas a false canonical success is not.

`commit_import`'s guard scope is byte-for-byte the scope it had at the start
head: only the position of the health read moved, from before the lock to after
it.

### T2 — operational canonical reads keep their operational classification

Before: after `File::open` succeeded, `decrypt_frames` mapped **every**
`read`/`read_exact` failure to `BlobAuthFailed` via `corrupt()`. A failing or
disconnected disk, a permission change or a transient fault therefore latched
`RepairRequired` and persisted `CORRUPTED` for canonical ciphertext that may be
entirely intact.

After: a single classifier decides by error kind.

| Condition                                                                                                                 | Code             | Why                                                         |
| ------------------------------------------------------------------------------------------------------------------------- | ---------------- | ----------------------------------------------------------- |
| `UnexpectedEof` reading required framing or ciphertext                                                                    | `BlobAuthFailed` | The stored stream is truncated — a genuine content failure. |
| AEAD authentication failure                                                                                               | `BlobAuthFailed` | Unchanged.                                                  |
| Invalid DVB1 framing / index / length / ID                                                                                | `BlobAuthFailed` | Unchanged.                                                  |
| Trailing-byte violation (extra bytes present)                                                                             | `BlobAuthFailed` | Unchanged.                                                  |
| `PermissionDenied`, `Interrupted`, `BrokenPipe`, `TimedOut`, `ConnectionAborted`, `Other`, any other non-EOF read failure | `Internal`       | Operational: says nothing about the stored bytes.           |

All five stored-stream read sites in `decrypt_frames` are covered: header,
header authentication tag, frame index/length, encrypted frame payload and the
trailing byte.

No new public `ErrorCode` was introduced. `Internal` is the existing operational
class, and `AppError::new` leaves `safe_details` empty, so no path, errno or OS
message crosses the boundary.

**Import-source semantics are untouched.** `encrypt` still maps source-side read
failures to `SourceUnreadable`. That contract is separate from reading an
already-canonical DVB1 blob and was not altered.

**The transactional sink guarantee is unchanged.** `decrypt` aborts the sink on
every error path regardless of code, so an operational read failure still aborts
the sink, returns no `DigestReceipt` and commits no partial plaintext. This is
asserted explicitly at every injected phase.

**DVB1 was not redesigned.** Magic bytes, format version, algorithm id, nonce
construction, header size, frame structure, AAD layout, cipher, chunk size and
key derivation are unchanged. The pre-existing DVB1 corpus and corruption
matrix pass unmodified.

## Tests added

| Test                                                                    | File                              | Covers                     |
| ----------------------------------------------------------------------- | --------------------------------- | -------------------------- |
| `write_admission_is_linearized_with_integrity_discovery`                | `crates/dvm-storage/src/tests.rs` | T1 CASE B (race)           |
| `writer_that_linearizes_first_commits_and_later_discovery_still_closes` | `crates/dvm-storage/src/tests.rs` | T1 CASE A (opposite order) |
| `operational_canonical_read_failure_never_condemns_intact_data`         | `crates/dvm-storage/src/tests.rs` | T2 storage integration     |
| `operational_read_failures_never_authenticate_as_corruption`            | `crates/dvm-crypto/src/dvb1.rs`   | T2 crypto matrix           |
| `truncation_still_authenticates_as_corruption`                          | `crates/dvm-crypto/src/dvb1.rs`   | T2 EOF/truncation control  |

### Determinism of the T1 race oracle

The interleaving is pinned by a `std::sync::Barrier`, not by sleeps.

`Vault::recover` aborts its sink **while still holding the database guard** and
**before** it latches repair state, and it does not release that guard until it
returns, which is after the latch. A test sink that waits on the barrier from
`abort` therefore releases the waiting mutator at a point where the discovering
thread provably owns the synchronization boundary. The mutator's own rendezvous
sits immediately **before** it acquires the guard, so it cannot hold the lock
while waiting and cannot acquire it until the latch is already visible.

Required sequence, as executed: healthy vault → canonical item exists → writer's
inputs prepared while healthy → canonical original removed → writer reaches
admission and blocks → `recover` discovers the failure and latches
`RepairRequired` under the guard → guard released → writer proceeds to admission
→ writer refuses. Asserted per mutator: refusal code, unchanged `blobs`,
`items`, `item_blobs` and `jobs` counts, unchanged job status, unchanged
`blobs.verified_at`, surviving `.part`, and `health() == RepairRequired`.

The `complete_job` arm deliberately leases a **different, intact** canonical
original from the one that fails. `complete_job` verifies its own blob before
publishing a result, so a lease on the damaged original would be refused by that
check and would prove nothing about write admission.

### Test-only seams

Three `cfg(test)` seams exist, all thread-local or field-gated and all absent
from production builds. None is reachable from the renderer, none is driven by
an environment variable, and none changes normal DVB1 or vault API semantics.

- `READ_FAULT` — one-shot canonical-read fault: serve N valid bytes, then fail
  with a chosen `std::io::ErrorKind`. Needed because operational read failures
  cannot be produced deterministically and cross-platform by damaging real
  storage.
- `ADMISSION_RENDEZVOUS` — the barrier slot used by the race oracle.
- `FaultyReader` (in `dvm-crypto` tests) — the same idea at the crypto layer, a
  pure in-test `Read` implementation over an in-memory stream.

`CanonicalRead` is a transparent pass-through to the open file in production;
its fault field exists only under `cfg(test)`.

## Negative controls

Each defect was restored in place while keeping the new tests and seams, so the
oracles fail on assertions rather than compile errors.

**T2** — `read_error` reduced to the start-head behaviour (every read failure
reported as `corrupt()`):

```
cargo test --locked -p dvm-crypto --lib -> EXIT 101
  operational_read_failures_never_authenticate_as_corruption  FAILED
    assertion `left == right` failed: header: PermissionDenied must stay operational
      left: BlobAuthFailed   right: Internal
  truncation_still_authenticates_as_corruption                ok
  authenticated_corruption_matrix_aborts_all_output           ok
  exact_roundtrip_boundary_matrix                             ok
```

`NEGATIVE_CONTROL_T2 = PASS`. The oracle detects the defect, and the truncation
control stays green, which proves the oracle is specific rather than a blanket
failure.

**T1** — `writable_db` reordered to the start-head ordering
(`require_writable()` → rendezvous → `db()`):

```
cargo test --locked -p dvm-storage --lib -> EXIT 101
  write_admission_is_linearized_with_integrity_discovery              FAILED
    Error: "commit_import admitted after integrity discovery"
  writer_that_linearizes_first_commits_and_later_discovery_still_closes  ok
```

Each mutator arm was additionally run first in the loop to prove it detects the
defect independently rather than being masked by an earlier arm:

```
order ["claim_job", ...]     -> Error: "claim_job admitted after integrity discovery"
order ["complete_job", ...]  -> Error: "complete_job admitted after integrity discovery"
order ["commit_import", ...] -> Error: "commit_import admitted after integrity discovery"
```

`NEGATIVE_CONTROL_T1 = PASS`. CASE A stays green throughout, proving the oracle
rejects only the illegal order.

The controls were applied by temporary in-place reversal of the fix alone; the
seams and tests were held constant, and no authoritative history was mutated.

## Commands and exit codes

| Command                                                                         | Exit                                       |
| ------------------------------------------------------------------------------- | ------------------------------------------ |
| `cargo fmt --all -- --check`                                                    | 0                                          |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 0                                          |
| `cargo test --locked -p dvm-crypto -- --nocapture`                              | 0 (6 passed, 5 compile-fail doc tests)     |
| `cargo test --locked -p dvm-storage -- --nocapture`                             | 0 (27 passed, 0 failed, 2 ignored)         |
| `cargo test --locked --release -p dvm-crypto -p dvm-storage -- --nocapture`     | 0 (6 + 27 passed, 2 ignored)               |
| `pnpm --filter @dvm/security-tests run test`                                    | 0 (130 passed, 5 files)                    |
| `pnpm lint`                                                                     | 0                                          |
| `pnpm typecheck`                                                                | 0                                          |
| `git diff --check`                                                              | 0                                          |
| `git diff --cached --check`                                                     | 0                                          |
| T1 race + opposite-order oracles (focused)                                      | 0                                          |
| T2 operational-read + `UnexpectedEof` matrices (focused)                        | 0                                          |
| T2 storage integration oracle (focused)                                         | 0                                          |
| Runtime corruption control (focused)                                            | 0                                          |
| Negative control T1, defect restored                                            | 101 (race oracle fails as designed)        |
| Negative control T2, defect restored                                            | 101 (operational matrix fails as designed) |

The five `error[E0277]` lines emitted by the `dvm-crypto` run are the intended
`compile_fail` doc tests proving key material cannot be serialized or debugged.
All five pass.

## Full local G1 acceptance

`pnpm verify:g1` -> EXIT 0, `G1 LOCAL ACCEPTANCE: PASS; multi-GB and crash gates executed`.

G0 sub-gate: `15 run, 0 skipped, 0 failed, 0 not reached`, `G0 VERDICT: PASS
(all steps executed and green)`. No mandatory step was skipped; the interactive
`runtime` step executed and passed.

| Gate step                                                                                                            | Exit | Elapsed  |
| -------------------------------------------------------------------------------------------------------------------- | ---- | -------- |
| `node scripts/verify-g0.mjs`                                                                                         | 0    | 383.18s  |
| `cargo test --locked --release -p dvm-crypto -p dvm-storage -- --nocapture`                                          | 0    | 5.326s   |
| `cargo test --locked --release -p dvm-storage --lib tests::multi_gb_bounded_memory -- --exact --ignored --nocapture` | 0    | 218.487s |

```
MULTI_GB size=2151677952 sparse=false chunk=4194304
  largest_buffer=4194320 configured_crypto_buffers=8388624
  source_sha256=db5700bafac53992293386a224c6d460eaeaef8c1084e1ad909b846dbab8c130
  recovered_sha256=db5700bafac53992293386a224c6d460eaeaef8c1084e1ad909b846dbab8c130
  recovered_bytes=2151677952 baseline_working_set=7163904
  peak_working_set=22921216 incremental_estimate=15757312
  elapsed_seconds=214.911 disk_before=7805890560 disk_after=8384217088
  BYTE_EQUALITY=PASS BOUNDED_MEMORY=PASS
```

Real-process crash matrix C1-C8 passed in both debug and release profiles.
Corruption matrix (`missing`, `flip`, `truncate`, `swap`) passed. The >2 GiB
corpus was not reduced.

### Host resource observations

Three runs on this host were terminated by the operating environment before
producing any gate verdict and are **not** recorded as gate outcomes:

- Two `pnpm verify:g1` runs were stopped during the release Tauri dependency
  build. Both failed compiler invocations with
  `STATUS_DLL_INIT_FAILED (0xc0000142)`, the Windows signature for refusing to
  initialize a DLL under commit pressure. Measured at the time: 15.72 GiB total
  RAM with 3.62 GiB free, and 17.67 GiB committed against a 22.75 GiB commit
  limit. In both runs every other G0 step passed, including
  `cargo test --workspace --locked` and Clippy with warnings denied; only
  `tauri-build` failed.
- One clean-room release build was stopped for the same reason.

The successful runs bounded compiler parallelism (`CARGO_BUILD_JOBS`) and, for
the clean-room release build, ran with more host memory available. No gate,
command, corpus size or source was changed to obtain them. The Tauri release
build then completed in 7m 05s locally and the clean-room release build in
10m 22s, both exit 0 with no `STATUS_DLL_INIT_FAILED`.

Disk: the transaction began with roughly 11.6 GiB free. After local acceptance
had passed and been recorded, 5.6 GiB of regenerable build output was reclaimed
from the main tree with `cargo clean` only, to make room for the clean-room
tree. No package cache, source, lockfile or corpus was removed or reduced.

## Clean-room revalidation

Fresh short-path checkout at `C:\dvm-g1-followup-cr`, cloned with no checkout
and set to `597d2ec2d09391613e4a08a27931748c59957d61`. Checkout tree hash
`6c07515c64218cb6f8615a524877599c246e5e1b` equals the candidate tree. No
`target`, `node_modules`, `dist`, local evidence directory or compiled
SQLCipher/OpenSSL artifact was copied in; both `libcrypto.lib` and `libssl.lib`
were built from source inside the clean room.

| Gate                                                                                | Result                                                           |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `pnpm install --frozen-lockfile`                                                    | EXIT 0                                                           |
| `git diff --exit-code -- pnpm-lock.yaml Cargo.lock`                                 | EXIT 0, lockfiles unchanged                                      |
| `pnpm verify:g1 --cleanroom`                                                        | EXIT 0, `G1 LOCAL ACCEPTANCE: PASS`                              |
| G0 sub-gate                                                                         | `15 run, 0 skipped, 0 failed, 0 not reached`, `G0 VERDICT: PASS` |
| `node scripts/verify-g0.mjs`                                                        | EXIT 0, 705.594s                                                 |
| `cargo test --locked --release -p dvm-crypto -p dvm-storage`                        | EXIT 0, 5.529s                                                   |
| multi-GB release gate                                                               | EXIT 0, 80.469s                                                  |
| T1 `write_admission_is_linearized_with_integrity_discovery`                         | ok                                                               |
| T1 `writer_that_linearizes_first_commits_and_later_discovery_still_closes`          | ok                                                               |
| T2 `operational_canonical_read_failure_never_condemns_intact_data`                  | ok                                                               |
| T2 `operational_read_failures_never_authenticate_as_corruption`                     | ok                                                               |
| T2 `truncation_still_authenticates_as_corruption`                                   | ok                                                               |
| Crash matrix `real_process_crash_matrix_c1_through_c8_and_job_commit`               | ok                                                               |
| Corruption matrix `missing_mutated_truncated_and_substituted_originals_fail_closed` | ok                                                               |
| Lockfiles at finish                                                                 | unchanged                                                        |
| Working tree at finish                                                              | clean                                                            |

```
MULTI_GB size=2151677952 sparse=false chunk=4194304
  largest_buffer=4194320 configured_crypto_buffers=8388624
  source_sha256=db5700bafac53992293386a224c6d460eaeaef8c1084e1ad909b846dbab8c130
  recovered_sha256=db5700bafac53992293386a224c6d460eaeaef8c1084e1ad909b846dbab8c130
  recovered_bytes=2151677952 baseline_working_set=7139328
  peak_working_set=22990848 incremental_estimate=15851520
  elapsed_seconds=77.741 disk_before=18363834368 disk_after=14557290496
  BYTE_EQUALITY=PASS BOUNDED_MEMORY=PASS
```

The clean room reproduced the same plaintext digest as the local run on a corpus
of the same full size. Because `dvm-crypto` error classification and storage
admission semantics both changed, this multi-GB and crash evidence was
regenerated here; no earlier clean-room result is reused for this commit.

## Scope

Changed paths in the follow-up remediation commit:

```
crates/dvm-crypto/src/dvb1.rs
crates/dvm-storage/src/jobs.rs
crates/dvm-storage/src/tests.rs
crates/dvm-storage/src/vault.rs
```

plus this evidence document, folded in by the evidence-only amend.

**Scope note on `crates/dvm-storage/src/jobs.rs`.** The transaction's change
allowlist named `vault.rs`, the storage tests and `dvb1.rs`. Section 13 of the
same transaction separately requires that `claim_job` and `complete_job` be
corrected to the lock-then-admit rule, and the Definition of Done requires "job
mutators audited/protected". Both functions live in `jobs.rs`, and the
correction is not expressible anywhere else: the defective ordering is the
literal `self.require_writable()?;` statement in each. The change is therefore
the minimum the transaction mandates — two call sites replaced by
`self.writable_db()?`, with no change to job semantics. It is recorded here
explicitly rather than absorbed silently.

Job semantics preserved and still green: transactional lease, ACK-after-success,
idempotent replay, bounded retries, stale-worker rejection.

Not modified: `Cargo.toml`, `Cargo.lock`, `package.json`, `pnpm-lock.yaml`,
DVB1 format version, nonce construction, AAD layout, chunk size, SQLCipher
configuration, `schema.sql`, schema version, key derivation, the VMK boundary,
Tauri capabilities, renderer IPC, the G0 workflow and the G1 workflow. No
dependency was added, removed or re-pinned.

## Regression surface

| Property                                                                                            | State                                                                                                                 |
| --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| R1 — only `NotFound` is `MissingBlob`; other open/metadata failures stay operational                | Preserved; `operational_canonical_io_is_never_reported_as_a_missing_blob` passes unchanged                            |
| R2 — runtime `MissingBlob`/`BlobAuthFailed` latches sticky `RepairRequired` and denies later writes | Preserved and strengthened; `runtime_canonical_corruption_latches_repair_required_and_blocks_writes` passes unchanged |
| R3 — one UTC ISO-8601 representation for `blobs.verified_at`                                        | Preserved; not reimplemented                                                                                          |
| R4 — `HashSet` startup membership                                                                   | Preserved; not reimplemented                                                                                          |
| Windows native Perl CI fix (commits 2 and 3)                                                        | Preserved; no workflow change in this commit                                                                          |
| DVB1 corruption matrix                                                                              | Passes unmodified                                                                                                     |
| Real-process crash matrix C1–C8                                                                     | Passes                                                                                                                |
| INV-001 … INV-010                                                                                   | Green                                                                                                                 |

T1 and T2 extend R1 and R2 rather than reversing them: R1 classified the _open_
of a canonical original, T2 classifies the _reads_ that follow it, and both
reserve data-loss verdicts for genuine data loss. R2 made runtime discovery
sticky; T1 makes the moment that stickiness is read linearizable with the
mutations it must block.

## Refuted Copilot findings — `fs.statfsSync`

Both threads assert that `fs.statfsSync` is POSIX-only and throws on Windows,
and that this crashes the gates before any check runs. The premise is false in
this repository's actual Windows runtime.

```
node --version                     -> v22.22.2
node -e "...fs.statfsSync(cwd)..." -> statfsSync OK {"bavail":2833637,"bsize":4096,"free":11606577152}
```

`scripts/verify-g0.mjs` and `scripts/verify-g1.mjs` both execute their
`statfsSync` telemetry call on this Windows host and in Windows CI, and both
gates ran to completion. No source change is authorized or warranted for these
findings.

Exact-head Windows CI evidence for these two threads is reported in the thread
replies themselves rather than retro-fitted into this document, because this
document is folded into the candidate commit before that commit is pushed and
CI can run against it. No result is back-dated here.

## Governance

PR #1 remains OPEN, non-draft and unmerged. No merge, no auto-merge, no rebase,
no reset, no force push, no tag, no release, no deployment. `main` is unchanged
at `08a6b3d7159566b13c122164862465e539f7d3b5`. Exactly one new commit was added
to the branch. G2 remains NOT STARTED. No subagent was used.
