# DVM-V2 / G1 — Material correctness and Windows CI bounded remediation

Transaction: `DVM-V2 / G1 — MATERIAL CORRECTNESS + WINDOWS CI BOUNDED REMEDIATION`.

This document records the remediation of the five open review findings that put
the published G1 candidate on HOLD. It supplements, and does not replace,
`G1-ZERO-LOSS-VAULT-STORAGE.md`.

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
