# G3 P1/P2 bounded remediation

Status: P1/P2 remediation VERIFIED; `LOCAL_G3=PASS`, `WINDOWS_CLEAN_ROOM=PASS`, and `LINUX_CANDIDATE=PASS`. Exact-source candidate verification is complete. Publication, exact-head CI and fresh review acceptance remain pending; no merge or G3 closure is claimed.

## Start identity

Verified on 2026-09-26 before source changes and after `git fetch origin`:

- Branch: `feat/dvm-v2-g3-recovery-backup-migration`.
- HEAD and origin feature: `53fec5e15061effc8fc62fee2d7dbb444adab5bb`.
- Tree: `5181ee377713607b4ab545f38e9e1fd1492d84b7`.
- Parent: `71cb293da23631a74a407d7f890f9c44f1da36ca`.
- Origin main: `be77cf71ccca104af0d085aee70e7b08ab3b2956`.
- Working tree: clean. PR #3: OPEN, non-draft, unmerged, exact required head.
- The unpublished `170e518...` candidate was not required as a parent.

## Bounded changes

- P1 / `PRRT_kwDOUZSIRc6mJ8ok`: dvm-storage owns a shared portable path generator and strict validator. New rows use `blobs/<uuid>.dvb`; normal recovery/reconciliation and backup snapshot verification accept that exact form and historical `blobs\<uuid>.dvb`. Readers do not rewrite legacy rows. IDs must be canonical lowercase hyphenated UUIDs. Native paths are derived from validated IDs; aliases, traversal, rooted paths, wrong IDs, streams and NUL suffixes are rejected. Archive-member validation is unchanged.
- P2 / `PRRT_kwDOUZSIRc6mJ8oq`: backup admission uses `symlink_metadata`. Atomic activation maps only `AlreadyExists` to `RestoreConflict`, sharing the existing restore classification. Other I/O errors retain `Internal` or `DiskFull`. The no-replace OS adapters are unchanged.
- Regressions exercise actual storage import/recovery/reopen, snapshot validation, encrypted backup and STRUCTURAL/FULL verification, restore and ordinary unlock/recovery with unchanged canonical rows. A test-only hook creates competitors immediately before the real activation syscall. Tests inspect competitor contents, zero backup-history rows, primary staging cleanup and early symlink refusal before snapshot creation.
- No dependency, lockfile, schema, migration, renderer, G4 or native credential changes.

## Historical local verification record

Toolchain: Windows x64 and WSL Ubuntu Linux x64; Rust/Cargo 1.94.1, Windows Node 22.22.2 and pnpm 10.27.0. Linux kernel: `6.18.33.2-microsoft-standard-WSL2`.

Linux uses an isolated clone at the exact start HEAD with the remediation source overlaid, plus existing native-library and Cargo build caches. This is runtime regression evidence, not fresh clean-room acceptance or an actual archive transfer between machines.

| Command / phase                                                                                   | Result                                                                                             |
| ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Required Git preflight and `gh pr view 3`                                                         | EXIT 0; all identities matched                                                                     |
| `node scripts/prepare-sodium.mjs` (Windows)                                                       | EXIT 0; pinned libsodium 1.0.22 verified                                                           |
| Unfixed Linux `cargo test --locked -p dvm-storage --lib portable_storage_relpath -- --nocapture`  | Expected FAIL: 1 passed, 2 failed; legacy recovery rejected and native comparison admitted aliases |
| Unfixed Linux `cargo test --locked -p dvm-backup --lib portable_storage_relpath -- --nocapture`   | Expected FAIL: 0 passed, 2 failed; `BackupInvalid` / `UnsupportedVaultVersion`                     |
| Unfixed Linux `cargo test --locked -p dvm-backup --lib backup_activation_conflict -- --nocapture` | Expected FAIL: 0 passed, 2 failed; `Internal` instead of `RestoreConflict`                         |
| Fixed Linux storage path regressions                                                              | EXIT 0; 3 passed                                                                                   |
| Fixed Linux `cargo test --locked -p dvm-storage --lib`                                            | EXIT 0; 52 passed, 1 existing ignored                                                              |
| Fixed Linux `cargo test --locked -p dvm-backup --lib -- --nocapture`                              | EXIT 0; 21 passed, 0 ignored                                                                       |
| `pnpm format:check`; `git diff --check`                                                           | EXIT 0                                                                                             |

Additional checks:

- Linux `cargo clippy --locked -p dvm-storage -p dvm-backup --all-targets --all-features -- -D warnings`: EXIT 0 after test formatting correction.
- Linux `node scripts/g3-negative-controls.mjs`: EXIT 0; all 9 controls detected; all source bytes restored.
- Windows `cargo test --locked -p dvm-storage --lib portable_storage_relpath -- --nocapture`: EXIT 0; 3 passed.
- Windows `cargo test --locked -p dvm-backup --lib -- --nocapture`: EXIT 0; 16 passed, 0 ignored.

An initial new cleanup assertion failed because SQLCipher snapshot `-wal` and `-shm` sidecars remained after activation refusal. Inspection confirmed the `.part` and `.snapshot` files were removed. The assertion now checks that existing primary-file cleanup behavior; sidecar lifecycle was not changed in this bounded transaction. This is not a claim of zero sidecar residue. The fixture removes its own temporary root after testing.

The first targeted Linux Clippy run found three missing semicolons in new test match arms. They were corrected without lint allowances; the subsequent run passed. SHA-256 read-back confirmed that all four changed Rust files in the Linux checkout match the Windows source after negative-control restoration. Linux raw transcripts and Windows backup output are retained locally under `.dvm-local/g3-p1-p2/`.

## Complete local gate and final read-back

`pnpm verify:g3`: **EXIT 0**. The uninterrupted run reported `G0 VERDICT: PASS`, `G1 LOCAL ACCEPTANCE: PASS`, `LOCAL_G2=PASS`, and `LOCAL_G3=PASS`, with `G3_MANDATORY_SKIPS=0` and `G3_TEST_RESIDUE=NONE`. Its complete transcript is `.dvm-local/g3-p1-p2/windows-g3.log`.

- G0: frozen install, unchanged lockfiles, formatting, lint, typecheck, desktop tests, Rust format, workspace Clippy, workspace Rust tests, security tests (137/137), renderer build, production Tauri build and runtime evidence all exited 0.
- Windows storage suite: 57 passed, 2 existing ignored, in both workspace and release runs. The mandatory ignored multi-GB test was then executed explicitly: 2,151,677,952 recovered bytes, matching source/recovered SHA-256, `BYTE_EQUALITY=PASS`, `BOUNDED_MEMORY=PASS`. Recorded incremental working-set estimate: 15,859,712 bytes. The test's `disk_before` was 17,491,070,976 bytes.
- G2 and G3 negative controls passed with source restoration. Real Windows credential integration passed. `G2_TEST_CREDENTIAL_RESIDUE=NONE` and `ZERO_BYTE_CREDENTIAL_RESIDUE=NONE` were recorded. A final `cmdkey /list` audit exited 0 and counted zero `dvm/` entry lines without recording credential identities.
- G3 release migration checks: 3 passed. Release backup suite: 16 passed, including legacy metadata backup/restore, collision regressions, destructive restore, and both crash matrices. Plaintext hash mismatch: NO; canonical metadata: PASS.
- Final `git fetch origin` and PR read-back: unchanged local/published HEAD `53fec5e15061effc8fc62fee2d7dbb444adab5bb`, unchanged main `be77cf71ccca104af0d085aee70e7b08ab3b2956`; PR #3 OPEN, non-draft, unmerged. The only changes are four Rust files, ADR-0013, and this evidence document. No commit, staging, push, review-thread write, or merge was performed.
- Final Rust file SHA-256 values match the pre-gate values and the verified Linux checkout. The binary Git diff of the five changed tracked files, excluding this new evidence document, is retained as `.dvm-local/g3-p1-p2/source.patch`; SHA-256: `fde254c2756c58c25a84a2524758ce1eb8f90fe8e0a7d3c5f79cb5c2bc418a4c`. This identifies the tested local delta against the start HEAD; it is not a published source commit.

## Exact-source candidate verification

The publication transaction began with the existing, intentionally uncommitted remediation. Full diff review, whitespace checks and live Git/PR read-back matched the required published identity and bounded six-file scope. The binary/source delta was recomputed before staging and matched SHA-256 `fde254c2756c58c25a84a2524758ce1eb8f90fe8e0a7d3c5f79cb5c2bc418a4c`.

- `VERIFIED_SOURCE_CANDIDATE`: `bb16eed1828fc4938b5eceb2423ad9ce74976faf`.
- Candidate tree: `87cef49480075ec49bd06c49ca077a23592ed441`.
- Candidate parent: `53fec5e15061effc8fc62fee2d7dbb444adab5bb`.
- Subject: `fix: make G3 recovery paths portable and preserve backup conflicts`.
- Exactly one unpublished remediation commit was created. The final publication commit is produced by amending only this evidence document after the two exact-candidate verification runs; its identity is recorded in publication read-back rather than self-referenced here.

### Fresh Windows clean room

Fresh `git clone --no-hardlinks` at `C:\dvm-p1p2-cr`, detached at the candidate SHA/tree above. No alternate Cargo target directory was used. Free disk before clone: 17,402,503,168 bytes; before frozen install: 17,367,609,344 bytes; before the gate: 17,301,659,648 bytes (over 16 GiB). Final read-back: 13,672,226,816 bytes free.

- `pnpm install --frozen-lockfile`: EXIT 0.
- `pnpm verify:g3 --cleanroom`: EXIT 0; `G0 VERDICT: PASS`, `G1 LOCAL ACCEPTANCE: PASS`, `CLEAN_ROOM_G2=PASS`, `CLEAN_ROOM_G3=PASS`; `G3_MANDATORY_SKIPS=0`.
- Windows storage: 57 passed, 2 existing ignored in ordinary workspace/release suites. The mandatory multi-GB test was then invoked explicitly and passed: 2,151,677,952 bytes recovered, matching SHA-256 `db5700bafac53992293386a224c6d460eaeaef8c1084e1ad909b846dbab8c130`, `BYTE_EQUALITY=PASS`, `BOUNDED_MEMORY=PASS`; incremental working-set estimate 15,859,712 bytes. Fixture cleanup completed.
- P1: all three storage regressions passed; backup strict snapshot validation and legacy metadata backup/restore regressions passed. P2: activation race conflict regression passed in workspace and release backup suites; dangling-symlink coverage is explicitly proven by the Linux suite below.
- G2 and G3 negative controls passed and restored source bytes. Windows release migration checks: 3 passed; release backup suite: 16 passed, 0 ignored. Destructive restore and backup/restore crash matrices passed; plaintext hash mismatch NO; canonical metadata PASS.
- Real Windows credential integration PASS; `G2_TEST_CREDENTIAL_RESIDUE=NONE`, `ZERO_BYTE_CREDENTIAL_RESIDUE=NONE`, `G3_TEST_RESIDUE=NONE`. Post-run `cmdkey /list`: EXIT 0 and zero `dvm/` entry lines, with credential identities withheld.
- Post-run HEAD/tree still match the candidate. Tracked lockfiles unchanged; `git status --porcelain` empty. `WINDOWS_CLEAN_ROOM=PASS`.

### Fresh Linux exact-candidate proof

Fresh isolated clone at `/home/gglig/.cache/dvm-g3-p1p2-candidate-20260926` in WSL Ubuntu, detached at candidate `bb16eed1828fc4938b5eceb2423ad9ce74976faf`, tree `87cef49480075ec49bd06c49ca077a23592ed441`. This checkout was created from the exact commit, with no working-tree patch overlay. Linux kernel `6.18.33.2-microsoft-standard-WSL2`; Rust 1.94.1. The existing Cargo build cache `/home/gglig/.cache/dvm-g3-w1-linux-20260925/target` was reused with two build jobs; this is exact-source Linux proof, not a dependency-cache-clean build. Repository-pinned native libsodium preparation exited 0.

| Required command                                                                | Result                                                 |
| ------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `cargo test --locked -p dvm-storage --lib`                                      | EXIT 0; 52 passed, 1 existing ignored                  |
| `cargo test --locked -p dvm-backup --lib -- --nocapture`                        | EXIT 0; 21 passed, 0 ignored                           |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | EXIT 0                                                 |
| `cargo test --workspace --locked`                                               | EXIT 0                                                 |
| `node scripts/g3-negative-controls.mjs`                                         | EXIT 0; all 9 controls detected; source bytes restored |

Explicit mechanical proofs:

- `PORTABLE_STORAGE_RELPATH=PASS`: `portable_storage_relpath_is_written_on_every_platform`.
- `WINDOWS_DB_PATH_ON_LINUX_NORMAL_RECOVERY=PASS`: `portable_storage_relpath_recovers_legacy_windows_and_portable_rows`.
- `WINDOWS_DB_PATH_ON_LINUX_BACKUP_VERIFY=PASS`: `portable_storage_relpath_backup_restore_preserves_legacy_metadata`, including STRUCTURAL/FULL verification and restored-vault ordinary recovery with unchanged legacy rows.
- `STORAGE_RELPATH_MALFORMED_MATRIX=PASS`: `portable_storage_relpath_rejects_aliases_and_traversal_before_plaintext` and `portable_storage_relpath_snapshot_accepts_only_exact_id_bound_forms`.
- `BACKUP_ACTIVATION_RACE_CONFLICT=PASS`: `backup_activation_conflict_preserves_competitor_and_records_no_history`.
- `BACKUP_DANGLING_SYMLINK_CONFLICT=PASS`: `backup_activation_conflict_detects_dangling_symlink_before_snapshot`.

These tests exercise historical Windows-form database values on Linux; they do not claim an actual archive transfer between machines. An initial runner invocation exited 127 because non-login Bash lacked Cargo's directory in PATH, before any test ran. Correcting the runner PATH required no source change; all required commands then passed. Final lockfile/source diff checks exited 0 and worktree status was empty. `LINUX_CANDIDATE=PASS`.

Raw transcripts and identity/proof read-backs for both platforms are retained locally under `.dvm-local/g3-p1p2-publication/`.

## Open cleanup observation and remaining acceptance

`OPEN_NON_BLOCKING_CLEANUP_OBSERVATION`: after refused backup activation, the application-owned SQLCipher snapshot primary `.snapshot` and backup `.part` are removed, but SQLite-created `-wal`/`-shm` sidecars may remain until the owning fixture/root is removed. No false backup success, source-vault mutation, plaintext exposure, corruption or recoverability defect was demonstrated. Snapshot sidecar lifecycle was **not changed or fixed** in this transaction. Whole-fixture cleanup passed the clean-room G3 residue gate.

Publication, exact-head remote CI, completed fresh Codex/Copilot reviews and conditional thread reconciliation are subsequent acceptance steps. PR #3 must remain OPEN and UNMERGED, main must remain `be77cf71ccca104af0d085aee70e7b08ab3b2956`, and G4 remains NOT STARTED. G3 closure is a separate transaction.
