# DVM-V2 / G3 — atomic backup file activation

Status: local G3, Windows clean room, and Linux exact-candidate proof PASS. Remote CI, review, and thread gates remain separate. This record does not close G3 or authorize PR #3 to merge.

## Start identity and review finding

- Branch `feat/dvm-v2-g3-recovery-backup-migration`; clean starting worktree.
- Start HEAD and `origin/feat/dvm-v2-g3-recovery-backup-migration`: `50534c109e2a2a54528163071bef148c2aeb6df8`.
- Start tree: `d3a650495df29d803b54b0fc6d4a7057c03468cd`; parent: `1828415edc1330ce5660082682ee72f31881f80c`.
- `origin/main`: `be77cf71ccca104af0d085aee70e7b08ab3b2956`. PR #3 was OPEN, non-draft, unmerged at preflight.
- Fresh Codex finding at thread `PRRT_kwDOUZSIRc6mTFo9`: Linux/non-Windows file activation used `hard_link(staging, destination)` followed by `remove_file(staging)`.

## Activation analysis and change

The successful hard link published the final archive. A subsequent staging unlink could fail, returning an ordinary error from `activate_file_noreplace` after publication. `create_backup` would then skip `backup_history`, return failure, and a retry would encounter `RestoreConflict`. Classification: `POST_ACTIVATION_CLEANUP_AMBIGUITY`.

Linux file activation now uses the already pinned rustix 1.1.4 `renameat_with(CWD, staging, CWD, destination, RenameFlags::NOREPLACE)`. The syscall is the single activation point: success moves the verified sibling staging archive to the final name; `AlreadyExists` leaves the destination untouched. The Linux file path no longer has a post-publication staging unlink. Windows `MoveFileExW` with flags zero is unchanged. Other non-Windows targets return `Unsupported` until an atomic no-replace file primitive is verified, matching the restore-directory policy.

Only `AlreadyExists` maps to `RestoreConflict`; permission, generic I/O, unsupported, and storage-full failures retain their existing operational mappings. `create_backup` continues to FULL-verify and sync staging before activation, then records `backup_history` best-effort and returns a `BackupReceipt`. Snapshot cleanup after activation remains best-effort; history failure does not invalidate the archive. No fallible staging cleanup occurs after successful activation.

## Oracle coverage

- Linux primitive success: staging bytes become final bytes and the staging name disappears.
- Existing final file and dangling symlink: primitive returns `AlreadyExists`, preserves the destination and staging; `create_backup` returns `RestoreConflict` without a receipt.
- Deterministic test-only pre-activation hook: competitor creates the final destination after FULL verification; `create_backup` preserves it and records no successful backup-history row.
- Old-behavior negative control: a temporary source mutation restores `hard_link` and injects deterministic post-link cleanup failure. The oracle must fail specifically because an activation error left the final destination published. The script restores exact source bytes in `finally` and does not commit the mutation.
- Backup crash matrix: checkpoints before activation leave no valid final archive; checkpoints after activation leave a FULL-verifiable final archive.

## Validation and publication

On the amended local source, Windows `cargo fmt --all -- --check` and `git diff --check` exited 0. In WSL Ubuntu, `cargo test --locked -p dvm-backup --lib -- --nocapture` exited 0: 22 passed, 0 failed. It printed `BACKUP_ATOMIC_ACTIVATION_SUCCESS=PASS`, `BACKUP_ATOMIC_ACTIVATION_CONFLICT=PASS`, `BACKUP_DANGLING_SYMLINK=PASS`, `BACKUP_ACTIVATION_RACE=PASS`, and `BACKUP_CRASH_MATRIX=PASS`. `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` exited 0. `cargo test --workspace --locked` exited 0. The latter run did not request `--nocapture`, so its marker lines are not used as evidence; its exit status covers the workspace tests. Linux `node scripts/g3-negative-controls.mjs` exited 0: ten controlled mutations failed their intended oracles and exact source bytes were restored. The injected post-link cleanup error produced the expected `activation returned an error after publishing the destination` failure and `POST_PUBLISH_FAILURE_NEGATIVE_CONTROL=PASS`.

On Windows, `cargo test --locked --release -p dvm-backup --lib -- --nocapture` exited 0: 16 passed, 0 failed. This includes the unchanged `MoveFileExW` path, backup activation race/conflict, FULL backup verification, P1/P2 backup regressions, destructive restore, and the backup/restore crash matrices. The Windows adapter body has no production diff. An initial debug build lacked Perl in its invocation PATH and failed before tests; a later debug build was stopped while building native OpenSSL after release-cache reuse was selected. Neither is counted as a test pass.

### Complete local Windows G3

`pnpm verify:g3` exited 0 on the amended source. The saved transcript is `.dvm-local/g3-atomic-local-2.log` (local ignored evidence). The real preflight saw 9,724,968,960 free bytes against the unchanged 8,589,934,592-byte requirement. The gate reported:

| Required result        | Observed result                                                                                                                                                |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| G0                     | `G0 VERDICT: PASS`                                                                                                                                             |
| G1                     | `G1 LOCAL ACCEPTANCE: PASS`; measured multi-GB and crash gates executed                                                                                        |
| G2                     | `LOCAL_G2=PASS`; `SECRET_LOG_LEAKAGE=NO`                                                                                                                       |
| G3                     | `LOCAL_G3=PASS`; `G3_MANDATORY_SKIPS=0`; `G3_TEST_RESIDUE=NONE`                                                                                                |
| Multi-GB               | 2,151,677,952 recovered bytes; matching source/recovered SHA-256; `BYTE_EQUALITY=PASS`; `BOUNDED_MEMORY=PASS`; fixture cleanup completed                       |
| Activation and restore | 16/16 release backup tests passed; `BACKUP_ACTIVATION_RACE=PASS`; `G3_BACKUP_CRASH_MATRIX=PASS`; `G3_RESTORE_CRASH_MATRIX=PASS`; `G3_DESTRUCTIVE_RESTORE=PASS` |
| Credential residue     | `G2_TEST_CREDENTIAL_RESIDUE=NONE`; `ZERO_BYTE_CREDENTIAL_RESIDUE=NONE`                                                                                         |
| Negative controls      | Windows G3 and inherited G2 controls passed; mutated source bytes restored                                                                                     |

To satisfy disk preflight while preserving existing generated evidence, prior clean-room build cache was moved to E: behind a junction. The first full G3 attempt was stopped after its G3 negative controls when inspection found an E: junction for the active `target` directory would fail G1's workspace-contained debug trim check. The active `target` was restored as a physical workspace directory. Existing ignored `.dvm-local` evidence was preserved on E: behind a junction, with an unmovable native source-tree remnant retained under the ignored `target` directory. The successful second attempt used no alternate Cargo target, and `G3_DISK_TRIM=PASS` confirms the unchanged safety check and cleanup ran. Tracked lockfiles remained unchanged; `git diff --check` passed.

### Source candidate and fresh exact-candidate proofs

- The one unpublished append-only source candidate is `7a072b5f862c7c7fb50e0e0ae62ff1f2dbb4ad8f`, parent `50534c109e2a2a54528163071bef148c2aeb6df8`, tree `0c55c1bba8666f74622f6f327e2ae51db66f04df`, subject `fix: make backup publication atomically no-replace`. It contains only the five bounded production, test, ADR, and evidence paths recorded in this transaction. The source worktree was clean after commit.
- Fresh Windows `git clone --no-hardlinks` at `C:\dvm-g3-atomic-cr` was detached at the exact source candidate SHA/tree. `pnpm install --frozen-lockfile` exited 0. `pnpm verify:g3 --cleanroom` exited 0; saved local transcript: `.dvm-local/g3-atomic-cleanroom.log` in that checkout. `G0 VERDICT: PASS`, `G1 LOCAL ACCEPTANCE: PASS`, `CLEAN_ROOM_G2=PASS`, `CLEAN_ROOM_G3=PASS`, `G3_MANDATORY_SKIPS=0`, and `G3_TEST_RESIDUE=NONE`. The measured multi-GB case recovered 2,151,677,952 bytes with matching source/recovered SHA-256, `BYTE_EQUALITY=PASS`, `BOUNDED_MEMORY=PASS`, and fixture cleanup. The release backup suite passed 16/16, including activation race, P1/P2 backup regressions, destructive restore, backup/restore crash matrices, and lock lifetime checks inherited through G0/G2. `G2_TEST_CREDENTIAL_RESIDUE=NONE`; tracked lockfiles unchanged; final HEAD/tree matched the candidate; worktree clean. `WINDOWS_CLEAN_ROOM=PASS`.
- Fresh isolated WSL Ubuntu `git clone --no-hardlinks` at `/home/gglig/.cache/dvm-g3-atomic-candidate-20260927` was detached at the same source candidate SHA/tree. Pinned Linux libsodium source preparation exited 0. `cargo test --locked -p dvm-backup --lib -- --nocapture` exited 0: 22 passed, 0 failed, with atomic success/conflict, dangling-symlink, race, FULL backup, destructive restore, and backup crash markers. `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` exited 0; `cargo test --workspace --locked` exited 0. `node scripts/g3-negative-controls.mjs` exited 0: all ten controls detected their expected failure, including `POST_PUBLISH_FAILURE_NEGATIVE_CONTROL=PASS`, and exact source bytes were restored. The existing Linux Cargo dependency cache was reused; source came solely from the exact candidate checkout. Final HEAD/tree matched the candidate; tracked lockfiles unchanged; worktree clean. `LINUX_CANDIDATE=PASS`.

`VERIFIED_SOURCE_CANDIDATE=7a072b5f862c7c7fb50e0e0ae62ff1f2dbb4ad8f`. This document is the only file amended after both exact-candidate proofs. The final amended SHA and tree are read back after the amendment and recorded in the publication report; embedding either hash inside its own commit would change that hash. Remote CI, reviews, and thread reconciliation remain pending until publication and exact-head readback.

## Scope and open observation

Changed scope: `crates/dvm-backup/src/activation.rs`, bounded activation tests in `crates/dvm-backup/src/dvbk1.rs`, the G3 negative-control script, and a narrow activation description in ADR-0013. No dependency, schema, migration, DVBK1 format, manifest, keyslot, credential, lock, renderer, or G4 change.

`OPEN_NON_BLOCKING_CLEANUP_OBSERVATION`: existing SQLCipher snapshot `-wal` and `-shm` sidecars may outlive refused activation. This transaction does not alter their lifecycle; no material effect on file activation correctness has been demonstrated.
