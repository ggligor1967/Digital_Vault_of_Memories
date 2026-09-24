# DVM-V2 / G3 recovery, backup, migration evidence

Status: implementation candidate. Local and clean-room acceptance passed; remote CI and exact-head reviews are pending. This document does not claim G3 closure.

## Baseline

- Parent `be77cf71ccca104af0d085aee70e7b08ab3b2956`; tree `67c0277b7dd49309a5a01f214462302ba3b41f5b`.
- Blueprint SHA-256 `23e320ce6ce84c81fe79eb239ed64b897530135c6715f2f6202534c3a13695e9`.
- Gates SHA-256 `dc49be40b0d0ba93b6cb4ba06c65456ee89818a8e79261f831092bf6a3a9b59a`.
- Historical v1 schema SHA-256 `8571a2b25e05b3b7ebab8a6e21eda8e03c8d7eb5bbc6a663128ad60edc4ccebc`.
- v2 migration SHA-256 `6e8bc872ef58e1a2f7af991cb9b9e103d7c1fcea4b2092f3d65c24fe68b163fb`.

## Verification record

`pnpm verify:g3` composes the prior G2/G1/G0 gate, release G3 storage and backup tests, crash and corruption matrices, destructive restore, residue check, and diff check. The `--ci` mode explicitly retains inherited G1 multi-GB and interactive skips; it still executes G3 destructive restore. Local and clean-room modes must have zero mandatory skips.

For disk-limited Windows builds, G3 sets `DVM_G3_TRIM_DEBUG_AFTER_G0=1`. After G0 has fully passed and returned, the G1 composer verifies that `target/debug` resolves within this checkout, then removes only that regenerable build output before its release tests and multi-GB fixture. Standalone G1/G2 and CI behavior are unchanged. The local operator also removed only `target/debug/incremental` and `target/debug/build` between verification runs to satisfy the initial G3 disk preflight.

## Final local acceptance

The final local `pnpm verify:g3` exited 0 on Windows 11 Home 10.0.26200 after the native bootstrap ordering correction. Its output recorded `G0 VERDICT: PASS`, `G3_DISK_TRIM=PASS`, `G1 LOCAL ACCEPTANCE: PASS`, `LOCAL_G2=PASS`, `LOCAL_G3=PASS`, `G3_MANDATORY_SKIPS=0`, and `G3_TEST_RESIDUE=NONE`. The G1 nonsparse 2,151,677,952-byte oracle reported exact source/recovered SHA-256 `db5700bafac53992293386a224c6d460eaeaef8c1084e1ad909b846dbab8c130`, 11,186,356,224 bytes free before the fixture, 6,882,357,248 at its measured endpoint, and a measured incremental peak working set of 15,925,248 bytes in the prior complete local run. The final local run again executed and passed the multi-GB oracle. The G3 corpus used a 2,097,152-byte plaintext member and a 65,536-byte streaming chunk; its stored DVB1 blob was 2,097,248 bytes. G3 peak working set was not separately measured.

The bundled runtime reported SQLCipher `4.14.0 community`, SQLite `3.51.3`, OpenSSL provider `3.6.3`, and WAL mode. The production encrypted online snapshot passed SQLCipher and SQLite integrity. The G3 child-process matrices, future-schema DB/WAL/blob no-mutation oracle, corruption and path matrices, concurrent import plus maintenance exclusion boundary, FULL verification, and destructive original-removal/restore all passed. SQLite rebuilt the transient future-schema `-shm` index during the refusal probe; the DB, WAL, and canonical blob bytes were unchanged. Passphrase and recovery unlock passed after restore; absent device credential failed safely.

Eight temporary source faults were detected by the intended G3 oracles: ignored migration checksum, mutation of a future schema, plaintext snapshot, traversal admission, omitted public-format AAD, skipped FULL blob, direct final restore write, and accepted plaintext hash mismatch. Each source buffer was restored exactly. The final local run's authenticated archive SHA-256 was `47208ff5cf8d70e262945aa57effd9317fbb5c178555d81f833eb76186644612`; randomized backup IDs and nonces make different test-run hashes expected.

## Fresh clean-room acceptance

The first clean-room attempt from unpublished candidate `fb2ebac61e9d3e64508662ca4199d6b092dce22b` failed before a valid G3 oracle result: the G3 negative controls compiled before the pinned libsodium preparation, so linking failed. The failed test-owned clone was removed after its exact path and process ownership were checked. The unpublished primary commit was amended to prepare pinned libsodium before the controls. A complete local G3 rerun passed before the fresh clone.

Fresh clone `C:\dvm-g3-cr` checked out candidate `b963ec4a2616178a259abb27dfe8273a7afec9a1` directly from parent `be77cf71ccca104af0d085aee70e7b08ab3b2956`, without `target` or `node_modules`. `pnpm install --frozen-lockfile` exited 0. `pnpm verify:g3 --cleanroom` exited 0 with `G0 VERDICT: PASS`, `G1 LOCAL ACCEPTANCE: PASS` including the multi-GB oracle, `CLEAN_ROOM_G2=PASS`, `G3_NEGATIVE_CONTROLS=PASS`, `G3_DESTRUCTIVE_RESTORE=PASS`, `G3_PLAINTEXT_HASH_MISMATCH=NO`, `G3_BACKUP_CRASH_MATRIX=PASS`, `G3_RESTORE_CRASH_MATRIX=PASS`, `CLEAN_ROOM_G3=PASS`, `G3_MANDATORY_SKIPS=0`, and `G3_TEST_RESIDUE=NONE`. No `dvm-g3-*` test-owned temporary residue remained, and the clean-room tracked worktree was clean. `Cargo.lock` SHA-256 stayed `c970ff0c854e5c69f5d9c771721af6d6e1c989ee29d02cc59701dcf5326d2dfb`; `pnpm-lock.yaml` stayed `3fa555f62cc647f5d7ef6765b49742e5f05ea009d64b6c3a1364162b7a0e07f9`. The clean-room authenticated archive SHA-256 was `de08596433e57538272342e29425282f6a692a65e6318c1cf19ba2fd10fd4d22`.

During the cold clean-room build, the already-verified source checkout's unused, regenerable `target/release` output (about 1.52 GiB) was removed after checking that no process used it. This did not change source, lockfiles, test vaults, or the clean-room clone.

The final amended source SHA is recorded by Git and the final report. CI run URLs and exact-head reviews are pending. Do not mark remote evidence or G3 closure before those results are observed.
