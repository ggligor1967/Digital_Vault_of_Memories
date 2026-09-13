# DVM-V2 / G1 — ZERO-LOSS VAULT STORAGE

Status: full local and fresh exact-candidate clean-room acceptance PASS.
Remote publication and exact-head CI are reported externally after the final amend.
Goal: preserve original plaintext bytes durably across process restart.
Base commit: 08a6b3d7159566b13c122164862465e539f7d3b5.
Base tree: 2166b4d4ee8194530d9b611e78450e48a0ed2603.
Verified source candidate: f613a3730103f344100b9743016c3b07e65c9ce6.
Final branch commit: reported externally after evidence-only amend.
Platform: Windows 11 Home 10.0.26200 x64, Rust 1.94.1 x86_64-pc-windows-msvc.
Start free disk: 24450445312 bytes (22.771252 GiB).

## Identity and toolchain

Start branch main, worktree/index clean, local and fetched origin/main equal the
base commit, GitHub default branch main. Created
feat/dvm-v2-g1-zero-loss-vault-storage at that exact base. Main unchanged.
Blueprint SHA-256: 23e320ce6ce84c81fe79eb239ed64b897530135c6715f2f6202534c3a13695e9.
Gates SHA-256: dc49be40b0d0ba93b6cb4ba06c65456ee89818a8e79261f831092bf6a3a9b59a.
Node 22.22.2, pnpm 10.27.0, Rust 1.94.1, Windows MSVC x64.
Native Strawberry Perl 5.42.3.1 portable was obtained from its upstream release;
archive SHA-256 6a081a811781c30aca51dbc036afd93092af91e3297901f02c17043795a10690
was checked before use. Package content caches reused; no system SQLCipher.

## Selected storage and cryptography

rusqlite 0.40.2, bundled-sqlcipher-vendored-openssl, libsqlite3-sys 0.38.2.
Runtime SQLCipher 4.14.0 community; openssl provider reports OpenSSL 3.6.3
9 Jun 2026. Locked openssl-src 300.6.1+3.6.3 / openssl-sys 0.9.117.
chacha20poly1305 0.11.0 (XChaCha20Poly1305), hkdf 0.13.0, sha2 0.11.0,
getrandom 0.4.3, zeroize 1.9.0. Existing uuid 1.26.1 and serde serialization
dependencies reused. All added direct dependencies exact pinned; pnpm lock unchanged.
See ADR-0002 through ADR-0005 for provider, key, framing and job policies.
Header version 1, schema version 1, DVB1 version 1, 4,194,304-byte plaintext chunks.

## Focused evidence

Optimized crypto: 4 unit tests plus 5 compile-fail secret-type doc tests passed.
Optimized storage: 20 active tests passed; child helper and multi-GB entries are
ignored in the ordinary test enumeration and invoked explicitly by their owners.
SQLCipher cipher_status=1, HMAC enabled, fully encrypted header, cipher integrity
and SQLite integrity checks pass. Same injected key reopens; wrong key fails an
actual schema/page read. Recognizable sentinel absent from DB and live WAL, and
checkpointed DB. Journal WAL, synchronous FULL, foreign keys ON, temp store MEMORY.

Import stages encrypted bytes, hashes the source in that one pass, flushes/syncs,
authenticates the candidate, atomically renames on the same volume, syncs canonical
contents, then commits blob/item/reference/job rows. Only commit returns receipt.
Restart recovery fixture: 4,194,305 bytes; original/stored/recovered SHA-256 all
b95d5443712d3dc2a76e829cf756c13efa5d16d07ff5ac1a862f5c0800cdf697.
Repeated/concurrent identical imports retain one immutable canonical blob and
distinct logical items/references. Same SHA with different size fails integrity.

Job tests prove persisted PENDING and leases, one attempt per claim, expiry
recovery, bounded backoff/max attempts, stale-worker refusal, cancellation,
unique idempotency keys, replay without duplicate effects, and transactional
result/ACK. Insert, deferred constraint commit and native connection interruption
fail without successful import. Deferred job commit failure rolls back both DONE
and result update.

Reconciliation quarantines staging under exclusive ownership, preserves physical
orphans, marks missing/unauthentic originals CORRUPTED, rejects future schema and
reader versions, and recovers expired leases. Ambiguous canonical data is not deleted.
Physical missing/mutated/truncated/substituted originals fail closed. Crypto
boundary matrix covers empty/one byte and all chunk boundaries; mutations cover
header/ciphertext/tag, truncation, reorder, duplicate, foreign chunk, wrong key/ID,
length mismatch and trailing bytes. Failed sinks never commit partial content.

| Crash point                        | Restart outcome                        | Result |
| ---------------------------------- | -------------------------------------- | ------ |
| C1 before candidate                | No committed import                    | PASS   |
| C2 candidate created               | Staging preserved; no committed import | PASS   |
| C3 first full frame                | Staging preserved; no committed import | PASS   |
| C4 full write before sync          | Staging preserved; no committed import | PASS   |
| C5 synced before rename            | Staging preserved; no committed import | PASS   |
| C6 immediately after rename        | Physical orphan quarantined            | PASS   |
| C7 inside transaction              | Rollback; physical orphan quarantined  | PASS   |
| C8 committed before caller receipt | Committed original preserved/recovered | PASS   |
| JOB_COMMIT before result commit    | Original preserved; DONE not committed | PASS   |

These are real child-process exits without Rust destructors; not ordinary returned
errors. Release storage configuration has no environment-controlled crash path;
all hooks and the helper module are cfg(test). Successful canonical state is
checked for full recovery; no observed success without recoverable original.

## Focused multi-GB test

Source non-sparse, 2,151,677,952 bytes (2 GiB + 4 MiB). Real streaming encrypted
output; independent SHA during fixture generation, SHA during import, and SHA
during recovery agree. Recovery independently compares every byte to the source.
SHA-256: db5700bafac53992293386a224c6d460eaeaef8c1084e1ad909b846dbab8c130.
Recovered bytes 2,151,677,952. Largest configured buffer 4,194,320 bytes; combined
crypto buffers 8,388,624 bytes, plus a 4 MiB comparison buffer in the test sink.
Baseline working set 7,114,752; peak 22,859,776; incremental estimate 15,745,024
bytes. Peak is OS process PeakWorkingSet64, not a precise per-allocation attribution.
Elapsed 93.977 seconds. Disk before 20,581,888,000; before fixture cleanup
16,278,630,400; after cleanup 20,582,117,376 bytes. BYTE_EQUALITY and
BOUNDED_MEMORY passed. Fixtures removed after completed evidence.

## Commands and corrections

Initial identity/status/branch/HEAD/tree/remotes/fetch/GitHub metadata/hash/disk
inspection and branch creation commands: EXIT 0. Full command ledger continues
below with acceptance evidence. Local development logs live under ignored .dvm-local.

| Command / attempt                                                                                                                                    | Exit        | Outcome                                               |
| ---------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ----------------------------------------------------- |
| cargo fetch                                                                                                                                          | 0           | Locked package sources available                      |
| cargo test --locked -p dvm-crypto (initial)                                                                                                          | 101         | API/compile correction; superseded                    |
| cargo test --locked -p dvm-storage (initial)                                                                                                         | 101         | Native Perl prerequisite missing                      |
| cargo test --locked -p dvm-crypto                                                                                                                    | 0           | 4 unit + then 2 doc tests                             |
| cargo test --locked -p dvm-storage -- --nocapture (native Perl)                                                                                      | 101         | rusqlite integer API corrections                      |
| cargo test -p dvm-storage -- --nocapture                                                                                                             | 101         | Test MutexGuard borrow corrections                    |
| cargo test --locked -p dvm-storage -- --nocapture                                                                                                    | 101         | SQLCipher pragmas return TEXT, not integer            |
| cargo test --locked -p dvm-storage -- --nocapture (corrected)                                                                                        | 0           | 17 active tests at that revision                      |
| cargo clippy --locked -p dvm-crypto -p dvm-storage --all-targets -- -D warnings                                                                      | 0           | Focused lint after style/doc corrections              |
| pnpm lint                                                                                                                                            | 0           | JavaScript lint                                       |
| pnpm typecheck                                                                                                                                       | 0           | All four workspace packages                           |
| pnpm format:check (initial)                                                                                                                          | 1           | Scratch planning notes moved under ignored .dvm-local |
| pnpm format:check                                                                                                                                    | 0           | Formatting corrected                                  |
| pnpm --filter @dvm/security-tests run test                                                                                                           | 0           | 129 assertions at focused revision                    |
| cargo test --locked --release -p dvm-crypto -p dvm-storage -- --nocapture (global memory locking)                                                    | -1073741571 | Windows STATUS_STACK_OVERFLOW                         |
| cargo test --locked --release -p dvm-storage tests::encrypted_sqlcipher_reopen_wrong_key_and_live_wal -- --exact --nocapture (global memory locking) | -1073741571 | Isolated reproduction                                 |
| Same isolated test with documented default allocation policy                                                                                         | 0           | SQLCipher 4.14.0/OpenSSL evidence captured            |
| cargo test --locked --release -p dvm-crypto -p dvm-storage -- --nocapture (corrected)                                                                | 0           | 4 crypto, 5 doc, 19 storage; crash matrix PASS        |
| cargo test --locked --release -p dvm-storage --lib tests::multi_gb_bounded_memory -- --exact --ignored --nocapture                                   | 0           | Mandatory >2 GiB focused test PASS                    |

The SQLCipher optional global memory-locking issue was diagnosed against bundled
upstream source, corrected to the documented default and regression-tested.
No authentication parameters or test corpus were weakened; see ADR-0002.

## Full local and clean-room acceptance

Full pnpm verify:g1 attempt 1: EXIT 1, stopped at Clippy EXIT 101 for the
104-line connection initializer. Removed the unnecessary legacy cipher-status
fallback; the pinned provider must report cipher_status=1. Workspace Clippy
then passed (EXIT 0), without suppressing the production lint.

Full pnpm verify:g1 attempt 2: EXIT 0, all mandatory local gates executed, no
mandatory skips or failures. Log: .dvm-local/g1-full-local-2.log. This includes:

| Command                                                                                                            | Exit | Evidence                                                 |
| ------------------------------------------------------------------------------------------------------------------ | ---- | -------------------------------------------------------- |
| pnpm install --frozen-lockfile                                                                                     | 0    | Frozen install                                           |
| git diff --exit-code -- pnpm-lock.yaml                                                                             | 0    | Unchanged                                                |
| cargo metadata --locked --format-version 1 --quiet                                                                 | 0    | Locked resolution                                        |
| git diff --exit-code -- Cargo.lock                                                                                 | 0    | No validation-induced change; intended lock delta staged |
| pnpm run format:check                                                                                              | 0    | Prettier                                                 |
| pnpm run lint                                                                                                      | 0    | ESLint                                                   |
| pnpm run typecheck                                                                                                 | 0    | Four packages                                            |
| pnpm --filter @dvm/desktop run test                                                                                | 0    | 26 tests                                                 |
| cargo fmt --all -- --check                                                                                         | 0    | Rust format                                              |
| cargo clippy --workspace --all-targets --all-features --locked -- -D warnings                                      | 0    | Full workspace                                           |
| cargo test --workspace --locked                                                                                    | 0    | 75 unit/integration + 5 compile-fail doc tests           |
| pnpm --filter @dvm/security-tests run test                                                                         | 0    | 129 assertions, future-gate guard PASS                   |
| pnpm run build                                                                                                     | 0    | Renderer production bundle                               |
| pnpm exec tauri build --no-bundle                                                                                  | 0    | Windows release executable                               |
| node scripts/runtime-evidence.mjs                                                                                  | 0    | Real Tauri IPC, graceful close, no crash markers         |
| node scripts/verify-g0.mjs (G1-owned runtime output)                                                               | 0    | All 15 foundation steps, 351.968 seconds                 |
| cargo test --locked --release -p dvm-crypto -p dvm-storage -- --nocapture                                          | 0    | 4 crypto + 20 storage + 5 doc tests, 20.336 seconds      |
| cargo test --locked --release -p dvm-storage --lib tests::multi_gb_bounded_memory -- --exact --ignored --nocapture | 0    | 126.247 seconds including measurements/cleanup           |
| git diff --check                                                                                                   | 0    | No whitespace errors                                     |

The final concurrency test starts with an empty vault, stages both candidates
before either can commit, and proves one canonical blob, two logical items,
two references, empty staging and exact recovery after reopen.
Ordinary cargo test lists two ignored entries: the helper is executed by the
crash matrix, and the large-file test is explicitly executed by verify:g1.
Neither represents a skipped mandatory local gate.

Attempt 2 large-file measurement: source/recovered 2,151,677,952 bytes and
SHA-256 db5700bafac53992293386a224c6d460eaeaef8c1084e1ad909b846dbab8c130.
Non-sparse, same configured buffers. Baseline working set 7,131,136 bytes,
peak 22,937,600, incremental estimate 15,806,464. Measured elapsed 124.523 seconds.
Disk before 16,264,241,152; before cleanup 11,959,738,368; after cleanup
16,263,208,960 bytes. Exact byte comparison, streaming hash and bounded memory PASS.

Runtime record: .dvm-local/g1-runtime-dc8d1cdc-4854-4945-8655-1e4525f0864e/summary.json.
First real foundation_status_served event after 9 seconds, contract 1.0.0/status ok,
2 diagnostic events; application alive when served, exited on request, no live
application remaining and no crash markers. Existing G0 captures were untouched.

Clean-room capacity planning after local acceptance: C: free 16,262,762,496;
measured local target contents 6,029,270,162 bytes. Conservative reserve for
equivalent build output + two 2,151,677,952-byte files + 3 GiB margin is
13,553,851,538 bytes. No cargo clean needed at this boundary.

Staging then detected CRLF schema bytes locally versus LF in the index, which
would change the checksum across builds. Normalized schema.sql to LF and added
a no-CR schema regression. A raw-file/index comparison confirmed zero differences
across all 34 staged files. No candidate existed before this correction.

Full local attempt 3 after that correction: pnpm verify:g1 EXIT 0.
All commands in the acceptance table ran again with EXIT 0 and the same test
counts. G0 aggregate 160.134 seconds, optimized suites 17.907 seconds, explicit
large-file command 57.394 seconds. No mandatory skips/failures. Log SHA-256
a9a27f59fe4ff43a7689c61ca7921cabc19feae3463eee02b5f4a177b5fc796e
for .dvm-local/g1-full-local-3.log.

Final local source/recovered size and SHA-256 remain the same as attempt 2.
Measured elapsed 55.710 seconds; baseline working set 7,135,232, peak 22,966,272,
incremental estimate 15,831,040 bytes. Disk before 16,223,739,904; before cleanup
11,928,317,952; after cleanup 16,231,788,544 bytes. BYTE_EQUALITY=PASS,
BOUNDED_MEMORY=PASS. The fixture and configured buffers were not reduced.
Final runtime event arrived after 3 seconds, 2 events, clean requested exit and
no crash markers; record .dvm-local/g1-runtime-ce42de7c-255a-47d1-8081-9a214b3c5a97/summary.json.
Removed 17 G1 test fixtures left by the earlier stack-overflow runs, checked by
Temp parent, generated UUID naming and exact creation-time window. No user files,
G0 evidence or package caches were removed. Cargo clean had not been used at that point.

The first candidate was 3c91e3e42f30490a35a80be63456d3ee8f419166.
During its clean-room run, checkpoint review found C6 after post-rename sync.
Moved the cfg(test) hook immediately after rename, before sync, as required by
the transaction. Production behavior is unchanged. Added a static placement
regression. The exact C1-C8/JOB_COMMIT optimized child-process suite passed
(EXIT 0), and the security suite passed all 130 assertions (EXIT 0).
Log: .dvm-local/g1-c6-exact-regression.log.
The first candidate's evidence is superseded for acceptance. Full local
verification and a fresh clean-room build must be repeated for the amended
candidate. No branch has been pushed.

Superseded clean-room run at C:\\dvm-g1-cleanroom completed with EXIT 0:
git clone --no-local --no-checkout, detached checkout of the first candidate,
and origin URL restoration each EXIT 0. No node_modules, target, dist, fixtures
or compiled SQLCipher artifacts were copied. pnpm install --frozen-lockfile
EXIT 0; pnpm verify:g1 --cleanroom EXIT 0. All 15 foundation steps passed
(950.967 seconds), optimized crypto/storage passed (751.983 seconds including
fresh native compilation), and the explicit multi-GB gate passed (160.011 seconds).
Working tree clean and both lockfiles unchanged after verification (EXIT 0).
Native openssl-sys build output reports vendored=1 and its clean-room build path.
Full log SHA-256: 2464b07ab051e9ebb6941eaff213c953be1b6b87998150c3239985bc83158d5e.
Large fixture: same 2,151,677,952 bytes and SHA-256, exact comparison PASS;
baseline 7,143,424, peak 22,908,928, incremental estimate 15,765,504 bytes,
elapsed 156.831 seconds. Disk before 8,785,805,312; before cleanup 7,156,940,800;
after cleanup 11,460,415,488 bytes. Free-space observations include unrelated OS
activity and are not treated as exact fixture allocation measurements.
This successful run does not qualify the subsequently corrected C6 placement.

Full local attempt 4, including corrected C6: pnpm verify:g1 EXIT 0.
Every command in the acceptance table passed again; security now has 130 tests.
G0 all 15 steps: 308.555 seconds; optimized suites: 4.883 seconds; mandatory
large-file command: 69.484 seconds. No mandatory gate skipped or failed.
Log .dvm-local/g1-full-local-4.log SHA-256:
7f2682116a53c464cc476fcf0eecb93a368e4e68a6983333d47994724442a5cb.
Source/recovered 2,151,677,952 bytes, unchanged SHA-256 and exact byte equality.
Baseline working set 7,131,136; peak 22,999,040; incremental estimate 15,867,904
bytes; measured elapsed 67.380 seconds. Disk before 11,473,997,824; before cleanup
7,834,693,632; after cleanup 12,138,168,320 bytes. Bounded memory PASS.
Live IPC event after 5 seconds, two events, clean close and no crash markers;
record .dvm-local/g1-runtime-13a5f1fa-6e93-4aa1-8efc-cb781964c043/summary.json.

Before a second fresh clean room, free disk was 12,143,529,984 bytes, below the
conservative build/fixture/margin reserve. After completed textual evidence was
captured, cargo clean --manifest-path C:\\dvm-g1-cleanroom\\Cargo.toml EXIT 0 removed
only the superseded clean-room generated target (5,737,036,000 logical bytes).
Resolved root/target paths and absence of external CARGO_TARGET_DIR were checked.
Free space afterward: 16,215,490,560 bytes. Package caches, user files, original
workspace outputs and all textual evidence were preserved.

## Final exact-candidate clean-room acceptance

Verified source: f613a3730103f344100b9743016c3b07e65c9ce6.
Verified source tree: b589cfbf4c2b2296ff297810d8ceee38b4e30acd.
Fresh path: C:\\dvm-g1-cr2, confirmed absent before creation.
Before clone: 16,214,663,168 bytes free. Only package content caches and the
documented native Perl prerequisite were reused. No target, node_modules, dist,
fixtures, compiled SQLCipher artifacts or external native library paths were copied.

| Command                                                                                                                  | Exit | Result                            |
| ------------------------------------------------------------------------------------------------------------------------ | ---- | --------------------------------- |
| git clone --no-local --no-checkout C:\\Users\\gglig\\my_project\\testcontainer\\Digital_Vault_of_Memories C:\\dvm-g1-cr2 | 0    | Fresh source clone                |
| git -C C:\\dvm-g1-cr2 checkout --detach f613a3730103f344100b9743016c3b07e65c9ce6                                         | 0    | Exact candidate                   |
| git -C C:\\dvm-g1-cr2 remote set-url origin https://github.com/ggligor1967/Digital_Vault_of_Memories.git                 | 0    | Canonical origin                  |
| pnpm install --frozen-lockfile                                                                                           | 0    | Fresh install, content cache only |
| pnpm verify:g1 --cleanroom                                                                                               | 0    | Every mandatory gate executed     |
| git diff --exit-code -- Cargo.lock pnpm-lock.yaml                                                                        | 0    | Both lockfiles unchanged          |
| git status --short                                                                                                       | 0    | CLEAN                             |
| git rev-parse HEAD HEAD^{tree}                                                                                           | 0    | Candidate and tree above          |

All acceptance-table commands ran with EXIT 0. Counts: renderer 26, workspace
75 unit/integration plus 5 compile-fail docs, security 130, optimized crypto 4,
optimized storage 20, optimized compile-fail docs 5, and explicit large-file 1.
No mandatory skips, failures or unreached checks. The ordinary ignored helper and
large-file entries were explicitly executed through their owning gates.
G0 aggregate: 1,481.857 seconds, all 15 steps; optimized suites: 793.047 seconds
including fresh native compilation; large-file command: 113.875 seconds.
Logs: .dvm-local/g1-cleanroom2-install.log and .dvm-local/g1-cleanroom2-full.log.
Full log SHA-256: dfdf67537e89240f584d25ebf163f52d54cc57b61b3d2dc55696b80f7011f01e.
Native build output confirms vendored=1 and libraries below this clean-room target.
SQLCipher 4.14.0 community, OpenSSL 3.6.3, cipher_status=1, WAL; wrong-key,
integrity, encrypted DB/WAL sentinel and checkpointed DB tests PASS.
C1-C8, including C6 immediately after rename, and JOB_COMMIT all PASS in both
workspace and optimized execution. Corruption, dedup/concurrency, durable job,
reconciliation and redaction/security suites all PASS.

Final clean-room large file: non-sparse, source/recovered 2,151,677,952 bytes.
Source/stored/recovered SHA-256:
db5700bafac53992293386a224c6d460eaeaef8c1084e1ad909b846dbab8c130.
Every recovered byte independently compared with the original source: PASS.
Chunk 4,194,304; largest buffer 4,194,320; combined crypto buffers 8,388,624 bytes,
plus the test's 4 MiB comparison buffer. Baseline working set 7,114,752;
peak 22,880,256; incremental estimate 15,765,504 bytes. Measured elapsed 101.769
seconds. Disk before 12,061,552,640; before cleanup 9,882,771,456; after fixture
cleanup 14,186,246,144 bytes. BYTE_EQUALITY=PASS; BOUNDED_MEMORY=PASS.

During optimized compilation, free disk fell to 7,137,882,112 bytes. To retain
the fixture and safe-shutdown reserve, a second authorized cargo clean removed
the original workspace's completed, textually evidenced G1 build outputs:
EXIT 0, 13,492 generated files, reported 5.7 GiB. Resolved workspace/target
boundaries were checked; no external CARGO_TARGET_DIR. Free afterward:
11,991,916,544 bytes. Active clean-room outputs, textual logs, G0 evidence,
package caches and user files were preserved. This cleanup changed no source.

Final clean-room runtime: real IPC event after 20 seconds, two events, contract
1.0.0/status ok, graceful requested close and no crash markers. Record:
C:\\dvm-g1-cr2\\.dvm-local\\g1-runtime-f63e7ec4-da4e-4308-bb81-082519fd8e83\\summary.json.
Both normative document hashes were recomputed afterward and remain the exact
authorized hashes. No source/configuration/dependency/test change followed this
verification; the final amendment changes only this evidence document.

## Scope, risks and limitations

No renderer or Tauri permission expansion; no production create/unlock command.
Source paths are encrypted metadata or transient Rust memory; public storage
errors/diagnostics expose safe codes only. No keys serialized or persisted.
No future feature crate implementation. G0 evidence is preserved; G1 runtime
regression writes a fresh evidence directory. No subagents, main writes or merge.
Startup performs full canonical authentication and may be slow for a large vault.
Memory tests establish bounded implementation and observed working set, not a
general OS paging guarantee. Crash suite proves process termination/restart,
not physical power-loss, failing hardware or compromised-host resistance.

G2 key lifecycle and all future feature gates remain NOT STARTED.
No raw key material belongs in this document.

Local implementation and exact-candidate clean-room verdict: PASS.
Publication/final commit/PR/exact-head CI provenance is reported externally;
formal G1 closure is a separate reconciliation unit. No G2 work is authorized here.
