# DVM-V2 / G3 — formal closure evidence (Blueprint v2 §52)

```text
gate_id: G3
source_commit: fd0406797f9b8c09d8ef8b9efbc624720c09b393
source_tree: 95e462eda95683215c5af3c1fbb069c1367133fb
baseline_main: be77cf71ccca104af0d085aee70e7b08ab3b2956
verdict: PASS
```

The source commit above is the accepted executable G3 identity. This later
documentation-only closure commit does not alter executable source identity.
Formal closure also requires the closure commit's own exact-head CI, final Codex
documentation review, zero unresolved material threads, and unchanged main;
the dedicated PR #3 formal-closure comment records those post-publication checks.
G4 is NOT STARTED and NOT AUTHORIZED. PR #3 remains open and unmerged in this
transaction; G4 requires merge, post-merge verification, and separate admission.

## Platform and toolchain

- Windows 11 Home 10.0.26200, x64; Node.js 22.22.2, pnpm 10.27.0, Rust/Cargo 1.94.1; pinned native libsodium 1.0.22; SQLCipher 4.14.0 community, SQLite 3.51.3, OpenSSL provider 3.6.3.
- Fresh Windows clean-room clone at `C:\dvm-g3-atomic-cr` used the exact verified source candidate before the evidence-only amendment. The accepted source head adds only that evidence amendment.
- WSL Ubuntu Linux x64 kernel `6.18.33.2-microsoft-standard-WSL2`, Rust/Cargo 1.94.1; isolated exact-candidate clone reused the existing Cargo dependency cache. It was source-exact proof, not a dependency-cache-clean build or physical archive transfer.

## Commands, exit codes, and counts

The [atomic activation remediation](G3-BACKUP-ACTIVATION-REMEDIATION.md),
[P1/P2 remediation](G3-P1-P2-REMEDIATION.md),
[lock-lifetime remediation](G3-LOCK-FAILURE-PATH-REMEDIATION.md),
[initial hold remediation](G3-HOLD-REMEDIATION-1.md), and
[original G3 evidence](G3-RECOVERY-BACKUP-MIGRATION.md) retain the earlier
command transcripts, failed attempts, and their exact candidate identities.
The final controlling source-candidate commands and results were:

| Platform              | Command                                                                                             | Exit code and result                                        |
| --------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| Windows local         | `pnpm verify:g3`                                                                                    | 0; G0/G1/G2/G3 PASS; 0 mandatory skips; no G3 test residue  |
| Windows clean room    | `pnpm install --frozen-lockfile`                                                                    | 0                                                           |
| Windows clean room    | `pnpm verify:g3 --cleanroom`                                                                        | 0; G0/G1/G2/G3 PASS; 0 mandatory skips; no G3 test residue  |
| Windows targeted      | `cargo test --locked --release -p dvm-backup --lib -- --nocapture`                                  | 0; 16 passed, 0 failed                                      |
| Linux exact candidate | repository-pinned libsodium source preparation (command spelling not retained in the source record) | 0                                                           |
| Linux exact candidate | `cargo test --locked -p dvm-backup --lib -- --nocapture`                                            | 0; 22 passed, 0 failed                                      |
| Linux exact candidate | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`                     | 0                                                           |
| Linux exact candidate | `cargo test --workspace --locked`                                                                   | 0                                                           |
| Linux exact candidate | `node scripts/g3-negative-controls.mjs`                                                             | 0; 10 controlled defects detected and source bytes restored |

The accepted final source head, after the evidence-only amendment, generated
successful [G0 push run](https://github.com/ggligor1967/Digital_Vault_of_Memories/actions/runs/36290398953),
[G1 push run](https://github.com/ggligor1967/Digital_Vault_of_Memories/actions/runs/36290399014),
[G2 PR run](https://github.com/ggligor1967/Digital_Vault_of_Memories/actions/runs/36290400284),
and [G3 push run](https://github.com/ggligor1967/Digital_Vault_of_Memories/actions/runs/36290398940).
The remaining G0/G1/G3 PR runs were also successful; PR #3 checks are the
canonical per-job read-back. All seven generated source-head runs completed
successfully. CI's inherited interactive and multi-GB skips are not counted as
CI pass evidence for those tests; local and clean-room gates covered them.

This documentation reconciliation ran `pnpm format:check`, `pnpm lint`,
`pnpm typecheck`, `pnpm --filter @dvm/security-tests run test`, and
`git diff --check`, each with exit code 0 after formatting the draft. The
security suite reported 137 passed across six test files. No repository-provided
documentation/link/status check was present in `package.json`, `scripts/`, or
`.github/workflows/`.

Unit-test counts reported by the final targeted suites are Windows release
backup 16/16 and Linux backup 22/22. The full workspace suites and composed
G0/G1/G2/G3 gates passed, but their aggregate unit count was not recorded as a
single comparable total. The Windows clean room passed the 2,151,677,952-byte
G1 import/recovery oracle and 16/16 release backup tests. Integration evidence
includes real Windows credentials, production SQLCipher snapshot integrity,
restore/unlock, migration, and backup/restore child-process crash matrices.
No separate aggregate e2e test count was reported; the destructive restore
scenario and real desktop G0 runtime evidence passed in the composed local gate.

The relevant measured large-file result recovered 2,151,677,952 bytes with
source/recovered SHA-256 equality, `BYTE_EQUALITY=PASS`, and
`BOUNDED_MEMORY=PASS`. The earlier complete G3 local record measured an
incremental peak working set of 15,925,248 bytes for that G1 oracle. No
separate G3 peak working-set or throughput benchmark was measured.

## Security and review disposition

G2 and G3 negative controls passed with exact source-byte restoration. The
final Linux candidate's ten G3 controls included the old post-publication
cleanup defect. FULL backup verification, corruption/path refusal,
future-schema DB/WAL/blob no-mutation, crash matrices, destructive restore,
real Windows credential cleanup, and no test residue passed in the recorded
gates. There is no standalone security-scan result claimed beyond these
repository security assertions and negative controls.

The [final Codex source review](https://github.com/ggligor1967/Digital_Vault_of_Memories/pull/3#issuecomment-5852392446)
reviewed `fd0406797f` and found no major issues. All five historical material
review threads were resolved; no new unresolved material thread was observed
at source-head reconciliation. Copilot was unavailable in the current repository
review UI: `COPILOT_REVIEW=NOT_COMPLETED`. The [owner's bounded G3 exception](https://github.com/ggligor1967/Digital_Vault_of_Memories/pull/3#issuecomment-5855183440)
was ratified; it is not a claim of Copilot review and does not authorize G4.

## Accepted risks and artifact identities

- SQLCipher snapshot `-wal`/`-shm` sidecar lifetime after refused activation: `OPEN_NON_BLOCKING_CLEANUP_OBSERVATION`; no cleanup fix is claimed.
- Process-crash and flush/rename evidence does not guarantee arbitrary hardware power-loss safety.
- No physical secure-erasure guarantee or protection against a compromised host.
- DVBK1 excludes device credentials; passphrase or recovery material must be retained separately.
- No release or production-readiness claim; G6 obligations remain open.
- No G4 implementation; the ratified Copilot exception is bounded to G3.

Current unchanged lockfile SHA-256 values: `Cargo.lock` =
`04139bcd7c0a0fc70642964c5f51b2067c4a625d1025b5dfc8ef0f76bc0550ce`;
`pnpm-lock.yaml` =
`3fa555f62cc647f5d7ef6765b49742e5f05ea009d64b6c3a1364162b7a0e07f9`.
The original local authenticated archive SHA-256 was
`47208ff5cf8d70e262945aa57effd9317fbb5c178555d81f833eb76186644612`;
the original clean-room archive SHA-256 was
`de08596433e57538272342e29425282f6a692a65e6318c1cf19ba2fd10fd4d22`.
Randomized backup IDs and nonces mean archive hashes differ by run. These
original-record archive hashes do not identify the final candidate's archive.
