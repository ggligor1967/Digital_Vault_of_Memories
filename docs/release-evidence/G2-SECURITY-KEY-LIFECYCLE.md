# G2 Security and Key Lifecycle — evidence

Gate: DVM-V2 / G2 — SECURITY_AND_KEY_LIFECYCLE

Status: LOCAL_G2 = PASS; CLEAN_ROOM_G2 = PASS; publication, exact-head CI and reviews pending.
This is not G2 closure or release readiness. G0 and G1 are CLOSED; G3 is not started.

## Identity

- Base: main, 7c7700cda069f781109453b20d0b318f383a595a
- Base tree: 89e90694bdc9dca1c5a565669099ecadf2988b43
- Branch: feat/dvm-v2-g2-security-key-lifecycle
- Initial index/worktree: clean; origin/main matched after fetch.
- Latest pre-candidate fetch: origin/main and local main remain the exact base.
- Blueprint SHA-256: 23e320ce6ce84c81fe79eb239ed64b897530135c6715f2f6202534c3a13695e9
- Gates SHA-256: dc49be40b0d0ba93b6cb4ba06c65456ee89818a8e79261f831092bf6a3a9b59a
- Verified source candidate: 3758a98b1021d33c99cc0cdd60f84914479bddd8
- Verified source tree: 5322b57dc35dcdc2dad6bee03f8c4534710d01de
- Final candidate: the unpublished evidence-only amend containing this document;
  its exact identity is recorded by Git and the publication report. The source
  candidate above remains the exact clean-room execution identity.

## Environment and dependencies

Windows 11 Home 10.0.26200; Node 22.22.2; pnpm 10.27.0; Rust/Cargo 1.94.1.
Initial free RAM 2049368 KiB of 16481336 KiB; initial C free disk 18937831424 bytes.
Native Strawberry Perl 5.42.3 exists. Gates prepend its process-local PATH and
set CARGO_BUILD_JOBS=2. Filesystem: NTFS, healthy. No global install, pagefile
change or subagent delegation. Latest post-local free disk: 14749687808 bytes.

New direct dependencies: libsodium-sys-stable =1.24.0, keyring-core =1.0.0,
windows-native-keyring-store =1.1.0. Native libsodium: **1.0.22-RELEASE**.
Reused chacha20poly1305 0.11.0, HKDF 0.13.0, SHA2 0.11.0, getrandom 0.4.3,
zeroize 1.9.0 and UUID 1.26.1. All direct versions exact; pnpm lockfile unchanged.
RustCrypto argon2 0.6.0 is disqualified and removed, including from Cargo.lock.

The binding's zip/tar/ureq dependencies are native build tooling only. A locked,
offline normal-dependency graph test excludes archive/download/provider stacks
from dvm-crypto. No provider SDK, application archive behavior, renderer API or
network capability is introduced. FUTURE_GATE_DEPENDENCY_GUARD = PASS.

## Accepted audit provenance and native reproducibility

The project explicitly accepts the published
[libsodium 1.0.12/1.0.13 assessment](https://www.privateinternetaccess.com/blog/libsodium-v1-0-12-and-v1-0-13-security-assessment/)
as provenance for the Argon2id implementation lineage. Its scope includes
password hashing/key derivation and section 3.5.8 reviews the 1.0.13 Argon2id
delta, reporting no new vulnerabilities from that delta. ADR-0007 records the
source comparison, binding selection and why this satisfies Blueprint section
9.1 under the explicit project decision.

AUDITED_LINEAGE = YES
EXACT_SELECTED_RELEASE_AUDITED = NO
ACCEPTED_PROJECT_AUDIT_PROVENANCE = YES

The assessment did not audit 1.0.22, the Rust binding or the DVM adapter. Later
native changes, the FFI boundary, compiler differences and the binary supply
chain remain audit-lineage limitations. Application tests are not audit evidence.

The official 1.0.22 Windows archive and Linux source archive Minisign signatures,
including trusted comments, verified against the upstream public key (exit 0).
ADR-0007 records the exact archive/signature/static-library hashes and URLs.
Every gate verifies the Windows archive and extracted library hashes, rejecting
ambient shared/pkg-config overrides and moving-version fallbacks. Cargo forces
the repository-owned static-library directory; the KDF also checks linked release
identity. The only application unsafe-code allowance is the private, bounded,
fallible sodium FFI module. Other modules retain their unsafe-code prohibition.

The same pinned source release supports the existing Linux G0 job without changing
G0/G1 workflows or installing system dependencies. Linux execution is unverified
locally until remote G0 runs; it cannot qualify Windows credential acceptance.

## Format, cost policy and threat model

Threat model: G2 implementation 2; ADR-0006 through ADR-0009. Every in-scope threat
is mapped to controls, tests and residual limitations in THREAT-MODEL.md.

Argon2id v1.3/0x13, 32-byte output, 16-byte fresh random salt. Minimum accepted
profile: **19456 KiB / t=2 / p=1**. Maximum memory 262144 KiB, iterations 10;
unsupported parallelism values are rejected rather than ignored. UTF-8 input is
exact, including whitespace, decomposed Unicode and embedded NUL. No normalization.
Calibration targets 250 ms without reducing the baseline. Fresh complete local
release measurement: **262144 KiB / t=2 / p=1, 274 ms** (workload-dependent).

Keyslot container/version 1 and length-prefixed deterministic AAD v1 remain as
specified in ADR-0006. Slot type/version/ID, vault identity, algorithm IDs, all KDF
costs, salt, nonce and device reference are authenticated. Wrapping uses existing
XChaCha20-Poly1305, a fresh 24-byte nonce and 48-byte ciphertext/tag. No plaintext
root, KEK, passphrase or recovery material is persisted. DB/blob HKDF domains and
DVB1/SQLCipher formats remain unchanged. Audit/backup key types add no G3 behavior.

Windows generic credential API through the selected native adapter uses explicit
Local persistence with readback. Sanitized test target patterns:
`dvm/provider/synthetic/g2-test-*` and `dvm/device/<random>/<random>`. No secret
values or root-key fingerprints are recorded in this evidence.

## Fresh local verification ledger

Commands ran in the authoritative Windows checkout. All source used by the
qualifying full run was final before the run started; later edits are evidence
only. Raw generated logs remain ignored under `.dvm-local/g2/`.

| Command / oracle                                                        | Exact exit / result                                                            |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Official Windows/source archive signature verification                  | 0; both signatures and trusted comments verified                               |
| cargo check -p dvm-crypto                                               | 0; selected binding/native adapter compiled                                    |
| cargo test --locked -p dvm-crypto --lib -- --nocapture                  | 0; 12 tests, including independent public Argon2id vectors at baseline and t=3 |
| cargo clippy --locked -p dvm-crypto --all-targets -- -D warnings        | 0; checked conversion replaced a lint-rejected cast before the full gate       |
| pnpm security:check                                                     | 0; 136 boundary, capability, CSP, dependency and architecture tests            |
| pnpm lint                                                               | 0                                                                              |
| cargo test --locked -p dvm-storage --lib security::tests -- --nocapture | 0; 9 tests, real Windows integration and crash matrices                        |
| node scripts/g2-negative-controls.mjs                                   | 0; six intended violations detected, exact source bytes restored               |
| pnpm verify:g2 (qualifying final libsodium run)                         | **0; LOCAL_G2=PASS**, 2026-09-14; no mandatory skips                           |
| git diff --check / git diff --cached --check                            | 0                                                                              |
| Native credential-reference inventory, synthetic G2 namespaces only     | 0 remaining references; no values or unrelated names emitted                   |

Qualifying raw trace: `.dvm-local/g2/local-sodium-complete-2.log`.
An earlier libsodium full run also exited 0 but preceded the Linux bootstrap
addition and does not qualify final source. Earlier RustCrypto verification is
superseded; it never established audit qualification or publication eligibility.

The qualifying full gate executed:

- G0: **16 steps run, 0 skipped, 0 failed, 0 not reached**. Frozen install and
  lockfile checks; format/lint/typecheck/frontend tests; Rust fmt, workspace Clippy
  with -D warnings, workspace tests; all 136 security tests; production renderer
  and Tauri builds; actual desktop IPC runtime. Every command exited 0.
- G1: optimized crypto/storage suites, real crash/corruption/reconciliation,
  dedup/jobs/write admission and explicit multi-GB proof. Imported and recovered
  **2151677952 bytes**, source/recovered SHA-256 equal; peak working set 23003136
  bytes, largest buffer 4194320 bytes, elapsed 90.046 seconds. Fixtures removed.
  BYTE_EQUALITY=PASS, BOUNDED_MEMORY=PASS; verify:g1 exited 0.
- G2: 9 targeted storage tests, 2 session tests and nine-class canary redaction
  test passed. Real Windows credential integration reported
  G2_TEST_CREDENTIAL_RESIDUE=NONE. Generated output scan: SECRET_LOG_LEAKAGE=NO.
- The ordinary Rust suite's two ignored helper/heavyweight cases are explicitly
  run by their parent crash matrix and the root multi-GB step. Neither proof is
  skipped on the mandatory local path.

## Security oracle results

- Passphrase: correct/wrong authentication, exact Unicode/NUL policy, fresh salt,
  minimum/maximum costs, persisted reopen, tampered parameters/wrapped VMK PASS.
  Independent public known-answer vectors match the replaced implementation;
  those public vectors prove compatibility, not audit provenance.
- WRONG_PASSPHRASE_NO_MUTATION=PASS: imported vault locked first; every durable
  file and byte snapshotted; BadPassphrase, LOCKED, no new credential/file/slot,
  exact snapshot equality and healthy recovery verified.
- PASSPHRASE_CHANGE_REWRAP_ONLY=PASS: representative empty/binary/Unicode/patterned
  corpus; same VMK and storage keys, unchanged DB and canonical blob bytes, old
  phrase fails, new phrase succeeds, exact originals recover. KDF_UPGRADE=PASS.
- Recovery: independently random 256-bit secret; 64-lowercase-hex trusted encoding;
  domain-separated HKDF KEK; same VMK, wrong/tampered recovery rejection, survives
  passphrase change, no plaintext persistence, default generation and explicit
  typed decline PASS. No renderer presentation command.
- Device: disabled by default; real OS-held random KEK; reference-only header;
  quick unlock, credential absence no-mutation, independent passphrase/recovery
  fallback and cleanup PASS. SLOT_INDEPENDENCE=PASS.
- Lock: CLOSED/LOCKED/UNLOCKING/OPEN/LOCKING and degraded state covered. Failed
  unlock drops live ownership; concurrent unlock serializes; lock orders against
  full operations; locked content returns VaultLocked; actual corrupt storage
  transitions to DEGRADED_READ_ONLY and blocks further content. PASS.
- Secret store: synthetic provider store/configured/trusted exact retrieve/delete/
  absence, Local persistence readback, error-path cleanup and absence from
  header/DB/log/IPC output PASS. No provider call or credential-read IPC exists.
- Tamper matrix: type/version/ID/vault binding/KDF algorithm and costs/salt/wrap
  algorithm/nonce/ciphertext/tag/device reference all fail closed. PASS.
- Header atomicity: injected failures and actual child-process crashes before
  temp, after temp, after sync, before activation, after activation. Old slots
  work before activation, new state afterward; recovery remains usable. PASS.
- Secret isolation: compile-fail Debug/Serialize tests on secret types PASS.
  Passphrase/recovery/VMK/three KEKs/DB/blob/provider canaries absent from errors,
  diagnostics, logging and IPC envelopes. SECRET_IPC_LEAKAGE=NO.
- Renderer registry remains exactly foundation_status. No content/secret getter,
  arbitrary filesystem/shell or provider networking. Existing capabilities and
  production CSP unchanged; static assertions and runtime boundary PASS.

Negative controls: archive hash mismatch exited 1 as expected; changed Argon2
iteration mapping, serialized-secret support, omitted slot-ID AAD, wrong-passphrase
file mutation and locked-content admission each triggered the intended oracle
with exit 101. The runner exited 0 only after exact source restoration. No
negative-control mutation is committed.

## Clean room

**CLEAN_ROOM_G2 = PASS**, 2026-09-14, Windows 11 Home 10.0.26200, with the same
pinned Node/pnpm/Rust/Cargo and native Strawberry Perl versions recorded above.

- Path: `C:\dvm-g2-cr`; cloned with `--no-hardlinks --no-checkout` from the local
  repository, then detached at source candidate
  `3758a98b1021d33c99cc0cdd60f84914479bddd8`. Clone and checkout exited 0.
- `node_modules`, `target` and `.dvm-local` were absent before installation.
  No build output, native library, credential artifact or vault fixture was copied.
- `pnpm install --frozen-lockfile`: **EXIT 0**, 10.7 seconds.
- `pnpm verify:g2 --cleanroom`: **EXIT 0**, CLEAN_ROOM_G2=PASS. Fresh pinned native
  download/hash verification, all six negative controls and exact source-byte
  restoration passed before the complete regression gate.
- G0: **16 steps run, 0 skipped, 0 failed, 0 not reached**, EXIT 0; includes fresh
  Rust/native compilation, production build and actual desktop IPC runtime.
- G1: optimized crypto 12 tests and storage 36 tests passed. The explicitly
  invoked multi-GB proof imported/recovered **2151677952 bytes**, matching
  SHA-256, peak working set **23023616 bytes**, largest buffer **4194320 bytes**,
  elapsed **153.201 seconds**. BYTE_EQUALITY=PASS, BOUNDED_MEMORY=PASS; fixtures
  removed. Complete G1 EXIT 0; no mandatory helper/heavyweight proof omitted.
- Release Argon2 calibration: **262144 KiB / t=2 / p=1, 280 ms**.
- G2: targeted storage 9, session 2 and nine-class canary redaction 1 tests passed.
  Real Windows integration reported WINDOWS_CREDENTIAL_INTEGRATION=PASS,
  PROVIDER_SECRET_ORACLE=PASS and G2_TEST_CREDENTIAL_RESIDUE=NONE. Final generated
  output scan: SECRET_LOG_LEAKAGE=NO; final git diff --check EXIT 0.
- Independent post-run native credential-reference inventory, restricted to
  synthetic G2 namespaces: **0 remaining references**; no values emitted.
- Detached HEAD still equals the exact source candidate; git status --short
  empty; git diff --exit-code -- Cargo.lock pnpm-lock.yaml EXIT 0. Original and
  clean-room lockfile SHA-256 values match: Cargo.lock
  `e799f7ea2cd74768d680d008e39d6f4ab62945204faf478f7aa6baec9a95e594`, pnpm-lock.yaml
  `3fa555f62cc647f5d7ef6765b49742e5f05ea009d64b6c3a1364162b7a0e07f9`.

Raw ignored traces: `.dvm-local/g2/cleanroom-install.log` and
`.dvm-local/g2/cleanroom-complete.log` in the original checkout. When free disk
approached the heavyweight gate's minimum during compilation, only the original
checkout's resolved, application-owned `target/release` rebuildable cache was
removed (1628391626 bytes). Clean-room artifacts and both source trees were
untouched; no global dependency or system setting changed. Post-run free C disk:
8890671104 bytes. This document is the only post-clean-room tracked change.

## Publication, CI and reviews

PENDING: final candidate push, one PR, exact-head G0/G1/G2 CI, fresh Codex and
Copilot reviews. No merge or auto-merge. Main remains unchanged. The inherited
CI mode explicitly excludes interactive runtime and multi-GB proof, which remain
mandatory locally and in the clean room. Windows credential tests may not be
silently skipped. No remote acceptance is inferred from local results.

## Limitations and exclusions

Accepted audit lineage is not an exact selected-release or FFI-adapter audit.
Trusted Rust APIs only; recovery presentation UX requires a future trusted
boundary. OS user-context protection does not isolate equal-user malware; active
process memory and compromised hosts are not guaranteed confidential. Voluntary
secret/content exports and loss of all unlock material remain user risks.

Process-crash testing is not arbitrary hardware power-loss certification. Complete
old headers can be replayed without an external anti-rollback anchor. A crash
between device credential storage and header activation can leave an unreferenced
OS credential; ordinary error cleanup and independent recovery are not a
cross-resource transaction. Native tests clean up their own credentials; abrupt
header crash tests use an in-memory store.

G3 backup/restore/migration, search, provider networking, media, plugins, mobile
and sync remain unimplemented. No global installs, main writes, force push,
merge, auto-merge, tag, release, deployment or subagents.

Verdict: LOCAL_G2 = PASS; CLEAN_ROOM_G2 = PASS; final G2 acceptance pending remote checks.
