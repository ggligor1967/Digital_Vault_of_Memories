# DVM-V2 / G2 — Header activation outcome and device credential lifecycle bounded remediation

Transaction:
`DVM-V2 / G2 — HEADER ACTIVATION OUTCOME + DEVICE CREDENTIAL LIFECYCLE BOUNDED REMEDIATION`.

This document records the remediation of the five open review findings that put
the published G2 candidate on HOLD. It supplements, and does not replace,
`G2-SECURITY-KEY-LIFECYCLE.md`. The original document records a candidate that
was placed on HOLD; that HOLD is a fact of this branch's history and is not
rewritten here.

G2 is **not** closed by this transaction. Formal closure is a separate
transaction.

## Identity

| Field                        | Value                                      |
| ---------------------------- | ------------------------------------------ |
| Repository                   | `ggligor1967/Digital_Vault_of_Memories`    |
| Branch                       | `feat/dvm-v2-g2-security-key-lifecycle`    |
| Base (`main`)                | `7c7700cda069f781109453b20d0b318f383a595a` |
| Starting G2 head             | `80bc56d765cfb6405f8fbe89a0ce3715a6716135` |
| Starting tree                | `0d46d6729a4c318a2575f9a0676bc9297f313bcd` |
| Pull request                 | #2, OPEN, non-draft, unmerged, base `main` |
| `verified_source_candidate`  | `fd136d5bc92c678e6b70e5bbf33e6b9f9c99c371` |
| Parent of remediation commit | `80bc56d765cfb6405f8fbe89a0ce3715a6716135` |

`verified_source_candidate` is the pre-amend candidate that local and clean-room
validation actually executed. This document was then folded into that same
commit with `git commit --amend --no-edit`, so the final published SHA differs
and is reported externally. No published commit was rewritten: the original G2
commit `80bc56d` is untouched and remains the parent. Exactly one commit is
added to the branch.

Start identity was verified before any mutation: working tree and index clean,
no merge, rebase, cherry-pick, revert, bisect or sequencer in progress,
`origin/main` at `7c7700c`, `origin/feat/dvm-v2-g2-security-key-lifecycle` at
`80bc56d`, PR #2 OPEN and unmerged. `origin/main` was unchanged throughout.

Platform: Windows 11 Home 10.0.26200 x64, Rust 1.94.1 x86_64-pc-windows-msvc,
Node 22.22.2, pnpm 10.27.0, native Strawberry Perl at `C:\Strawberry\perl\bin`.

## Review baseline

The live review surface was re-read before implementation.
`pullRequest.reviewThreads.totalCount` was exactly 5, all unresolved and not
outdated. No additional thread existed, so nothing was silently absorbed into
scope.

| Ref | Thread                  | Reviewer | Path                                  | Classification          |
| --- | ----------------------- | -------- | ------------------------------------- | ----------------------- |
| H1  | `PRRT_kwDOUZSIRc6iRW-q` | Codex    | `crates/dvm-storage/src/security.rs`  | P1 material correctness |
| D1  | `PRRT_kwDOUZSIRc6iRVaT` | Copilot  | `crates/dvm-crypto/src/keyslots.rs`   | P2 material correctness |
| D2  | `PRRT_kwDOUZSIRc6iRVa1` | Copilot  | `crates/dvm-storage/src/security.rs`  | P2 material correctness |
| D3  | `PRRT_kwDOUZSIRc6iRW-w` | Codex    | `crates/dvm-storage/src/security.rs`  | P2 material correctness |
| P3  | `PRRT_kwDOUZSIRc6iRVbl` | Copilot  | `crates/dvm-observability/src/lib.rs` | Non-material cleanup    |

Implementation order was H1 → D2 → D1 → D3 → P3, because H1 defines the
commit/activation semantics that cleanup precedence and device rotation compose
with.

## H1 — the header activation point

### Before

`replace_header` returned `Result<(), AppError>`. The atomic
`fs::rename` and the subsequent reopen/`sync_all` lived inside one closure, so a
failure of the post-rename durability step produced an ordinary `Err` that was
indistinguishable from a pre-rename failure. Two concrete losses followed:

- `change_passphrase` reported failure although the new passphrase slot was
  already the only one in the active header, inviting the caller to keep using a
  passphrase that no longer opens the vault;
- `create_with_policy` dropped the generated `RecoverySecret` on that same path,
  leaving a persisted recovery slot whose credential was irretrievably lost.

### Activation point

`HEADER_ACTIVATED` is defined as the successful atomic replacement of
`vault.header` by the validated new header — the `fs::rename` call. It is the
single linearization point of the keyslot lifecycle:

- before it, the old header is authoritative;
- after it, the new header is authoritative.

No API blurs those states. `replace_header` now returns
`Result<HeaderDurability, NotActivated>`; the staged write, flush, sync and
rename are one closure whose failure is the only way to produce `NotActivated`,
and every statement after the rename can only produce an `Ok` value.

### Outcome model

Three trusted, non-secret types were added to `dvm_domain::security`. None
derives `Serialize`, so none can reach renderer IPC.

| Type               | Meaning                                                                                                   |
| ------------------ | --------------------------------------------------------------------------------------------------------- |
| `NotActivated`     | Failure strictly before activation. Carries the primary `AppError` plus a `CleanupOutcome`.               |
| `HeaderDurability` | `Durable`, or `Uncertain(AppError)` for a post-activation durability/verification failure.                |
| `Activated<T>`     | The operation passed the activation point. Carries the newly authoritative material, durability, cleanup. |

`Committed<T> = Result<Activated<T>, NotActivated>` is the return type of every
keyslot lifecycle operation. The phase is enforced by construction: the success
arm can only be built after activation and the failure arm only before it.

`AppError` deliberately does **not** implement `From<NotActivated>`, so a
pre-activation failure cannot be silently collapsed into an ordinary error by
`?`. Converting requires the explicit `NotActivated::into_primary`.

### Creation preserves recovery material

`create_with_policy` returns `Committed<CreatedVault>`, where `CreatedVault`
carries both the locked backend and the generated `Option<RecoverySecret>`. The
canonicalised root is resolved **before** activation, so nothing fallible stands
between the activation point and delivery of the recovery credential. The
post-activation header re-read that `select` used to perform is retained, but it
can only downgrade durability through `HeaderDurability::degraded`; it can never
withhold the now-persisted recovery secret.

`ProtectedVault::create` is now a thin delegation and no longer discards the
recovery secret through an intermediate tuple.

### Passphrase and device commit semantics

`change_passphrase` and `enable_device` both return `Committed<()>`. Once the
replacement slot activates, the new credential is authoritative and the caller
receives `Ok(Activated { .. })` whose `durability()` may report uncertainty. The
old credential is never implied to be still valid. `enable_device` never deletes
the credential referenced by the active new header.

### Pre/post activation matrix

Injection points, all exercised by
`header_failure_matrix_separates_pre_and_post_activation`,
`creation_delivers_recovery_material_once_the_header_activates` and
`device_enrollment_retains_the_credential_it_activated`:

| Injection point        | Phase           | Required behaviour                                                            |
| ---------------------- | --------------- | ----------------------------------------------------------------------------- |
| `before-temp`          | pre-activation  | old header byte-identical; new credential not active; temp credential cleaned |
| `after-temp`           | pre-activation  | as above                                                                      |
| `after-sync`           | pre-activation  | as above                                                                      |
| `before-activation`    | pre-activation  | as above                                                                      |
| `after-activation`     | post-activation | new header authoritative; credential preserved; uncertainty reported          |
| `post-activation-sync` | post-activation | as above                                                                      |

`post-activation-sync` is a new seam covering the reopen/`sync_all` durability
step itself, which previously had no dedicated injection point.

The real child-process crash matrix
(`abrupt_process_crash_header_activation_matrix`) runs over the same six points
and remains green; for both post-activation points the new passphrase opens the
vault and the old one does not.

The passphrase oracle additionally asserts, inside the live session, that the
canonical blob set and `metadata.db` digest are unchanged, that the reopened
VMK's DB subkey is identical, and that the imported blob still recovers
byte-exactly.

## D2 — primary error precedence and cleanup evidence

### Before

```rust
if let Err(error) = self.credentials.store(..) {
    self.credentials.delete(&reference)?;   // replaces `error`
    return Err(error);                       // unreachable when delete fails
}
```

A cleanup failure replaced the primary credential-store error, and the same
pattern appeared on the header-update path.

### After

Cleanup runs through `OpenVault::discard`, which never propagates:

```rust
fn discard(&self, reference: &str) -> CleanupOutcome {
    match self.credentials.delete(reference) {
        Ok(()) => CleanupOutcome::Completed,
        Err(error) => CleanupOutcome::Failed(Box::new(error)),
    }
}
```

| Property                             | Result                                                              |
| ------------------------------------ | ------------------------------------------------------------------- |
| `PRIMARY_ERROR_PRESERVED`            | YES — the primary `AppError` is carried in `NotActivated::primary`  |
| `SECONDARY_CLEANUP_FAILURE_RECORDED` | YES — typed `CleanupOutcome`, reachable on both success and failure |
| `SECRET_LEAKAGE`                     | NO — see below                                                      |

The cleanup status is a typed non-secret value rather than a diagnostics event,
because the observability crate's event-name and field allow-lists are
deliberately closed and expanding them is outside this transaction's scope.

Composition with activation:

- activation did **not** occur → the new credential is cleaned up best-effort,
  the header/store error stays primary, and the cleanup disposition is recorded
  separately;
- activation **did** occur → the credential the active header references is
  never deleted; only an unreferenced predecessor is removed, and a failure
  there leaves the activation standing and is surfaced as
  `Activated::cleanup()`.

No `CleanupOutcome` or `NotActivated` variant carries credential bytes, a KEK, a
passphrase, recovery material or a credential reference. `AppError` is the only
payload, and it is the canonical non-secret envelope. The D2 oracle renders both
`Display` and `Debug` of a failure carrying real residue and asserts the
credential reference does not appear.

## D1 — one canonical credential-reference grammar

### Before

`validate_slot` accepted `b.is_ascii_alphanumeric()`, so uppercase was admitted
into a persisted device slot, while the Windows adapter accepted only
lowercase/digits/`/`/`-`. A header could therefore be admitted whose device
credential the adapter would refuse, making quick unlock impossible.

### After

`dvm_domain::security::is_canonical_credential_reference` is the single
predicate:

- length in `12..=160` bytes;
- exact application prefix `dvm/device/` or `dvm/provider/`;
- bytes restricted to lowercase ASCII letters, digits, `/` and `-`.

`is_canonical_device_reference` restricts that to the device prefix.
`crates/dvm-crypto/src/keyslots.rs` and
`crates/dvm-storage/src/credentials.rs` both call it, so there is no duplicated
predicate that can drift. Uppercase is rejected, never normalised; a malformed
persisted reference fails closed at `header::parse` and the vault refuses to
unlock.

The adapter's previous 180-byte ceiling narrowed to 160 to match keyslot
admission. Every reference production generates is far shorter: a device
reference is 84 bytes (`dvm/device/` + two canonical UUIDs) and a provider
reference is at most 142 bytes.

`credential_reference_language_is_shared_by_keyslot_and_adapter` proves
`CREDENTIAL_REFERENCE_LANGUAGE_EQUAL`:

- for every candidate, keyslot admission implies adapter admission;
- for every candidate under the device prefix, the two verdicts are equal;
- exactly one candidate in the table is admitted — the canonical generated form;
- 64 freshly generated production references are accepted by both;
- a persisted header whose device reference is mutated to uppercase fails closed
  with `CORRUPT_HEADER`, and the vault does not unlock.

Table covered: canonical generated form, uppercase suffix, single uppercase
letter, underscore, backslash, space, non-ASCII, empty suffix, missing trailing
separator, overlength, wrong prefix, leading slash, provider prefix, empty.

## D3 — stale device slot re-enrollment

### Before

`enable_device` rejected any existing `device-v1` slot with `CorruptHeader`. If
the Windows credential was lost or deleted, passphrase and recovery unlock kept
working but quick unlock could never be re-enrolled, and no removal or rotation
API existed anywhere in the repository.

### After

`OpenVault` already represents an authenticated OPEN session, so trusted
re-enrollment is authorised. `enable_device` now:

1. finds any existing device slot and reads its referenced OS credential;
2. `Some(_)` → the slot is healthy and is refused with `CorruptHeader`,
   unchanged;
3. `Err(..)` → an **operational** store failure, propagated as a failure; no
   credential is created and no rotation happens;
4. `Ok(None)` → **proven absence**, which authorises replacement.

Rotation order is exactly §22 of the transaction: authenticate, identify the
stale slot, generate a new device KEK and reference, store the new OS
credential, build a replacement slot wrapping the **same VMK**, atomically
activate the header, and only then remove the unreferenced predecessor under D2
semantics. The old credential is never deleted before activation. No new VMK is
derived, and neither the passphrase nor the recovery slot is touched.

`stale_device_slot_is_re_enrolled_only_on_proven_absence` covers:

| Case                                             | Required outcome                                                        |
| ------------------------------------------------ | ----------------------------------------------------------------------- |
| healthy device slot                              | refused `CORRUPT_HEADER`; header and store byte-identical               |
| credential store fails operationally             | `PROVIDER_UNAVAILABLE`; header unchanged; no credential created/removed |
| credential genuinely absent                      | re-enrollment succeeds; durable; predecessor reclaimed                  |
| new credential store fails                       | `PROVIDER_AUTH_FAILED`; old header unchanged; no residue                |
| header fails before activation                   | `INTERNAL` primary; cleanup `Completed`; old header unchanged           |
| header fails before activation and cleanup fails | `INTERNAL` primary preserved; cleanup `Failed(DISK_FULL)`; residue real |
| post-activation cleanup of the predecessor fails | activation stands; `Activated::cleanup()` is `Failed` (D2 oracle)       |
| post-activation durability failure               | slot active; credential preserved (H1 device matrix)                    |

After the final successful path: exactly one `device-v1` slot, exactly one
referenced credential, three keyslots in total, the passphrase and recovery
slots byte-identical to before re-enrollment, and canonical blobs and
`metadata.db` unchanged.

Slot independence after re-enrollment is proven directly: passphrase, recovery
and device each unwrap the same VMK (identical DB subkey) and each recovers the
imported blob byte-exactly. Deleting the new device credential then makes quick
unlock fail safely while passphrase and recovery still work and the durable
snapshot is unchanged. The test ends with no credential residue.

## P3 — observability test name

`a_key_that_sanitises_away_is_dropped` →
`a_key_that_is_not_allowlisted_becomes_the_redacted_field_key`. The assertion is
unchanged: a non-allowlisted key becomes `redacted_field`, it is not dropped. No
behaviour changed. Classification: `NON_MATERIAL_CLEANUP`.

## Negative controls

Four controls were added to `scripts/g2-negative-controls.mjs`, which mutates a
source file, requires the named oracle to fail with the expected marker, and
restores the original bytes in `finally` with a byte-equality assertion. No
negative-control mutation is committed.

| Control                                | Restored START defect                                  | Oracle that must fail                                               |
| -------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------- |
| `activated-header-ambiguity`           | post-rename failure returned as an ordinary error      | `header_failure_matrix_separates_pre_and_post_activation`           |
| `credential-reference-validator-drift` | keyslot validator accepts references the adapter won't | `credential_reference_language_is_shared_by_keyslot_and_adapter`    |
| `cleanup-overrides-primary-failure`    | `delete(..)?` replaces the primary store error         | `cleanup_failure_is_recorded_without_replacing_the_primary_failure` |
| `stale-device-slot-unrecoverable`      | any existing device slot ⇒ `CorruptHeader`             | `stale_device_slot_is_re_enrolled_only_on_proven_absence`           |

All ten controls (six pre-existing, four new) reported
`detected by expected oracle; EXIT 101` (the archive-pin control exits 1 by
design), and the script reported `G2_NEGATIVE_CONTROLS=PASS; all source bytes
restored`.

A `replaceBlock` helper was added so multi-line seams join with the newline the
checkout actually uses, keeping the controls correct in both a CRLF working tree
and a fresh `eol=lf` clean-room checkout.

## Targeted validation

| Command                                                                         | Exit |
| ------------------------------------------------------------------------------- | ---- |
| `cargo fmt --all -- --check`                                                    | 0    |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 0    |
| `cargo test --locked -p dvm-crypto -- --nocapture`                              | 0    |
| `cargo test --locked -p dvm-storage -- --nocapture`                             | 0    |
| `cargo test --locked -p dvm-observability -- --nocapture`                       | 0    |
| `cargo test --locked --release -p dvm-crypto -p dvm-storage -- --nocapture`     | 0    |
| `cargo test --locked --package dvm-domain --test contract_drift`                | 0    |
| `node scripts/g2-negative-controls.mjs`                                         | 0    |
| `pnpm --filter @dvm/security-tests run test`                                    | 0    |
| `pnpm lint`                                                                     | 0    |
| `pnpm typecheck`                                                                | 0    |
| `pnpm format:check`                                                             | 0    |
| `git diff --check`                                                              | 0    |

Release-mode `dvm-storage` reported 41 passed, 0 failed, 2 ignored. The
`@dvm/security-tests` suite reported 6 files, 136 tests passed.

New oracle markers observed:

```
H1_HEADER_ACTIVATION_MATRIX=PASS H1_PASSPHRASE_COMMIT=PASS
H1_CREATE_RECOVERY_PRESERVED=PASS
H1_DEVICE_ACTIVATION_MATRIX=PASS
D1_CREDENTIAL_REFERENCE_LANGUAGE_EQUAL=PASS
D2_PRIMARY_ERROR_PRESERVED=PASS D2_CLEANUP_RECORDED=PASS D2_SECRET_LEAKAGE=NO
D3_STALE_DEVICE_RE_ENROLLMENT=PASS D3_SLOT_INDEPENDENCE=PASS D3_RESIDUE=NONE
```

Preserved markers:

```
G2_PROCESS_CRASH_HEADER_MATRIX=PASS
WRONG_PASSPHRASE_NO_MUTATION=PASS LOCKED_ACCESS=PASS
PASSPHRASE_CHANGE_REWRAP_ONLY=PASS SLOT_INDEPENDENCE=PASS KDF_UPGRADE=PASS
WINDOWS_CREDENTIAL_INTEGRATION=PASS PROVIDER_SECRET_ORACLE=PASS G2_TEST_CREDENTIAL_RESIDUE=NONE
```

## Full local G2 regression

`node scripts/verify-g2.mjs` (no arguments: no mandatory step is skipped).

| Stage                                                                | Result                                        |
| -------------------------------------------------------------------- | --------------------------------------------- |
| `scripts/prepare-sodium.mjs`                                         | EXIT 0, `G2_NATIVE_PIN=PASS libsodium=1.0.22` |
| `scripts/g2-negative-controls.mjs`                                   | EXIT 0, `G2_NEGATIVE_CONTROLS=PASS`           |
| `scripts/verify-g1.mjs` (composes G0)                                | EXIT 0                                        |
| G0 foundation gate                                                   | 16 steps run, 0 skipped, 0 failed, EXIT 0     |
| G1 local acceptance                                                  | `PASS; multi-GB and crash gates executed`     |
| `cargo test --release -p dvm-storage --lib security::tests`          | EXIT 0, 14 passed, 0 failed                   |
| `cargo test --release -p dvm-application --lib session::tests`       | EXIT 0, 2 passed                              |
| `cargo test --release -p dvm-observability --lib g2_secret_canaries` | EXIT 0, 1 passed                              |
| generated-evidence secret scan                                       | no canary match                               |
| `git diff --check`                                                   | EXIT 0                                        |

Final line: `SECRET_LOG_LEAKAGE=NO LOCAL_G2=PASS`. Overall exit code 0.

The G0 gate ran every step including the frozen `pnpm install`, both lockfile
`git diff --exit-code` checks, Prettier, ESLint, TypeScript, renderer tests,
rustfmt, Clippy with `-D warnings`, the full `cargo test --workspace --locked`
(which carries the contract-drift test), the static security suite, the
production renderer bundle, the Tauri release compile smoke and the interactive
desktop runtime-evidence capture. Nothing was skipped.

The `>2 GiB` G1 regression requirement is unchanged: the mandatory measured
Windows multi-GB import/recovery gate ran and passed. No corpus was reduced and
no gate was weakened.

**LOCAL_G2 = PASS.**

## Clean-room revalidation

Fresh short-path Windows checkout at `C:\dvm-g2-remediation-cr`, created by
`git clone --no-hardlinks` of the candidate branch. Nothing was copied from the
development tree: the checkout contained no `target`, no `node_modules`, no
`.dvm-local`, no credential artefact and no test vault.

| Field                                    | Value                                      |
| ---------------------------------------- | ------------------------------------------ |
| Candidate                                | `fd136d5bc92c678e6b70e5bbf33e6b9f9c99c371` |
| Tree                                     | `c3930b4bb4dd27a66deb41893b8259951a868b1a` |
| Path                                     | `C:\dvm-g2-remediation-cr`                 |
| `pnpm install --frozen-lockfile`         | EXIT 0                                     |
| `node scripts/verify-g2.mjs --cleanroom` | EXIT 0                                     |

The clean-room tree and the candidate tree are the same object
(`c3930b4`), so the validated source is exactly what was committed.

| Stage                               | Result                                                                                                                                   |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| native pin                          | `G2_NATIVE_PIN=PASS libsodium=1.0.22`                                                                                                    |
| negative controls                   | `G2_NEGATIVE_CONTROLS=PASS; all source bytes restored`                                                                                   |
| G0 foundation gate                  | 16 steps run, 0 skipped, 0 failed, EXIT 0, 433.6s                                                                                        |
| G1 acceptance                       | `PASS; multi-GB and crash gates executed`                                                                                                |
| G1 multi-GB regression              | 2 151 677 952 bytes, `BYTE_EQUALITY=PASS BOUNDED_MEMORY=PASS`, source and recovered SHA-256 identical, peak working set 23 072 768 bytes |
| H1                                  | `H1_HEADER_ACTIVATION_MATRIX=PASS H1_PASSPHRASE_COMMIT=PASS`, `H1_CREATE_RECOVERY_PRESERVED=PASS`, `H1_DEVICE_ACTIVATION_MATRIX=PASS`    |
| D1                                  | `D1_CREDENTIAL_REFERENCE_LANGUAGE_EQUAL=PASS`                                                                                            |
| D2                                  | `D2_PRIMARY_ERROR_PRESERVED=PASS D2_CLEANUP_RECORDED=PASS D2_SECRET_LEAKAGE=NO`                                                          |
| D3                                  | `D3_STALE_DEVICE_RE_ENROLLMENT=PASS D3_SLOT_INDEPENDENCE=PASS D3_RESIDUE=NONE`                                                           |
| real Windows credential integration | `WINDOWS_CREDENTIAL_INTEGRATION=PASS PROVIDER_SECRET_ORACLE=PASS G2_TEST_CREDENTIAL_RESIDUE=NONE`                                        |
| process-crash header matrix         | `G2_PROCESS_CRASH_HEADER_MATRIX=PASS`                                                                                                    |
| `git diff --check`                  | EXIT 0                                                                                                                                   |

Final line: `SECRET_LOG_LEAKAGE=NO CLEAN_ROOM_G2=PASS`.

After the run: the clean-room working tree was clean, `HEAD` and tree were
still `fd136d5` / `c3930b4`, `git diff --exit-code -- pnpm-lock.yaml Cargo.lock`
exited 0, no `dvm-g2-*` test vault remained under the user temp directory, and
`cmdkey /list` showed no `dvm/` credential target. Credential residue: NONE.

### Host resource interruptions

Two earlier attempts at this clean-room run were aborted by host resource
exhaustion, not by the candidate. The volume was at 99% capacity, which caps the
Windows page file and therefore the commit limit (22.7 GiB total, 4.0 GiB
available at the time).

| Attempt | Outcome                                                                        |
| ------- | ------------------------------------------------------------------------------ |
| 1       | G0 passed 16/16, then the release build failed with `os error 112` (disk full) |
| 2       | Terminated by the host under memory pressure during the G0 release build       |
| 3       | Terminated by the host under memory pressure during the G0 release build       |
| 4       | Completed: `CLEAN_ROOM_G2=PASS`                                                |

Recovery actions were confined to reclaimable caches and changed no tracked
file: `cargo clean` in both trees (15.4 GiB of rebuildable build output) and
`pnpm store prune` (which reclaimed only 15 packages, so it was not the material
lever). The passing run rebuilt from a cold `target` directory that `cargo
clean` had emptied. No gate was weakened, no corpus was reduced, no step was
skipped, and no evidence was carried over from an aborted attempt.

**CLEAN_ROOM_G2 = PASS.**

## Scope

Changed paths:

| Path                                            | Reason                                                        |
| ----------------------------------------------- | ------------------------------------------------------------- |
| `crates/dvm-domain/src/security.rs`             | phase-aware outcome types and the canonical reference grammar |
| `crates/dvm-crypto/src/keyslots.rs`             | D1 — slot admission calls the shared predicate                |
| `crates/dvm-storage/src/security.rs`            | H1, D2, D3                                                    |
| `crates/dvm-storage/src/security/tests.rs`      | new and updated oracles                                       |
| `crates/dvm-storage/src/credentials.rs`         | D1 — adapter admission calls the shared predicate             |
| `crates/dvm-observability/src/lib.rs`           | P3 rename only                                                |
| `scripts/g2-negative-controls.mjs`              | four new negative controls required by the transaction        |
| `docs/adr/ADR-0006-g2-keyslot-envelope.md`      | activation point, phase-aware outcome, reference grammar      |
| `docs/adr/ADR-0008-windows-credential-store.md` | shared grammar, stale re-enrollment, cleanup precedence       |
| `docs/threat-model/THREAT-MODEL.md`             | reconciliation of the changed semantics                       |
| `docs/release-evidence/G2-HOLD-REMEDIATION.md`  | this document                                                 |

`crates/dvm-domain/src/security.rs` and `crates/dvm-storage/src/credentials.rs`
are outside the transaction's enumerated source list. Both were required: the
transaction authorises domain security-type changes where a phase-aware outcome
demands them, and D1 explicitly requires one shared validation contract rather
than duplicated predicates, which cannot be expressed without touching the
adapter. No other file outside the allowlist was modified.

Not changed, and verified so:

| Constraint                         | State                                                                      |
| ---------------------------------- | -------------------------------------------------------------------------- |
| Dependencies                       | none added, removed or changed                                             |
| `Cargo.lock`, `pnpm-lock.yaml`     | unchanged                                                                  |
| Argon2id / libsodium contract      | unchanged (libsodium 1.0.22, `libsodium-sys-stable` 1.24.0, Argon2id v1.3) |
| DVB1, SQLCipher, G1 storage format | unchanged                                                                  |
| Tauri capabilities, CSP            | unchanged                                                                  |
| CI workflows                       | unchanged                                                                  |
| G3 implementation                  | not started                                                                |
| `ErrorCode` / IPC contract surface | unchanged; `contract_drift` passes                                         |

No new `ErrorCode` variant was introduced, so the generated TypeScript contract
is byte-identical and the renderer surface is untouched.

## Preserved G2 evidence

These accepted results were regenerated, not assumed, and remain PASS:
`DEPENDENCY_SCOPE`, `G2_1` passphrase slot, `G2_2` recovery slot,
`VMK_HIERARCHY`, `LOCK_STATE`, `INV-011`…`INV-015`, `LEAST_PRIVILEGE`,
`REDACTION`, `KEYSLOT_AUTHENTICATION`, header-update crash matrix and
`G1_REGRESSION`. `AUDITED_LINEAGE = YES`,
`EXACT_SELECTED_RELEASE_AUDITED = NO`,
`ACCEPTED_PROJECT_AUDIT_PROVENANCE = YES` are unchanged.

Security invariants at transaction end: no root secret reaches the renderer, no
generic filesystem, shell, network or provider authority exists, and no
plaintext VMK, passphrase, recovery material or device KEK is persisted or
logged. Provider secrets live only in the OS credential store.

## Known limitations

- Post-activation durability uncertainty is reported, not repaired. A caller
  that receives `HeaderDurability::Uncertain` knows the new credential is
  authoritative but must treat the durability of that header as unproven until
  the next successful open.
- A failed cleanup leaves a real, unreferenced OS credential. It wraps no key
  the authoritative header uses and grants no access, but nothing in G2
  reclaims it automatically; there is no background reconciliation job.
- Stale-device re-enrollment requires an already authenticated OPEN session.
  Someone who can delete the OS credential can force re-enrollment inside such
  a session; this grants no authority the session does not already have.
- Abrupt process-crash tests use an in-memory credential store. Automatic
  reclamation of an OS credential after arbitrary process termination is not
  claimed.
- `EXACT_SELECTED_RELEASE_AUDITED` remains `NO`; the accepted audit lineage of
  ADR-0007 is unchanged by this transaction.
- This document establishes remediation, not G2 closure. PR #2 remains OPEN and
  unmerged.

No secret value appears anywhere in this document.
