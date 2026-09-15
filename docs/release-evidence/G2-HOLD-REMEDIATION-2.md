# DVM-V2 / G2 — Device credential recovery and store settlement bounded remediation

Transaction:
`DVM-V2 / G2 — DEVICE CREDENTIAL RECOVERY + STORE SETTLEMENT BOUNDED REMEDIATION`.

This document records the remediation of the four material review findings that
kept the G2 candidate on HOLD after the preceding bounded remediation. It
supplements, and does not replace, `G2-SECURITY-KEY-LIFECYCLE.md` and
`G2-HOLD-REMEDIATION.md`. Both earlier documents record facts of this branch's
history and are not rewritten here.

G2 is **not** closed by this transaction. Formal closure is a separate
transaction.

## Identity

| Field                        | Value                                      |
| ---------------------------- | ------------------------------------------ |
| Repository                   | `ggligor1967/Digital_Vault_of_Memories`    |
| Branch                       | `feat/dvm-v2-g2-security-key-lifecycle`    |
| Base (`main`)                | `7c7700cda069f781109453b20d0b318f383a595a` |
| Starting G2 head             | `ff5b500b59c63ffa4a00d317d472bed8a4462a4b` |
| Starting tree                | `35a6e982b55d21ef2954167fc8d18bab0bb812cb` |
| Pull request                 | #2, OPEN, non-draft, unmerged, base `main` |
| `verified_source_candidate`  | `b025e4d21f0993298eeee8cc0f0c8763bf3ae717` |
| Parent of remediation commit | `ff5b500b59c63ffa4a00d317d472bed8a4462a4b` |

`verified_source_candidate` is the pre-amend candidate that local and clean-room
validation actually executed. This document was then folded into that same
commit with `git commit --amend --no-edit`, so the final published SHA differs
and is reported externally. No published commit was rewritten: the previous
remediation commit `ff5b500` is untouched and remains the parent. Exactly one
commit is added to the branch.

Start identity was verified before any mutation: working tree and index clean,
no merge, rebase, cherry-pick, revert, bisect or sequencer in progress,
`origin/main` at the canonical baseline and the origin feature branch at the
expected start head.

## Review baseline

The live review surface was re-read before implementation. Twelve threads
existed: three previously fixed and already resolved, two previously fixed but
still unresolved and marked outdated, four new and material, and three new and
non-material. Nothing was silently absorbed into scope.

| Ref | Thread                  | Reviewer | Path                                    | Classification          |
| --- | ----------------------- | -------- | --------------------------------------- | ----------------------- |
| U1  | `PRRT_kwDOUZSIRc6iUksR` | Codex    | `crates/dvm-storage/src/security.rs`    | P2 material correctness |
| U2  | `PRRT_kwDOUZSIRc6iUksY` | Codex    | `crates/dvm-domain/src/security.rs`     | P2 material correctness |
| U3  | `PRRT_kwDOUZSIRc6iUksZ` | Codex    | `crates/dvm-storage/src/credentials.rs` | P2 material correctness |
| U4  | `PRRT_kwDOUZSIRc6iUllb` | Copilot  | `crates/dvm-storage/src/security.rs`    | P2 material correctness |
| H1  | `PRRT_kwDOUZSIRc6iRW-q` | Codex    | `crates/dvm-storage/src/security.rs`    | fixed earlier, outdated |
| D3  | `PRRT_kwDOUZSIRc6iRW-w` | Codex    | `crates/dvm-storage/src/security.rs`    | fixed earlier, outdated |
| N1  | `PRRT_kwDOUZSIRc6iUllq` | Copilot  | `scripts/verify-g2.mjs`                 | non-material            |
| N2  | `PRRT_kwDOUZSIRc6iUll6` | Copilot  | `crates/dvm-storage/src/header.rs`      | non-material            |
| N3  | `PRRT_kwDOUZSIRc6iUlmC` | Copilot  | `crates/dvm-storage/src/header.rs`      | non-material            |

Implementation order was U2 → U4 → U1 → U3: U2 fixes the settlement predicate
that every other oracle asserts against, U4 is a self-contained classification
boundary, U1 depends on the settlement predicate being correct, and U3 composes
the cleanup precedence rule established by the previous transaction with the
adapter's own write path.

## U1 — device credential usability, not presence

### Before

`enable_device` classified a persisted device slot by whether the operating
system held _any_ value for its reference:

```rust
if self.credentials.retrieve(&existing)?.is_some() {
    return Err(AppError::new(ErrorCode::CorruptHeader).into());
}
```

`Ok(None)` authorized replacement; `Ok(Some(_))` was taken as proof that quick
unlock worked. A credential that was truncated, extended, overwritten, copied
from another vault, or left wrapping a superseded root therefore made
`enable_device` return `CorruptHeader` forever. Because there is no separate
removal API, even a passphrase-authenticated session could not restore quick
unlock.

### After

Classification is decided by what the credential can do. A new
`DeviceSlotHealth` names the two outcomes, and `OpenVault::device_health`
decides between them:

| Store read     | Credential                                 | Classification           |
| -------------- | ------------------------------------------ | ------------------------ |
| `Err(..)`      | —                                          | propagated unchanged     |
| `Ok(None)`     | absent                                     | `Unusable` (replaceable) |
| `Ok(Some(..))` | wrong length                               | `Unusable` (replaceable) |
| `Ok(Some(..))` | authentication fails                       | `Unusable` (replaceable) |
| `Ok(Some(..))` | authenticates, unwraps a root ≠ active VMK | `Unusable` (replaceable) |
| `Ok(Some(..))` | authenticates, unwraps the active VMK      | `Healthy` (not rotated)  |

Three facts together prove health and nothing less does: exact device-key
length, successful authentication of the slot envelope, and root identity with
the vault's active VMK. Authenticated decryption alone is explicitly not
enough, because a slot can authenticate under its own credential and still
yield a superseded root.

`DEVICE_HEALTHY_IFF_UNWRAPS_ACTIVE_VMK = YES`. Root identity is compared in
trusted memory through the same derived-key equality the passphrase rewrap path
already uses (`storage_keys()?.0.as_bytes()`). No root, no derived key and no
fingerprint is serialized, logged or returned.

An operational store failure is neither absence nor damage: `retrieve` errors
propagate with `?` before any classification, so an outage can never rotate a
slot it cannot classify. That distinction is what keeps a transient fault from
destroying a working quick unlock.

Re-enrollment is unchanged in every other respect. It generates a fresh
`DeviceKey` and a fresh canonical reference, wraps the **same** active VMK,
replaces the device slot in place, and leaves the passphrase and recovery slots
byte-identical. The VMK is never rotated, and exactly one `device-v1` slot
exists after activation. A healthy slot is refused with the existing
`CorruptHeader` classification; no new public `ErrorCode` was introduced.

### Oracle

`present_but_unusable_device_credential_is_re_enrolled` runs the full matrix
over five ways a present credential becomes unusable, each against a fresh
vault with real imported content:

| Damage           | How it is produced                                                     |
| ---------------- | ---------------------------------------------------------------------- |
| `Short`          | the healthy credential truncated to 31 bytes                           |
| `Long`           | the healthy credential extended to 33 bytes                            |
| `Overwritten`    | 32 bytes of inverted material: right length, authentication fails      |
| `CrossVault`     | a real, valid device credential read out of a second independent vault |
| `SupersededRoot` | a slot wrapping a different root under the same vault id and reference |

`SupersededRoot` is the case that authenticated decryption alone would accept:
the envelope is produced by `keyslots::wrap_device` with the vault's own id and
the slot's own reference, so its AAD and tag verify, and only the root
comparison rejects it.

For every case the oracle asserts, in order: the damaged credential is still
present in the store; `UnlockCredential::Device` fails; `enable_device`
succeeds and reports `is_fully_settled()`; the reference changed; exactly one
`device-v1` slot remains and the header still has three slots; the store holds
exactly the new reference and nothing else; the passphrase and recovery slots
are byte-identical to the pre-damage header; blobs and `metadata.db` are
unchanged; the replacement is then refused as healthy with `CorruptHeader` and
`CleanupOutcome::NotRequired`; an injected `retrieve` failure yields
`PROVIDER_UNAVAILABLE` with no header or credential mutation; and finally all
three credentials — passphrase, recovery and device — unlock the vault, derive
the same VMK, and recover the imported bytes exactly.

## U2 — completed cleanup is settled

### Before

```rust
self.durability.is_durable() && matches!(self.cleanup, CleanupOutcome::NotRequired)
```

`CleanupOutcome::Completed` means the unreferenced credential _was_ removed, so
a durable stale-device replacement had no remaining work — yet the advertised
convenience predicate reported every successfully cleaned rotation as
unsettled.

### After

```rust
self.durability.is_durable() && !self.cleanup.is_failed()
```

Only `CleanupOutcome::Failed` names a credential known to remain and to need
reclaiming later, so only it prevents a durable activation from being fully
settled. The predicate asks `CleanupOutcome::is_failed` rather than repeating
the list of settled variants, so the two cannot drift apart.

### Oracle

`settlement_truth_table_is_exhaustive` pins the predicate over both axes in
full, not only the combinations the current lifecycle paths happen to produce:

| Durability  | Cleanup       | `is_fully_settled` |
| ----------- | ------------- | ------------------ |
| `Durable`   | `NotRequired` | `true`             |
| `Durable`   | `Completed`   | `true`             |
| `Durable`   | `Failed(..)`  | `false`            |
| `Uncertain` | `NotRequired` | `false`            |
| `Uncertain` | `Completed`   | `false`            |
| `Uncertain` | `Failed(..)`  | `false`            |

`SETTLEMENT_TRUTH_TABLE = PASS`. A second test,
`completed_cleanup_reports_no_remaining_credential`, keeps the predicate and
the `CleanupOutcome` accessors from disagreeing about the same outcome.

## U3 — the credential store is write, verify, compensate

### Before

```rust
entry.set_secret(secret.as_bytes()).map_err(|_| failure())?;
local(&entry)
```

`set_secret` has already persisted the credential by the time `local` reads the
persisted attributes back. If attribute retrieval failed, or reported a
persistence class other than `Local`, the adapter returned an error and left
the newly written credential in place. Provider callers merely propagate that
error, so a secret could remain stored — possibly under the explicitly
forbidden Enterprise persistence, precisely because this adapter refused it.

### After

Storing is a three-step transaction:

```rust
entry.set_secret(secret.as_bytes()).map_err(|_| failure())?;
if let Err(primary) = verify_persisted(reference, &entry) {
    record(compensate(reference, &entry));
    return Err(primary);
}
Ok(())
```

`compensate` deletes exactly the entry this call wrote, treating `NoEntry` as
success, and returns a `CleanupOutcome` rather than a `Result` so that it
cannot become the value the caller sees. `record` stores that non-secret
classification beside the failure. The post-write verification failure is
always primary: a failed compensation is secondary evidence and never replaces
it. This is the same precedence rule the previous transaction established for
the keyslot lifecycle, applied inside the adapter.

The compensation branch is production code. `verify_persisted` is deliberately
separate from the read path's own `local` check so that the test seam cannot
perturb `retrieve`. In a production build both seam predicates are `const fn`
returning `false`, so the adapter carries no switch and cannot be steered from
outside the crate; only the test build carries state, and it is scoped to a
single credential reference so it cannot disturb any other test using the real
store concurrently. The seam _reports_ a non-`Local` persistence result; it
never writes a forbidden persistence class.

`POST_WRITE_VERIFICATION_FAILURE_ATTEMPTS_DELETE = YES`.

### Oracle

`post_write_persistence_failure_removes_the_credential_it_wrote` runs against
the real Windows credential store, under an RAII guard that disarms the seam
and removes the synthetic credential on every exit path:

| Case                                 | Required outcome                                                    |
| ------------------------------------ | ------------------------------------------------------------------- |
| verification passes                  | credential persists; no compensation recorded                       |
| verification fails, removal succeeds | `PROVIDER_UNAVAILABLE`; `Completed` recorded; readback returns none |
| verification fails, removal fails    | `PROVIDER_UNAVAILABLE` still primary; `Failed(DISK_FULL)` recorded  |

The compensation fault is classified `DISK_FULL`, distinctly from the
adapter's own `PROVIDER_UNAVAILABLE`, so a masked primary failure is detectable
by code alone rather than by inspection. In the failing-removal case the
credential is read back and asserted to be genuinely still present, so a
recorded cleanup failure cannot be a fabrication. Neither the primary error nor
the recorded secondary evidence may render the synthetic secret or the
credential reference; both are asserted absent.

## U4 — an absent device slot is not a passphrase failure

### Before

One generic lookup mapped every missing slot to the same classification:

```rust
.ok_or_else(|| AppError::new(ErrorCode::BadPassphrase))?
```

A vault that simply has no `device-v1` slot therefore failed quick unlock with
`BAD_PASSPHRASE`, contradicting the intended semantics that a missing device
credential disables only the device path.

### After

One selection boundary carries both the required slot type and the
classification for that slot being absent:

```rust
let (kind, absent) = match credential {
    UnlockCredential::Passphrase(_) => ("passphrase-v1", ErrorCode::BadPassphrase),
    UnlockCredential::Recovery(_) => ("recovery-v1", ErrorCode::BadPassphrase),
    UnlockCredential::Device => ("device-v1", ErrorCode::ProviderUnavailable),
};
```

No special case is scattered through unrelated code, successful authentication
is unchanged, and no new public `ErrorCode` was added. Absent passphrase and
recovery slots keep their existing authentication classification.

### Oracle

`device_unlock_without_a_device_slot_reports_provider_unavailable` asserts that
on a vault with passphrase and recovery slots but no device slot,
`UnlockCredential::Device` returns `PROVIDER_UNAVAILABLE`; that the durable
byte-and-file-set snapshot is unchanged and no credential was created; that a
wrong passphrase still returns `BAD_PASSPHRASE` and both configured paths still
unlock; and that on a vault created with recovery declined, a recovery attempt
still returns `BAD_PASSPHRASE` while a device attempt returns
`PROVIDER_UNAVAILABLE`.

## Negative controls

Four controls were added to `scripts/g2-negative-controls.mjs`, and one
pre-existing control was retargeted because U1 replaced the line it mutated.
Each control mutates a source file, requires the named oracle to fail with the
expected marker, and restores the original bytes in `finally` with a
byte-equality assertion. No negative-control mutation is committed.

| Control                                     | Restored START defect                                        | Oracle that must fail                                              |
| ------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------ |
| `present-device-credential-assumed-healthy` | any present credential treated as healthy without unwrapping | `present_but_unusable_device_credential_is_re_enrolled`            |
| `completed-cleanup-reported-unsettled`      | `matches!(cleanup, NotRequired)` settlement predicate        | `settlement_truth_table_is_exhaustive`                             |
| `post-write-verification-leaves-credential` | compensating delete removed after verification failure       | `post_write_persistence_failure_removes_the_credential_it_wrote`   |
| `missing-device-slot-as-bad-passphrase`     | absent device slot classified `BAD_PASSPHRASE`               | `device_unlock_without_a_device_slot_reports_provider_unavailable` |
| `stale-device-slot-unrecoverable`           | a `retrieve` error swallowed into absence (retargeted seam)  | `stale_device_slot_is_re_enrolled_only_on_proven_absence`          |

The two outage oracles were also given explicit failure messages naming the
defect they detect, so a control that turns an operational credential-store
failure into _any_ classification is caught by one marker rather than by a
generic "failure expected" string.

All fourteen controls (ten pre-existing, four new) reported `detected by
expected oracle; EXIT 101` — the archive-pin control exits 1 by design — and
the script reported `G2_NEGATIVE_CONTROLS=PASS; all source bytes restored`.

## Previous remediation regression

The preceding remediation stays green. Re-run and passing:

| Ref | Oracle                                                              | Marker                                                              |
| --- | ------------------------------------------------------------------- | ------------------------------------------------------------------- |
| H1  | `header_failure_matrix_separates_pre_and_post_activation`           | `H1_HEADER_ACTIVATION_MATRIX=PASS H1_PASSPHRASE_COMMIT=PASS`        |
| H1  | `creation_delivers_recovery_material_once_the_header_activates`     | `H1_CREATE_RECOVERY_PRESERVED=PASS`                                 |
| H1  | `device_enrollment_retains_the_credential_it_activated`             | `H1_DEVICE_ACTIVATION_MATRIX=PASS`                                  |
| D1  | `credential_reference_language_is_shared_by_keyslot_and_adapter`    | `D1_CREDENTIAL_REFERENCE_LANGUAGE_EQUAL=PASS`                       |
| D2  | `cleanup_failure_is_recorded_without_replacing_the_primary_failure` | `D2_PRIMARY_ERROR_PRESERVED=PASS D2_CLEANUP_RECORDED=PASS`          |
| D3  | `stale_device_slot_is_re_enrolled_only_on_proven_absence`           | `D3_STALE_DEVICE_RE_ENROLLMENT=PASS D3_SLOT_INDEPENDENCE=PASS`      |
| P3  | `a_key_that_is_not_allowlisted_becomes_the_redacted_field_key`      | passes in the `dvm-observability` suite alongside the canary oracle |

U2 changes what `is_fully_settled` reports for a completed cleanup, which is
exactly the D3 re-enrollment case. The D3 oracle asserted
`durability().is_durable()` and `cleanup() == Completed` separately, so it was
already correct under both predicates and needed no change.

## Non-material thread adjudication

Re-adjudicated at the exact head after implementation. None was implemented,
and no product or security code was changed to silence a comment.

| Ref | Subject                                        | Classification                   |
| --- | ---------------------------------------------- | -------------------------------- |
| N1  | `spawnSync` with `shell: true` in verify-g2    | `NON_MATERIAL_TOOLING_HARDENING` |
| N2  | duplicate production validation in `parse`     | `NON_MATERIAL_REDUNDANCY`        |
| N3  | duplicate production validation in `serialize` | `NON_MATERIAL_REDUNDANCY`        |

N1: every command and argument list in `verify-g2.mjs` is a literal structured
array written in the script itself. No argument is derived from a filename, an
environment variable, a network response or any other attacker-influenced
input, so routing through a shell widens no reachable command surface. The
finding is real as style and hardening, and is not a G2 security defect.

N2/N3: `parse` calls `parse_trusted_fixture` (which validates production slots
when `keyslots` is non-empty) and then `validate_production` again; `serialize`
is symmetric. The second call is redundant work, not incorrect work: both paths
fail closed identically, and the redundancy is what makes the production
admission boundary explicit at each public entry point rather than implied by a
callee. Defence in depth on the header admission path is deliberately retained.

## Targeted validation

| Command                                                                         | Exit |
| ------------------------------------------------------------------------------- | ---- |
| `cargo fmt --all -- --check`                                                    | 0    |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 0    |
| `cargo test --locked -p dvm-domain -- --nocapture`                              | 0    |
| `cargo test --locked -p dvm-crypto -- --nocapture`                              | 0    |
| `cargo test --locked -p dvm-storage -- --nocapture`                             | 0    |
| `cargo test --locked --release -p dvm-storage -- --nocapture`                   | 0    |
| `cargo test --locked --package dvm-domain --test contract_drift`                | 0    |
| `node scripts/g2-negative-controls.mjs`                                         | 0    |
| `pnpm --filter @dvm/security-tests run test`                                    | 0    |
| `pnpm lint`                                                                     | 0    |
| `pnpm typecheck`                                                                | 0    |
| `pnpm format:check`                                                             | 0    |
| `git diff --check`                                                              | 0    |

The release `dvm-storage` run reported `44 passed; 0 failed; 2 ignored`. Both
ignored tests are pre-existing and are invoked explicitly by `verify:g1`: the
named child of the crash matrix and the heavyweight multi-GB gate. Neither is a
mandatory skip.

## Full local G2 regression

Command: `pnpm verify:g2`. Exit 0. Final line:
`SECRET_LOG_LEAKAGE=NO LOCAL_G2=PASS`.

| Stage                               | Result                                                                                                                                   |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| native pin                          | `G2_NATIVE_PIN=PASS libsodium=1.0.22 target=x86_64-pc-windows-msvc`                                                                      |
| negative controls                   | 14/14 detected; `G2_NEGATIVE_CONTROLS=PASS; all source bytes restored`                                                                   |
| G0 foundation gate                  | `steps: 16 run, 0 skipped, 0 failed, 0 not reached`                                                                                      |
| G1 acceptance                       | `G1 LOCAL ACCEPTANCE: PASS; multi-GB and crash gates executed`                                                                           |
| G1 multi-GB regression              | 2 151 677 952 bytes, `BYTE_EQUALITY=PASS BOUNDED_MEMORY=PASS`, source and recovered SHA-256 identical, peak working set 23 126 016 bytes |
| U1                                  | `U1_PRESENT_UNUSABLE_DEVICE_RE_ENROLLMENT=PASS U1_HEALTHY_SLOT_PRESERVED=PASS U1_RESIDUE=NONE`                                           |
| U2                                  | `SETTLEMENT_TRUTH_TABLE=PASS`                                                                                                            |
| U3                                  | `POST_WRITE_VERIFICATION_FAILURE_ATTEMPTS_DELETE=YES U3_PRIMARY_ERROR_PRESERVED=PASS U3_RESIDUE=NONE`                                    |
| U4                                  | `U4_MISSING_DEVICE_SLOT_CLASSIFICATION=PASS U4_NO_MUTATION=PASS`                                                                         |
| H1                                  | `H1_HEADER_ACTIVATION_MATRIX=PASS H1_PASSPHRASE_COMMIT=PASS`, `H1_CREATE_RECOVERY_PRESERVED=PASS`, `H1_DEVICE_ACTIVATION_MATRIX=PASS`    |
| D1                                  | `D1_CREDENTIAL_REFERENCE_LANGUAGE_EQUAL=PASS`                                                                                            |
| D2                                  | `D2_PRIMARY_ERROR_PRESERVED=PASS D2_CLEANUP_RECORDED=PASS D2_SECRET_LEAKAGE=NO`                                                          |
| D3                                  | `D3_STALE_DEVICE_RE_ENROLLMENT=PASS D3_SLOT_INDEPENDENCE=PASS D3_RESIDUE=NONE`                                                           |
| real Windows credential integration | `WINDOWS_CREDENTIAL_INTEGRATION=PASS PROVIDER_SECRET_ORACLE=PASS G2_TEST_CREDENTIAL_RESIDUE=NONE`                                        |
| process-crash header matrix         | `G2_PROCESS_CRASH_HEADER_MATRIX=PASS`                                                                                                    |
| `git diff --check`                  | EXIT 0                                                                                                                                   |

No mandatory step was skipped and no corpus was reduced. The only `ignored`
Rust tests are the two pre-existing ones `verify:g1` invokes explicitly.

**LOCAL_G2 = PASS.**

## Clean-room revalidation

Fresh short-path Windows checkout at `C:\dvm-g2-followup-cr`, created by
`git clone --no-hardlinks` of the candidate branch. Nothing was copied from the
development tree: before the run the checkout contained no `target`, no
`node_modules`, no `.dvm-local`, no credential artefact and no test vault, and
the whole Rust build ran from cold.

| Field                                    | Value                                      |
| ---------------------------------------- | ------------------------------------------ |
| Candidate                                | `b025e4d21f0993298eeee8cc0f0c8763bf3ae717` |
| Tree                                     | `b7faf0014908df452639513d3782ebef2625b991` |
| Path                                     | `C:\dvm-g2-followup-cr`                    |
| `pnpm install --frozen-lockfile`         | EXIT 0                                     |
| `node scripts/verify-g2.mjs --cleanroom` | EXIT 0                                     |

The clean-room tree and the candidate tree are the same object
(`b7faf00`), so the validated source is exactly what was committed.

| Stage                               | Result                                                                                                                                   |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| native pin                          | `G2_NATIVE_PIN=PASS libsodium=1.0.22 target=x86_64-pc-windows-msvc`                                                                      |
| negative controls                   | 14/14 detected; `G2_NEGATIVE_CONTROLS=PASS; all source bytes restored`                                                                   |
| G0 foundation gate                  | `steps: 16 run, 0 skipped, 0 failed, 0 not reached`                                                                                      |
| G1 acceptance                       | `G1 LOCAL ACCEPTANCE: PASS; multi-GB and crash gates executed`                                                                           |
| G1 multi-GB regression              | 2 151 677 952 bytes, `BYTE_EQUALITY=PASS BOUNDED_MEMORY=PASS`, source and recovered SHA-256 identical, peak working set 22 982 656 bytes |
| U1                                  | `U1_PRESENT_UNUSABLE_DEVICE_RE_ENROLLMENT=PASS U1_HEALTHY_SLOT_PRESERVED=PASS U1_RESIDUE=NONE`                                           |
| U2                                  | `SETTLEMENT_TRUTH_TABLE=PASS`                                                                                                            |
| U3                                  | `POST_WRITE_VERIFICATION_FAILURE_ATTEMPTS_DELETE=YES U3_PRIMARY_ERROR_PRESERVED=PASS U3_RESIDUE=NONE`                                    |
| U4                                  | `U4_MISSING_DEVICE_SLOT_CLASSIFICATION=PASS U4_NO_MUTATION=PASS`                                                                         |
| H1                                  | `H1_HEADER_ACTIVATION_MATRIX=PASS H1_PASSPHRASE_COMMIT=PASS`, `H1_CREATE_RECOVERY_PRESERVED=PASS`, `H1_DEVICE_ACTIVATION_MATRIX=PASS`    |
| D1                                  | `D1_CREDENTIAL_REFERENCE_LANGUAGE_EQUAL=PASS`                                                                                            |
| D2                                  | `D2_PRIMARY_ERROR_PRESERVED=PASS D2_CLEANUP_RECORDED=PASS D2_SECRET_LEAKAGE=NO`                                                          |
| D3                                  | `D3_STALE_DEVICE_RE_ENROLLMENT=PASS D3_SLOT_INDEPENDENCE=PASS D3_RESIDUE=NONE`                                                           |
| real Windows credential integration | `WINDOWS_CREDENTIAL_INTEGRATION=PASS PROVIDER_SECRET_ORACLE=PASS G2_TEST_CREDENTIAL_RESIDUE=NONE`                                        |
| process-crash header matrix         | `G2_PROCESS_CRASH_HEADER_MATRIX=PASS`                                                                                                    |
| `git diff --check`                  | EXIT 0                                                                                                                                   |

Final line: `SECRET_LOG_LEAKAGE=NO CLEAN_ROOM_G2=PASS`.

After the run: the clean-room working tree was clean, `HEAD` and tree were still
`b025e4d` / `b7faf00`, `git diff --exit-code -- pnpm-lock.yaml Cargo.lock` exited
0, no `dvm-g2-*` test vault remained under the user temp directory, and
`cmdkey /list` showed no `dvm/` credential target. Credential residue: NONE.

### Host resource note

Before this run the volume was at 99% capacity with 7.1 GiB free, which the
previous transaction recorded as enough to abort a clean-room run. Space was
reclaimed by deleting only rebuildable Rust build output — the `target`
directories of four clean-room checkouts belonging to already-completed prior
transactions, whose results are already recorded in the committed G1 and G2
evidence documents. Those checkouts, their `node_modules` and their `.git`
directories were left intact, no tracked file in this repository was touched, no
gate was weakened, no corpus was reduced and no step was skipped. The clean-room
run then completed on the first attempt with 15 GiB free at its narrowest point.

## Scope

Changed paths:

| Path                                             | Reason                                                  |
| ------------------------------------------------ | ------------------------------------------------------- |
| `crates/dvm-domain/src/security.rs`              | U2 settlement predicate and its truth-table oracle      |
| `crates/dvm-storage/src/security.rs`             | U1 usability classification, U4 slot selection boundary |
| `crates/dvm-storage/src/security/tests.rs`       | new U1/U3/U4 oracles and sharpened outage markers       |
| `crates/dvm-storage/src/credentials.rs`          | U3 write-verify-compensate transaction and its seam     |
| `scripts/g2-negative-controls.mjs`               | four new controls; one retargeted seam                  |
| `docs/adr/ADR-0008-windows-credential-store.md`  | changed usability, classification and write semantics   |
| `docs/threat-model/THREAT-MODEL.md`              | reconciliation of the changed semantics                 |
| `docs/release-evidence/G2-HOLD-REMEDIATION-2.md` | this document                                           |

Every functional path is in the transaction's enumerated list.
`scripts/g2-negative-controls.mjs` is test infrastructure required by the
transaction's negative-control clause: U1 replaced the exact line one existing
control mutated, so leaving it untouched would have broken the harness.
ADR-0008 and the threat model were updated because the semantics they state
actually changed — "only proven absence authorizes replacement" is no longer
true, and post-write compensation is new adapter behaviour.

Not changed, and verified so:

| Constraint                         | State                                                                      |
| ---------------------------------- | -------------------------------------------------------------------------- |
| Dependencies                       | none added, removed or changed                                             |
| `Cargo.lock`, `pnpm-lock.yaml`     | unchanged                                                                  |
| Argon2id / libsodium contract      | unchanged (libsodium 1.0.22, `libsodium-sys-stable` 1.24.0, Argon2id v1.3) |
| Keyslot binary/serialized format   | unchanged; no AAD field added, removed or reordered                        |
| DVB1, SQLCipher, G1 storage format | unchanged                                                                  |
| Tauri capabilities, CSP            | unchanged                                                                  |
| CI workflows                       | unchanged                                                                  |
| G3 implementation                  | not started                                                                |
| `ErrorCode` / IPC contract surface | unchanged; `contract_drift` passes                                         |

No new `ErrorCode` variant was introduced, so the generated TypeScript contract
is byte-identical and the renderer surface is untouched. `CredentialStore` keeps
its exact trait signature, so no caller outside the adapter changed.

## Preserved G2 evidence

These accepted results were regenerated, not assumed, and remain PASS:
`DEPENDENCY_SCOPE`, `G2_1` passphrase slot, `G2_2` recovery slot,
`VMK_HIERARCHY`, `LOCK_STATE`, `INV-011`…`INV-015`, `LEAST_PRIVILEGE`,
`REDACTION`, `KEYSLOT_AUTHENTICATION`, phase-aware header activation,
primary/cleanup error separation, credential-reference grammar equality,
header-update crash matrix and `G1_REGRESSION`. `AUDITED_LINEAGE = YES`,
`EXACT_SELECTED_RELEASE_AUDITED = NO`,
`ACCEPTED_PROJECT_AUDIT_PROVENANCE = YES` are unchanged.

Security invariants at transaction end: no root secret reaches the renderer, no
generic filesystem, shell, network or provider authority exists, and no
plaintext VMK, passphrase, recovery material or device KEK is persisted or
logged. Provider secrets live only in the OS credential store. The new root
comparison in `device_health` happens entirely in trusted memory and produces
no serializable artefact.

## Known limitations

- Re-enrollment of an unusable device slot requires an already authenticated
  OPEN session. Someone who can delete or overwrite the operating-system
  credential can force re-enrollment inside such a session; this grants no
  authority the session does not already have.
- The root comparison in `device_health` reuses the existing derived-key
  equality of the passphrase rewrap path. It is an ordinary memory comparison,
  not a constant-time one; both operands are already-derived local key material
  in a trusted process, and no attacker-observable timing channel is claimed for
  it.
- A device slot whose credential cannot unwrap the active VMK is reported as
  replaceable, not diagnosed. G2 does not tell the user _why_ quick unlock
  broke, only that re-enrollment is available.
- Post-write compensation is best-effort. If both the persistence verification
  and the removal fail, a real unreferenced credential remains in the operating
  system store; it wraps no key the authoritative header uses and grants no
  access, but nothing in G2 reclaims it automatically.
- The forbidden-persistence branch is proven through a reference-scoped
  deterministic seam that _reports_ a non-`Local` result. No test writes an
  Enterprise-persistence credential to the real store, so the production
  behaviour when Windows genuinely assigns a different persistence class is
  proven by control flow rather than by observing that class in the wild.
- Post-activation durability uncertainty is still reported, not repaired, and
  abrupt process-crash tests still use an in-memory credential store.
