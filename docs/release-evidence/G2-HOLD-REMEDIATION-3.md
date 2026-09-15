# G2 HOLD Remediation 3 — Credential Lookup Classification and Invalid Stored Secrets

Bounded remediation of the one remaining material fresh-review finding on
DVM-V2 / G2. No gate is advanced by this document: G2 remains under review, PR
number 2 remains open and unmerged, and G3 is not started.

## Start identity

| Fact                            | Value                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------- |
| Repository                      | `ggligor1967/Digital_Vault_of_Memories`                                       |
| Branch                          | `feat/dvm-v2-g2-security-key-lifecycle`                                       |
| START HEAD                      | `536a229f1a5ffe94f02f1023f18c828fdc00f483`                                    |
| START tree                      | `45ad55bf54f0616f84a19085d8be1d403f1bb138`                                    |
| START parent                    | `ff5b500b59c63ffa4a00d317d472bed8a4462a4b`                                    |
| `origin/main`                   | `7c7700cda069f781109453b20d0b318f383a595a`                                    |
| Pull request                    | number 2, open, non-draft, unmerged, base `main`                              |
| Working tree and index at start | clean; no merge, rebase, cherry-pick, revert, bisect or sequencer in progress |

## Finding

`PRRT_kwDOUZSIRc6iXDRO` — a zero-byte credential in Windows Credential Manager
is present but unusable, and could not be repaired.

## Root cause

The defect was not in device health. It was in the port's type.

`CredentialStore::retrieve` returned `Result<Option<SecretValue>, AppError>`.
That shape can express only two facts — "absent" and "here it is" — plus a
single undifferentiated error. A persisted credential, however, is external
input: Windows returns whatever is recorded under a reference, including
representations no trusted value may hold.

`WindowsCredentialStore::retrieve` therefore converted raw persisted bytes
straight into a `SecretValue`:

```rust
local(&entry)?;
Ok(Some(SecretValue::new(bytes)?))
```

`SecretValue::new` rejects empty input. For a zero-byte stored credential the
`?` turned that rejection into `Err(ProviderAuthFailed)` — an error the rest of
the system cannot tell apart from the credential service being unreachable.

The consequences followed from that one erased distinction:

- `device_health` propagated the error instead of classifying the slot, so the
  slot was never reported `Unusable`;
- `enable_device` correctly refuses to rotate on an operational error, so
  re-enrollment was refused;
- an authenticated passphrase or recovery user therefore could not repair or
  re-enroll quick unlock for a reachable corruption class.

The same `retrieve` also collapsed two further distinct facts into
`ProviderUnavailable`: failing to _query_ a credential's attributes, and
successfully learning that its persistence class is one this adapter forbids.
The first is an outage; the second is a property of the stored entry.

Special-casing zero bytes in `device_health` would have hidden the symptom and
left the abstraction — and every other caller — unchanged. The boundary was
fixed instead.

## The lookup contract

`CredentialLookup` (`crates/dvm-domain/src/security.rs`) is a trusted,
non-serializable classification of one lookup:

```rust
pub enum CredentialLookup {
    Missing,
    Present(SecretValue),
    InvalidStoredValue,
}
```

Read together with the enclosing `Result`, four outcomes are now distinct:

| Result                   | Meaning                                                                                 |
| ------------------------ | --------------------------------------------------------------------------------------- |
| `Ok(Missing)`            | the store answered; no entry exists                                                     |
| `Ok(Present(secret))`    | the store answered; the persisted value satisfies the trusted `SecretValue` invariant   |
| `Ok(InvalidStoredValue)` | the store answered; an entry exists and what it holds is invalid or policy-unusable     |
| `Err(error)`             | the operating-system credential service itself failed; nothing is known about the entry |

Properties held by construction and by test:

- No `Serialize` and no `Debug`, proven by two `compile_fail` doctests
  alongside the existing pair for `SecretValue`.
- `InvalidStoredValue` carries no payload. `CredentialLookup::classify` consumes
  the `Zeroizing<Vec<u8>>`; bytes the invariant rejects are dropped there, and
  therefore zeroized, without ever being handled downstream.
- `SecretValue` is unchanged. It still rejects empty and over-2560-byte values.
  Weakening it was the wrong repair: an empty credential is invalid persisted
  state, and it is now named as such rather than admitted.
- No new `ErrorCode`. `InvalidStoredValue` is an internal classification;
  external behavior continues to use `ProviderUnavailable` and
  `ProviderAuthFailed`.
- Not exposed to the renderer. The IPC contract is generated from
  `ErrorCode`, `FoundationHealth`, `FoundationStatus` and `AppError` only; the
  `contract_drift` test passes unchanged, proving the TypeScript mirror is
  unaffected.

## Windows classification

`WindowsCredentialStore::retrieve` now judges raw persisted state before any of
it is trusted. The blob never leaves the function: it is read into zeroizing
storage, classified, and either promoted or dropped.

| Persisted state                                                    | Result                                     |
| ------------------------------------------------------------------ | ------------------------------------------ |
| `NoEntry`                                                          | `Ok(Missing)`                              |
| valid bounded bytes                                                | `Ok(Present(SecretValue))`                 |
| zero bytes                                                         | `Ok(InvalidStoredValue)`                   |
| oversize bytes                                                     | `Ok(InvalidStoredValue)` (see limitations) |
| attribute query succeeds and reports a forbidden persistence class | `Ok(InvalidStoredValue)`                   |
| `get_secret` fails                                                 | `Err(ProviderUnavailable)`                 |
| `get_attributes` fails                                             | `Err(ProviderUnavailable)`                 |

`local` — the write path's stricter reading, where a forbidden persistence class
is a failure to be compensated rather than a value to classify — is now
expressed in terms of the same `persisted_locally` predicate, so the read and
write paths cannot drift about what "local" means while still drawing opposite
conclusions from it.

Raw bytes are never logged, never returned in an error, never placed in
evidence, and never cross renderer IPC.

## Device behavior

`device_health`:

| Lookup                                   | Health                            |
| ---------------------------------------- | --------------------------------- |
| `Missing`                                | `Unusable`                        |
| `InvalidStoredValue`                     | `Unusable`                        |
| `Present`, wrong length                  | `Unusable`                        |
| `Present`, AEAD or unwrap failure        | `Unusable`                        |
| `Present`, unwraps a different valid VMK | `Unusable`                        |
| `Present`, unwraps the active VMK        | `Healthy`                         |
| `Err`                                    | propagated unchanged; no rotation |

`unlock(UnlockCredential::Device)` reports `ProviderUnavailable` for a missing
device slot, a `Missing` store entry and an `InvalidStoredValue` entry alike.
None of the three is a failed authentication, none enters `OPEN`, and a failed
unlock performs no durable mutation. Passphrase and recovery paths are
untouched.

## Provider-secret behavior

`ProviderSecretStore::configured` and `::retrieve` now share one private
`lookup`, so they cannot disagree about what is stored.

| Lookup               | `configured()`            | `retrieve()`              |
| -------------------- | ------------------------- | ------------------------- |
| `Missing`            | `Ok(false)`               | `Ok(None)`                |
| `Present`            | `Ok(true)`                | `Ok(Some(secret))`        |
| `InvalidStoredValue` | `Err(ProviderAuthFailed)` | `Err(ProviderAuthFailed)` |
| `Err`                | propagated unchanged      | propagated unchanged      |

A malformed provider credential is deliberately not reported as absent.
Reporting `false` would invite a caller to overwrite persisted state it never
saw, and would leave the corruption unreported; reporting `true` would promise a
credential that cannot be used. It fails as an authentication problem — the
credential service answered perfectly well — and carries none of the offending
bytes. Deleting the entry restores the unconfigured state, so the condition is
repairable rather than terminal. No provider networking was added.

## Oracles

### Zero-byte, on the real Windows credential store

`zero_length_stored_device_credential_is_classified_and_re_enrolled` plants a
genuine zero-byte credential in Windows Credential Manager through the same
entry builder and persistence class the adapter uses, leaving the device slot
and its reference exactly as the authoritative header records them.

| Property                                          | Result                                                                 |
| ------------------------------------------------- | ---------------------------------------------------------------------- |
| Stored length                                     | exactly 0 bytes                                                        |
| Lookup                                            | `InvalidStoredValue`                                                   |
| Absence still distinct                            | an unwritten reference reports `Missing` from the same adapter         |
| Device health                                     | `Unusable`                                                             |
| Device unlock                                     | `ProviderUnavailable`; vault not opened; no durable byte changed       |
| Re-enrollment from an authenticated session       | succeeds, fully settled                                                |
| New credential                                    | present, valid, exactly 32 bytes                                       |
| New slot                                          | wraps the same VMK                                                     |
| Old credential                                    | no longer authoritative; absent from the store                         |
| Device slots remaining                            | exactly 1 (3 keyslots total)                                           |
| Passphrase and recovery slots                     | byte-identical to before the damage                                    |
| Blob content                                      | unchanged; plaintext recovered identically under all three credentials |
| Passphrase / recovery / quick unlock after repair | all PASS, same VMK                                                     |
| Credential residue                                | none                                                                   |

Marker: `U1_ZERO_LENGTH_RE_ENROLLMENT=PASS ZERO_BYTE_CREDENTIAL_RESIDUE=NONE`

The classification read is captured rather than propagated with `?`, so an
implementation that promotes raw bytes straight into the trusted value reports
the classification as wrong rather than the test as erroring — which is exactly
the confusion under remediation.

### Malformed stored device credentials

`present_but_unusable_device_credential_is_re_enrolled` runs a seven-class
matrix. Its in-memory store was changed to hold raw persisted bytes rather than
`SecretValue`s, because a mock that can hold only trusted values classifies
every entry as usable by construction and would agree with any implementation.
It now runs the same production classifier the real adapter does.

| Damage                 | Lookup               | Health     | Repair      |
| ---------------------- | -------------------- | ---------- | ----------- |
| 31 bytes               | `Present`            | `Unusable` | re-enrolled |
| 33 bytes               | `Present`            | `Unusable` | re-enrolled |
| wrong 32 bytes         | `Present`            | `Unusable` | re-enrolled |
| cross-vault credential | `Present`            | `Unusable` | re-enrolled |
| superseded root        | `Present`            | `Unusable` | re-enrolled |
| 0 bytes                | `InvalidStoredValue` | `Unusable` | re-enrolled |
| 2561 bytes             | `InvalidStoredValue` | `Unusable` | re-enrolled |

Each class additionally asserts the lookup classification directly, not only the
repair it enables: a lookup that reported absence would drive the same
re-enrollment while describing the store's contents incorrectly. Every class
also proves that the healthy replacement is _not_ rotated again
(`CorruptHeader`, `CleanupOutcome::NotRequired`) and that an operational
retrieval failure rotates nothing.

Markers: `U1_PRESENT_UNUSABLE_DEVICE_RE_ENROLLMENT=PASS`,
`U1_HEALTHY_SLOT_PRESERVED=PASS`, `U1_RESIDUE=NONE`.

### Provider lookup semantics

`provider_secret_lookup_semantics` covers all four outcomes, both invalid
classes (0 and 2561 bytes), the leak check on both returned errors, and the
repair by deletion. Marker: `PROVIDER_LOOKUP_SEMANTICS=PASS`.

## Negative controls

Sixteen temporarily injected defects, every byte restored in `finally` and the
restoration verified by comparison. Two are new to this remediation.

| Control                                    | Mutation                                                                                                                                      | Detected by                             |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `invalid-stored-credential-fails-the-read` | restores the START implementation: `Ok(CredentialLookup::Present(SecretValue::new(bytes)?))`, and a forbidden persistence class back to `Err` | real-Windows zero-byte oracle, EXIT 101 |
| `invalid-stored-value-reported-as-absent`  | `classify` maps a rejected value to `Missing` instead of `InvalidStoredValue`                                                                 | provider lookup oracle, EXIT 101        |

The first is the required proof that the zero-byte regression oracle fails
against the START implementation. The second closes the comfortable wrong
answer: reporting an unusable entry as absent still drives re-enrollment, so the
device oracle alone cannot see it, and only the provider semantics expose it.

Two existing controls were re-pointed at the new seam text without weakening
what they assert: `stale-device-slot-unrecoverable` and
`present-device-credential-assumed-healthy`.

All sixteen detected by their expected oracle; `G2_NEGATIVE_CONTROLS=PASS; all
source bytes restored`.

## Previous remediation regression

| Item                                  | Result |
| ------------------------------------- | ------ |
| H1 header activation                  | PASS   |
| D1 credential-reference grammar       | PASS   |
| D2 cleanup precedence                 | PASS   |
| D3 stale-device replacement           | PASS   |
| U2 settlement truth table             | PASS   |
| U3 post-write compensation            | PASS   |
| U4 missing device-slot classification | PASS   |
| INV-011 .. INV-015                    | PASS   |
| G1 full regression                    | PASS   |

U3 is unchanged by design: `store` still verifies persistence after
`set_secret`, still attempts a compensating delete on verification failure,
still keeps the verification failure primary, and still records the cleanup
classification beside it. The read path was changed; the write path was not.

## Targeted validation

| Command                                                                         | Exit                   |
| ------------------------------------------------------------------------------- | ---------------------- |
| `cargo fmt --all -- --check`                                                    | 0                      |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 0                      |
| `cargo test --locked -p dvm-domain -- --nocapture`                              | 0                      |
| `cargo test --locked -p dvm-storage -- --nocapture`                             | 0                      |
| `cargo test --locked -p dvm-application -- --nocapture`                         | 0                      |
| `cargo test --locked --release -p dvm-storage -- --nocapture`                   | 0                      |
| `cargo test --locked --package dvm-domain --test contract_drift`                | 0                      |
| `node scripts/g2-negative-controls.mjs`                                         | 0                      |
| `pnpm --filter @dvm/security-tests run test`                                    | 0 (136 tests, 6 files) |
| `pnpm lint`                                                                     | 0                      |
| `pnpm typecheck`                                                                | 0                      |
| `pnpm format:check`                                                             | 0                      |
| `git diff --check`                                                              | 0                      |

## Local G2

`pnpm verify:g2` — EXIT 0, `LOCAL_G2=PASS`, mandatory skips 0
(`steps: 16 run, 0 skipped, 0 failed, 0 not reached`). G0 composed at EXIT 0;
`G1 LOCAL ACCEPTANCE: PASS; multi-GB and crash gates executed`.

Markers observed: `U1_ZERO_LENGTH_RE_ENROLLMENT=PASS`,
`U1_PRESENT_UNUSABLE_DEVICE_RE_ENROLLMENT=PASS`,
`U1_HEALTHY_SLOT_PRESERVED=PASS`, `PROVIDER_LOOKUP_SEMANTICS=PASS`,
`U4_MISSING_DEVICE_SLOT_CLASSIFICATION=PASS`, `U4_NO_MUTATION=PASS`,
`U3_PRIMARY_ERROR_PRESERVED=PASS`, `U3_RESIDUE=NONE`,
`POST_WRITE_VERIFICATION_FAILURE_ATTEMPTS_DELETE=YES`,
`H1_HEADER_ACTIVATION_MATRIX=PASS`, `H1_DEVICE_ACTIVATION_MATRIX=PASS`,
`H1_CREATE_RECOVERY_PRESERVED=PASS`, `H1_PASSPHRASE_COMMIT=PASS`,
`D1_CREDENTIAL_REFERENCE_LANGUAGE_EQUAL=PASS`,
`D2_PRIMARY_ERROR_PRESERVED=PASS`, `D2_CLEANUP_RECORDED=PASS`,
`D2_SECRET_LEAKAGE=NO`, `D3_STALE_DEVICE_RE_ENROLLMENT=PASS`,
`D3_SLOT_INDEPENDENCE=PASS`, `D3_RESIDUE=NONE`,
`WINDOWS_CREDENTIAL_INTEGRATION=PASS`, `PROVIDER_SECRET_ORACLE=PASS`,
`G2_PROCESS_CRASH_HEADER_MATRIX=PASS`, `G2_NATIVE_PIN=PASS`,
`G2_NEGATIVE_CONTROLS=PASS`, `G2_TEST_CREDENTIAL_RESIDUE=NONE`,
`ZERO_BYTE_CREDENTIAL_RESIDUE=NONE`, `SECRET_LOG_LEAKAGE=NO`.

## Clean room

Fresh clone at `C:\dvm-g2-credential-lookup-cr`, checked out at the candidate
commit. No `target`, `node_modules`, `.dvm-local`, credential artefact or test
vault was copied in; the clone contained none of them.

| Property                         | Result                                                                                                                                                                 |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Candidate under test             | `9704ce26d3e293de73db39cfb45901aacf36db42`                                                                                                                             |
| Tree                             | `dc6f6bd1fe30fe7abcfa3efae312dbaad576e526`                                                                                                                             |
| `pnpm install --frozen-lockfile` | EXIT 0                                                                                                                                                                 |
| `pnpm verify:g2 --cleanroom`     | EXIT 0, `CLEAN_ROOM_G2=PASS`                                                                                                                                           |
| Mandatory skips                  | 0 (`steps: 16 run, 0 skipped, 0 failed, 0 not reached`)                                                                                                                |
| G0                               | `G0 VERDICT: PASS (all steps executed and green)`                                                                                                                      |
| G1                               | `G1 LOCAL ACCEPTANCE: PASS; multi-GB and crash gates executed`                                                                                                         |
| Zero-byte oracle                 | `U1_ZERO_LENGTH_RE_ENROLLMENT=PASS`                                                                                                                                    |
| Provider lookup                  | `PROVIDER_LOOKUP_SEMANTICS=PASS`                                                                                                                                       |
| Windows credential integration   | `WINDOWS_CREDENTIAL_INTEGRATION=PASS`                                                                                                                                  |
| Negative controls                | `G2_NEGATIVE_CONTROLS=PASS; all source bytes restored`                                                                                                                 |
| Credential residue               | `G2_TEST_CREDENTIAL_RESIDUE=NONE`, `ZERO_BYTE_CREDENTIAL_RESIDUE=NONE`, `U1_RESIDUE=NONE`, `U3_RESIDUE=NONE`, `D3_RESIDUE=NONE`; `cmdkey /list` shows no `dvm/*` entry |
| Secret leakage                   | `SECRET_LOG_LEAKAGE=NO`, `D2_SECRET_LEAKAGE=NO`                                                                                                                        |
| `Cargo.lock` / `pnpm-lock.yaml`  | unchanged                                                                                                                                                              |
| Working tree after the run       | clean                                                                                                                                                                  |

### Environment events during clean-room execution

Two clean-room attempts were terminated by host resource limits before the
green run. Both are recorded because neither was a defect, and because the
distinction was established by evidence rather than assumed:

- **Out-of-memory during `cargo clippy`.** The host killed the run, and the
  gate recorded `exit 101` for the clippy step. Clippy was then executed
  directly in the same clean room and returned **EXIT 0** with no diagnostic,
  establishing the 101 as a kill artefact rather than a lint failure. The build
  cache was subsequently warmed at `CARGO_BUILD_JOBS=1` — build parallelism
  only, no source, configuration or gate change — and the gate re-run.
- **`BLOCKED_BY_DISK_PRESSURE` in the G1 multi-GB gate.** That gate refuses to
  run below `2 * (2 GiB + chunk) + 2 GiB` free space, and two coexisting
  `target` directories had left 4.0 GB. The primary checkout's `target`
  directory — untracked, git-ignored, regenerable build output containing no
  tracked file — was removed, restoring 10.1 GB, and the gate then executed the
  multi-GB and crash gates to completion.

Neither event altered any candidate. Both were observed while validating the
first candidate, `04a7c5a`, which also reached `CLEAN_ROOM_G2=PASS` once the
host limits were cleared. The clean room recorded above is a separate, fresh
clone at the final commit; its run was uninterrupted and needed no retry — a
single `pnpm verify:g2 --cleanroom` over the unmodified candidate tree.

## Scope

Changed paths:

- `crates/dvm-domain/src/security.rs`
- `crates/dvm-storage/src/credentials.rs`
- `crates/dvm-storage/src/security.rs`
- `crates/dvm-storage/src/security/tests.rs`
- `crates/dvm-application/src/provider_secrets.rs`
- `scripts/g2-negative-controls.mjs`
- `docs/release-evidence/G2-HOLD-REMEDIATION-3.md` (this file)

Unchanged: `Cargo.lock`, `pnpm-lock.yaml`, every `Cargo.toml` and
`package.json`, every workflow. libsodium 1.0.22, libsodium-sys-stable 1.24.0
and Argon2id v1.3 are untouched, as are the keyslot format, AAD construction,
DVB1, SQLCipher configuration, Tauri permissions and CSP. No G3 work.

## Follow-up commit: cross-platform dead code

The first remediation commit, `b8479166f13829f71f390615a8f405038868e8d6`, was
pushed and failed exact-head CI. The failure was real and deterministic, and it
is recorded here rather than rewritten away.

`missing()`, one of the three lookup-classification predicates added to the G2
test module, had call sites only inside `#[cfg(windows)]` tests. On
`ubuntu-latest` it was therefore dead code, and G0's
`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
rejected it under `-D dead-code`. Windows G0 passed, as did G1; the local and
clean-room gates run on Windows only, so neither could observe it.

The fix asserts the `Missing` classification directly in
`provider_secret_lookup_semantics`, which is cross-platform. This removes the
dead code by using the predicate rather than by silencing the lint, and it
closes a genuine gap in that oracle: absence had been asserted only indirectly,
through `configured()` returning `false`, while the other two classes were
asserted as classifications. All three are now asserted the same way.

No production code changed. The correction is one assertion in one test.

Because `b847916` was already published, it was not amended, reset or
force-pushed. The fix is a second, append-only commit. That exceeds the
single-commit envelope this transaction authorized, and the deviation is
recorded deliberately: the alternative was leaving a red branch behind an
unamendable commit.

A local proxy for the non-Windows build was added to the verification for this
commit: the Windows-gated test items were temporarily disabled
(`#[cfg(windows)]` → `#[cfg(all(windows, any()))]`) and clippy re-run, so that
cfg-dependent dead code in the test module is observable on a Windows host. All
three predicates, and every other helper added by this remediation, are live
under that configuration. The only diagnostics it produces concern
`#[cfg(windows)]` items inside `credentials.rs` that do not exist at all on a
non-Windows target, including pre-existing ones unrelated to this change.

## Known limitations

- **Oversize credentials are unrepresentable on real Windows.** Windows
  Credential Manager refuses a blob above its own 2560-byte limit — an attempt
  to write 2561 bytes is rejected at the platform with `TooLong("secret",
2560)`, and no entry is created. The class is therefore covered
  deterministically in-memory rather than on the real store. This is a property
  of the platform, not an untested path: `SecretValue`'s upper bound and the
  Windows limit are the same number, so on Windows the bound can only ever be
  reached from below.
- **Forbidden persistence class is classified, not separately proven on the real
  store.** The adapter always writes with `persistence = Local`, and the test
  seam writes through the same builder, so a non-local persisted credential
  cannot be staged without a second external writer. The distinction that
  matters — an attribute _query_ failure remaining `Err`, versus a successful
  query reporting a forbidden class becoming `InvalidStoredValue` — is expressed
  in a single predicate shared by the read and write paths.
- **`metadata.db` bytes are not a session-stable invariant.** Opening and
  closing a SQLCipher vault rewrites the file, so the zero-byte oracle compares
  stored content as blob bytes and as the plaintext each credential recovers
  rather than as a database digest. Comparing the digest would test SQLite, not
  the repair.
- **Windows-only gates.** `pnpm verify:g2`, locally and in the clean room, runs
  only on Windows; the cross-platform half of G0 exists only in CI. The
  simulation described above narrows that gap for cfg-dependent dead code in
  the G2 test module, but it is a proxy, not a Linux build.
- This remediation does not advance G2. G2 acceptance depends on exact-head CI
  and fresh reviews recorded separately.
