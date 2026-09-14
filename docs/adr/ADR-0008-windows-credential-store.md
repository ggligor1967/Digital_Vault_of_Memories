# ADR-0008: Windows local credential persistence

Status: implemented; native integration passed in focused Windows tests. Full
acceptance is recorded separately in the G2 evidence document.

Use Windows Credential Manager generic credentials, explicitly
`CRED_PERSIST_LOCAL_MACHINE` (same Windows user, same computer). Do not use
PasswordVault, Enterprise persistence, an ambient default store, plaintext
configuration, provider SDKs or renderer credential APIs.

Select exactly windows-native-keyring-store 1.1.0 (MSRV 1.88), default features
disabled, and keyring-core 1.0.0 (MSRV 1.85). The adapter explicitly supplies
`persistence=Local` at entry creation and checks persisted attributes when
reading. The upstream default is Enterprise and is deliberately overridden.
Disable search support; use exact application-owned references admitted by the
single canonical grammar shared with keyslot validation (ADR-0006), so the two
never drift apart. All adapter operations are serialized. Bound secrets at 2560
bytes. Translate OS errors into canonical errors without source text. Returned backend secret buffers use
zeroization. No new unsafe code is needed in the workspace.

Provider storage exposes trusted store/retrieve/delete and a configured boolean.
Device references contain the vault UUID and an independent random credential
UUID, authenticated in the slot AAD; device KEKs never enter a header.
Synthetic tests use unique targets and teardown readback. An absent credential
disables quick-unlock without changing the header, VMK or other slots. Because
that leaves no other way to restore quick unlock, an authenticated open session
may replace a stale device slot: enrollment generates a new credential and slot
wrapping the same VMK, and touches neither the passphrase nor the recovery slot.
Only proven absence authorizes this. A credential-store read that fails
operationally is returned as a failure, never interpreted as absence, so an
outage cannot rotate away a working credential.

Windows user-context credential protection does not isolate against malware
running as that user. No network authentication or egress is introduced.

The OS store and vault header are not one atomic transaction. An abrupt process
termination after device credential creation but before header activation can
leave an unreferenced OS credential. Normal error paths remove it best-effort
once the phase-aware outcome confirms the old header is still authoritative, and
a predecessor credential is removed only after a replacement has activated. That
cleanup is secondary evidence: it never replaces the primary failure and never
turns a completed activation into a failure, so a failed removal is reported as
a recorded unreferenced credential. Passphrase/recovery access stays independent.
Tests inject abrupt crashes into header replacement using an in-memory credential
store; native credential tests use cleanup guards and explicit absence readback.

Sources: [Microsoft CREDENTIALW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw),
[native store persistence](https://docs.rs/windows-native-keyring-store/1.1.0/windows_native_keyring_store/),
[keyring-core](https://docs.rs/keyring-core/1.0.0/keyring_core/).
