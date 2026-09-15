# Security

## Current scope

G0 and G1 are CLOSED. G2 security and key lifecycle is current; acceptance is
recorded in [G2 evidence](docs/release-evidence/G2-SECURITY-KEY-LIFECYCLE.md).
Implementation is not a release-readiness claim. The desktop currently exposes
only foundation status. Production security mechanisms are trusted Rust APIs;
there is no vault creation/recovery presentation UI.
Argon2id uses pinned libsodium 1.0.22 through libsodium-sys-stable 1.24.0.
The project accepts the 1.0.12/1.0.13 assessment as audit provenance for its
Argon2id lineage; the selected 1.0.22 release and Rust adapter are not claimed to
be independently audited. See [ADR-0007](docs/adr/ADR-0007-argon2-policy.md) for
scope, reproducibility controls and residual lineage limitations.

## Encrypted assets and VMK protection

SQLCipher protects private metadata, original filenames and source hints. DVB1
XChaCha20-Poly1305 protects original bytes in bounded authenticated chunks. Blob
names are random identifiers. Recovery requires whole-original authentication,
length and plaintext hash equality before a transactional sink reports success.
No normal import writes plaintext staging. G1 corruption/reconciliation semantics
and storage key domains remain unchanged.

An OS-random 256-bit VMK is independently wrapped by authenticated keyslots.
Passphrases do not generate VMKs. Argon2id version 0x13 derives a wrapping KEK
using a fresh 16-byte salt, at least 19456 KiB, 2 iterations and 1 lane. Calibration
targets 250 ms and never goes below that baseline. Bounded persisted costs prevent
unbounded header-driven allocation. Passphrases are exact UTF-8, without trimming
or Unicode normalization; visually equivalent forms can differ. Empty and
oversized passphrases are rejected. A passphrase change or KDF upgrade wraps the
same VMK using new salt/nonce, without re-encrypting canonical data.

Default creation generates a separate 256-bit random recovery credential. A
trusted caller may explicitly acknowledge declining recovery after a data-loss
warning. Recovery uses domain-separated HKDF and an independent authenticated
slot; it survives passphrase changes. Recovery material is never persisted by
DVM or sent to the renderer. A future trusted presentation design must preserve
this boundary. Losing all unlock credentials permanently loses access.

Every slot authenticates its type, version, ID, algorithm/KDF fields, salt,
nonce, vault ID and device reference using deterministic versioned AAD. Unknown
mandatory formats fail closed. Empty keyslots are reserved for explicitly named
G1 injected-key fixtures and are rejected by production admission.

## Optional device and provider credentials

Quick-unlock is disabled by default. Enabling it generates a separate random
32-byte device KEK and stores it in Windows Credential Manager as a generic
credential with explicit Local persistence: the same Windows user on the same
computer, without Enterprise roaming semantics. Only its non-secret reference
is in the header. A missing/deleted credential disables this path while leaving
passphrase and recovery usable. It never creates a replacement VMK.

Provider credentials also use only this native OS store through a backend-only
`ProviderSecretStore`. Its public status is configured/not-configured; raw values
are never IPC responses or stored in SQLCipher, settings, localStorage or logs.
References follow `dvm/provider/<provider>/<profile>`. There is no provider SDK,
remote provider call or new egress authority. Windows user-context protection
does not protect against malicious software running as that same user.

## Session and renderer boundary

The typed state model is CLOSED → LOCKED → UNLOCKING → OPEN, with failed unlock
returning LOCKED. OPEN → LOCKING → LOCKED drops the live storage/key owner.
Unhealthy storage changes admission to DEGRADED_READ_ONLY. Every application
content operation requires OPEN and holds the same synchronization guard as lock.
Wrong credentials are rejected before database opening or reconciliation. Tests
compare durable file sets/hashes, not just the returned error.

The session owns the one active VMK/storage lifetime. Secret types do not
implement Serialize or exposing Debug. Releasable secret buffers use zeroization;
compiler/register/OS copies and storage-engine internals cannot all be proven
absent from process memory.

The WebView receives no VMK, DB key, BlobRootKey, device KEK, recovery material or
provider credential. Its capability grants zero plugin permissions. There is no
generic filesystem, shell, process, credential getter or HTTP command. The only
registered IPC operation is foundation status, so it cannot query private content
in any state. Production CSP has no remote script/provider origin or unsafe-eval.
Development HMR permissions are separately asserted.

## Diagnostics and evidence

Diagnostic field values are public only for exact supported status, contract
version and error-code values. All other fields are redacted; unknown event and
field names are replaced. Error detail construction accepts only a fixed public
operational message or a redacted marker. The legacy structural sanitizer is not
used as secret classification. Native errors are converted without their source
text. Original names, private path components and secret material must not enter
logs, IPC failure envelopes or evidence.

Diagnostics use stdout and the explicitly configured `DVM_G0_DIAGNOSTICS_FILE`
sink. G2 tests use synthetic canaries, secret-safe assertions and uniquely named
OS credentials with cleanup/readback. Evidence scanning is limited to generated
G2 output, never arbitrary user data. No real API keys are used in tests.

## Threat model and remaining limitations

The [threat model](docs/threat-model/THREAT-MODEL.md) maps in-scope threats to
controls and test obligations. Confidentiality is not guaranteed against malware
with equal/higher privilege while OPEN, a compromised OS, active process-memory
inspection, voluntary export/disclosure or loss of passphrase and all recovery
material. DVM does not claim resistance to a fully compromised host.

Atomic same-directory header replacement protects against tested process crashes.
It does not certify arbitrary hardware power loss or filesystems that violate
flush/rename semantics. Without an external monotonic anchor, a complete older
header can be replayed. KDF costs slow offline guesses but do not rate-limit an
attacker with copied vault files. File sizes and non-secret header metadata remain
visible. Recovery credentials cannot recreate deleted content.

An abrupt crash during optional device enrollment can leave an unreferenced OS
credential because the OS store and header cannot activate atomically together.
This does not remove the independent passphrase/recovery paths. Header crash
tests use an in-memory credential store; real OS tests explicitly clean up.

G3 backup, restore and migration are not implemented. Search, AI/networking,
media pipelines, plugins, mobile, sync and release hardening remain later gates.
Dependency scans, SBOM, signing and coordinated disclosure are G6 requirements.

## Reporting and licence

There is no published release or established coordinated-disclosure process.
Raise concerns in the repository issue tracker without posting secrets or private
vault data. G6 must establish a disclosure contact and response commitments.

No licence has been chosen. Until one is, the work is under exclusive copyright
of its contributors and grants no redistribution rights. Choosing a licence is a
prerequisite for the first release.
