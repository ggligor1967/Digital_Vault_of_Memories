# G2 threat model

Version: G2 implementation 2. Status: verification in progress; individual results
are recorded in the G2 evidence document. G0 and G1 are CLOSED. This document does
not establish release readiness. ADR-0007 records the project's accepted libsodium
Argon2id audit lineage, native build pin and exact-release audit limitation.

## Assets and boundaries

Canonical originals and private metadata belong in DVB1 and SQLCipher. VMK,
derived DB/blob/audit/backup keys, passphrase/recovery/device KEKs and provider
credentials belong exclusively to trusted Rust and the user-scoped OS credential
store where applicable. Recovery material belongs to the user through a future
trusted presentation boundary, never renderer IPC. Logs and evidence must contain
only public classifications. The WebView is less trusted than the Rust backend.

## Controls and evidence mapping

| In-scope threat                               | Required control                                                               | Test/evidence obligation                                              | Remaining limitation                                                                                    |
| --------------------------------------------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Locked vault directory copied                 | Random VMK; independent authenticated keyslots; SQLCipher/DVB1                 | Passphrase/recovery unlock and G1 byte recovery                       | Offline guessing depends on passphrase strength; sizes and header metadata visible                      |
| Ciphertext tampering                          | AEAD; bound vault/slot metadata                                                | Slot tamper matrix; G1 corruption suite                               | Deletion and denial of service remain possible                                                          |
| Lost/stolen vault files                       | Independent recovery slot                                                      | Recovery after passphrase change                                      | Recovery material cannot replace missing data; backup is G3                                             |
| Wrong passphrase attempts                     | Authenticate before opening storage                                            | Durable snapshot unchanged on failed unlock                           | No claim of offline rate limiting                                                                       |
| Corrupt keyslots                              | Bounded strict versioned parser and AAD                                        | Malformed/unknown/tampered slot rejection                             | Corrupting all slots can destroy access                                                                 |
| Renderer compromise                           | Empty plugin capabilities; fixed IPC registry; restrictive CSP                 | Static registry/capability/CSP tests and shell runtime                | Renderer can see content intentionally presented during future unlocked workflows                       |
| Credential leakage through IPC/log/config/DB  | Nonserializable secret owners, redacted fields, OS-only credential persistence | Compile-fail isolation and synthetic canary scans                     | Compiler/OS memory copies cannot all be erased                                                          |
| Crash during slot update                      | Same-directory synced staging and atomic replacement                           | Failure injection before/after activation                             | Hardware power loss and filesystems that violate flush/rename semantics are outside process-crash proof |
| Stolen device without user credential context | Windows generic credential with Local persistence                              | Real Windows write/read/delete and persistence readback               | Not protection against an already authenticated or compromised OS session                               |
| Provider-secret leakage                       | Backend-only provider store; no provider networking                            | Real synthetic provider oracle, no IPC getter                         | Equal-user processes may access Windows generic credentials                                             |
| Format downgrade                              | Exact versions and crypto IDs; minimum/maximum KDF bounds                      | Parser and tamper tests                                               | An attacker with a complete old header can replay it; no external anti-rollback anchor                  |
| Lock races                                    | One synchronized owner for live vault and VMK                                  | Concurrent unlock, lock/operation ordering, failed unlock drops state | Rust/backend callers are trusted; this is not a hostile native plugin sandbox                           |

## Explicit residual risks

DVM cannot guarantee confidentiality when malware has equal/higher privilege
while the vault is OPEN, the OS is compromised, an attacker reads active process
memory, the user voluntarily exports/sends content or secrets, or the user loses
the passphrase AND all recovery material. No resistance to a fully compromised
host is claimed. Optional device quick-unlock trusts the current Windows user
context; it does not substitute an application password for OS authentication.

The OS credential store and header are separate durable resources. A crash between
device credential creation and header activation can leave an unreferenced OS
credential; ordinary error paths clean it up when pre-activation is confirmed.
Independent passphrase/recovery access is preserved. Abrupt header-crash tests
use an in-memory store; native integration tests verify their own credential
cleanup, not automatic reclamation after arbitrary process termination.

## Scope

G2 does not implement recovery presentation UI, backup/restore/migration, search,
AI/provider requests, media, plugins, mobile or sync. No new renderer command or
capability is needed for the trusted security mechanism. Production creation
returns recovery material only to a nonserializable trusted Rust caller. A future
UI must decide how to present it without transferring root recovery authority to
the renderer.
