# Security

## Current state — read this first

Digital Vault of Memories has closed G0 and is implementing **G1: zero-loss vault storage** through trusted Rust APIs and test-key injection. The renderer still exposes only foundation status.

G1 implements encrypted storage primitives: SQLCipher, a random VMK type,
HKDF-separated storage keys and authenticated DVB1 streaming. Acceptance status
is recorded in G1 evidence; implementation alone is not verification. G2
passphrase, recovery and device-key lifecycle is NOT implemented. There is no
production vault creation/unlock UX and no persisted raw key. Do not use an
injected-key test vault for irreplaceable data.

## What G0 does establish

The boundary. Blueprint v2 makes five invariants about where authority lives, and all five are decided by the structure of the code rather than by later feature work:

| Invariant | Statement                                                  | How G0 holds it                                                                          |
| --------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| INV-011   | The renderer never receives vault keys or provider secrets | G1 keys stay in Rust; IPC still carries only foundation versions and health              |
| INV-012   | The renderer has no arbitrary shell execution              | The window's capability grants no plugin permissions; no shell plugin is a dependency    |
| INV-013   | The renderer has no arbitrary host filesystem access       | As above; no filesystem plugin is a dependency, and the renderer may not import `node:*` |
| INV-014   | Remote egress is explicit and scoped                       | No network dependency exists; the production CSP permits no remote origin                |
| INV-015   | Locked vault content is unreachable through IPC            | G1 storage has no IPC surface; the command surface remains foundation status             |

These are enforced mechanically, not by review:

- `tests/security/src/capabilities.test.ts` reads every capability file and fails on any filesystem, shell, process or HTTP permission, on any wildcard, and on any legacy Tauri 1 allowlist pattern.
- `tests/security/src/csp.test.ts` fails if the production policy gains `unsafe-eval`, an inline script source, a remote origin or a CDN — and separately fails if the development policy adds any source the repository has not recorded a reason for.
- `tests/security/src/dependency-scope.test.ts` reads every `package.json` and `Cargo.toml` and fails if a dependency belonging to a later gate appears, including any AI or model-provider package.
- `tests/security/src/architecture.test.ts` fails if any renderer module other than the single IPC adapter imports Tauri, if any renderer module imports a Node built-in, or if a React component calls `invoke` directly.

They run on `pnpm test`, on `pnpm verify:g0`, and in CI on Windows.

## The trust boundary

```text
React renderer  ── untrusted ──►  typed Tauri command  ──►  Rust  ── trusted ──►  OS
```

The renderer owns presentation and nothing else. It has no database connection, no file handle, no credential and no network client. Anything it needs from the machine, it asks for by name through a typed command that validates its input in Rust.

Concretely, at G0:

- `apps/desktop/src-tauri/capabilities/main-window.json` declares `"permissions": []`. The window is granted no Tauri plugin capability whatsoever. Application-defined commands remain reachable, which is exactly the intended surface.
- `withGlobalTauri` is `false`, so no ambient `window.__TAURI__` object exists.
- `freezePrototype` is `true`.
- The asset protocol is disabled with an empty scope.

## Content Security Policy

Production (`app.security.csp`):

```text
default-src 'self'; script-src 'self'; style-src 'self';
img-src 'self' asset: data: blob:; font-src 'self';
media-src 'self' asset: blob:;
connect-src 'self' ipc: http://ipc.localhost;
worker-src 'self'; manifest-src 'self';
object-src 'none'; base-uri 'none'; frame-src 'none';
frame-ancestors 'none'; form-action 'none'
```

`http://ipc.localhost` is Tauri's loopback IPC origin on Windows, not a network destination. Every asset is bundled locally, so no CDN or font host appears anywhere.

Development (`app.security.devCsp`) has the following five source additions across four directives, each recorded in `tests/security/src/csp.test.ts`; unrecorded additions fail the test:

| Directive     | Development addition    | Why                                                                                                                                                                      |
| ------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `style-src`   | `'unsafe-inline'`       | Vite injects styles as inline `<style>` elements during hot module replacement. The production bundle emits a static stylesheet, so production keeps `style-src 'self'`. |
| `connect-src` | `ws://localhost:5173`   | The Vite HMR websocket. There is no dev server in production.                                                                                                            |
| `connect-src` | `http://localhost:5173` | Vite module and asset requests during development.                                                                                                                       |
| `font-src`    | `data:`                 | Vite may inline fonts as data URLs before the production asset pipeline runs.                                                                                            |
| `worker-src`  | `blob:`                 | Vite dependency pre-bundling can create blob workers in development.                                                                                                     |

Neither policy permits `'unsafe-eval'`, and neither permits an inline script source. A separate test asserts that the development policy never _removes_ a production restriction, so "it only works in dev" can never be resolved by loosening production.

## The error envelope

Failures cross the IPC boundary as the canonical envelope of Blueprint v2 §23.1:

```rust
AppError { code, message_key, retryable, correlation_id, safe_details? }
```

There is deliberately no field that can carry a stack trace, a source-error chain, an absolute path or a secret. `message_key` is a localisation key rather than prose, so the backend never embeds interpolated internal data in a user-visible string. `safe_details` passes through an allow-list filter that keeps only ASCII letters, digits and a small punctuation set, which removes structural separators but does not redact private words. G1 errors therefore use code-only constructors and never populate details from source paths, filenames or keys. Anything the backend needs to keep for diagnosis stays local and is correlated through `correlation_id`.

The renderer normalises any rejection that is _not_ a well-formed envelope — a transport failure, an unregistered command, an unparseable payload — to `INTERNAL` and carries no detail across, because it has no way to know that detail is safe.

## Diagnostics

`crates/dvm-observability` emits single-line JSON events with a fixed event name and a small set of string fields, each passed through the same allow-list filter. There is no free-form payload. G0 emits exactly two events: `foundation_status_served` and `desktop_shell_start_failed`.

Diagnostics go to standard output, and additionally to a file when the `DVM_G0_DIAGNOSTICS_FILE` environment variable names one. That file sink exists because a Windows release build runs under the `windows` subsystem with no attached console, so the runtime-evidence procedure needs a reliable capture channel. Nothing writes anywhere the caller did not name.

## Dependency and licence scanning

Blueprint v2 §30 sets supply-chain policy, and `Gates.yaml` assigns the mandatory `dependency_scans`, `license_scan` and `sbom` requirements to **gate G6**, not to G0. G0 therefore does not introduce a scanning stack, and no scan result is a G0 blocker.

What G0 does instead is keep the attack surface small enough to reason about: exact pinned versions everywhere, both lockfiles committed, no dependency lifecycle scripts enabled (`onlyBuiltDependencies: []`), and a test that fails if a later-gate dependency appears early.

## Reporting a vulnerability

The project has no published release and no users, so there is no coordinated-disclosure process yet. Until one exists, raise security concerns the same way as any other defect, through the repository's issue tracker, and say clearly in the title that the issue is security-related.

When the project reaches gate G6 this section is replaced by a real disclosure policy with a contact address and response commitments, as Blueprint v2 §29 requires before any release.

## Licence

No licence has been chosen. Until one is, the work is under exclusive copyright of its contributors and grants no redistribution rights. Choosing a licence is a prerequisite for the first release, not for G0.

## G1 data handling

Original names and source hints are written solely to encrypted metadata. Blob
and staging names are random identifiers. The typed storage_failure diagnostic
emits only an error code, ignoring even safe_details. G0's character sanitizer
is not treated as a content-redaction mechanism. Private-path regression tests
exercise the real failing import path and serialized diagnostic output.

DVB1 consumers receive provisional chunks through a transactional sink. Whole
original success requires authenticated header/frames, declared length, EOF and
stored hash equality. Failed reads abort provisional output. No normal import
creates a plaintext staging copy. Originals are never rewritten by jobs.

Process-crash tests exist only in cfg(test); no release environment variable
triggers process termination. Reconciliation quarantines ambiguous data rather
than deleting it. Corrupt/missing originals prevent normal writes and mark items
CORRUPTED. These are process-restart tests, not hardware power-failure certification.
