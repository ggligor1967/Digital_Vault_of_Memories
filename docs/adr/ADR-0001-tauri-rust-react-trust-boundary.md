# ADR-0001 — Tauri 2 + Rust trusted backend with a React renderer

- **Status:** Accepted
- **Date:** 2026-09-13
- **Gate:** G0 — Repository Foundation
- **Normative source:** `Digital_Vault_of_Memories_Blueprint_v2.md` §6, §20, §23, §40; `Gates.yaml` INV-011 – INV-015
- **Supersedes:** the Blueprint v1 renderer-centric architecture

## Context

Digital Vault of Memories keeps irreplaceable personal data — photographs, video, audio, documents — on the user's own machine, encrypted at rest, and promises that an accepted import is recoverable byte for byte. Blueprint v2 exists because the previous implementation could not keep that promise: it held the database in `sql.js` and `localStorage`, hashed whole files into an `ArrayBuffer`, queued browser `File` objects in JSON, used a constant passphrase, and gave the renderer broad Tauri filesystem and shell permissions along with provider credentials.

Each of those is a different bug, but they share one cause. **Authority lived in the renderer.** Once the untrusted layer can open files, run processes and hold keys, no amount of later care re-establishes the guarantee, because the guarantee was never structural.

Blueprint v2 therefore states five invariants that are all statements about where authority lives:

- **INV-011** — the renderer never receives the Vault Master Key, the raw database key, the blob root key or a provider secret;
- **INV-012** — the renderer has no arbitrary shell execution;
- **INV-013** — the renderer has no arbitrary host filesystem access;
- **INV-014** — every remote request maps to a visible, approved egress scope;
- **INV-015** — while a vault is locked, its content is not queryable through IPC.

Gate G0's job is to make those invariants true and _testable_ before any feature exists, so that later gates extend a proven boundary instead of negotiating with one.

The decision to be recorded is not "which UI framework". It is: **where is the line between trusted and untrusted code, what may cross it, and what makes that enforceable rather than aspirational?**

## Decision

### The trusted native boundary is Rust, reached only through typed Tauri commands

```text
┌──────────────────────────────────────────────┐
│ React + TypeScript + Vite   — UNTRUSTED      │
│ views, state, accessibility, sanitised input │
│ no SQL · no crypto · no credentials · no fs  │
└───────────────────┬──────────────────────────┘
                    │ typed IPC, generated from Rust
┌───────────────────▼──────────────────────────┐
│ Tauri 2 shell (dvm-desktop) — composition    │
│ registers commands, maps failures to AppError│
└───────────────────┬──────────────────────────┘
┌───────────────────▼──────────────────────────┐
│ dvm-application  — use cases                 │
├──────────────────────────────────────────────┤
│ dvm-domain       — contracts, invariants     │
├──────────────────────────────────────────────┤
│ infrastructure   — G1+: storage, crypto,     │
│                    search, AI, media, backup │
└──────────────────────────────────────────────┘
```

Dependencies point inward (Blueprint v2 §6.2). The shell depends on the application layer; the application layer depends on the domain; infrastructure implements domain ports. Nothing below the shell depends on Tauri, which is what allows the application layer to be exercised without a desktop process.

### The renderer's window is granted zero plugin permissions

`apps/desktop/src-tauri/capabilities/main-window.json` declares `"permissions": []`.

This is stricter than the `core:default` set Tauri's own examples show. It is possible because Tauri 2 allows commands the application registers through `invoke_handler` by default; capabilities gate _plugin_ commands. Since the renderer needs nothing but the application's own typed commands, the correct minimal set is empty — and an empty set is a much easier thing to defend in review than a list whose members someone has to keep justifying.

Supporting configuration: `withGlobalTauri: false` (no ambient `window.__TAURI__`), `freezePrototype: true`, and the asset protocol disabled with an empty scope.

### Exactly one renderer module may import Tauri

`apps/desktop/src/ipc/tauri-adapter.ts` is the only file permitted to import `@tauri-apps/api`. Components depend on the `FoundationPort` interface and receive an implementation as a prop from the composition root in `main.tsx`.

Two things follow, and both matter more than the tidiness:

1. The whole React tree can be rendered in a unit test against a fake port, with no native process. Blueprint v2 §6.2 requires adapters to be replaceable in tests; this is what makes that real for the renderer.
2. "The renderer does not depend on Tauri" becomes a checkable property. `tests/security/src/architecture.test.ts` parses the imports of every renderer module and fails if a second one appears.

### The IPC contract is generated from the Rust types, not written twice

Blueprint v2 §40.2 requires that Rust and TypeScript DTOs be generated or validated from a shared schema. `packages/contracts/src/generated/contract.ts` is emitted by `pnpm contracts:generate`, and a Rust test fails if the committed file stops matching the Rust types.

The generator does not restate the types. It observes them: field names come from the keys Serde actually emits, optionality from diffing a fully-populated value against an empty one, field types are declared once and then verified against the JSON kind Serde produced, and union members come from `ErrorCode::ALL` and `FoundationHealth::ALL`, which an exhaustive `match` and a uniqueness test hold to the enums.

### Failures cross as the canonical error envelope

```rust
AppError { code, message_key, retryable, correlation_id, safe_details? }
```

Per Blueprint v2 §23.1, with the full §23.2 error-class set declared up front plus `INTERNAL`. There is no field that can carry a stack trace, a source-error chain, an absolute path or a secret. `message_key` is a localisation key rather than prose, so the trusted backend never chooses presentation language and never interpolates internal data into a user-visible string. `safe_details` passes through an allow-list filter that keeps only ASCII letters, digits and light punctuation, destroying paths, URLs and quoted credentials as a class rather than trying to recognise them.

The renderer normalises any rejection that is not a well-formed envelope to `INTERNAL` and carries no detail across, because it cannot know that detail is safe.

## Consequences

### Accepted

- **Every host capability costs a round trip and a typed command.** Reading a file the user picked will require a Rust command with validated input, not a filesystem call from a component. This is the cost of the boundary and it is the point of the boundary.
- **Adding a command means touching three places** — a Rust command, a port method, an adapter method — plus regenerating the contract. The friction is deliberate: it makes "the renderer can now do X" a visible change.
- **Rust compile times dominate the inner loop.** The renderer iterates in milliseconds through Vite; the shell does not.
- **Windows-first means the Windows quirks are ours.** One already surfaced: Cargo's unit-test executables receive no application manifest, so the Common Controls v6 entry points Tauri imports resolve against the v5 library in `System32` and the test binary dies at load with `STATUS_ENTRYPOINT_NOT_FOUND`. `build.rs` declares the dependency for every linked target to fix it.

### Gained

- The five authority invariants are structural, and four automated suites fail the build if they erode.
- The application layer is testable without a window, and the renderer is testable without a process.
- The Rust/TypeScript contract cannot drift silently.
- The production CSP can stay at `default-src 'self'` with no remote origin at all, because every asset is bundled locally and remote work happens in Rust.

### Deferred

Secret storage (G2), the egress policy that gives INV-014 something to enforce (G5), and the sandboxing model for plugins (G8, and out of MVP scope). G0 establishes where those will live, not what they do.

## Alternatives considered

### Electron with a Node main process

Rejected. Node in the trusted process makes the boundary porous by default: `nodeIntegration`, `contextIsolation` and preload scripts are opt-in hardening around an environment that starts with full filesystem and process access, and a single misconfiguration re-opens everything. Rust starts from no ambient authority, and Tauri 2's capability model makes each grant an explicit, reviewable, testable declaration. Bundle size and memory favour Tauri too, but that is not why.

### Tauri with a broad `core:default` capability

Rejected for G0. `core:default` includes path-resolution APIs the renderer has no use for, and it invites the habit of adding permissions when something is inconvenient. Starting empty means every future grant is a deliberate change with an ADR attached.

### `tauri-specta` for contract generation

Rejected for now, and revisited when it stabilises. It is the natural choice for a Tauri 2 project, but its only releases are `2.0.0-rc.*` pre-releases. Pinning a release candidate — and the `specta` derive stack behind it — into the foundation every later gate builds on would trade a real determinism guarantee for convenience, and it is a large framework in service of a single command. The repository-local generator is roughly 400 lines, has no dependency beyond `serde_json`, and gives a stronger property than most generators do: it derives the TypeScript from the _observed Serde behaviour_ of the real types rather than from a parallel derive.

### Hand-written TypeScript types mirroring the Rust types

Rejected outright. Blueprint v2 §40.2 forbids it, and it is precisely the arrangement that produces a renderer confidently reading a field the backend renamed three commits ago.

### A shared renderer for desktop and a future mobile client

Rejected, consistent with Blueprint v2 §32 and the future ADR-0011. Domain contracts are shared; presentation is not. Assuming otherwise was a v1 mistake.

## Security implications

| Concern                              | Treatment at G0                                                                                                                     | Enforced by                                                                    |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Renderer holds a secret (INV-011)    | No secret exists; the only payload is version strings and a health discriminant                                                     | `foundation.rs::status_carries_no_host_state`                                  |
| Renderer shell access (INV-012)      | No shell plugin; no permission granted                                                                                              | `capabilities.test.ts`, `dependency-scope.test.ts`                             |
| Renderer filesystem access (INV-013) | No filesystem plugin; no permission; `node:*` imports banned in the renderer                                                        | `capabilities.test.ts`, `architecture.test.ts`, ESLint `no-restricted-imports` |
| Unscoped remote egress (INV-014)     | No network dependency; production CSP permits no remote origin                                                                      | `csp.test.ts`, `dependency-scope.test.ts`                                      |
| Script injection                     | `script-src 'self'`, no `unsafe-eval`, no `unsafe-inline`, no CDN, all assets bundled                                               | `csp.test.ts`                                                                  |
| Development weakening production     | Dev-only CSP additions are enumerated with reasons; a test fails on any unlisted addition and on any removed production restriction | `csp.test.ts`                                                                  |
| Internal state leaking to the UI     | Envelope has no field for it; `safe_details` is allow-list filtered; non-envelope rejections normalise to `INTERNAL`                | `error.rs` tests, `parse.test.ts`, `App.test.tsx`                              |
| Diagnostics leaking paths or secrets | Fixed event names, allow-list-filtered string fields, no free-form payload                                                          | `dvm-observability` tests                                                      |
| Later-gate scope creep               | Dependency denylist keyed by gate                                                                                                   | `dependency-scope.test.ts`                                                     |

The residual risk worth naming: the sanitiser is a _structural_ defence. It destroys the separators that make a path or URL usable, but it is not a content classifier, so a Windows path reduces to its words with the separators gone. The primary control is that callers pass only values the trusted backend chose — which at G0 holds by construction, since the only fields ever emitted are compile-time constants. When G1 introduces values derived from user data, that control needs to be re-argued rather than assumed.

## References

- Blueprint v2 §4 (threat model), §6 (canonical architecture), §20 (Tauri security model), §23 (error model), §40 (frontend contract)
- `Gates.yaml` — INV-011 … INV-015, gate G0
- Tauri 2 capabilities: <https://tauri.app/security/capabilities/>
- Tauri 2 configuration reference: <https://v2.tauri.app/reference/config/>
