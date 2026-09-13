# Digital Vault of Memories

A local-first desktop application for importing, preserving, organising, searching and exporting personal digital memories — photographs, videos, audio, documents and text — with the original bytes treated as more important than anything derived from them.

**Status: gate G0 — repository foundation. This is not yet a usable product.**

The application currently starts, shows the version of its renderer and of its trusted Rust backend, and confirms that the two agree on the IPC contract. There is no vault, no encryption, no storage, no search and no AI. Those arrive gate by gate, in the order fixed by [`Digital_Vault_of_Memories_Blueprint_v2.md`](Digital_Vault_of_Memories_Blueprint_v2.md) §36, and none of them may be started before the gate they belong to is authorised.

| Gate   | Scope                                                                                     | State       |
| ------ | ----------------------------------------------------------------------------------------- | ----------- |
| **G0** | Repository foundation: workspace, lockfiles, Tauri 2 shell, typed IPC, error envelope, CI | **current** |
| G1     | Zero-loss vault storage                                                                   | not started |
| G2     | Security and key lifecycle                                                                | not started |
| G3     | Recovery, backup, migration                                                               | not started |
| G4     | Deterministic search                                                                      | not started |
| G5     | AI provider layer                                                                         | not started |
| G6     | Product hardening / release candidate                                                     | not started |

## Why the architecture looks like this

The renderer is untrusted. It is a React application with no filesystem access, no shell access, no database connection and no credentials — the Tauri capability for its window grants it zero plugin permissions. Everything that touches the machine happens in Rust, behind typed commands whose request and response shapes are generated from the Rust types so the two sides cannot drift.

That boundary is not decoration. Blueprint v2 exists because the previous architecture made guarantees it could not keep, and the invariants that prevent a repeat (INV-011 through INV-015) are all statements about where authority lives. Establishing and testing the boundary before any feature exists is the entire purpose of G0.

See [`docs/adr/ADR-0001-tauri-rust-react-trust-boundary.md`](docs/adr/ADR-0001-tauri-rust-react-trust-boundary.md) for the decision and its consequences.

## Prerequisites (Windows)

The primary target is Windows, and the commands below were verified on Windows 11 with PowerShell.

| Tool                      | Version                                                         | How it is pinned                                                              |
| ------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Node.js                   | 22.22.2                                                         | [`.node-version`](.node-version), `engines` in [`package.json`](package.json) |
| pnpm                      | 10.27.0                                                         | `packageManager` in [`package.json`](package.json)                            |
| Rust                      | 1.94.1 (`x86_64-pc-windows-msvc`)                               | [`rust-toolchain.toml`](rust-toolchain.toml)                                  |
| Visual Studio Build Tools | 2022 or newer, with the _Desktop development with C++_ workload | —                                                                             |
| WebView2 Runtime          | any current version (preinstalled on Windows 11)                | —                                                                             |

Install Rust through [rustup](https://rustup.rs/); it reads `rust-toolchain.toml` and installs the pinned toolchain, `rustfmt` and `clippy` automatically on first use.

Enable pnpm through Corepack, which honours the pinned `packageManager` version:

```powershell
corepack enable
```

### Clone into a short path

Keep the clone within roughly 100 characters of the drive root — `C:\src\digital-vault-of-memories` is fine, a path nested under several long directories is not.

This is a Node limitation rather than a project one, and it fails in a way that does not name the real cause. pnpm's virtual store adds about 100 characters of its own to every dependency path, and Node's ESM resolver cannot read a `package.json` beyond the 260-character `MAX_PATH` limit even when `LongPathsEnabled` is set in the registry — while `fs.readFileSync` on the very same file succeeds. The visible symptom is a startup error from a dependency that is present and intact:

```text
ERR_PACKAGE_IMPORT_NOT_DEFINED: Package import specifier "#module-evaluator" is not defined
```

If you see that, measure your clone path before investigating anything else.

## Install

```powershell
git clone <repository-url> digital-vault-of-memories
cd digital-vault-of-memories
pnpm install --frozen-lockfile
```

`--frozen-lockfile` is not optional in CI and should not be skipped locally: it is what makes a clone reproduce the same dependency graph. If it fails, the lockfile and the manifests disagree and that is a defect, not an inconvenience.

## Everyday commands

All commands run from the repository root.

```powershell
pnpm format            # rewrite formatting with Prettier
pnpm format:check      # verify formatting without writing
pnpm lint              # ESLint across every workspace package
pnpm typecheck         # TypeScript, every workspace package
pnpm test              # unit tests: renderer + repository security assertions
pnpm build             # production renderer bundle into apps/desktop/dist
```

Rust:

```powershell
pnpm rust:fmt:check    # cargo fmt --all -- --check
pnpm rust:clippy       # cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
pnpm rust:test         # cargo test --workspace --locked
pnpm rust:metadata     # cargo metadata --locked
```

## Running the application

```powershell
pnpm dev
```

This starts the Vite dev server on `http://localhost:5173` and launches the Tauri shell against it. The port is fixed: it appears in `tauri.conf.json` as `build.devUrl` and in the development Content-Security-Policy, and a test fails if the three ever disagree.

To compile the release binary without producing an installer:

```powershell
pnpm tauri:build:smoke
```

## The IPC contract

`packages/contracts/src/generated/contract.ts` is generated from the Rust types in `crates/dvm-domain` and must never be edited by hand. After changing a contract type:

```powershell
pnpm contracts:generate   # rewrite the TypeScript mirror
pnpm contracts:check      # fail if the committed file no longer matches Rust
```

`pnpm contracts:check` also runs as part of `pnpm rust:test`, so a forgotten regeneration fails the build rather than reaching a reviewer.

## Verifying gate G0

One command runs every gate check in order and prints each command with its exact exit code:

```powershell
pnpm verify:g0
```

It covers the frozen install, both lockfiles, formatting, linting, typechecking, the renderer tests, `cargo fmt`, Clippy with warnings denied, the Rust tests, the security and scope assertions, the production bundle, the Tauri release compile, and the runtime evidence capture.

Two flags exist for environments that cannot do everything:

```powershell
pnpm verify:g0 --no-runtime        # no interactive desktop session (CI)
pnpm verify:g0 --no-tauri-build    # skip the release compile
```

Skipped steps are reported as skipped and are explicitly _not_ counted as passing.

### Runtime evidence

```powershell
pnpm runtime:evidence
```

This starts the real application, waits for the renderer to call `foundation_status` over the real Tauri transport, and captures the sanitised structured event the backend emits when it serves that call:

```json
{ "event": "foundation_status_served", "contract_version": "1.0.0", "status": "ok" }
```

It then verifies the process was alive when the event was served, shuts it down, and checks the captured output for crash residue. Artefacts land in the gitignored `.dvm-local/g0-runtime-evidence/` directory. A screenshot is not accepted as a substitute — compiling successfully is not evidence that the boundary works.

## Repository layout

```text
apps/desktop/            Tauri 2 shell (src-tauri/) and React renderer (src/)
crates/dvm-domain/       Contracts: error envelope, foundation status, TS generator
crates/dvm-application/  Use cases behind typed ports
crates/dvm-observability/Sanitised structured diagnostics
crates/dvm-{crypto,storage,search,ai,media,backup}/
                         Reserved workspace members; no implementation before their gate
packages/contracts/      Generated TypeScript mirror of the Rust contract
packages/test-fixtures/  Deterministic fixtures and fake ports
tests/security/          Capability, CSP, dependency-scope and architecture assertions
tests/{integration,crash,e2e,performance}/
                         Reserved; populated from G1 onwards
docs/adr/                Architecture decision records
docs/release-evidence/   Per-gate evidence records
scripts/                 Verification and evidence tooling
```

## Documentation

- [`Digital_Vault_of_Memories_Blueprint_v2.md`](Digital_Vault_of_Memories_Blueprint_v2.md) — the normative specification. It outranks every other document here.
- [`Digital_Vault_of_Memories_Blueprint_v2_Gates.yaml`](Digital_Vault_of_Memories_Blueprint_v2_Gates.yaml) — machine-readable invariants and gate requirements.
- [`SECURITY.md`](SECURITY.md) — the security model and how to report a vulnerability.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to work within the gate discipline.
- [`docs/release-evidence/G0-REPOSITORY-FOUNDATION.md`](docs/release-evidence/G0-REPOSITORY-FOUNDATION.md) — the G0 evidence record.

## Licence

Not yet chosen. See [`SECURITY.md`](SECURITY.md).
