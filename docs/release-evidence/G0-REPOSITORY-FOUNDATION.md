# Gate evidence — DVM-V2 / G0 — REPOSITORY FOUNDATION

**Gate ID:** `G0` — `REPOSITORY_FOUNDATION` (`Gates.yaml`, mandatory)
**Goal:** a deterministic clean-clone foundation.
**Verdict:** `PASS`

---

## 1. Starting repository classification

**Classification:** `NEW_EMPTY_REPOSITORY`

Evidence recorded before any file was modified:

```text
$ git status --short
?? Digital_Vault_of_Memories_Blueprint_v2.md
?? Digital_Vault_of_Memories_Blueprint_v2_Gates.yaml

$ git branch --show-current
master

$ git rev-parse HEAD
fatal: ambiguous argument 'HEAD': unknown revision or path not in the working tree.

$ git remote -v
(no output — no remote configured)

$ git log --oneline
fatal: your current branch 'master' does not have any commits yet

$ find . -path ./.git -prune -o -type f -print | wc -l
2
```

The repository contained exactly two tracked-candidate files, both untracked, and no commits.

### Legacy v1 material

**None.** No Blueprint v1 implementation was present, so §4 of the execution prompt (`LEGACY_V1_REMOVAL`) does not apply and no file was removed under it.

### Unrelated work preserved

Both pre-existing files are the normative specification documents themselves. Neither was modified: their SHA-256 hashes below are unchanged from the pre-implementation state, and `.prettierignore` excludes them so no formatting pass can alter them.

---

## 2. Normative sources

Both documents were already present at the repository root and are included verbatim in the G0 commit, so the repository is self-contained with respect to the specification it was built from.

| File                                                | SHA-256                                                            |
| --------------------------------------------------- | ------------------------------------------------------------------ |
| `Digital_Vault_of_Memories_Blueprint_v2.md`         | `23e320ce6ce84c81fe79eb239ed64b897530135c6715f2f6202534c3a13695e9` |
| `Digital_Vault_of_Memories_Blueprint_v2_Gates.yaml` | `dc49be40b0d0ba93b6cb4ba06c65456ee89818a8e79261f831092bf6a3a9b59a` |

Recomputed after implementation with `sha256sum`; both match the pre-implementation values.

---

## 3. Source

| Field           | Value                                      |
| --------------- | ------------------------------------------ |
| Branch          | `feat/dvm-v2-g0-repository-foundation`     |
| `source_commit` | `cc4386011c098af8d5ca0df884d69f1bab22a279` |
| Date            | 2026-09-13                                 |
| Platform        | Windows 11 Home 10.0.26200                 |
| Architecture    | `x86_64-pc-windows-msvc`                   |
| Shell           | PowerShell / Git Bash                      |

> **Note on the final commit hash.** Per the single-commit protocol, the commit verified in the clean room is recorded here as `source_commit`. The final commit is that commit amended with this evidence file and nothing else, so it cannot contain its own hash. The final hash is reported in the transaction response.

---

## 4. Toolchain

Resolved from official sources at implementation time and then pinned. No `latest` specifier is persisted anywhere in the repository.

| Component         | Version                                          | Pinned in                                                  |
| ----------------- | ------------------------------------------------ | ---------------------------------------------------------- |
| Node.js           | 22.22.2                                          | `.node-version`, `engines.node`                            |
| pnpm              | 10.27.0                                          | `packageManager`                                           |
| Rust              | 1.94.1 (`e408947bf 2026-03-25`)                  | `rust-toolchain.toml`                                      |
| Cargo             | 1.94.1 (`29ea6fb6a 2026-03-24`)                  | `rust-toolchain.toml`                                      |
| rustfmt           | 1.8.0-stable                                     | `rust-toolchain.toml` components                           |
| Clippy            | 0.1.94                                           | `rust-toolchain.toml` components                           |
| Tauri (Rust)      | 2.11.5                                           | `Cargo.toml` `[workspace.dependencies]`, exact `=`         |
| `tauri-build`     | 2.6.3                                            | `Cargo.toml`, exact `=`                                    |
| Tauri CLI (npm)   | 2.11.4                                           | `package.json`                                             |
| `@tauri-apps/api` | 2.11.1                                           | `apps/desktop/package.json`                                |
| React / React DOM | 19.3.0                                           | `apps/desktop/package.json`                                |
| TypeScript        | 6.0.3                                            | `package.json`                                             |
| Vite              | 8.3.0                                            | `apps/desktop/package.json`                                |
| Vitest            | 5.0.0                                            | `apps/desktop/package.json`, `tests/security/package.json` |
| ESLint            | 10.10.0                                          | `package.json`                                             |
| Prettier          | 3.9.6                                            | `package.json`                                             |
| MSVC              | Visual Studio Build Tools 2026, MSVC 14.51.36231 | environment prerequisite                                   |
| WebView2 Runtime  | 152.0.4191.66                                    | environment prerequisite                                   |

### Why TypeScript is 6.0.3 and not 7.0.2

TypeScript 7.0.2 is the current `latest` tag. It was **not** selected. `typescript-eslint@8.70.0` — the current release, and the only maintained one — declares `"typescript": ">=4.8.4 <6.1.0"`. Choosing TypeScript 7 would mean either running the type-aware lint rules against an unsupported compiler or dropping type-aware linting entirely, and the second is a real loss: rules such as `no-floating-promises` and `no-unsafe-argument` are what make the IPC boundary's `unknown` handling checkable. 6.0.3 is the newest release inside the supported range. This is recorded as an accepted risk in §14 and should be revisited when `typescript-eslint` supports TypeScript 7.

---

## 5. Repository topology

The canonical topology of Blueprint v2 §7 is reconstructed by `git clone`. Directories with no G0 content carry a `.gitkeep` that names the gate which will populate them; none contains placeholder implementation.

```text
digital-vault-of-memories/
├── Digital_Vault_of_Memories_Blueprint_v2.md
├── Digital_Vault_of_Memories_Blueprint_v2_Gates.yaml
├── README.md  SECURITY.md  CONTRIBUTING.md
├── package.json  pnpm-workspace.yaml  pnpm-lock.yaml
├── Cargo.toml  Cargo.lock  rust-toolchain.toml  rustfmt.toml  clippy.toml
├── tsconfig.base.json  eslint.config.js  .prettierrc.json  .prettierignore
├── .gitattributes  .gitignore  .node-version
├── .github/workflows/g0-foundation.yml
├── apps/desktop/
│   ├── index.html            <- Vite project root; NOT under public/
│   ├── package.json  vite.config.ts  tsconfig.json  tsconfig.node.json
│   ├── vitest.setup.ts
│   ├── src/{app,features,components,ipc,styles}/
│   └── src-tauri/
│       ├── Cargo.toml  build.rs  tauri.conf.json
│       ├── capabilities/main-window.json
│       ├── icons/            <- 17 desktop icons from `tauri icon`
│       └── src/{lib.rs,main.rs}
├── crates/
│   ├── dvm-domain/           <- contracts + TypeScript generator  (implemented)
│   ├── dvm-application/      <- FoundationService                 (implemented)
│   ├── dvm-observability/    <- sanitised diagnostics             (implemented)
│   └── dvm-{crypto,storage,search,ai,media,backup}/  <- reserved, no implementation
├── packages/
│   ├── contracts/            <- generated TypeScript mirror
│   └── test-fixtures/        <- fakes and fixtures
├── migrations/               <- .gitkeep (G1/G3)
├── tests/
│   ├── security/             <- implemented: 125 assertions
│   └── {integration,crash,e2e,performance}/  <- .gitkeep (G1+)
├── docs/
│   ├── adr/ADR-0001-tauri-rust-react-trust-boundary.md
│   ├── release-evidence/G0-REPOSITORY-FOUNDATION.md
│   └── {architecture,threat-model}/  <- .gitkeep
└── scripts/
    ├── verify-g0.mjs  runtime-evidence.mjs  generate-source-icon.mjs
```

Six reserved crates each contain exactly one `lib.rs` holding a module doc comment and a single `AUTHORISED_FROM_GATE` constant. `tests/security/src/dependency-scope.test.ts` fails if any of them acquires a dependency or defines a function before its gate opens.

---

## 6. Dependency summary

| Ecosystem            | Direct                     | Locked total | Lockfile                    |
| -------------------- | -------------------------- | ------------ | --------------------------- |
| npm (pnpm workspace) | 25                         | 212          | `pnpm-lock.yaml`, committed |
| Cargo                | 5 third-party + 3 internal | 441          | `Cargo.lock`, committed     |

Direct Rust dependencies, all pinned with an exact `=` requirement in `[workspace.dependencies]`:

```toml
serde       = "=1.0.229"
serde_json  = "=1.0.151"
tauri       = "=2.11.5"
tauri-build = "=2.6.3"
uuid        = "=1.26.1"
```

Every npm dependency is pinned to an exact version; the only non-exact specifiers are `workspace:*` links between the repository's own packages. `tests/security/src/foundation.test.ts` fails on any floating specifier in either ecosystem.

### pnpm build-script policy

`pnpm-workspace.yaml` declares `onlyBuiltDependencies: []`.

pnpm 10 blocks dependency lifecycle scripts by default, and that protection is **not** relaxed repository-wide. No dependency in the G0 graph required a build script — `pnpm install` completed with no ignored-script warning — so the allowlist is empty. Adding a package to it in future requires naming the exact package and the reason. A test asserts the declaration is present and that no blanket override (`dangerouslyAllowAllBuilds`) has appeared.

### No later-gate dependency present

`tests/security/src/dependency-scope.test.ts` reads every `package.json` and `Cargo.toml` and fails if a dependency belonging to G1–G6 appears — SQLCipher, `rusqlite`, `sqlx`, Argon2, ChaCha20, keyring, HNSW, `tantivy`, OpenAI, Anthropic, Ollama, LangChain, ONNX Runtime, FFmpeg and others — and separately fails on `tauri-plugin-fs`, `tauri-plugin-shell`, `tauri-plugin-http` or their npm equivalents. The suite passes: no such dependency exists.

---

## 7. Commands executed with exit codes

All commands were run from the repository root on Windows 11 through `node scripts/verify-g0.mjs`, which is the same entry point the CI workflow calls.

### Reproducibility

| Command                                              | Exit |
| ---------------------------------------------------- | ---- |
| `pnpm install --frozen-lockfile`                     | `0`  |
| `git diff --exit-code -- pnpm-lock.yaml`             | `0`  |
| `cargo metadata --locked --format-version 1 --quiet` | `0`  |
| `git diff --exit-code -- Cargo.lock`                 | `0`  |

The two `git diff` steps exist to satisfy the explicit STOP condition that a frozen install must not mutate the lockfile: an exit code of `0` proves neither lockfile changed as a result of the preceding step.

### Frontend

| Command                               | Exit |
| ------------------------------------- | ---- |
| `pnpm run format:check`               | `0`  |
| `pnpm run lint`                       | `0`  |
| `pnpm run typecheck`                  | `0`  |
| `pnpm --filter @dvm/desktop run test` | `0`  |
| `pnpm run build`                      | `0`  |

### Rust

| Command                                                                         | Exit |
| ------------------------------------------------------------------------------- | ---- |
| `cargo fmt --all -- --check`                                                    | `0`  |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | `0`  |
| `cargo test --workspace --locked`                                               | `0`  |

### Security and scope

| Command                                      | Exit |
| -------------------------------------------- | ---- |
| `pnpm --filter @dvm/security-tests run test` | `0`  |

### Build

| Command                             | Exit |
| ----------------------------------- | ---- |
| `pnpm exec tauri build --no-bundle` | `0`  |

`--no-bundle` was validated against `pnpm exec tauri build --help` for the installed CLI (2.11.4) before use; it is a real flag of this version and skips only installer generation, not compilation.

### Runtime

| Command                             | Exit |
| ----------------------------------- | ---- |
| `node scripts/runtime-evidence.mjs` | `0`  |

### Aggregate

| Command                      | Exit                                    |
| ---------------------------- | --------------------------------------- |
| `node scripts/verify-g0.mjs` | `0` — 15 steps run, 0 skipped, 0 failed |

---

## 8. Test results

| Suite                                                                                           | Tests   | Result   |
| ----------------------------------------------------------------------------------------------- | ------- | -------- |
| Renderer (`@dvm/desktop`, Vitest + Testing Library, jsdom)                                      | 26      | pass     |
| Repository security and scope (`@dvm/security-tests`, Vitest, node)                             | 125     | pass     |
| Rust unit tests — `dvm-domain` 27, `dvm-observability` 10, `dvm-application` 6, `dvm-desktop` 5 | 48      | pass     |
| Rust integration test — `dvm-domain::contract_drift`                                            | 3       | pass     |
| **Total**                                                                                       | **202** | **pass** |

No test asserts a tautology. The Rust suite covers error-code completeness against Blueprint v2 §23.2, wire-format agreement between Serde and the hand-written `as_wire_str`, envelope field-set and optionality, sanitiser behaviour against Windows paths, UNC paths and URLs, foundation-status serialisation, contract-version compatibility, and the generated-contract drift check. The renderer suite covers loading, connected, incompatible-contract and error states, single-invocation-per-mount, non-envelope rejection handling, accessibility roles, and every runtime type guard against hostile shapes.

### Security and configuration assertions

All automated, all in `tests/security/`:

| Assertion                                                                          | Source                                                              |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| No filesystem capability in any capability file                                    | `capabilities.test.ts`                                              |
| No shell execute/spawn capability                                                  | `capabilities.test.ts`                                              |
| No process, HTTP, wildcard or legacy allowlist permission                          | `capabilities.test.ts`                                              |
| The G0 window grants **zero** plugin permissions                                   | `capabilities.test.ts`, and again in Rust in `src-tauri/src/lib.rs` |
| Every capability is window-scoped and local, never remote                          | `capabilities.test.ts`                                              |
| Capability identifiers and `tauri.conf.json` references agree in both directions   | `capabilities.test.ts`                                              |
| `withGlobalTauri: false`, `freezePrototype: true`, asset protocol disabled         | `capabilities.test.ts`                                              |
| Production CSP has no `'unsafe-eval'`                                              | `csp.test.ts`                                                       |
| Production CSP has no inline script source, no remote origin, no CDN, no AI domain | `csp.test.ts`                                                       |
| Every development-only CSP source is enumerated with a reason                      | `csp.test.ts`                                                       |
| The development CSP removes no production restriction                              | `csp.test.ts`                                                       |
| The dev-server port agrees across `vite.config.ts`, `devUrl` and the dev CSP       | `csp.test.ts`                                                       |
| No G1–G6 dependency present                                                        | `dependency-scope.test.ts`                                          |
| No AI or model-provider dependency present                                         | `dependency-scope.test.ts`                                          |
| Reserved crates have no dependencies and define no functions                       | `dependency-scope.test.ts`                                          |
| Exactly one renderer module imports Tauri                                          | `architecture.test.ts`                                              |
| No renderer module imports a Node built-in or an infrastructure module             | `architecture.test.ts`                                              |
| No component calls `invoke` directly                                               | `architecture.test.ts`                                              |
| No crate outside the shell depends on Tauri                                        | `architecture.test.ts`                                              |
| Canonical topology present; `index.html` at the Vite root, not under `public/`     | `foundation.test.ts`                                                |
| No `%PUBLIC_URL%` or other CRA template syntax                                     | `foundation.test.ts`                                                |
| Both lockfiles committed; no floating version in either ecosystem                  | `foundation.test.ts`                                                |
| Node, pnpm and Rust pinned to exact versions                                       | `foundation.test.ts`                                                |
| Every `pnpm` command shown in the README is a script that exists                   | `foundation.test.ts`                                                |
| Product version identical across all four manifests                                | `foundation.test.ts`, and in Rust in `src-tauri/src/lib.rs`         |

---

## 9. Security boundary

| Property                               | State                                                                                                      |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Broad filesystem grants                | **none** — `capabilities/main-window.json` declares `"permissions": []`                                    |
| Shell execute/spawn grants             | **none** — no shell plugin is a dependency in either ecosystem                                             |
| Renderer host authority                | **none** — `withGlobalTauri: false`; `node:*` imports banned by ESLint and by an architecture test         |
| Renderer secrets                       | **none** — no secret exists at G0; the only IPC payload is three version strings and a health discriminant |
| Production CSP `'unsafe-eval'`         | **absent**                                                                                                 |
| Asset protocol                         | disabled, empty scope                                                                                      |
| `dangerousDisableAssetCspModification` | not set                                                                                                    |

### Capability

```json
{
  "identifier": "main-window",
  "windows": ["main"],
  "local": true,
  "permissions": []
}
```

An empty permission set is stricter than the `core:default` baseline Tauri's documentation shows. It works because Tauri 2 allows commands the application registers through `invoke_handler` by default and gates only _plugin_ commands. This was not assumed — it was proven at runtime: the application served `foundation_status` with this capability in force (§10).

### Production CSP

```text
default-src 'self'; script-src 'self'; style-src 'self';
img-src 'self' asset: data: blob:; font-src 'self';
media-src 'self' asset: blob:;
connect-src 'self' ipc: http://ipc.localhost;
worker-src 'self'; manifest-src 'self';
object-src 'none'; base-uri 'none'; frame-src 'none';
frame-ancestors 'none'; form-action 'none'
```

`http://ipc.localhost` is Tauri's loopback IPC origin on Windows, not a network destination. Every asset is bundled locally: the production build emits one JS chunk and one extracted CSS file, so `style-src` needs no inline allowance.

### Development CSP delta

Five additions, each with a recorded reason, and no removals. A test fails on any sixth addition and on any lost production restriction.

| Directive     | Added in development    | Reason                                                                                                                    |
| ------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `style-src`   | `'unsafe-inline'`       | Vite injects `<style>` elements during HMR. Production emits a static stylesheet, so production keeps `style-src 'self'`. |
| `connect-src` | `ws://localhost:5173`   | Vite HMR websocket. No dev server exists in production.                                                                   |
| `connect-src` | `http://localhost:5173` | Vite module and asset requests during development.                                                                        |
| `font-src`    | `data:`                 | Vite may inline fonts as data URLs before the production asset pipeline runs.                                             |
| `worker-src`  | `blob:`                 | Vite dependency pre-bundling can create blob workers in development.                                                      |

Neither policy permits `'unsafe-eval'` or an inline script source.

---

## 10. Runtime evidence

Captured autonomously by `node scripts/runtime-evidence.mjs`. Compilation was **not** accepted as proof, and no screenshot forms part of this evidence.

**Launch method:** `tauri dev` — a debug build of the real shell, served by the real Vite dev server, communicating over the real Tauri IPC transport. The debug profile keeps a console attached on Windows, and the backend additionally appends each diagnostic event to the file named by `DVM_G0_DIAGNOSTICS_FILE`, so capture does not depend on console attachment.

**Procedure and observations:**

1. The Tauri CLI was spawned directly through Node so the captured process id is the real root of the tree.
2. Vite started on `http://127.0.0.1:5173`; the shell compiled and launched `target\debug\dvm-desktop.exe`.
3. The React renderer mounted and called `foundation_status` through `apps/desktop/src/ipc/tauri-adapter.ts`.
4. The trusted backend served the command and emitted the diagnostic event, captured **3 seconds** after launch:

   ```json
   { "event": "foundation_status_served", "contract_version": "1.0.0", "status": "ok" }
   ```

   Two identical events were captured. This is expected and not a defect: React `StrictMode` intentionally double-invokes effects in development. The renderer test `queries the backend exactly once per mount` asserts the single-call behaviour of the hook itself.

5. The process was confirmed alive at the moment the event was served.
6. The application window was asked to close (`taskkill /IM dvm-desktop.exe`, no `/F`); it ran its own shutdown path and exited within the grace period.
7. The supervising CLI then exited on request, without needing to be forced.
8. The captured output was scanned for `panicked at`, `STATUS_ACCESS_VIOLATION`, `STATUS_ENTRYPOINT_NOT_FOUND`, `STATUS_STACK_BUFFER_OVERRUN`, `fatal runtime error` and `Exception 0x`. **None found.**
9. No process with the application's image name remained.

**Machine-readable summary** (`.dvm-local/g0-runtime-evidence/summary.json`, gitignored):

```json
{
  "gate": "G0",
  "launch_method": "tauri dev (debug build, real Tauri IPC transport)",
  "process_alive_when_served": true,
  "seconds_to_first_event": 3,
  "foundation_status_event": {
    "event": "foundation_status_served",
    "contract_version": "1.0.0",
    "status": "ok"
  },
  "termination": "exited on request",
  "application_closed_on_request": true,
  "process_alive_after_termination": false,
  "application_running_after_termination": false,
  "crash_markers_found": []
}
```

Raw artefacts stay in the gitignored `.dvm-local/g0-runtime-evidence/` directory rather than being committed: the captured Cargo output contains absolute build paths, which have no place in a repository that treats path disclosure as a defect.

**What this proves:** the typed IPC boundary works end to end at runtime — renderer → Tauri transport → registered command → application service → domain contract → serialised response — with a capability granting zero plugin permissions.

---

## 11. Clean-room reproduction

Reproducibility was proven from a fresh clone of the exact source commit, not from the populated development tree.

| Field                            | Value                                                                                                                                                                                |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Verified source commit           | `cc4386011c098af8d5ca0df884d69f1bab22a279`                                                                                                                                           |
| Clone method                     | `git clone --branch feat/dvm-v2-g0-repository-foundation --single-branch file:///C:/Users/gglig/my_project/testcontainer/Digital_Vault_of_Memories C:/dvm-g0-cleanroom`              |
| Location                         | `C:\dvm-g0-cleanroom` — outside the primary working tree                                                                                                                             |
| Tracked files in the clone       | 114                                                                                                                                                                                  |
| `git status --short` after clone | empty                                                                                                                                                                                |
| Copied into the clone            | nothing: `node_modules`, `target` and `apps/desktop/dist` were all confirmed absent before the first command                                                                         |
| Shared with the host             | only the Cargo registry cache and the pnpm content store, which a clean clone would otherwise repopulate from the network. No build output, no `node_modules`, no compiled artefact. |
| Line endings                     | LF confirmed in the fresh checkout despite `core.autocrlf=true` on the host — `.gitattributes` `eol=lf` does its job                                                                 |
| Result                           | **PASS** — every command exited `0`                                                                                                                                                  |

### Commands and exit codes

| #   | Command                                                                         | Exit                                                                                                                |
| --- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| 1   | `pnpm install --frozen-lockfile`                                                | `0`                                                                                                                 |
| 2   | `git diff --exit-code -- pnpm-lock.yaml`                                        | `0`                                                                                                                 |
| 3   | `cargo metadata --locked --format-version 1 --quiet`                            | `0`                                                                                                                 |
| 4   | `git diff --exit-code -- Cargo.lock`                                            | `0`                                                                                                                 |
| 5   | `pnpm run format:check`                                                         | `0`                                                                                                                 |
| 6   | `pnpm run lint`                                                                 | `0`                                                                                                                 |
| 7   | `pnpm run typecheck`                                                            | `0`                                                                                                                 |
| 8   | `pnpm --filter @dvm/desktop run test`                                           | `0` (26 tests)                                                                                                      |
| 9   | `cargo fmt --all -- --check`                                                    | `0`                                                                                                                 |
| 10  | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | `0`                                                                                                                 |
| 11  | `cargo test --workspace --locked`                                               | `0` (51 tests)                                                                                                      |
| 12  | `pnpm --filter @dvm/security-tests run test`                                    | `0` (125 tests)                                                                                                     |
| 13  | `pnpm run build`                                                                | `0`                                                                                                                 |
| 14  | `node scripts/runtime-evidence.mjs --timeout 600`                               | `0`                                                                                                                 |
| 15  | `pnpm exec tauri build --no-bundle`                                             | `0` — `Finished release profile [optimized] in 5m 06s`, produced `target\release\dvm-desktop.exe` (3,132,928 bytes) |

Steps 1–13 ran as one invocation of `node scripts/verify-g0.mjs --no-tauri-build`. Steps 14 and 15 were run as separate commands from the same clone of the same commit, because the host had insufficient free disk to hold the debug and release artefact sets simultaneously: the clean room's `target/debug` was deleted after step 14 to make room for step 15. No source, configuration, lockfile or dependency changed between the passes — `git status --short` in the clone was empty before, between and after — and no build output was reused across them.

### Post-run integrity

After every command had run, the clone was re-checked:

```text
$ git rev-parse HEAD
cc4386011c098af8d5ca0df884d69f1bab22a279

$ git status --short
(empty)

$ git diff --exit-code -- pnpm-lock.yaml Cargo.lock
(exit 0 — neither lockfile was mutated by any build, test or install)
```

### Clean-room runtime evidence

The runtime procedure was executed in the clean room as well as in the development tree, and produced the same result from a tree that had never run the application before:

```json
{
  "gate": "G0",
  "launch_method": "tauri dev (debug build, real Tauri IPC transport)",
  "process_alive_when_served": true,
  "seconds_to_first_event": 18,
  "foundation_status_event": {
    "event": "foundation_status_served",
    "contract_version": "1.0.0",
    "status": "ok"
  },
  "termination": "exited on request",
  "application_closed_on_request": true,
  "process_alive_after_termination": false,
  "application_running_after_termination": false,
  "crash_markers_found": []
}
```

### Comparison with the primary tree

No material difference. Every step that ran in both produced exit code `0` and the same test counts (26 / 51 / 125). The clean room took longer only because it compiled from an empty `target`.

### A defect the clean room found, and what was done about it

The first clean-room attempt was made in this session's scratchpad, at a path 175 characters deep. It failed at step 8:

```text
ERR_PACKAGE_IMPORT_NOT_DEFINED: Package import specifier "#module-evaluator"
is not defined imported from ...\node_modules\.pnpm\vitest@5.0.0_...\vitest\dist\chunks\index.B89dZ0-N.js
```

The package was present and intact, and its `package.json` did define `#module-evaluator`. The cause was isolated with a minimal three-file reproduction — a package declaring an `imports` field, built once at a short path and once padded past 260 characters:

| Probe | `package.json` path length | `fs.readFileSync` | Node ESM `#specifier` resolution |
| ----- | -------------------------- | ----------------- | -------------------------------- |
| short | 179                        | succeeds          | resolves                         |
| deep  | 340                        | succeeds          | `ERR_PACKAGE_IMPORT_NOT_DEFINED` |

So Node 22's ESM resolver cannot read a `package.json` beyond `MAX_PATH` even though `LongPathsEnabled` is `0x1` in the registry and the JavaScript filesystem API reads the identical file without complaint. pnpm's virtual store adds roughly 100 characters to every dependency path, which is what pushed vitest's manifest to 277 characters in that location.

This is a Node limitation on Windows, not a repository defect, and the fix was to relocate the clean room to `C:\dvm-g0-cleanroom`. It is nevertheless a trap a contributor can fall into, and it fails without naming its cause, so the source commit was amended to document it under _Clone into a short path_ in `README.md` before the clean-room run recorded above. That amendment is why the verified source commit is `cc43860` and not the first candidate.

---

## 12. CI foundation

| Field              | Value                                                                                                                                                                          |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Provider           | GitHub Actions                                                                                                                                                                 |
| Workflow           | `.github/workflows/g0-foundation.yml`                                                                                                                                          |
| Provider choice    | Default per the execution prompt. The repository is new and had no CI configuration of any kind, so no established provider was displaced. No second CI system was introduced. |
| Windows            | First-class: `windows-latest` is the primary matrix entry and the only one that uploads an artefact.                                                                           |
| Portability signal | `ubuntu-latest` runs alongside with `fail-fast: false`. No platform is advertised as supported until its packaging and recovery gates pass.                                    |

**CI runs the same implementation as local development.** The workflow does not restate any gate check: after setting up the pinned toolchain it calls `node scripts/verify-g0.mjs --no-runtime`. There is one implementation of "is the foundation green?", so local and CI cannot drift into checking different things.

The workflow additionally verifies that the Node and Rust versions the runner actually installed match `.node-version` and `rust-toolchain.toml`, and fails if they do not.

**Local validation of the workflow:** parsed with a YAML parser; structure confirmed — 2 jobs (`verify`, `evidence`), 3 triggers, a 2-entry OS matrix, 10 steps in `verify`.

```text
REMOTE CI EXECUTION:
NOT EXECUTED — remote mutation not authorized.
```

No remote exists, nothing was pushed, and no independent remote CI evidence exists for this commit. The `runtime` step is reported by the script as `SKIPPED` in CI — a hosted runner has no interactive desktop session — and is explicitly **not** counted as passing there. Its evidence is §10 of this document.

---

## 13. Dependency and licence scans

```text
G0 STATUS: DEFERRED — not a G0 blocking requirement.
```

Blueprint v2 §30 sets supply-chain policy, and `Gates.yaml` assigns `dependency_scans`, `license_scan` and `sbom` to gate **G6** (`PRODUCT_HARDENING_RELEASE_CANDIDATE`). No scanning stack was introduced, in line with the instruction not to expand G0 to accommodate one.

- **Existing scans preserved:** not applicable — the repository was new and contained no scanning configuration. Nothing was removed.
- **Advisory result:** none produced.

What G0 does contribute towards the eventual scan is a small, fully pinned dependency graph (212 npm packages, 441 Cargo packages), both lockfiles committed, no dependency lifecycle scripts enabled, and an automated test that fails if a later-gate dependency appears early.

---

## 14. Known accepted risks

1. **TypeScript is one major version behind `latest`.** 6.0.3 rather than 7.0.2, because `typescript-eslint@8.70.0` supports `<6.1.0` and dropping type-aware linting would cost more than the newer compiler gains. Revisit when `typescript-eslint` supports TypeScript 7. No G0 requirement is affected.

2. **The diagnostics sanitiser is structural, not semantic.** It destroys the separators that make a path, URL or connection string usable, but it is not a content classifier: a Windows path reduces to its words with the separators removed. At G0 this is not exploitable — the only fields ever emitted are compile-time constants — but the control that makes it safe is _what callers pass_, not the filter. G1 introduces the first values derived from user data and must re-argue this rather than inherit it.

3. **Mobile crate types omitted.** `apps/desktop/src-tauri` declares `crate-type = ["rlib"]` instead of Tauri's scaffolded `["staticlib", "cdylib", "rlib"]`. The two omitted types exist only so the crate can be linked into an Android or iOS host, which is gate G7 and an explicit MVP non-goal. G7 restores them. Recorded because it is a deliberate deviation from the scaffolding default.

4. **Mobile icon assets omitted.** `pnpm tauri icon` also generated `icons/android/` and `icons/ios/`. Both were removed: they are G7 scope and would put ~100 mobile assets in a G0 commit. The 17 desktop icons the bundle references are committed, and `scripts/generate-source-icon.mjs` regenerates the source mark deterministically.

5. **Two `foundation_status` calls per launch in development.** React `StrictMode` double-invokes effects in development builds. This is intended React behaviour, not a defect, and does not occur in a production build.

6. **A workspace-wide manifest link argument on Windows.** `apps/desktop/src-tauri/build.rs` emits a `/MANIFESTDEPENDENCY` link argument declaring Common Controls v6 for every target it links, not only the application binary. Without it, Cargo's unit-test executables receive no manifest, the Common Controls v6 entry points Tauri imports resolve against the v5 library in `System32`, and the test binary dies at load with `STATUS_ENTRYPOINT_NOT_FOUND` (0xC0000139). `cargo:rustc-link-arg-tests` is not an alternative: it applies only to `[[test]]` targets, and this crate's tests live in the library. The linker merges the argument with the identical dependency in Tauri's own manifest for the shipped binary.

7. **The checkout path must stay short on Windows.** Node 22's ESM resolver cannot read a `package.json` beyond the 260-character `MAX_PATH` limit even when `LongPathsEnabled` is `0x1`, and pnpm's virtual store adds roughly 100 characters to every dependency path. A clone nested deeply enough fails at `pnpm test` with `ERR_PACKAGE_IMPORT_NOT_DEFINED`, naming a package that is present and correct. Proven with a minimal reproduction and documented in `README.md`; see §11 for the measurements. This is a property of the toolchain, not of the repository, and no repository change can fix it — but it will cost a contributor an afternoon if it is not written down.

8. **Low free disk space on the implementation machine.** The host had between 90 MB and 5.8 GB free throughout, on a 586 GB drive that is otherwise full. No gate result was affected — every command completed and its exit code is recorded — but the constraint shaped the procedure: the primary tree's `target/` was cleaned before the clean-room run, and the clean room's `target/debug` was deleted between its runtime-evidence step and its release-compile step because the two artefact sets did not fit at once (§11). Recorded because G1 introduces larger builds and this machine has no headroom for them as it stands.

---

## 15. Known blockers

**None.**

---

## 16. Scope check

No G1 or later functionality was implemented. Specifically absent: vault creation, vault encryption, SQLCipher, the DVB1 blob format, Argon2id keyslots, recovery keys, Windows Credential Manager integration, import, deduplication, durable jobs, startup reconciliation, FTS5, embeddings, vector search, any AI provider, backup, restore, DVBK1, media processing, plugins, mobile, sync and collaboration.

The reserved crates and `.gitkeep` placeholders preserve the canonical architecture without containing implementation, and a test enforces that.

---

## 17. Verdict

```text
G0.1  workspace + lockfiles              PASS
G0.2  Tauri 2 shell + React renderer     PASS
G0.3  typed IPC + error envelope         PASS
G0.4  CI foundation                      PASS

RUNTIME SUBGATE                          PASS
CLEAN-ROOM REPRODUCTION                  PASS

GLOBAL G0                                PASS
```

Next authorised unit: **DVM-V2 / G1 — ZERO-LOSS VAULT STORAGE**.
