# Contributing

## The one rule that shapes everything else

Work happens **one gate at a time**, in the order fixed by [`Digital_Vault_of_Memories_Blueprint_v2.md`](Digital_Vault_of_Memories_Blueprint_v2.md) §36. G0 is closed. The current gate is **G1 — zero-loss vault storage**.

This is not process for its own sake. Blueprint v2 replaced an architecture that made guarantees it could not keep, and it did so by ordering the work so that correctness, security and recoverability are proven _before_ the features that depend on them. A change that implements part of G1 while G0 is open does not accelerate anything; it removes the evidence that G0 was ever true.

G1 authorizes native SQLCipher, SQLite access, XChaCha20-Poly1305, HKDF, SHA-256, OS randomness, zeroization and storage correctness/testing dependencies only. Argon2, keyring, AI/model providers, HNSW/search, FFmpeg/media, backup/archive and plugin frameworks remain prohibited.

`tests/security/src/dependency-scope.test.ts` enforces this mechanically. Adding a later-gate dependency fails the build with the gate name in the message.

## Precedence when documents disagree

```text
Blueprint v2 invariants
  > Blueprint v2 gate requirements / Gates.yaml
  > approved ADRs
  > existing implementation
```

If you find a genuine conflict, stop and write it down — an issue or a draft ADR — rather than silently picking an interpretation. Blueprint v2 §50 is explicit that a lower-level document losing to the Blueprint is a reconciliation task, not a judgement call for whoever noticed.

An ADR may refine a decision. It may not weaken an invariant without the Blueprint and the corresponding tests changing in the same commit.

## Setting up

See [`README.md`](README.md#prerequisites-windows). In short:

```powershell
corepack enable
pnpm install --frozen-lockfile
```

Toolchain versions are pinned in `.node-version`, the `packageManager` field, and `rust-toolchain.toml`. Do not float them. If a version needs to move, move it deliberately in its own change and record why.

## Before you push

```powershell
pnpm verify:g0
```

That runs every gate check in order and prints each command with its exact exit code. It is the same script CI runs, so a green run locally means a green run in CI for everything except the platform matrix.

If you only touched the renderer, the fast loop is:

```powershell
pnpm lint
pnpm typecheck
pnpm --filter @dvm/desktop run test
```

If you only touched Rust:

```powershell
pnpm rust:fmt:check
pnpm rust:clippy
pnpm rust:test
```

## Things that will fail review

**Weakening a check to make it pass.** Adding `// eslint-disable`, `#[allow(...)]`, `.skip()`, or loosening a CSP directive to get green is the failure mode the gates exist to prevent. A narrow exception is acceptable when it is justified inline and the justification is about the code, not about the deadline — see the `#[expect(clippy::needless_pass_by_value, reason = "...")]` in `apps/desktop/src-tauri/src/lib.rs` for the shape.

**Editing generated files.** `packages/contracts/src/generated/` is produced by `pnpm contracts:generate` from the Rust types. Change the Rust type, regenerate, commit both. The drift test will catch you otherwise, which is the point.

**Calling `invoke` from a component.** The renderer depends on the `FoundationPort` interface in `apps/desktop/src/ipc/`. Exactly one module — `tauri-adapter.ts` — imports `@tauri-apps/api`, and an architecture test asserts that stays true. Components take their port as a prop so the whole tree can be rendered in a test with no native process.

**Adding a Tauri permission because something is easier that way.** `capabilities/main-window.json` grants zero plugin permissions. Vault operations are typed commands that validate their input in Rust (Blueprint v2 §20.2). If you think you need a permission, you need an ADR first.

**Tests that assert nothing.** `assert!(true)` and its relatives are worse than no test: they make a coverage number go up while making the suite less trustworthy. Test the behaviour that would actually break.

## Writing tests

Rust unit tests live beside the code in `#[cfg(test)] mod tests`. Integration tests that cross crates go in the crate's `tests/` directory.

Renderer tests use Testing Library and a fake port from `@dvm/test-fixtures`. Assert on what a user or a screen reader would perceive — roles, labels, text — rather than on implementation details.

Repository-level assertions (capabilities, CSP, dependency scope, architecture, topology) go in `tests/security/`. They read the repository as data and deliberately do not import application code: an assertion you can satisfy by changing an export is not an assertion.

Clippy denies `unwrap`, `expect`, `panic`, `todo` and `unimplemented` in the trusted backend, because it must never terminate the process or fabricate a value on an error path. `clippy.toml` allows all of them in tests, where a failed assumption _should_ abort loudly.

## Commits

Conventional-commit prefixes (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`). Keep the subject imperative and under about 72 characters.

Blueprint v2 §53 requires documentation to change in the same commit as the behaviour it describes. That includes the README when a command changes, `SECURITY.md` when the boundary changes, and an ADR when a decision changes.

## Gate evidence

Closing a gate produces a record in `docs/release-evidence/`. Blueprint v2 §52 fixes what it must contain: the source commit, the platform and toolchain, every command executed with its exact exit code, test counts, known accepted risks, and a verdict of `PASS`, `FAIL` or `BLOCKED`.

Two rules about evidence are worth stating plainly, because both are easy to violate with good intentions:

- **Screenshots are not evidence** for storage, security or recovery correctness. They can supplement a command transcript; they cannot replace one.
- **A successful compile is not runtime proof.** Where a gate requires runtime behaviour, it requires a captured, mechanical observation of that behaviour — for G0, that is `pnpm runtime:evidence`.

Do not report `PASS` for a step you skipped. `pnpm verify:g0` reports skipped steps as skipped for exactly this reason.

## G1 acceptance

Run `pnpm verify:g1` before a candidate commit. Tests must use real SQLCipher,
DVB1 originals, restart equality, transactional failure injection and child-process
crashes at C1–C8. Returned errors alone are not crash evidence. The >2 GiB test is
mandatory locally and in the clean room. Never count a skipped gate as PASS.
No renderer permission expansion, production empty-keyslot vault creation, raw
key persistence or G2 features are authorized. Keep all direct dependencies exact.

The single final G1 commit protocol verifies a candidate SHA in a fresh short-path
checkout, then amends only its evidence document. Source changes invalidate that
clean-room result. Do not merge the G1 PR in the implementation transaction.
