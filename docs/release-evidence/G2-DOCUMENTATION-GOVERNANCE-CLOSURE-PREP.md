# G2 Documentation and Governance Closure Preparation

Documentation-only transaction preparing DVM-V2 / G2 for closure reconciliation.
It changes no executable behavior, advances no gate, and starts no G3 work. PR
number 2 remains open and unmerged and `main` is untouched.

## Start identity

| Fact                   | Value                                       |
| ---------------------- | ------------------------------------------- |
| Repository             | `ggligor1967/Digital_Vault_of_Memories`     |
| Branch                 | `feat/dvm-v2-g2-security-key-lifecycle`     |
| START HEAD             | `a21a6c39e7e1146098d64e0b3bfe780769aebd59`  |
| START tree             | `8cd1ebb49eee687392913865df1e407e28fc11aa`  |
| `origin/main`          | `7c7700cda069f781109453b20d0b318f383a595a`  |
| Pull request           | number 2, open, non-draft, unmerged         |
| Working tree and index | clean; no merge, rebase or sequencer active |

## Governance: ratification of the two-commit remediation

The credential-lookup remediation was published as **two** commits rather than
the single commit its transaction authorized. That deviation has been explicitly
ratified as a bounded governance exception. It is recorded here, in full, rather
than normalized away.

| Commit                                     | Role                                                                   |
| ------------------------------------------ | ---------------------------------------------------------------------- |
| `b8479166f13829f71f390615a8f405038868e8d6` | Credential lookup classification and invalid stored secret remediation |
| `a21a6c39e7e1146098d64e0b3bfe780769aebd59` | Append-only follow-up; ratified bounded governance exception           |

**Reason for the exception.** `b847916` was pushed and then failed exact-head
Ubuntu G0 CI on a real, deterministic, cfg-dependent dead-code defect: the
`missing()` lookup predicate had call sites only inside `#[cfg(windows)]` tests,
so on `ubuntu-latest` it was dead code and `-D dead-code` rejected it. The local
and clean-room G2 gates run on Windows only and structurally could not observe
it. Because `b847916` was already published, it could not be amended, reset or
force-pushed, so the correction was necessarily a second, append-only commit.

**Scope of the ratification.** It applies only to the already-existing second
commit. It does not authorize force push, rewrite or amendment of published
history, additional implementation scope, merge, or G3 work.

**Standing requirement.** The two-commit remediation history must remain
explicitly recorded in G2 closure evidence rather than being normalized or
hidden. This section, together with the `Follow-up commit: cross-platform dead
code` section of `G2-HOLD-REMEDIATION-3.md`, is that record, and it carries
forward into the closure reconciliation unit.

No separate commit was created for this ratification; it is recorded inside this
documentation transaction, as directed.

## Documentation drift reconciled

Every change below is a comment or a test label. The G2 implementation left a
set of module and field comments describing a G1-era world that the branch had
already moved past — comments asserting that keyslots were reserved, always
empty, or absent from production, in a tree where they are the production
admission mechanism. A comment that confidently states the opposite of the code
is worse than no comment, because it is read as authority.

| Location                                      | Was                                                                                    | Now                                                                                           |
| --------------------------------------------- | -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `crates/dvm-storage/src/lib.rs`               | "G1 native encrypted storage. No renderer commands or production keyslots."            | "Native encrypted storage, keyslot lifecycle and OS credentials. No renderer commands."       |
| `crates/dvm-crypto/src/lib.rs`                | "G1 secret types and authenticated streaming storage primitives."                      | "Secret types, authenticated streaming storage primitives and keyslot wrapping."              |
| `crates/dvm-storage/src/header.rs`            | "…; no key wrapping at G1."                                                            | "…; validates slots, wraps no keys."                                                          |
| `crates/dvm-domain/src/storage.rs`            | "Trusted G1 storage contracts."                                                        | "Trusted storage contracts."                                                                  |
| `crates/dvm-domain/src/storage.rs`            | `keyslot_format_version`: "Future G2 container format, not a wrapping implementation." | "Keyslot envelope format version, not a wrapping implementation."                             |
| `crates/dvm-domain/src/storage.rs`            | `keyslots`: "Reserved, always empty at the G1 internal test boundary."                 | "Authenticated keyslot envelopes; empty only at the internal test boundary."                  |
| `crates/dvm-domain/src/lib.rs`                | "Trusted G1 storage contracts."                                                        | "Trusted storage contracts."                                                                  |
| `tests/security/src/dependency-scope.test.ts` | "G1 permits its explicitly selected native storage and crypto dependencies."           | "Each open gate permits only its explicitly selected native storage and crypto dependencies." |
| `tests/security/src/dependency-scope.test.ts` | "…even though G1 is current."                                                          | "…even though G1 is open."                                                                    |
| `tests/security/src/dependency-scope.test.ts` | `describe('G1 storage boundary')`                                                      | `describe('native storage boundary')`                                                         |
| `tests/security/src/dependency-scope.test.ts` | `it('keeps G1 out of renderer commands …')`                                            | `it('keeps vault operations and key material out of the renderer …')`                         |

### What was deliberately left alone

A sweep of every remaining `G1` reference in a doc comment found them to be
historical or scoping statements that are still factually correct, and they were
not touched: "from G1 onwards" in the application, domain and desktop crate
docs; the `injected_key_header` and trusted-fixture boundaries in `header.rs`,
which really are the G1-era compatibility surface; the G1 canonical import and
sink contracts referenced from `security.rs`; the G1 test module header; and
"G1 implements no repair operation" in `vault.rs`, which remains true at G2.
Rewriting accurate history would be churn, not reconciliation.

The `shell: true` observation in `scripts/verify-g2.mjs` is also untouched. It is
not documentation, and changing the gate runner would be an executable change
this transaction forbids. Its thread records that no untrusted input reaches the
shell, so the security premise does not apply.

## No executable behavior change

- No Rust statement, expression, signature, type or attribute changed. Every
  edit is a `//!` or `///` line.
- No assertion changed in any test. The two TypeScript edits inside test bodies
  are the `describe` and `it` title strings; every `expect` in those blocks is
  byte-identical.
- Verified against the two security tests that read the edited files:
  `g2-boundary.test.ts` asserts on `#[allow(unsafe_code)]\nmod sodium;` and on
  the `parse()` body and `header.keyslots.is_empty()`; `dependency-scope.test.ts`
  asserts on `#[cfg(test)] mod tests;`. None of them reads a doc comment, so no
  assertion depended on the text that changed.
- No dependency, lockfile, workflow, crypto, keyslot-format, AAD, DVB1,
  SQLCipher, Tauri-permission or CSP change.

## Bounded verification

Recorded in the transaction report; every command exited 0.

## Threads

The two documentation threads raised by the fresh Copilot review at
`a21a6c39e7` are addressed by this transaction, as is the stale `describe`
label thread. The `shell: true` thread remains open by design, with its premise
answered.

## Governance

PR number 2 open and unmerged; `main` unchanged at
`7c7700cda069f781109453b20d0b318f383a595a`; exactly one normal fast-forward
commit published; no merge, auto-merge, force push, tag, release or deployment;
G3 not started.
