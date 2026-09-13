/**
 * Public surface of the Digital Vault of Memories IPC contract.
 *
 * Everything here is generated from the Rust types in `crates/dvm-domain` by
 * `pnpm contracts:generate`, and `pnpm contracts:check` fails the build if the
 * generated file stops matching them (Blueprint v2 §40.2).
 *
 * This barrel is the only hand-written file in the package. It exists so that
 * consumers import a stable module specifier rather than a path that mentions
 * `generated`, and so that the generator only ever has to rewrite one file.
 */
export * from './generated/contract.ts';
