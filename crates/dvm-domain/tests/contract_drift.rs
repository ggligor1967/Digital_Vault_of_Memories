//! Fails when the committed TypeScript contract stops describing the Rust
//! contract types.
//!
//! This is the mechanism that satisfies Blueprint v2 §40.2 for gate G0: the
//! renderer's view of the IPC boundary is not maintained by hand alongside the
//! Rust view, it is generated from it, and this test is what makes "generated"
//! an enforced property rather than a convention.
//!
//! Run `pnpm contracts:generate` to update the committed file after changing a
//! contract type.

use std::path::{Path, PathBuf};

use dvm_domain::codegen::{GENERATED_CONTRACT_PATH, typescript_source, verify_against_serde};

/// Resolves the repository root from this crate's manifest directory.
///
/// `crates/dvm-domain` is always two levels below the root, so the traversal
/// is a plain join rather than a filesystem search.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// Normalises line endings so the comparison is stable on Windows checkouts
/// regardless of the contributor's `core.autocrlf` setting.
fn normalise(source: &str) -> String {
    source.replace("\r\n", "\n")
}

#[test]
fn contract_tables_agree_with_the_rust_types() {
    let problems = verify_against_serde();

    assert!(
        problems.is_empty(),
        "the contract field tables contradict the live Serde representation:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn committed_typescript_contract_is_up_to_date() {
    let path = repository_root().join(GENERATED_CONTRACT_PATH);

    let committed = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("could not read {GENERATED_CONTRACT_PATH}: {error}. Run `pnpm contracts:generate`.")
    });

    assert_eq!(
        normalise(&committed),
        typescript_source(),
        "{GENERATED_CONTRACT_PATH} is out of date. Run `pnpm contracts:generate` and commit the result."
    );
}

#[test]
fn committed_typescript_contract_is_marked_generated() {
    let path = repository_root().join(GENERATED_CONTRACT_PATH);
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("could not read {GENERATED_CONTRACT_PATH}: {error}. Run `pnpm contracts:generate`.")
    });

    assert!(
        committed.starts_with("// GENERATED FILE"),
        "the committed contract must announce that it is generated"
    );
}
