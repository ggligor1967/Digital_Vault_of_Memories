//! Writes the generated TypeScript contract module.
//!
//! Invoked through `pnpm contracts:generate`. The complementary check —
//! "is the committed file still correct?" — is the `contract_drift` test, so
//! CI never needs to run this binary or write to the working tree.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use dvm_domain::codegen::{GENERATED_CONTRACT_PATH, typescript_source, verify_against_serde};

/// Resolves the repository root from this crate's manifest directory.
///
/// `crates/dvm-domain` is always two levels below the root, so this needs no
/// filesystem probing and no environment variable beyond the one Cargo sets.
fn repository_root() -> Option<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
}

fn main() -> ExitCode {
    let problems = verify_against_serde();
    if !problems.is_empty() {
        eprintln!("refusing to generate: the contract tables contradict the Rust types:");
        for problem in &problems {
            eprintln!("  - {problem}");
        }
        return ExitCode::FAILURE;
    }

    let Some(root) = repository_root() else {
        eprintln!("could not resolve the repository root from CARGO_MANIFEST_DIR");
        return ExitCode::FAILURE;
    };

    let target = root.join(GENERATED_CONTRACT_PATH);
    if let Some(parent) = target.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        eprintln!("could not create the output directory: {error}");
        return ExitCode::FAILURE;
    }

    match std::fs::write(&target, typescript_source()) {
        Ok(()) => {
            println!("wrote {GENERATED_CONTRACT_PATH}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("could not write {GENERATED_CONTRACT_PATH}: {error}");
            ExitCode::FAILURE
        }
    }
}
