//! Tauri build script.
//!
//! Generates the capability schemas under `gen/`, embeds the application
//! configuration, and links the Windows resources. It must run before the
//! crate compiles.

fn main() {
    declare_common_controls_v6_dependency();
    tauri_build::build();
}

/// Declares the Common Controls v6 side-by-side dependency for every binary
/// this crate links, including Cargo's test harnesses.
///
/// Tauri pulls in `SetWindowSubclass`, `RemoveWindowSubclass`, `DefSubclassProc`
/// and `TaskDialogIndirect`, which exist only in `comctl32.dll` version 6.
/// Reaching version 6 requires a side-by-side manifest; without one Windows
/// loads the version 5 library from `System32` and the process dies with
/// `STATUS_ENTRYPOINT_NOT_FOUND` (0xC0000139) before any code runs.
///
/// `tauri-build` embeds a manifest into the *application* binary, but Cargo
/// compiles unit tests into their own executables and those receive no
/// manifest, so `cargo test` fails at process load for a reason unrelated to
/// the tests. `cargo:rustc-link-arg-tests` does not help: it applies only to
/// `[[test]]` targets, and this crate's tests live in the library. The link
/// argument is therefore emitted for every target; the linker merges it with
/// the identical dependency in Tauri's manifest for the shipped binary.
fn declare_common_controls_v6_dependency() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    println!(
        "cargo:rustc-link-arg=/MANIFESTDEPENDENCY:type='win32' \
         name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
         processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
    );
}
