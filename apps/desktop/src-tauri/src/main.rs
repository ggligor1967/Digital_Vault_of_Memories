//! Desktop entry point.
//!
//! Kept to a single call so that everything testable lives in the library
//! target (`dvm_desktop_lib`).

// Release builds must not open a console window on Windows. Debug builds keep
// the console attached, because the G0 runtime-evidence procedure reads the
// structured diagnostic event from standard output.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> std::process::ExitCode {
    dvm_desktop_lib::run()
}
