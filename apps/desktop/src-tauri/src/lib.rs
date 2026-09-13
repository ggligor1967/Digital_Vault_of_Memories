//! Tauri 2 desktop shell — the trusted native boundary.
//!
//! This crate is the composition root of Blueprint v2 §6.1. Everything above
//! it (the React renderer) is untrusted presentation; everything below it
//! (`dvm-application`, `dvm-domain`, and from G1 the infrastructure crates) is
//! trusted native code.
//!
//! The shell's job is deliberately small:
//!
//! 1. construct the application services,
//! 2. expose them as typed Tauri commands,
//! 3. translate failures into the canonical [`AppError`] envelope.
//!
//! It contains no business logic. A command handler that grows a decision
//! belongs in `dvm-application` instead — that separation is what the G0
//! architecture tests defend.
//!
//! # What the renderer cannot reach through this boundary
//!
//! The capability file `capabilities/main-window.json` grants the window no
//! plugin permissions whatsoever, so there is no filesystem, shell, HTTP or
//! dialog surface to abuse (INV-012, INV-013). The only reachable entry point
//! is [`foundation_status`], whose payload is three version strings and a
//! health discriminant.

use dvm_application::FoundationService;
use dvm_domain::{AppError, ErrorCode, FoundationStatus};

/// Version of the desktop application itself.
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the foundation status of the trusted backend.
///
/// This is the single typed IPC command established by gate G0. Serving it
/// emits one sanitised structured diagnostic event, which is what the runtime
/// evidence procedure captures to prove the boundary actually works at
/// runtime rather than only compiling (execution prompt §19).
///
/// # Errors
///
/// Returns [`ErrorCode::Internal`] if the diagnostic sink was configured but
/// could not be written. The status itself cannot fail at G0; the error path
/// exists so that the envelope is exercised end to end, and so that the
/// command signature does not have to change when it can.
#[expect(
    clippy::needless_pass_by_value,
    reason = "Tauri's command macro requires State<'_, T> to be taken by value; \
              it is a cheap handle, not the managed value itself"
)]
#[tauri::command]
fn foundation_status(
    service: tauri::State<'_, FoundationService>,
) -> Result<FoundationStatus, AppError> {
    let status = service.status();

    match FoundationService::served_event(&status).emit() {
        dvm_observability::EmitOutcome::StdoutOnly
        | dvm_observability::EmitOutcome::StdoutAndSink => Ok(status),
        dvm_observability::EmitOutcome::SinkFailed => Err(AppError::new(ErrorCode::Internal)
            .retryable()
            .with_safe_details("diagnostics sink unavailable")),
    }
}

/// Builds the Tauri application.
///
/// Separated from [`run`] so that the command registration and managed state
/// can be asserted in tests without starting an event loop.
fn builder() -> tauri::Builder<tauri::Wry> {
    tauri::Builder::default()
        .manage(FoundationService::new(
            APP_VERSION,
            dvm_application::CRATE_VERSION,
        ))
        .invoke_handler(tauri::generate_handler![foundation_status])
}

/// Name of the diagnostic event emitted when the shell cannot start.
const SHELL_START_FAILED_EVENT: &str = "desktop_shell_start_failed";

/// Starts the desktop application and reports the process exit status.
///
/// A startup failure is reported as a sanitised diagnostic event and a
/// non-zero exit code rather than a panic. Blueprint v2 §23.3 forbids
/// converting a failure into an apparent success, and a panic here would do
/// the opposite disservice: it would print a Rust backtrace, which may contain
/// build paths, to whatever captured the process.
#[must_use = "the exit code must reach the process, otherwise a failed startup looks successful"]
pub fn run() -> std::process::ExitCode {
    match builder().run(tauri::generate_context!()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let _outcome = dvm_observability::DiagnosticEvent::new(SHELL_START_FAILED_EVENT)
                .with_field("reason", &error.to_string())
                .emit();
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{APP_VERSION, builder};
    use dvm_application::FoundationService;
    use dvm_domain::{API_CONTRACT_VERSION, FoundationHealth};

    #[test]
    fn the_shell_reports_its_own_crate_version_as_the_app_version() {
        let status = FoundationService::new(APP_VERSION, dvm_application::CRATE_VERSION).status();

        assert_eq!(status.app_version, APP_VERSION);
        assert_eq!(status.backend_version, dvm_application::CRATE_VERSION);
        assert_eq!(status.api_contract_version, API_CONTRACT_VERSION);
        assert_eq!(status.status, FoundationHealth::Ok);
    }

    #[test]
    fn the_app_version_matches_the_bundled_tauri_configuration() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).expect("config must parse");

        assert_eq!(
            config["version"].as_str(),
            Some(APP_VERSION),
            "tauri.conf.json version must match the crate version, otherwise the renderer is \
             shown a version the installer does not use"
        );
    }

    #[test]
    fn the_window_the_capability_targets_actually_exists() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).expect("config must parse");
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/main-window.json"))
                .expect("capability must parse");

        let configured_labels: Vec<&str> = config["app"]["windows"]
            .as_array()
            .expect("at least one window must be configured")
            .iter()
            .filter_map(|w| w["label"].as_str())
            .collect();

        for target in capability["windows"]
            .as_array()
            .expect("the capability must target windows")
        {
            let label = target.as_str().expect("window labels are strings");
            assert!(
                configured_labels.contains(&label),
                "capability targets window {label:?}, which tauri.conf.json does not define"
            );
        }
    }

    #[test]
    fn the_capability_grants_no_plugin_permission() {
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/main-window.json"))
                .expect("capability must parse");

        let permissions = capability["permissions"]
            .as_array()
            .expect("permissions must be an array");

        assert!(
            permissions.is_empty(),
            "G0 grants the renderer no plugin permission; adding one requires an ADR and an \
             update to the security tests. Found: {permissions:?}"
        );
    }

    /// Builds the application without running it. This exercises
    /// `generate_handler!` and the managed-state wiring, so a command that
    /// fails to register is a test failure rather than a runtime surprise.
    #[test]
    fn the_application_builder_wires_up_without_panicking() {
        let _builder = builder();
    }
}
