//! Application layer for Digital Vault of Memories.
//!
//! This is the middle ring of Blueprint v2 §6.2:
//!
//! ```text
//! presentation -> application -> domain/ports <- infrastructure
//! ```
//!
//! It orchestrates use cases. It does not define contracts (that is
//! `dvm-domain`) and it does not talk to the operating system, the database,
//! the network or the filesystem (that is infrastructure, from G1 onwards).
//!
//! # Scope at gate G0
//!
//! One use case exists: [`FoundationService::status`], which backs the
//! `foundation_status` IPC command. Its value is structural — it proves that
//! the Tauri command layer is a thin adapter over an application service that
//! can be exercised without a desktop process, rather than a place where
//! business logic accumulates.

use dvm_domain::{API_CONTRACT_VERSION, FoundationHealth, FoundationStatus};
use dvm_observability::DiagnosticEvent;

/// Name of the diagnostic event emitted when the foundation status is served.
///
/// The runtime-evidence procedure of the G0 execution prompt (§19) greps for
/// this exact event, so it is a contract with the verification script and not
/// merely a log message.
pub const FOUNDATION_STATUS_SERVED_EVENT: &str = "foundation_status_served";

/// Version of the trusted application core.
///
/// Reported to the renderer as `backend_version`. It is deliberately distinct
/// from the desktop application's own version: the shell and the core are
/// separate crates and are allowed to version independently.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Serves the `foundation_status` use case.
///
/// The version strings are injected rather than read from the environment:
/// the application layer must remain testable without a build, and only the
/// composition root (the Tauri shell) knows which crate's version is the
/// "application" version.
#[derive(Debug, Clone)]
pub struct FoundationService {
    app_version: String,
    backend_version: String,
}

impl FoundationService {
    /// Creates the service from the versions of the composition root.
    #[must_use]
    pub fn new(app_version: impl Into<String>, backend_version: impl Into<String>) -> Self {
        Self {
            app_version: app_version.into(),
            backend_version: backend_version.into(),
        }
    }

    /// Returns the current foundation status.
    ///
    /// At G0 the status is always [`FoundationHealth::Ok`]: the foundation has
    /// no subsystem that can degrade. That is stated here rather than left
    /// implicit so the first gate that *can* degrade has an obvious place to
    /// change.
    #[must_use]
    pub fn status(&self) -> FoundationStatus {
        FoundationStatus::new(
            self.app_version.clone(),
            self.backend_version.clone(),
            API_CONTRACT_VERSION,
            FoundationHealth::Ok,
        )
    }

    /// Builds the sanitised diagnostic event proving the command was served.
    ///
    /// Returned rather than emitted so that the caller decides when the write
    /// happens, and so that the event's content is unit-testable without
    /// capturing process output.
    #[must_use]
    pub fn served_event(status: &FoundationStatus) -> DiagnosticEvent {
        DiagnosticEvent::new(FOUNDATION_STATUS_SERVED_EVENT)
            .with_field("contract_version", &status.api_contract_version)
            .with_field("status", status.status.as_wire_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{FOUNDATION_STATUS_SERVED_EVENT, FoundationService};
    use dvm_domain::{API_CONTRACT_VERSION, FoundationHealth};

    #[test]
    fn status_reports_the_injected_versions() {
        let status = FoundationService::new("1.2.3", "4.5.6").status();

        assert_eq!(status.app_version, "1.2.3");
        assert_eq!(status.backend_version, "4.5.6");
    }

    #[test]
    fn status_reports_the_domain_contract_version() {
        let status = FoundationService::new("0.1.0", "0.1.0").status();

        assert_eq!(status.api_contract_version, API_CONTRACT_VERSION);
        assert!(status.is_compatible_with(API_CONTRACT_VERSION));
    }

    #[test]
    fn the_g0_foundation_is_never_degraded() {
        let status = FoundationService::new("0.1.0", "0.1.0").status();

        assert_eq!(status.status, FoundationHealth::Ok);
    }

    #[test]
    fn status_is_deterministic_across_calls() {
        let service = FoundationService::new("0.1.0", "0.1.0");

        assert_eq!(service.status(), service.status());
    }

    #[test]
    fn the_served_event_matches_the_runtime_evidence_contract() {
        let status = FoundationService::new("0.1.0", "0.1.0").status();
        let line = FoundationService::served_event(&status).to_json_line();

        assert!(line.contains(FOUNDATION_STATUS_SERVED_EVENT));
        assert!(line.contains(&format!(r#""contract_version":"{API_CONTRACT_VERSION}""#)));
        assert!(line.contains(r#""status":"ok""#));
    }

    #[test]
    fn the_served_event_leaks_no_host_state() {
        let status = FoundationService::new("0.1.0", "0.1.0").status();
        let line = FoundationService::served_event(&status).to_json_line();

        assert!(!line.contains('\\'));
        assert!(!line.contains("://"));
    }
}
