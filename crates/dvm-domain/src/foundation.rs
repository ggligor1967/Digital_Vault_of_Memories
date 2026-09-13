//! The `foundation_status` contract.
//!
//! [`FoundationStatus`] is the payload of the single typed IPC command
//! established by `DVM-V2 / G0 — REPOSITORY FOUNDATION`. Its purpose is not to
//! be useful to an end user; it is to make the architectural boundary of
//! Blueprint v2 §6 *executable and testable* before any feature exists, so
//! that later gates extend a proven boundary rather than inventing one.
//!
//! # What this type deliberately does not carry
//!
//! Blueprint v2 §40.1 and INV-011/INV-013 forbid the renderer from receiving
//! host authority or internal state. Accordingly `FoundationStatus` exposes no
//! filesystem path, no environment variable, no machine identifier, no user
//! identity and no build host information — only three version strings and a
//! health discriminant, all of which are compile-time constants of the
//! trusted backend.

use serde::{Deserialize, Serialize};

/// Health discriminant reported by the trusted backend.
///
/// Blueprint v2 §41 requires the application to prefer an explicit degraded
/// state over a silent failure. The discriminant is therefore part of the
/// contract from G0 rather than being retrofitted once a subsystem can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundationHealth {
    /// The trusted backend initialised normally and the boundary is intact.
    #[serde(rename = "ok")]
    Ok,
    /// The trusted backend is reachable but is operating with reduced
    /// guarantees. Not reachable at G0: no G0 subsystem can degrade.
    #[serde(rename = "degraded")]
    Degraded,
}

impl FoundationHealth {
    /// The exact string this discriminant takes on the IPC wire.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Degraded => "degraded",
        }
    }

    /// Every declared health discriminant, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Ok, Self::Degraded];
}

/// Result of the `foundation_status` command.
///
/// Field names are `snake_case` on the wire, matching the Blueprint v2 §23.1
/// convention for IPC payloads. Keeping one casing on both sides of the
/// boundary removes an entire class of drift: there is no rename table that
/// can disagree with itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundationStatus {
    /// Version of the desktop application, as compiled into the trusted
    /// backend.
    pub app_version: String,
    /// Version of the trusted Rust backend crate serving this command.
    pub backend_version: String,
    /// Version of the renderer-facing IPC contract
    /// ([`crate::API_CONTRACT_VERSION`]).
    pub api_contract_version: String,
    /// Health discriminant.
    pub status: FoundationHealth,
}

impl FoundationStatus {
    /// Builds a status payload.
    ///
    /// Takes the version strings as parameters rather than reading them from
    /// the environment so that the domain layer stays free of infrastructure
    /// concerns (Blueprint v2 §6.2) and so that tests can construct any
    /// combination without a running application.
    #[must_use]
    pub fn new(
        app_version: impl Into<String>,
        backend_version: impl Into<String>,
        api_contract_version: impl Into<String>,
        status: FoundationHealth,
    ) -> Self {
        Self {
            app_version: app_version.into(),
            backend_version: backend_version.into(),
            api_contract_version: api_contract_version.into(),
            status,
        }
    }

    /// Whether a renderer compiled against `renderer_contract_version` may
    /// trust this payload.
    ///
    /// G0 requires exact equality. A tolerant compatibility rule would need a
    /// negotiated range, which Blueprint v2 §40.2 defers to the first gate
    /// that actually persists data through IPC.
    #[must_use]
    pub fn is_compatible_with(&self, renderer_contract_version: &str) -> bool {
        self.api_contract_version == renderer_contract_version
    }
}

#[cfg(test)]
mod tests {
    use super::{FoundationHealth, FoundationStatus};
    use crate::API_CONTRACT_VERSION;

    fn sample() -> FoundationStatus {
        FoundationStatus::new("0.1.0", "0.1.0", API_CONTRACT_VERSION, FoundationHealth::Ok)
    }

    #[test]
    fn serialised_status_has_exactly_the_contract_fields() {
        let value = serde_json::to_value(sample()).expect("FoundationStatus must serialise");
        let object = value
            .as_object()
            .expect("FoundationStatus serialises to an object");

        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();

        assert_eq!(
            keys,
            [
                "api_contract_version",
                "app_version",
                "backend_version",
                "status"
            ]
        );
    }

    #[test]
    fn status_round_trips_through_json() {
        let original = sample();
        let json = serde_json::to_string(&original).expect("must serialise");
        let restored: FoundationStatus = serde_json::from_str(&json).expect("must deserialise");

        assert_eq!(original, restored);
    }

    #[test]
    fn health_serialises_to_the_documented_wire_strings() {
        for health in FoundationHealth::ALL {
            let json = serde_json::to_string(health).expect("must serialise");
            assert_eq!(json, format!("\"{}\"", health.as_wire_str()));
        }
    }

    #[test]
    fn an_ok_status_reports_the_ok_discriminant() {
        let json = serde_json::to_value(sample()).expect("must serialise");

        assert_eq!(json["status"], "ok");
    }

    #[test]
    fn compatibility_requires_exact_contract_equality() {
        let status = sample();

        assert!(status.is_compatible_with(API_CONTRACT_VERSION));
        assert!(!status.is_compatible_with("0.9.0"));
        assert!(!status.is_compatible_with("1.0.1"));
        assert!(!status.is_compatible_with(""));
    }

    /// INV-011 / INV-013: the payload must not become a channel for host
    /// state. This test fails if a field is ever added whose serialised value
    /// looks like a path, a URL or an environment reference.
    #[test]
    fn status_carries_no_host_state() {
        let value = serde_json::to_value(sample()).expect("must serialise");
        let object = value
            .as_object()
            .expect("FoundationStatus serialises to an object");

        for (key, field) in object {
            let rendered = field.to_string();
            for forbidden in ['\\', '/', ':'] {
                assert!(
                    !rendered.contains(forbidden),
                    "field {key} may not contain {forbidden:?}: a path or URL would leak host state"
                );
            }
            assert!(
                !rendered.contains('%'),
                "field {key} may not contain an environment reference"
            );
        }
    }
}
