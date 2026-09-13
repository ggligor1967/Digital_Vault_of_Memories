//! Repository-local generator for the TypeScript mirror of the IPC contract.
//!
//! # Why this exists rather than a code-generation framework
//!
//! Blueprint v2 §40.2 requires that Rust and TypeScript DTOs be *generated or
//! validated from a shared schema* so they cannot drift. The obvious candidate
//! for a Tauri 2 project is `tauri-specta`, but at the time G0 was implemented
//! its only releases are `2.0.0-rc.*` pre-releases. Pinning a release
//! candidate — and the `specta` derive stack behind it — into the foundation
//! that every later gate builds on would trade a real determinism guarantee
//! for convenience, and would be a large framework in service of a single
//! command. The execution prompt (§16) explicitly permits, and prefers, the
//! smallest deterministic repository-local approach in that situation. The
//! decision is recorded in `docs/adr/ADR-0001`.
//!
//! # How drift is actually prevented
//!
//! The generator never restates the Rust types. It observes them:
//!
//! * **Field names** come from serialising a real value and reading the keys
//!   Serde produced. A renamed or added Rust field changes the observed key
//!   set immediately.
//! * **Optionality** comes from serialising the same type twice — once with
//!   every `Option` populated, once with every `Option` empty — and diffing
//!   the two key sets. A field is optional exactly when Serde omits it.
//! * **Field types** are declared once, in [`FieldSpec`], and then verified
//!   against the JSON kind Serde actually emitted, so a declared `string` that
//!   became a number is a build failure rather than a runtime surprise.
//! * **Union members** come from [`ErrorCode::ALL`] and
//!   [`FoundationHealth::ALL`], which the compiler and the `dvm-domain` unit
//!   tests hold to the enums themselves.
//!
//! [`verify_against_serde`] runs all of the above and is executed by the
//! `contract_drift` integration test, so `cargo test` fails if the committed
//! TypeScript no longer describes the Rust types.

use serde_json::Value;

use crate::{API_CONTRACT_VERSION, AppError, ErrorCode, FoundationHealth, FoundationStatus};

/// Path of the generated TypeScript module, relative to the repository root.
pub const GENERATED_CONTRACT_PATH: &str = "packages/contracts/src/generated/contract.ts";

/// Name of the single typed IPC command established by gate G0.
pub const FOUNDATION_STATUS_COMMAND: &str = "foundation_status";

/// The JSON kind a contract field is expected to take on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonKind {
    /// A JSON string.
    Str,
    /// A JSON boolean.
    Bool,
}

impl JsonKind {
    /// Whether `value` is of this kind.
    fn matches(self, value: &Value) -> bool {
        match self {
            Self::Str => value.is_string(),
            Self::Bool => value.is_boolean(),
        }
    }

    /// Human-readable name, used in mismatch reports.
    const fn describe(self) -> &'static str {
        match self {
            Self::Str => "string",
            Self::Bool => "boolean",
        }
    }
}

/// One field of a generated TypeScript interface.
pub struct FieldSpec {
    /// Wire name. Verified against the key Serde actually emits.
    pub name: &'static str,
    /// TypeScript type expression.
    pub ts_type: &'static str,
    /// Underlying JSON kind, verified against the value Serde actually emits.
    pub kind: JsonKind,
    /// Whether Serde omits the field when it is absent.
    pub optional: bool,
    /// Doc comment emitted above the field.
    pub doc: &'static str,
}

/// Fields of the generated `AppError` interface.
const APP_ERROR_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "code",
        ts_type: "ErrorCode",
        kind: JsonKind::Str,
        optional: false,
        doc: "Stable machine-readable classification.",
    },
    FieldSpec {
        name: "message_key",
        ts_type: "string",
        kind: JsonKind::Str,
        optional: false,
        doc: "Localisation key. Never pre-rendered prose.",
    },
    FieldSpec {
        name: "retryable",
        ts_type: "boolean",
        kind: JsonKind::Bool,
        optional: false,
        doc: "Whether re-attempting the same operation is meaningful.",
    },
    FieldSpec {
        name: "correlation_id",
        ts_type: "string",
        kind: JsonKind::Str,
        optional: false,
        doc: "Opaque identifier correlating this envelope with local diagnostics.",
    },
    FieldSpec {
        name: "safe_details",
        ts_type: "string",
        kind: JsonKind::Str,
        optional: true,
        doc: "Optional sanitised detail. Never a path, secret or internal message.",
    },
];

/// Fields of the generated `FoundationStatus` interface.
const FOUNDATION_STATUS_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        name: "app_version",
        ts_type: "string",
        kind: JsonKind::Str,
        optional: false,
        doc: "Version of the desktop application.",
    },
    FieldSpec {
        name: "backend_version",
        ts_type: "string",
        kind: JsonKind::Str,
        optional: false,
        doc: "Version of the trusted Rust backend crate serving the command.",
    },
    FieldSpec {
        name: "api_contract_version",
        ts_type: "string",
        kind: JsonKind::Str,
        optional: false,
        doc: "Version of the renderer-facing IPC contract.",
    },
    FieldSpec {
        name: "status",
        ts_type: "FoundationHealth",
        kind: JsonKind::Str,
        optional: false,
        doc: "Health discriminant.",
    },
];

/// A sample `AppError` with every optional field populated.
fn app_error_with_all_fields() -> AppError {
    AppError::new(ErrorCode::Internal).with_safe_details("sample")
}

/// A sample `AppError` with every optional field empty.
fn app_error_with_no_optional_fields() -> AppError {
    AppError::new(ErrorCode::Internal)
}

/// A sample `FoundationStatus`.
fn foundation_status_sample() -> FoundationStatus {
    FoundationStatus::new("0.0.0", "0.0.0", API_CONTRACT_VERSION, FoundationHealth::Ok)
}

/// Serialises `value` and returns its object representation.
fn as_object(value: &impl serde::Serialize) -> Result<serde_json::Map<String, Value>, String> {
    let json = serde_json::to_value(value).map_err(|e| format!("serialisation failed: {e}"))?;
    match json {
        Value::Object(map) => Ok(map),
        other => Err(format!("expected a JSON object, got {other}")),
    }
}

/// Checks one interface's [`FieldSpec`] table against the values Serde emits.
///
/// `full` must have every optional field populated; `minimal` must have none
/// of them populated. When the type has no optional fields the same value may
/// be passed twice.
fn verify_interface(
    interface: &str,
    fields: &[FieldSpec],
    full: &impl serde::Serialize,
    minimal: &impl serde::Serialize,
    problems: &mut Vec<String>,
) {
    let full_object = match as_object(full) {
        Ok(object) => object,
        Err(error) => {
            problems.push(format!("{interface}: {error}"));
            return;
        }
    };
    let minimal_object = match as_object(minimal) {
        Ok(object) => object,
        Err(error) => {
            problems.push(format!("{interface}: {error}"));
            return;
        }
    };

    let declared: Vec<&str> = fields.iter().map(|f| f.name).collect();

    for key in full_object.keys() {
        if !declared.contains(&key.as_str()) {
            problems.push(format!(
                "{interface}: Rust serialises field `{key}`, but the TypeScript contract does not declare it"
            ));
        }
    }

    for field in fields {
        let Some(value) = full_object.get(field.name) else {
            problems.push(format!(
                "{interface}: the TypeScript contract declares field `{}`, but Rust does not serialise it",
                field.name
            ));
            continue;
        };

        if !field.kind.matches(value) {
            problems.push(format!(
                "{interface}.{}: declared as {} but Rust serialised {value}",
                field.name,
                field.kind.describe()
            ));
        }

        let omitted_when_absent = !minimal_object.contains_key(field.name);
        if omitted_when_absent != field.optional {
            let declared_as = if field.optional {
                "optional"
            } else {
                "required"
            };
            let observed_as = if omitted_when_absent {
                "omitted"
            } else {
                "always present"
            };
            problems.push(format!(
                "{interface}.{}: declared {declared_as}, but Serde leaves it {observed_as}",
                field.name
            ));
        }
    }
}

/// Verifies every generated declaration against the live Serde behaviour of
/// the Rust types.
///
/// Returns the list of contradictions; an empty list means the generated
/// TypeScript is a faithful mirror. All contradictions are collected rather
/// than short-circuiting on the first, so one run reports the whole picture.
#[must_use]
pub fn verify_against_serde() -> Vec<String> {
    let mut problems = Vec::new();

    verify_interface(
        "AppError",
        APP_ERROR_FIELDS,
        &app_error_with_all_fields(),
        &app_error_with_no_optional_fields(),
        &mut problems,
    );

    let status = foundation_status_sample();
    verify_interface(
        "FoundationStatus",
        FOUNDATION_STATUS_FIELDS,
        &status,
        &status,
        &mut problems,
    );

    for code in ErrorCode::ALL {
        match serde_json::to_value(code) {
            Ok(Value::String(wire)) if wire == code.as_wire_str() => {}
            Ok(other) => problems.push(format!(
                "ErrorCode::{code:?}: Serde emitted {other}, expected \"{}\"",
                code.as_wire_str()
            )),
            Err(error) => problems.push(format!("ErrorCode::{code:?}: {error}")),
        }
    }

    for health in FoundationHealth::ALL {
        match serde_json::to_value(health) {
            Ok(Value::String(wire)) if wire == health.as_wire_str() => {}
            Ok(other) => problems.push(format!(
                "FoundationHealth::{health:?}: Serde emitted {other}, expected \"{}\"",
                health.as_wire_str()
            )),
            Err(error) => problems.push(format!("FoundationHealth::{health:?}: {error}")),
        }
    }

    problems
}

/// Header comment placed at the top of the generated module.
const GENERATED_HEADER: &str = "\
// GENERATED FILE — DO NOT EDIT.
//
// Emitted by `pnpm contracts:generate`, which runs the `dvm-contracts-gen`
// binary in `crates/dvm-domain`. The declarations below are derived from the
// live Serde representation of the Rust contract types, not restated by hand.
//
// `pnpm contracts:check` (and therefore `cargo test` and CI) fails if this
// file stops matching the Rust types, so the two sides of the IPC boundary
// cannot drift silently — Blueprint v2 §40.2.
";

/// Renders a doc comment line at the given indentation.
fn doc_comment(indent: &str, text: &str) -> String {
    format!("{indent}/** {text} */")
}

/// Renders one TypeScript interface from its field table.
///
/// Returns the lines of the declaration; the caller joins them. Building the
/// output as lines rather than by appending to one buffer keeps each rendering
/// step a pure function of its inputs, which is what makes the generator
/// trivially deterministic.
fn render_interface(name: &str, doc: &str, fields: &[FieldSpec]) -> Vec<String> {
    let mut lines = vec![doc_comment("", doc), format!("export interface {name} {{")];

    for field in fields {
        lines.push(doc_comment("  ", field.doc));
        let optional_marker = if field.optional { "?" } else { "" };
        lines.push(format!(
            "  {}{}: {};",
            field.name, optional_marker, field.ts_type
        ));
    }

    lines.push("}".to_owned());
    lines
}

/// Renders a string-literal union plus the runtime array of its members.
fn render_union(name: &str, doc: &str, members: &[&str], const_name: &str) -> Vec<String> {
    let mut lines = vec![doc_comment("", doc), format!("export type {name} =")];

    for (index, member) in members.iter().enumerate() {
        let terminator = if index + 1 == members.len() { ";" } else { "" };
        lines.push(format!("  | '{member}'{terminator}"));
    }

    lines.push(String::new());
    lines.push(doc_comment(
        "",
        &format!("Every declared {name}, in Rust declaration order."),
    ));
    lines.push(format!("export const {const_name}: readonly {name}[] = ["));

    for member in members {
        lines.push(format!("  '{member}',"));
    }

    lines.push("];".to_owned());
    lines
}

/// Produces the full source of the generated TypeScript contract module.
///
/// The output is byte-deterministic: it depends only on the Rust types, never
/// on the environment, the clock or the filesystem.
#[must_use]
pub fn typescript_source() -> String {
    let error_codes: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.as_wire_str()).collect();
    let healths: Vec<&str> = FoundationHealth::ALL
        .iter()
        .map(|h| h.as_wire_str())
        .collect();

    let mut lines: Vec<String> = GENERATED_HEADER.lines().map(str::to_owned).collect();

    lines.push(String::new());
    lines.push(doc_comment(
        "",
        "Version of the renderer-facing IPC contract this module describes.",
    ));
    lines.push(format!(
        "export const API_CONTRACT_VERSION = '{API_CONTRACT_VERSION}';"
    ));

    lines.push(String::new());
    lines.push(doc_comment(
        "",
        "Name of the single typed IPC command established by gate G0.",
    ));
    lines.push(format!(
        "export const FOUNDATION_STATUS_COMMAND = '{FOUNDATION_STATUS_COMMAND}';"
    ));

    lines.push(String::new());
    lines.extend(render_union(
        "ErrorCode",
        "Stable machine-readable error classification (Blueprint v2 §23.2).",
        &error_codes,
        "ERROR_CODES",
    ));

    lines.push(String::new());
    lines.extend(render_interface(
        "AppError",
        "The canonical typed error envelope (Blueprint v2 §23.1).",
        APP_ERROR_FIELDS,
    ));

    lines.push(String::new());
    lines.extend(render_union(
        "FoundationHealth",
        "Health discriminant reported by the trusted backend.",
        &healths,
        "FOUNDATION_HEALTHS",
    ));

    lines.push(String::new());
    lines.extend(render_interface(
        "FoundationStatus",
        "Result of the `foundation_status` command.",
        FOUNDATION_STATUS_FIELDS,
    ));

    // One trailing newline, no trailing blank line.
    lines.push(String::new());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::{typescript_source, verify_against_serde};

    #[test]
    fn the_generated_contract_agrees_with_serde() {
        let problems = verify_against_serde();

        assert!(
            problems.is_empty(),
            "the TypeScript contract contradicts the Rust types:\n  {}",
            problems.join("\n  ")
        );
    }

    #[test]
    fn generation_is_deterministic() {
        assert_eq!(typescript_source(), typescript_source());
    }

    #[test]
    fn generated_source_uses_lf_only() {
        assert!(
            !typescript_source().contains('\r'),
            "generated source must be LF-only so the drift check is reproducible"
        );
    }

    #[test]
    fn generated_source_declares_both_contract_types() {
        let source = typescript_source();

        assert!(source.contains("export interface AppError {"));
        assert!(source.contains("export interface FoundationStatus {"));
        assert!(source.contains("export type ErrorCode ="));
        assert!(source.contains("export type FoundationHealth ="));
    }

    #[test]
    fn optional_fields_are_emitted_with_a_question_mark() {
        let source = typescript_source();

        assert!(source.contains("safe_details?: string;"));
        assert!(source.contains("correlation_id: string;"));
    }
}
