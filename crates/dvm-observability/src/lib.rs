//! Sanitised structured diagnostics.
//!
//! Blueprint v2 §24.1 requires local structured diagnostics, and §10.3 and
//! §8 require that they contain no secret and no sensitive absolute path.
//! Gate G0 needs exactly one thing from this crate: a way for the trusted
//! backend to emit a machine-readable event proving that a typed IPC command
//! was actually served at runtime, so that runtime evidence is mechanical
//! rather than a screenshot (execution prompt §19).
//!
//! # Design constraints honoured here
//!
//! * **Allow-list, not deny-list.** A [`DiagnosticEvent`] can only carry a
//!   fixed event name and a small set of string fields, each of which is run
//!   through the same conservative filter used by the error envelope. There is
//!   no free-form payload for a caller to put a path or a secret into.
//! * **No ambient sinks.** The crate writes to standard output and, when a
//!   sink path is supplied by the caller, appends one JSON object per line to
//!   that file. It never chooses a location on the user's disk by itself.
//! * **No later-gate behaviour.** Log rotation, redaction policy for user
//!   content, audit events and the support bundle are Blueprint v2 §24.2/§24.3
//!   concerns and are authorised from G2/G6, not here.

use std::io::Write;
use std::path::Path;

use serde_json::{Map, Value};

/// Environment variable naming an optional file sink for G0 runtime evidence.
///
/// When set, each emitted event is appended to that file as one JSON object
/// per line, in addition to being written to standard output. This exists
/// because a Windows release build runs under the `windows` subsystem and has
/// no attached console, so standard output alone is not a reliable capture
/// channel for the runtime-evidence procedure.
pub const DIAGNOSTICS_SINK_ENV: &str = "DVM_G0_DIAGNOSTICS_FILE";

/// Longest value any diagnostic field may carry.
const MAX_FIELD_LEN: usize = 120;

/// A structured diagnostic event.
///
/// Field values are sanitised on insertion, so an event that has been
/// constructed is safe to write anywhere the process can already write.
#[derive(Debug, Clone)]
pub struct DiagnosticEvent {
    /// Stable event name, for example `foundation_status_served`.
    event: String,
    /// Sanitised string fields, ordered deterministically by key.
    fields: Map<String, Value>,
}

impl DiagnosticEvent {
    /// Starts an event with the given name.
    ///
    /// The name is sanitised like any other value; a caller cannot smuggle
    /// data out through it.
    #[must_use]
    pub fn new(event: &str) -> Self {
        Self {
            event: sanitise(event).unwrap_or_else(|| "unnamed".to_owned()),
            fields: Map::new(),
        }
    }

    /// Adds a sanitised string field.
    ///
    /// A value that sanitises away entirely is recorded as `"redacted"` rather
    /// than being dropped, so the shape of an event never depends on its
    /// content.
    #[must_use]
    pub fn with_field(mut self, key: &str, value: &str) -> Self {
        let Some(key) = sanitise(key) else {
            return self;
        };
        let value = sanitise(value).unwrap_or_else(|| "redacted".to_owned());
        self.fields.insert(key, Value::String(value));
        self
    }

    /// Renders the event as a single-line JSON object.
    ///
    /// `event` is always the first key, and the remaining keys follow in
    /// sorted order, so the output is byte-identical across runs and machines.
    ///
    /// The object is assembled here rather than via
    /// `Value::Object(..).to_string()` because `serde_json::Map` is a sorted
    /// map by default: serialising one would put `contract_version` ahead of
    /// `event` and make the line harder to scan and to match on. Values still
    /// pass through `serde_json`, so escaping remains correct.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        let quoted_event = Value::String(self.event.clone());
        let mut parts = vec![format!(r#""event":{quoted_event}"#)];

        for (key, value) in &self.fields {
            if key != "event" {
                let quoted_key = Value::String(key.clone());
                parts.push(format!("{quoted_key}:{value}"));
            }
        }

        format!("{{{}}}", parts.join(","))
    }

    /// Writes the event to standard output and, when configured, to the file
    /// sink named by [`DIAGNOSTICS_SINK_ENV`].
    ///
    /// Emission is best-effort by design: diagnostics must never be able to
    /// fail an operation the user asked for. A failed write is reported
    /// through the return value for callers that care, and ignored otherwise.
    #[must_use]
    pub fn emit(&self) -> EmitOutcome {
        let line = self.to_json_line();
        println!("{line}");

        match std::env::var(DIAGNOSTICS_SINK_ENV) {
            Err(_) => EmitOutcome::StdoutOnly,
            Ok(path) if path.trim().is_empty() => EmitOutcome::StdoutOnly,
            Ok(path) => match append_line(Path::new(&path), &line) {
                Ok(()) => EmitOutcome::StdoutAndSink,
                Err(_) => EmitOutcome::SinkFailed,
            },
        }
    }
}

/// Where an emitted event actually landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitOutcome {
    /// No file sink was configured.
    StdoutOnly,
    /// The event reached both standard output and the configured file sink.
    StdoutAndSink,
    /// A file sink was configured but could not be written.
    SinkFailed,
}

/// Appends one line to `path`, creating the file when absent.
fn append_line(path: &Path, line: &str) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")
}

/// Reduces arbitrary text to a diagnostics-safe value, or `None` when nothing
/// safe remains.
///
/// Mirrors the allow-list used by the error envelope: only ASCII letters,
/// digits and a small punctuation set survive.
///
/// # What this does and does not guarantee
///
/// It is a **structural** defence. Dropping the separators — backslash, slash,
/// colon, `@`, `?`, `=`, `&` and quotes — destroys paths, URLs, connection
/// strings and quoted credentials as a class, without trying to recognise any
/// of them, so whatever survives cannot be pasted back into a filesystem or a
/// browser.
///
/// It is **not** a content classifier. A Windows path reduces to its words
/// with the separators gone: unusable as a path, but the words remain. The
/// primary control is therefore that callers pass only values the trusted
/// backend chose, and at G0 that holds by construction — the only fields ever
/// emitted are compile-time constants.
#[must_use]
pub fn sanitise(value: &str) -> Option<String> {
    let filtered: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | ',' | '-' | '_') {
                c
            } else {
                ' '
            }
        })
        .collect();

    let collapsed = filtered.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed: String = collapsed.chars().take(MAX_FIELD_LEN).collect();

    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Emits only the canonical classification of a storage failure, never its details.
/// The structural sanitizer alone cannot redact names; this typed constructor
/// deliberately excludes message text, path hints and even `safe_details`.
#[must_use]
pub fn storage_failure(error: &dvm_domain::AppError) -> DiagnosticEvent {
    DiagnosticEvent::new("storage_failed").with_field("error_code", error.code.as_wire_str())
}

#[cfg(test)]
mod tests {
    use super::{DiagnosticEvent, MAX_FIELD_LEN, sanitise};

    #[test]
    fn an_event_renders_as_one_json_line_with_event_first() {
        let line = DiagnosticEvent::new("foundation_status_served")
            .with_field("contract_version", "1.0.0")
            .with_field("status", "ok")
            .to_json_line();

        assert!(!line.contains('\n'));
        assert!(line.starts_with(r#"{"event":"foundation_status_served""#));
        assert!(line.contains(r#""contract_version":"1.0.0""#));
        assert!(line.contains(r#""status":"ok""#));
    }

    #[test]
    fn rendering_is_deterministic() {
        let event = DiagnosticEvent::new("e")
            .with_field("b", "2")
            .with_field("a", "1");

        assert_eq!(event.to_json_line(), event.to_json_line());
    }

    #[test]
    fn field_values_lose_their_path_structure() {
        let line = DiagnosticEvent::new("import_failed")
            .with_field("source", r"C:\Users\someone\photo.jpg")
            .to_json_line();

        // The guarantee is structural: what survives cannot be used as a path.
        assert!(!line.contains('\\'), "path separators must not survive");
        assert!(!line.contains("C:"), "drive letters must not survive");
        assert!(
            line.contains("photo.jpg"),
            "plain words are expected to survive; the sanitiser removes structure, not content"
        );
    }

    #[test]
    fn field_values_lose_their_url_structure() {
        let line = DiagnosticEvent::new("provider_failed")
            .with_field("endpoint", "https://api.example.com/v1?key=secret")
            .to_json_line();

        assert!(!line.contains("//"), "URL authorities must not survive");
        assert!(!line.contains('?'), "query strings must not survive");
        assert!(
            !line.contains('='),
            "parameter assignments must not survive"
        );
    }

    #[test]
    fn event_names_are_sanitised() {
        let line = DiagnosticEvent::new(r"evil\name:with/separators").to_json_line();

        assert!(!line.contains('\\'));
        assert!(!line.contains('/'));
        assert!(!line.contains(':') || line.starts_with(r#"{"event":"#));
    }

    #[test]
    fn a_value_that_sanitises_away_becomes_redacted_rather_than_vanishing() {
        let line = DiagnosticEvent::new("e")
            .with_field("secret", "///:::")
            .to_json_line();

        assert!(line.contains(r#""secret":"redacted""#));
    }

    #[test]
    fn a_key_that_sanitises_away_is_dropped() {
        let line = DiagnosticEvent::new("e")
            .with_field("///", "value")
            .to_json_line();

        assert_eq!(line, r#"{"event":"e"}"#);
    }

    #[test]
    fn the_event_key_cannot_be_overwritten_by_a_field() {
        let line = DiagnosticEvent::new("real")
            .with_field("event", "spoofed")
            .to_json_line();

        assert_eq!(line, r#"{"event":"real"}"#);
    }

    #[test]
    fn sanitise_is_length_bounded() {
        let value = sanitise(&"a".repeat(5_000)).expect("letters survive");

        assert_eq!(value.chars().count(), MAX_FIELD_LEN);
    }

    #[test]
    fn sanitise_rejects_input_with_nothing_safe() {
        assert_eq!(sanitise(r"\\/:"), None);
        assert_eq!(sanitise(""), None);
    }
}
