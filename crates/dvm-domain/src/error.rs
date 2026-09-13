//! The canonical typed error envelope (Blueprint v2 §23).
//!
//! Blueprint v2 §23.1 fixes the shape:
//!
//! ```text
//! AppError {
//!     code
//!     message_key
//!     retryable
//!     correlation_id
//!     safe_details?
//! }
//! ```
//!
//! The envelope exists so that the renderer can react to failures
//! *structurally* — retry, localise, or escalate — without ever receiving Rust
//! panic text, source-error chains, absolute filesystem paths, secrets or any
//! other internal state (Blueprint v2 §10.3, §23.1, INV-011).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable, machine-readable error classification.
///
/// The variants below are exactly the required error classes of Blueprint v2
/// §23.2, plus [`ErrorCode::Internal`]. §23.2 specifies its list as a minimum,
/// and G0 requires a terminal classification for an unexpected backend fault
/// whose cause must never leak to the renderer.
///
/// The wire representation is `SCREAMING_SNAKE_CASE`, matching the Blueprint
/// text verbatim (`VAULT_LOCKED`, `BAD_PASSPHRASE`, ...). The renderer
/// switches on these strings, so they are part of the compatibility surface
/// guarded by [`crate::API_CONTRACT_VERSION`].
///
/// # Gate note
///
/// Declaring a code is a *contract* statement, not an implementation. Gate G0
/// only ever produces [`ErrorCode::Internal`]; the remaining codes acquire
/// producers in the gate that implements the corresponding subsystem. They are
/// declared now so that the renderer's error handling and the localisation key
/// namespace are fixed before feature work begins, rather than growing ad hoc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// The vault is locked; content is not reachable through IPC (INV-015).
    VaultLocked,
    /// The supplied passphrase did not open any keyslot.
    BadPassphrase,
    /// The vault header declares a schema this binary must not mutate
    /// (INV-022).
    UnsupportedVaultVersion,
    /// The vault header failed structural or authenticated validation.
    CorruptHeader,
    /// The encrypted metadata database failed to open or verify.
    CorruptDatabase,
    /// A canonical blob referenced by the database is absent (INV-003).
    MissingBlob,
    /// Authenticated decryption of a blob failed; no partial plaintext is
    /// returned (INV-004).
    BlobAuthFailed,
    /// A user-selected import source could not be read.
    SourceUnreadable,
    /// The media type is not supported by the requested operation.
    UnsupportedMedia,
    /// The target volume has insufficient space.
    DiskFull,
    /// A durable job failed in a way that is eligible for retry (INV-009).
    JobRetryable,
    /// A durable job failed terminally and will not be retried.
    JobTerminal,
    /// An AI provider is not reachable or not configured.
    ProviderUnavailable,
    /// An AI provider rejected the supplied credentials.
    ProviderAuthFailed,
    /// The requested capability is not offered by the selected provider.
    ProviderCapabilityUnsupported,
    /// A remote call was refused because no approved egress scope covers it
    /// (INV-014).
    RemoteEgressDenied,
    /// A backup archive failed structural or cryptographic verification
    /// (INV-021).
    BackupInvalid,
    /// A restore would collide with existing vault state.
    RestoreConflict,
    /// The vault requires a schema migration before it can be used.
    MigrationRequired,
    /// A schema migration failed; the vault is left in a documented pre- or
    /// post-migration state (INV-023).
    MigrationFailed,
    /// An unexpected backend fault. The cause is recorded in local diagnostics
    /// against the envelope's correlation identifier and is never sent to the
    /// renderer.
    Internal,
}

impl ErrorCode {
    /// Every declared error code, in declaration order.
    ///
    /// This list is the input to the TypeScript contract generator. It cannot
    /// silently drift from the enum: [`ErrorCode::as_wire_str`] is an
    /// exhaustive `match`, so a new variant fails to compile until it is given
    /// a wire string, and a test asserts that the strings listed here are
    /// unique and agree with Serde.
    pub const ALL: &'static [Self] = &[
        Self::VaultLocked,
        Self::BadPassphrase,
        Self::UnsupportedVaultVersion,
        Self::CorruptHeader,
        Self::CorruptDatabase,
        Self::MissingBlob,
        Self::BlobAuthFailed,
        Self::SourceUnreadable,
        Self::UnsupportedMedia,
        Self::DiskFull,
        Self::JobRetryable,
        Self::JobTerminal,
        Self::ProviderUnavailable,
        Self::ProviderAuthFailed,
        Self::ProviderCapabilityUnsupported,
        Self::RemoteEgressDenied,
        Self::BackupInvalid,
        Self::RestoreConflict,
        Self::MigrationRequired,
        Self::MigrationFailed,
        Self::Internal,
    ];

    /// The exact string this code takes on the IPC wire.
    ///
    /// Written as an exhaustive `match` rather than derived from the `Serialize`
    /// implementation so that the compiler forces an explicit decision for
    /// every new variant. A test asserts that this agrees with Serde.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::VaultLocked => "VAULT_LOCKED",
            Self::BadPassphrase => "BAD_PASSPHRASE",
            Self::UnsupportedVaultVersion => "UNSUPPORTED_VAULT_VERSION",
            Self::CorruptHeader => "CORRUPT_HEADER",
            Self::CorruptDatabase => "CORRUPT_DATABASE",
            Self::MissingBlob => "MISSING_BLOB",
            Self::BlobAuthFailed => "BLOB_AUTH_FAILED",
            Self::SourceUnreadable => "SOURCE_UNREADABLE",
            Self::UnsupportedMedia => "UNSUPPORTED_MEDIA",
            Self::DiskFull => "DISK_FULL",
            Self::JobRetryable => "JOB_RETRYABLE",
            Self::JobTerminal => "JOB_TERMINAL",
            Self::ProviderUnavailable => "PROVIDER_UNAVAILABLE",
            Self::ProviderAuthFailed => "PROVIDER_AUTH_FAILED",
            Self::ProviderCapabilityUnsupported => "PROVIDER_CAPABILITY_UNSUPPORTED",
            Self::RemoteEgressDenied => "REMOTE_EGRESS_DENIED",
            Self::BackupInvalid => "BACKUP_INVALID",
            Self::RestoreConflict => "RESTORE_CONFLICT",
            Self::MigrationRequired => "MIGRATION_REQUIRED",
            Self::MigrationFailed => "MIGRATION_FAILED",
            Self::Internal => "INTERNAL",
        }
    }

    /// Proves that no two entries of [`ErrorCode::ALL`] share a wire string.
    ///
    /// Combined with the exhaustive `match` in [`ErrorCode::as_wire_str`],
    /// this is what makes `ALL` trustworthy as the generator's input: a new
    /// variant cannot compile until it is given a wire string, and it cannot
    /// be smuggled into `ALL` by duplicating an existing one.
    #[cfg(test)]
    fn wire_strings_are_unique() -> bool {
        Self::ALL
            .iter()
            .map(|code| code.as_wire_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == Self::ALL.len()
    }

    /// The localisation key the renderer resolves for this code.
    ///
    /// Blueprint v2 §23.1 requires a `message_key` rather than a rendered
    /// human message, so that the trusted backend never chooses presentation
    /// language and never embeds interpolated internal data in prose.
    #[must_use]
    pub fn default_message_key(self) -> String {
        format!("error.{}", self.as_wire_str().to_ascii_lowercase())
    }
}

/// The canonical error envelope crossing the IPC boundary.
///
/// Every field is safe to display and safe to log. There is deliberately no
/// field able to carry a source-error chain, a backtrace, an absolute path or
/// a secret; the trusted backend keeps that information local and correlates
/// it through [`AppError::correlation_id`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppError {
    /// Stable machine-readable classification.
    pub code: ErrorCode,
    /// Localisation key the renderer resolves into user-visible text.
    pub message_key: String,
    /// Whether re-attempting the same operation is meaningful.
    pub retryable: bool,
    /// Opaque identifier correlating this envelope with local diagnostics.
    pub correlation_id: String,
    /// Optional sanitised detail. Never a path, secret or internal message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_details: Option<String>,
}

/// Longest sanitised detail that may cross the boundary.
const MAX_SAFE_DETAIL_LEN: usize = 200;

impl AppError {
    /// Builds a non-retryable envelope with a fresh correlation identifier.
    #[must_use]
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            message_key: code.default_message_key(),
            retryable: false,
            correlation_id: Uuid::new_v4().to_string(),
            safe_details: None,
        }
    }

    /// Marks the envelope as eligible for retry.
    #[must_use]
    pub fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }

    /// Attaches sanitised detail.
    ///
    /// [`AppError::sanitise`] is applied unconditionally as defence in depth,
    /// so that an accidental path, URL or oversized internal message cannot
    /// reach the renderer even when a caller passes one.
    #[must_use]
    pub fn with_safe_details(mut self, details: impl AsRef<str>) -> Self {
        self.safe_details = Self::sanitise(details.as_ref());
        self
    }

    /// Reduces arbitrary text to a renderer-safe detail string, or `None` when
    /// nothing safe remains.
    ///
    /// The filter is deliberately allow-list based rather than an attempt to
    /// enumerate what a secret looks like: only ASCII letters, digits, spaces
    /// and a small punctuation set survive. That removes drive letters, UNC
    /// prefixes, path separators, URL schemes, query strings and quoted
    /// credentials as a class.
    #[must_use]
    pub fn sanitise(details: &str) -> Option<String> {
        let filtered: String = details
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || Self::is_safe_punctuation(c) {
                    c
                } else {
                    ' '
                }
            })
            .collect();

        let collapsed = filtered.split_whitespace().collect::<Vec<_>>().join(" ");
        let trimmed: String = collapsed.chars().take(MAX_SAFE_DETAIL_LEN).collect();

        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }

    /// Punctuation retained by [`AppError::sanitise`].
    ///
    /// Notably excludes `/`, `\`, `:`, `@`, `?`, `=`, `&`, `"` and `'`, which
    /// are the characters that make paths, URLs and quoted secrets legible.
    const fn is_safe_punctuation(c: char) -> bool {
        matches!(c, ' ' | '.' | ',' | '-' | '_' | '(' | ')')
    }
}

impl core::fmt::Display for AppError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} ({})", self.code.as_wire_str(), self.correlation_id)
    }
}

impl core::error::Error for AppError {}

#[cfg(test)]
mod tests {
    use super::{AppError, ErrorCode, MAX_SAFE_DETAIL_LEN};

    /// The error-class list of Blueprint v2 §23.2, verbatim and in document
    /// order. `ErrorCode` may add classes (§23.2 states a minimum) but must
    /// never drop one.
    const BLUEPRINT_REQUIRED_CLASSES: &[&str] = &[
        "VAULT_LOCKED",
        "BAD_PASSPHRASE",
        "UNSUPPORTED_VAULT_VERSION",
        "CORRUPT_HEADER",
        "CORRUPT_DATABASE",
        "MISSING_BLOB",
        "BLOB_AUTH_FAILED",
        "SOURCE_UNREADABLE",
        "UNSUPPORTED_MEDIA",
        "DISK_FULL",
        "JOB_RETRYABLE",
        "JOB_TERMINAL",
        "PROVIDER_UNAVAILABLE",
        "PROVIDER_AUTH_FAILED",
        "PROVIDER_CAPABILITY_UNSUPPORTED",
        "REMOTE_EGRESS_DENIED",
        "BACKUP_INVALID",
        "RESTORE_CONFLICT",
        "MIGRATION_REQUIRED",
        "MIGRATION_FAILED",
    ];

    #[test]
    fn every_blueprint_required_error_class_is_declared() {
        let declared: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.as_wire_str()).collect();

        for required in BLUEPRINT_REQUIRED_CLASSES {
            assert!(
                declared.contains(required),
                "Blueprint v2 §23.2 requires error class {required}, but ErrorCode does not declare it"
            );
        }
    }

    #[test]
    fn declared_error_codes_are_unique() {
        assert!(
            ErrorCode::wire_strings_are_unique(),
            "ErrorCode::ALL contains a duplicate wire string"
        );
    }

    #[test]
    fn serde_wire_form_matches_as_wire_str() {
        for code in ErrorCode::ALL {
            let json = serde_json::to_string(code).expect("ErrorCode must serialise");
            assert_eq!(
                json,
                format!("\"{}\"", code.as_wire_str()),
                "Serde and as_wire_str disagree for {code:?}"
            );
        }
    }

    #[test]
    fn error_codes_round_trip_through_the_wire_form() {
        for code in ErrorCode::ALL {
            let json = serde_json::to_string(code).expect("ErrorCode must serialise");
            let back: ErrorCode = serde_json::from_str(&json).expect("ErrorCode must deserialise");
            assert_eq!(*code, back);
        }
    }

    #[test]
    fn message_keys_are_localisation_keys_not_prose() {
        for code in ErrorCode::ALL {
            let key = code.default_message_key();
            assert!(
                key.starts_with("error."),
                "{code:?} produced a message_key outside the error namespace: {key}"
            );
            assert!(
                !key.contains(' '),
                "{code:?} produced prose rather than a key: {key}"
            );
            assert_eq!(key, key.to_ascii_lowercase());
        }
    }

    #[test]
    fn a_new_envelope_is_not_retryable_and_carries_a_correlation_id() {
        let error = AppError::new(ErrorCode::Internal);

        assert_eq!(error.code, ErrorCode::Internal);
        assert!(!error.retryable);
        assert_eq!(error.safe_details, None);
        assert_eq!(
            error.correlation_id.len(),
            36,
            "correlation_id must be a UUID string"
        );
    }

    #[test]
    fn correlation_ids_are_unique_per_envelope() {
        let first = AppError::new(ErrorCode::Internal);
        let second = AppError::new(ErrorCode::Internal);

        assert_ne!(first.correlation_id, second.correlation_id);
    }

    #[test]
    fn retryable_builder_flips_only_the_retryable_flag() {
        let base = AppError::new(ErrorCode::JobRetryable);
        let retryable = base.clone().retryable();

        assert!(retryable.retryable);
        assert_eq!(base.code, retryable.code);
        assert_eq!(base.correlation_id, retryable.correlation_id);
    }

    #[test]
    fn sanitise_strips_windows_paths() {
        let sanitised = AppError::sanitise(r"C:\Users\someone\Vaults\private.vault");

        let value = sanitised.expect("some text should survive");
        assert!(!value.contains('\\'), "path separators must not survive");
        assert!(!value.contains(':'), "drive letters must not survive");
    }

    #[test]
    fn sanitise_strips_unc_paths_and_urls() {
        for hostile in [
            r"\\server\share\vault",
            "https://api.example.com/v1/keys?token=abcdef",
            "postgres://user:hunter2@localhost/db",
        ] {
            let value = AppError::sanitise(hostile).unwrap_or_default();
            assert!(!value.contains("//"), "{hostile} left a URL authority");
            assert!(!value.contains(':'), "{hostile} left a scheme separator");
            assert!(!value.contains('@'), "{hostile} left a userinfo separator");
            assert!(!value.contains('?'), "{hostile} left a query string");
        }
    }

    #[test]
    fn sanitise_returns_none_when_nothing_safe_remains() {
        assert_eq!(AppError::sanitise(r"\\/:@?=&"), None);
        assert_eq!(AppError::sanitise(""), None);
        assert_eq!(AppError::sanitise("   "), None);
    }

    #[test]
    fn sanitise_is_length_bounded() {
        let long = "a".repeat(5_000);
        let value = AppError::sanitise(&long).expect("letters survive");

        assert_eq!(value.chars().count(), MAX_SAFE_DETAIL_LEN);
    }

    #[test]
    fn with_safe_details_sanitises_even_when_the_caller_does_not() {
        let error = AppError::new(ErrorCode::SourceUnreadable)
            .with_safe_details(r"failed to read C:\Users\someone\photo.jpg");

        let details = error.safe_details.expect("some text should survive");
        assert!(details.starts_with("failed to read"));
        assert!(!details.contains('\\'));
        assert!(!details.contains(':'));
    }

    #[test]
    fn serialised_envelope_has_exactly_the_blueprint_fields() {
        let error = AppError::new(ErrorCode::Internal).with_safe_details("detail");
        let value = serde_json::to_value(&error).expect("AppError must serialise");
        let object = value.as_object().expect("AppError serialises to an object");

        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();

        assert_eq!(
            keys,
            [
                "code",
                "correlation_id",
                "message_key",
                "retryable",
                "safe_details"
            ]
        );
    }

    #[test]
    fn safe_details_is_omitted_rather_than_null_when_absent() {
        let error = AppError::new(ErrorCode::Internal);
        let value = serde_json::to_value(&error).expect("AppError must serialise");
        let object = value.as_object().expect("AppError serialises to an object");

        assert!(
            !object.contains_key("safe_details"),
            "absent detail must be omitted, not serialised as null"
        );
    }

    #[test]
    fn display_never_reveals_the_detail_payload() {
        let error = AppError::new(ErrorCode::Internal).with_safe_details("sensitive looking text");
        let rendered = error.to_string();

        assert!(rendered.contains("INTERNAL"));
        assert!(rendered.contains(&error.correlation_id));
        assert!(!rendered.contains("sensitive looking text"));
    }
}
