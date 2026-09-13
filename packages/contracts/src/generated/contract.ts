// GENERATED FILE — DO NOT EDIT.
//
// Emitted by `pnpm contracts:generate`, which runs the `dvm-contracts-gen`
// binary in `crates/dvm-domain`. The declarations below are derived from the
// live Serde representation of the Rust contract types, not restated by hand.
//
// `pnpm contracts:check` (and therefore `cargo test` and CI) fails if this
// file stops matching the Rust types, so the two sides of the IPC boundary
// cannot drift silently — Blueprint v2 §40.2.

/** Version of the renderer-facing IPC contract this module describes. */
export const API_CONTRACT_VERSION = '1.0.0';

/** Name of the single typed IPC command established by gate G0. */
export const FOUNDATION_STATUS_COMMAND = 'foundation_status';

/** Stable machine-readable error classification (Blueprint v2 §23.2). */
export type ErrorCode =
  | 'VAULT_LOCKED'
  | 'BAD_PASSPHRASE'
  | 'UNSUPPORTED_VAULT_VERSION'
  | 'CORRUPT_HEADER'
  | 'CORRUPT_DATABASE'
  | 'MISSING_BLOB'
  | 'BLOB_AUTH_FAILED'
  | 'SOURCE_UNREADABLE'
  | 'UNSUPPORTED_MEDIA'
  | 'DISK_FULL'
  | 'JOB_RETRYABLE'
  | 'JOB_TERMINAL'
  | 'PROVIDER_UNAVAILABLE'
  | 'PROVIDER_AUTH_FAILED'
  | 'PROVIDER_CAPABILITY_UNSUPPORTED'
  | 'REMOTE_EGRESS_DENIED'
  | 'BACKUP_INVALID'
  | 'RESTORE_CONFLICT'
  | 'MIGRATION_REQUIRED'
  | 'MIGRATION_FAILED'
  | 'INTERNAL';

/** Every declared ErrorCode, in Rust declaration order. */
export const ERROR_CODES: readonly ErrorCode[] = [
  'VAULT_LOCKED',
  'BAD_PASSPHRASE',
  'UNSUPPORTED_VAULT_VERSION',
  'CORRUPT_HEADER',
  'CORRUPT_DATABASE',
  'MISSING_BLOB',
  'BLOB_AUTH_FAILED',
  'SOURCE_UNREADABLE',
  'UNSUPPORTED_MEDIA',
  'DISK_FULL',
  'JOB_RETRYABLE',
  'JOB_TERMINAL',
  'PROVIDER_UNAVAILABLE',
  'PROVIDER_AUTH_FAILED',
  'PROVIDER_CAPABILITY_UNSUPPORTED',
  'REMOTE_EGRESS_DENIED',
  'BACKUP_INVALID',
  'RESTORE_CONFLICT',
  'MIGRATION_REQUIRED',
  'MIGRATION_FAILED',
  'INTERNAL',
];

/** The canonical typed error envelope (Blueprint v2 §23.1). */
export interface AppError {
  /** Stable machine-readable classification. */
  code: ErrorCode;
  /** Localisation key. Never pre-rendered prose. */
  message_key: string;
  /** Whether re-attempting the same operation is meaningful. */
  retryable: boolean;
  /** Opaque identifier correlating this envelope with local diagnostics. */
  correlation_id: string;
  /** Optional sanitised detail. Never a path, secret or internal message. */
  safe_details?: string;
}

/** Health discriminant reported by the trusted backend. */
export type FoundationHealth =
  | 'ok'
  | 'degraded';

/** Every declared FoundationHealth, in Rust declaration order. */
export const FOUNDATION_HEALTHS: readonly FoundationHealth[] = [
  'ok',
  'degraded',
];

/** Result of the `foundation_status` command. */
export interface FoundationStatus {
  /** Version of the desktop application. */
  app_version: string;
  /** Version of the trusted Rust backend crate serving the command. */
  backend_version: string;
  /** Version of the renderer-facing IPC contract. */
  api_contract_version: string;
  /** Health discriminant. */
  status: FoundationHealth;
}
