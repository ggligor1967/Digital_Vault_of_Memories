/**
 * Runtime narrowing of IPC payloads.
 *
 * The compiler cannot check what crosses a process boundary, and
 * `invoke<T>()` is an unchecked assertion. These guards turn that assertion
 * into a check, so a contract mismatch surfaces as a clear failure in the
 * renderer instead of as `undefined` reaching the DOM.
 *
 * The guards validate against the *generated* constants, so they cannot drift
 * from the Rust definitions any more than the generated file itself can.
 */
import {
  ERROR_CODES,
  FOUNDATION_HEALTHS,
  type AppError,
  type ErrorCode,
  type FoundationHealth,
  type FoundationStatus,
} from '@dvm/contracts';

/** Narrows `value` to a non-null object. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/** Narrows `value` to one of the generated error codes. */
export function isErrorCode(value: unknown): value is ErrorCode {
  return typeof value === 'string' && (ERROR_CODES as readonly string[]).includes(value);
}

/** Narrows `value` to one of the generated health discriminants. */
export function isFoundationHealth(value: unknown): value is FoundationHealth {
  return typeof value === 'string' && (FOUNDATION_HEALTHS as readonly string[]).includes(value);
}

/**
 * Narrows `value` to the canonical error envelope.
 *
 * Anything else — a bare string, a JavaScript `Error`, a Tauri transport
 * failure — is not an envelope and must not be presented as one.
 */
export function isAppError(value: unknown): value is AppError {
  if (!isRecord(value)) {
    return false;
  }

  const detailsAreValid =
    value.safe_details === undefined || typeof value.safe_details === 'string';

  return (
    isErrorCode(value.code) &&
    typeof value.message_key === 'string' &&
    typeof value.retryable === 'boolean' &&
    typeof value.correlation_id === 'string' &&
    detailsAreValid
  );
}

/** Narrows `value` to a foundation status payload. */
export function isFoundationStatus(value: unknown): value is FoundationStatus {
  if (!isRecord(value)) {
    return false;
  }

  return (
    typeof value.app_version === 'string' &&
    typeof value.backend_version === 'string' &&
    typeof value.api_contract_version === 'string' &&
    isFoundationHealth(value.status)
  );
}
