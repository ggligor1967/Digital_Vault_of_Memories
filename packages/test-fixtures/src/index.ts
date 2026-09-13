/**
 * Deterministic fixtures and fake ports shared by Digital Vault of Memories
 * tests.
 *
 * Blueprint v2 §6.2 requires infrastructure adapters to be replaceable in
 * tests. For the renderer that means the React tree is exercised against a
 * fake implementation of the IPC port rather than against a running desktop
 * process — a unit test must not need a native window, and a native window
 * must not be the only way to prove the UI behaves.
 *
 * Nothing here is a test double for a *later* gate. As G1+ ports appear, their
 * fakes belong here too.
 */
import {
  API_CONTRACT_VERSION,
  type AppError,
  type ErrorCode,
  type FoundationStatus,
} from '@dvm/contracts';

/**
 * A `FoundationStatus` with stable, obviously-synthetic values.
 *
 * @param overrides - Fields to replace.
 */
export function makeFoundationStatus(overrides: Partial<FoundationStatus> = {}): FoundationStatus {
  return {
    app_version: '0.1.0',
    backend_version: '0.1.0',
    api_contract_version: API_CONTRACT_VERSION,
    status: 'ok',
    ...overrides,
  };
}

/**
 * An `AppError` envelope with stable, obviously-synthetic values.
 *
 * @param code - The error classification to report.
 * @param overrides - Fields to replace.
 */
export function makeAppError(
  code: ErrorCode = 'INTERNAL',
  overrides: Partial<AppError> = {},
): AppError {
  return {
    code,
    message_key: `error.${code.toLowerCase()}`,
    retryable: false,
    correlation_id: '00000000-0000-4000-8000-000000000000',
    ...overrides,
  };
}

/** Records how a fake port was used, so tests can assert on call counts. */
export interface FakePortCalls {
  /** Number of times `foundationStatus` was invoked. */
  foundationStatus: number;
}

/**
 * The subset of the renderer's IPC surface that fixtures can stand in for.
 *
 * Declared structurally rather than imported from the desktop application so
 * that this package stays free of a dependency on the app it is used to test.
 */
export interface FoundationPortLike {
  /** Resolves with the trusted backend's foundation status. */
  foundationStatus(): Promise<FoundationStatus>;
}

/** A fake port plus the record of how it was called. */
export interface FakeFoundationPort extends FoundationPortLike {
  /** Call counters. */
  readonly calls: FakePortCalls;
}

/**
 * Builds a fake port that resolves with `status`.
 *
 * @param status - The status to resolve with. Defaults to a healthy status.
 */
export function fakeFoundationPort(
  status: FoundationStatus = makeFoundationStatus(),
): FakeFoundationPort {
  const calls: FakePortCalls = { foundationStatus: 0 };

  return {
    calls,
    foundationStatus(): Promise<FoundationStatus> {
      calls.foundationStatus += 1;
      return Promise.resolve(status);
    },
  };
}

/**
 * Builds a fake port that rejects with an `AppError` envelope.
 *
 * @param error - The envelope to reject with.
 */
export function failingFoundationPort(error: AppError = makeAppError()): FakeFoundationPort {
  const calls: FakePortCalls = { foundationStatus: 0 };

  return {
    calls,
    foundationStatus(): Promise<FoundationStatus> {
      calls.foundationStatus += 1;
      return Promise.reject(error);
    },
  };
}

/**
 * Builds a fake port whose promise never settles, for asserting loading state.
 */
export function pendingFoundationPort(): FakeFoundationPort {
  const calls: FakePortCalls = { foundationStatus: 0 };

  return {
    calls,
    foundationStatus(): Promise<FoundationStatus> {
      calls.foundationStatus += 1;
      return new Promise<FoundationStatus>(() => {
        // Intentionally never settles.
      });
    },
  };
}
