/**
 * The only module in the renderer that is allowed to import Tauri.
 *
 * Keeping the native call in exactly one file is what makes the claim "React
 * components do not depend on Tauri" checkable rather than aspirational: an
 * architecture test asserts that no other file under `src/` imports
 * `@tauri-apps/api`.
 */
import { invoke } from '@tauri-apps/api/core';
import { FOUNDATION_STATUS_COMMAND, type AppError } from '@dvm/contracts';

import { isAppError, isFoundationStatus } from './parse.ts';
import type { FoundationPort } from './port.ts';

/**
 * Wraps a rejection from `invoke` so that callers always receive an
 * `AppError` envelope.
 *
 * A Rust command that returns `Err(AppError)` rejects with the serialised
 * envelope. A transport-level failure — the backend gone, the command not
 * registered, the payload unparseable — rejects with something else, and that
 * something else must not be shown to the user as if the backend had
 * classified it. It is normalised to `INTERNAL` here, with no detail carried
 * across, because the renderer has no way to know it is safe.
 */
function toAppError(cause: unknown): AppError {
  if (isAppError(cause)) {
    return cause;
  }

  return {
    code: 'INTERNAL',
    message_key: 'error.internal',
    retryable: true,
    correlation_id: 'renderer-transport',
  };
}

/**
 * The production implementation of {@link FoundationPort}, backed by Tauri IPC.
 */
export const tauriFoundationPort: FoundationPort = {
  async foundationStatus() {
    let payload: unknown;

    try {
      payload = await invoke(FOUNDATION_STATUS_COMMAND);
    } catch (cause: unknown) {
      throw toAppError(cause);
    }

    if (!isFoundationStatus(payload)) {
      throw toAppError(undefined);
    }

    return payload;
  },
};
