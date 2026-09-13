/**
 * Loads the foundation status through the injected IPC port.
 *
 * The hook owns the request lifecycle and nothing else: it does not know that
 * Tauri exists, and it does not decide how the result looks. That keeps the
 * three concerns — transport, state, presentation — independently testable.
 */
import { useEffect, useState } from 'react';

import { API_CONTRACT_VERSION, type AppError, type FoundationStatus } from '@dvm/contracts';

import { isAppError, type FoundationPort } from '../../ipc/index.ts';

/** The renderer's view of the foundation request. */
export type FoundationState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly status: FoundationStatus; readonly compatible: boolean }
  | { readonly kind: 'error'; readonly error: AppError };

/** Envelope used when the port rejects with something that is not an envelope. */
const UNCLASSIFIED_FAILURE: AppError = {
  code: 'INTERNAL',
  message_key: 'error.internal',
  retryable: true,
  correlation_id: 'renderer-unclassified',
};

/**
 * Requests the foundation status once, on mount.
 *
 * @param port - The IPC port to use. Injected so tests supply a fake.
 */
export function useFoundationStatus(port: FoundationPort): FoundationState {
  const [state, setState] = useState<FoundationState>({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;

    void port
      .foundationStatus()
      .then((status) => {
        if (cancelled) {
          return;
        }
        setState({
          kind: 'ready',
          status,
          // Blueprint v2 §40.2: an IPC shape mismatch must be visible. The
          // renderer reports the backend as reachable-but-incompatible rather
          // than quietly rendering fields it may be misreading.
          compatible: status.api_contract_version === API_CONTRACT_VERSION,
        });
      })
      .catch((cause: unknown) => {
        if (cancelled) {
          return;
        }
        setState({ kind: 'error', error: isAppError(cause) ? cause : UNCLASSIFIED_FAILURE });
      });

    return () => {
      cancelled = true;
    };
  }, [port]);

  return state;
}
