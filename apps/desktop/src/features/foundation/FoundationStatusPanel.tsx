/**
 * The entire G0 user interface.
 *
 * It shows just enough to prove the architectural boundary is real: the
 * renderer's own build version, the versions the trusted backend reports, and
 * whether the two agree on the IPC contract. Gate G0 explicitly forbids a
 * dashboard, vault interaction or any visual-polish work, so there is nothing
 * else here on purpose.
 */
import { StatusRow } from '../../components/StatusRow.tsx';
import type { FoundationPort } from '../../ipc/index.ts';

import { useFoundationStatus } from './useFoundationStatus.ts';

/** Props for {@link FoundationStatusPanel}. */
export interface FoundationStatusPanelProps {
  /** IPC port used to reach the trusted backend. */
  port: FoundationPort;
  /** Renderer build version, injected at the composition root. */
  frontendVersion: string;
}

/** Renders the foundation status. */
export function FoundationStatusPanel({ port, frontendVersion }: FoundationStatusPanelProps) {
  const state = useFoundationStatus(port);

  return (
    <section className="panel" aria-labelledby="foundation-heading">
      <h1 id="foundation-heading" className="panel__title">
        Digital Vault of Memories
      </h1>

      <p className="panel__status" data-testid="foundation-status" role="status">
        Foundation status: <strong>{describe(state.kind, stateIsCompatible(state))}</strong>
      </p>

      <dl className="panel__rows">
        <StatusRow
          label="Frontend version"
          value={frontendVersion}
          valueTestId="frontend-version"
        />
        <StatusRow
          label="Backend version"
          value={state.kind === 'ready' ? state.status.backend_version : '—'}
          valueTestId="backend-version"
        />
        <StatusRow
          label="Contract version"
          value={state.kind === 'ready' ? state.status.api_contract_version : '—'}
          valueTestId="contract-version"
        />
      </dl>

      {state.kind === 'error' && (
        <p className="panel__error" role="alert" data-testid="foundation-error">
          <span data-testid="error-code">{state.error.code}</span>
          {' · '}
          <span data-testid="error-message-key">{state.error.message_key}</span>
          {' · '}
          <span data-testid="error-correlation-id">{state.error.correlation_id}</span>
        </p>
      )}
    </section>
  );
}

/** Whether the loaded state reported a compatible contract. */
function stateIsCompatible(state: ReturnType<typeof useFoundationStatus>): boolean {
  return state.kind === 'ready' && state.compatible;
}

/** Maps the request state to the single word shown to the user. */
function describe(kind: 'loading' | 'ready' | 'error', compatible: boolean): string {
  switch (kind) {
    case 'loading':
      return 'Connecting';
    case 'ready':
      return compatible ? 'Connected' : 'Incompatible';
    case 'error':
      return 'Unavailable';
  }
}
