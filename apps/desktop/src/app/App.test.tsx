/**
 * Renderer behaviour, exercised against a fake IPC port.
 *
 * No native process is involved: Blueprint v2 §6.2 requires infrastructure
 * adapters to be replaceable in tests, and these tests are the proof that the
 * React tree really does depend on the port interface rather than on Tauri.
 * Runtime proof that the *real* adapter works is a separate concern, covered
 * by the runtime-evidence procedure.
 */
import { render, screen, waitFor } from '@testing-library/react';
import {
  fakeFoundationPort,
  failingFoundationPort,
  makeAppError,
  makeFoundationStatus,
  pendingFoundationPort,
} from '@dvm/test-fixtures';
import { API_CONTRACT_VERSION } from '@dvm/contracts';
import { describe, expect, it } from 'vitest';

import { App } from './App.tsx';

describe('App', () => {
  it('shows a connecting state before the backend answers', () => {
    render(<App port={pendingFoundationPort()} frontendVersion="0.1.0" />);

    expect(screen.getByTestId('foundation-status')).toHaveTextContent('Connecting');
    expect(screen.getByTestId('backend-version')).toHaveTextContent('—');
  });

  it('reports Connected once the backend answers with a compatible contract', async () => {
    render(<App port={fakeFoundationPort()} frontendVersion="0.1.0" />);

    await waitFor(() => {
      expect(screen.getByTestId('foundation-status')).toHaveTextContent('Connected');
    });
  });

  it('displays the three versions that prove the boundary is live', async () => {
    const port = fakeFoundationPort(
      makeFoundationStatus({ app_version: '0.1.0', backend_version: '0.1.0' }),
    );

    render(<App port={port} frontendVersion="9.9.9" />);

    await waitFor(() => {
      expect(screen.getByTestId('backend-version')).toHaveTextContent('0.1.0');
    });

    // The renderer shows its *own* build version, not the one the backend
    // reports: that is what makes a shell/renderer mismatch visible.
    expect(screen.getByTestId('frontend-version')).toHaveTextContent('9.9.9');
    expect(screen.getByTestId('contract-version')).toHaveTextContent(API_CONTRACT_VERSION);
  });

  it('queries the backend exactly once per mount', async () => {
    const port = fakeFoundationPort();

    render(<App port={port} frontendVersion="0.1.0" />);

    await waitFor(() => {
      expect(screen.getByTestId('foundation-status')).toHaveTextContent('Connected');
    });
    expect(port.calls.foundationStatus).toBe(1);
  });

  it('reports Incompatible rather than Connected when the contract versions differ', async () => {
    const port = fakeFoundationPort(makeFoundationStatus({ api_contract_version: '99.0.0' }));

    render(<App port={port} frontendVersion="0.1.0" />);

    await waitFor(() => {
      expect(screen.getByTestId('foundation-status')).toHaveTextContent('Incompatible');
    });
    expect(screen.getByTestId('foundation-status')).not.toHaveTextContent('Connected');
  });

  it('reports Unavailable and surfaces the envelope when the backend refuses', async () => {
    const error = makeAppError('INTERNAL', {
      correlation_id: '11111111-2222-4333-8444-555555555555',
      retryable: true,
    });

    render(<App port={failingFoundationPort(error)} frontendVersion="0.1.0" />);

    await waitFor(() => {
      expect(screen.getByTestId('foundation-status')).toHaveTextContent('Unavailable');
    });

    const alert = screen.getByTestId('foundation-error');
    expect(alert).toHaveAttribute('role', 'alert');
    expect(screen.getByTestId('error-code')).toHaveTextContent('INTERNAL');
    expect(screen.getByTestId('error-message-key')).toHaveTextContent('error.internal');
    expect(screen.getByTestId('error-correlation-id')).toHaveTextContent(error.correlation_id);
  });

  it('shows a localisation key rather than backend prose', async () => {
    render(<App port={failingFoundationPort()} frontendVersion="0.1.0" />);

    await waitFor(() => {
      expect(screen.getByTestId('error-message-key')).toBeInTheDocument();
    });

    const rendered = screen.getByTestId('error-message-key').textContent;
    expect(rendered).toMatch(/^error\.[a-z_]+$/);
  });

  it('classifies a non-envelope rejection as INTERNAL instead of rendering it', async () => {
    const hostilePort = {
      foundationStatus: () => Promise.reject(new Error(String.raw`C:\Users\someone\secret.txt`)),
    };

    render(<App port={hostilePort} frontendVersion="0.1.0" />);

    await waitFor(() => {
      expect(screen.getByTestId('error-code')).toHaveTextContent('INTERNAL');
    });

    expect(document.body.textContent).not.toContain('secret.txt');
  });

  it('renders no error region while the request is in flight or successful', async () => {
    const { rerender } = render(<App port={pendingFoundationPort()} frontendVersion="0.1.0" />);
    expect(screen.queryByTestId('foundation-error')).not.toBeInTheDocument();

    rerender(<App port={fakeFoundationPort()} frontendVersion="0.1.0" />);
    await waitFor(() => {
      expect(screen.getByTestId('foundation-status')).toHaveTextContent('Connected');
    });
    expect(screen.queryByTestId('foundation-error')).not.toBeInTheDocument();
  });

  it('exposes the panel as a labelled region with a heading', () => {
    render(<App port={pendingFoundationPort()} frontendVersion="0.1.0" />);

    expect(
      screen.getByRole('heading', { name: 'Digital Vault of Memories', level: 1 }),
    ).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Digital Vault of Memories' })).toBeInTheDocument();
    expect(screen.getByRole('status')).toBeInTheDocument();
  });
});
