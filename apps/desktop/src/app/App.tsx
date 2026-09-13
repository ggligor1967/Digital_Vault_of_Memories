/**
 * Root component.
 *
 * Deliberately thin: it receives the IPC port from the composition root and
 * hands it to the one feature that exists. Routing, layout shells and global
 * providers are not G0 concerns.
 */
import { FoundationStatusPanel } from '../features/foundation/FoundationStatusPanel.tsx';
import type { FoundationPort } from '../ipc/index.ts';

/** Props for {@link App}. */
export interface AppProps {
  /** IPC port used to reach the trusted backend. */
  port: FoundationPort;
  /** Renderer build version. */
  frontendVersion: string;
}

/** Renders the application. */
export function App({ port, frontendVersion }: AppProps) {
  return (
    <main className="app">
      <FoundationStatusPanel port={port} frontendVersion={frontendVersion} />
    </main>
  );
}
