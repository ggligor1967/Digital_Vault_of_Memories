/**
 * Renderer composition root.
 *
 * This is the only place that chooses a concrete IPC implementation. Every
 * component below it receives the port as a prop, which is what allows the
 * whole tree to be rendered in a unit test with no native process
 * (Blueprint v2 §6.2).
 */
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './app/App.tsx';
import { tauriFoundationPort } from './ipc/tauri-adapter.ts';
import './styles/app.css';

const container = document.getElementById('root');

if (!container) {
  throw new Error('index.html must provide a #root element');
}

createRoot(container).render(
  <StrictMode>
    <App port={tauriFoundationPort} frontendVersion={__APP_VERSION__} />
  </StrictMode>,
);
