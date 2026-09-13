/**
 * Renderer-side IPC boundary.
 *
 * Components import from here. They do not import `@tauri-apps/api`, and they
 * do not import `tauri-adapter.ts` directly — the concrete adapter is injected
 * at the composition root (`src/main.tsx`) so that the React tree can be
 * rendered in a test with a fake port.
 */
export type { FoundationPort } from './port.ts';
export { isAppError, isErrorCode, isFoundationHealth, isFoundationStatus } from './parse.ts';
