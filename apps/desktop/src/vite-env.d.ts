/// <reference types="vite/client" />

/**
 * Renderer build version, injected by Vite from `apps/desktop/package.json`.
 *
 * The renderer displays this alongside the version the trusted backend
 * reports, so that a shell/renderer mismatch is visible rather than silent.
 */
declare const __APP_VERSION__: string;
