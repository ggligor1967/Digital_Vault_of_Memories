import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

const packageJson = JSON.parse(
  readFileSync(fileURLToPath(new URL('./package.json', import.meta.url)), 'utf8'),
) as { version: string };

/**
 * Port the Tauri shell expects the dev server on.
 *
 * It must stay in sync with `build.devUrl` and with the `ws://localhost:5173`
 * entry in the development CSP in `src-tauri/tauri.conf.json`; a security test
 * asserts that it does.
 */
const DEV_SERVER_PORT = 5173;

export default defineConfig({
  plugins: [react()],

  // `index.html` sits at the Vite project root, not under `public/`
  // (Blueprint v2 §36 / G0). `root` is therefore this directory and no
  // `%PUBLIC_URL%`-style templating is involved.
  root: fileURLToPath(new URL('.', import.meta.url)),

  // Relative asset URLs so the production bundle loads under Tauri's custom
  // protocol without needing a remote origin in the CSP.
  base: './',

  define: {
    __APP_VERSION__: JSON.stringify(packageJson.version),
  },

  server: {
    port: DEV_SERVER_PORT,
    // Fail loudly rather than silently moving to another port: a different
    // port would not match `devUrl` or the development CSP.
    strictPort: true,
    host: '127.0.0.1',
  },

  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Every asset is bundled locally. Nothing is fetched from a CDN, which is
    // what lets the production CSP stay at `default-src 'self'`
    // (Blueprint v2 §20.5).
    assetsInlineLimit: 0,
    sourcemap: false,
    target: 'es2023',
  },

  test: {
    environment: 'jsdom',
    globals: false,
    setupFiles: ['./vitest.setup.ts'],
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
    restoreMocks: true,
  },
});
