/**
 * Vitest setup for the renderer test suite.
 *
 * Two things happen here:
 *
 * 1. the jest-dom matchers are registered, so assertions read as DOM intent
 *    (`toBeInTheDocument`, `toHaveTextContent`) rather than as node poking;
 * 2. Testing Library's DOM cleanup is wired up explicitly.
 *
 * The second is not optional in this project. Testing Library only installs
 * its own `afterEach` cleanup when Vitest's globals are enabled, and this
 * suite runs with `globals: false` so that every test helper is an explicit
 * import. Without this hook each render would leak into the next test's
 * document and queries would match duplicates.
 */
import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

afterEach(() => {
  cleanup();
});
