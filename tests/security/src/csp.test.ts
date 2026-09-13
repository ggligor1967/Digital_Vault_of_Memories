/**
 * Content-Security-Policy assertions (Blueprint v2 §20.5).
 *
 * Two things are enforced here. First, the production policy is genuinely
 * restrictive: no `unsafe-eval`, no remote script origin, no CDN. Second — and
 * this is the part that erodes quietly — every difference between the
 * development and production policies is one the repository has explicitly
 * accounted for, so "it only works in dev" can never be fixed by loosening
 * production.
 */
import { describe, expect, it } from 'vitest';

import { loadTauriConfig, parseCsp, readRepoFile } from './repository.ts';

const config = loadTauriConfig();
const production = parseCsp(config.app.security.csp);
const development = parseCsp(config.app.security.devCsp);

/**
 * Sources the development policy may add, per directive, and why.
 *
 * Anything outside this table is a test failure: the point is that a
 * development-only relaxation has to be argued for in the repository, not
 * discovered later in a threat model.
 */
const ALLOWED_DEV_ADDITIONS: Record<string, { source: string; reason: string }[]> = {
  'style-src': [
    {
      source: "'unsafe-inline'",
      reason:
        'Vite injects styles as inline <style> elements during HMR. The production bundle emits a static stylesheet, so production keeps style-src at self.',
    },
  ],
  'connect-src': [
    {
      source: 'ws://localhost:5173',
      reason: 'Vite HMR websocket. Never present in production, which has no dev server.',
    },
    {
      source: 'http://localhost:5173',
      reason: 'Vite module and asset requests during development.',
    },
  ],
  'font-src': [
    {
      source: 'data:',
      reason: 'Vite may inline fonts as data URLs before the production asset pipeline runs.',
    },
  ],
  'worker-src': [
    {
      source: 'blob:',
      reason: 'Vite dependency pre-bundling can create blob workers in development.',
    },
  ],
};

/** Directives that must be present in both policies. */
const REQUIRED_DIRECTIVES = [
  'default-src',
  'script-src',
  'style-src',
  'img-src',
  'font-src',
  'connect-src',
  'object-src',
  'base-uri',
  'frame-ancestors',
  'form-action',
];

describe('production CSP', () => {
  it('is configured', () => {
    expect(config.app.security.csp).toBeTypeOf('string');
    expect(config.app.security.csp.length).toBeGreaterThan(0);
  });

  it('declares every required directive', () => {
    for (const directive of REQUIRED_DIRECTIVES) {
      expect(production.has(directive), `production CSP is missing ${directive}`).toBe(true);
    }
  });

  it("never enables 'unsafe-eval'", () => {
    expect(config.app.security.csp).not.toContain('unsafe-eval');
  });

  it("never enables 'unsafe-inline' for scripts", () => {
    expect(production.get('script-src') ?? []).not.toContain("'unsafe-inline'");
  });

  it('allows scripts only from the application itself', () => {
    expect(production.get('script-src')).toEqual(["'self'"]);
  });

  it('allows styles only from the application itself', () => {
    expect(production.get('style-src')).toEqual(["'self'"]);
  });

  it('permits no remote origin in any directive', () => {
    // `http://ipc.localhost` is Tauri's loopback IPC origin on Windows, not a
    // network destination. Everything else host-shaped is a finding.
    const TAURI_IPC_ORIGIN = 'http://ipc.localhost';
    const remote: string[] = [];

    for (const [directive, sources] of production) {
      for (const source of sources) {
        const isHostShaped = /^(https?|wss?):\/\//.test(source);
        if (isHostShaped && source !== TAURI_IPC_ORIGIN) {
          remote.push(`${directive}: ${source}`);
        }
      }
    }

    expect(remote).toEqual([]);
  });

  it('references no AI provider or CDN domain', () => {
    const forbidden = [
      'openai',
      'anthropic',
      'googleapis',
      'generativelanguage',
      'ollama',
      'cdn.',
      'jsdelivr',
      'unpkg',
      'cloudflare',
      'fonts.gstatic',
    ];

    for (const needle of forbidden) {
      expect(config.app.security.csp.toLowerCase()).not.toContain(needle);
    }
  });

  it('locks down object, base, frame and form vectors', () => {
    expect(production.get('object-src')).toEqual(["'none'"]);
    expect(production.get('base-uri')).toEqual(["'none'"]);
    expect(production.get('frame-ancestors')).toEqual(["'none'"]);
    expect(production.get('form-action')).toEqual(["'none'"]);
  });

  it('permits IPC only over the Tauri-internal origins', () => {
    expect(production.get('connect-src')).toEqual(["'self'", 'ipc:', 'http://ipc.localhost']);
  });
});

describe('development CSP', () => {
  it('is configured separately from production', () => {
    expect(config.app.security.devCsp).toBeTypeOf('string');
    expect(config.app.security.devCsp).not.toEqual(config.app.security.csp);
  });

  it("never enables 'unsafe-eval'", () => {
    expect(config.app.security.devCsp).not.toContain('unsafe-eval');
  });

  it("never enables 'unsafe-inline' for scripts", () => {
    expect(development.get('script-src') ?? []).not.toContain("'unsafe-inline'");
  });

  it('declares every required directive', () => {
    for (const directive of REQUIRED_DIRECTIVES) {
      expect(development.has(directive), `development CSP is missing ${directive}`).toBe(true);
    }
  });

  it('adds only sources the repository has accounted for', () => {
    const unexplained: string[] = [];

    for (const [directive, devSources] of development) {
      const productionSources = new Set(production.get(directive) ?? []);
      const permitted = new Set(
        (ALLOWED_DEV_ADDITIONS[directive] ?? []).map((addition) => addition.source),
      );

      for (const source of devSources) {
        if (!productionSources.has(source) && !permitted.has(source)) {
          unexplained.push(`${directive}: ${source}`);
        }
      }
    }

    expect(
      unexplained,
      'every development-only CSP source must be listed in ALLOWED_DEV_ADDITIONS with a reason',
    ).toEqual([]);
  });

  it('removes no production restriction', () => {
    const weakened: string[] = [];

    for (const [directive, productionSources] of production) {
      const devSources = new Set(development.get(directive) ?? []);
      if (!development.has(directive)) {
        weakened.push(`${directive} is absent from the development policy`);
        continue;
      }
      for (const source of productionSources) {
        if (!devSources.has(source)) {
          weakened.push(`${directive} lost ${source}`);
        }
      }
    }

    expect(weakened).toEqual([]);
  });

  it('points its dev-server sources at the port Vite is configured to use', () => {
    const viteConfig = readRepoFile('apps/desktop/vite.config.ts');
    const match = /DEV_SERVER_PORT\s*=\s*(\d+)/.exec(viteConfig);

    expect(match, 'vite.config.ts must declare DEV_SERVER_PORT').not.toBeNull();
    const port = match?.[1] ?? '';
    expect(port).not.toBe('');

    expect(config.build.devUrl).toContain(`:${port}`);

    // Only the dev-server origins are checked. `http://ipc.localhost` is
    // Tauri's own IPC origin and has nothing to do with the Vite port.
    const devServerSources = (development.get('connect-src') ?? []).filter((source) =>
      /^(https?|wss?):\/\/localhost/.test(source),
    );

    expect(devServerSources.length).toBeGreaterThan(0);
    for (const devSource of devServerSources) {
      expect(devSource).toContain(`:${port}`);
    }
  });
});
