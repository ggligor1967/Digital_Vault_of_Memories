/**
 * Tauri capability assertions.
 *
 * Blueprint v2 §20.2 and invariants INV-012/INV-013 forbid the renderer from
 * holding arbitrary shell or filesystem authority. Those are the invariants
 * most likely to be eroded by a future convenience change ("just add
 * `fs:allow-read-file` so the picker works"), so they are asserted here
 * against the capability files themselves rather than trusted to review.
 */
import { describe, expect, it } from 'vitest';

import {
  CAPABILITIES_DIR,
  loadCapabilities,
  loadTauriConfig,
  repoPathExists,
} from './repository.ts';

/**
 * Permission identifier prefixes and fragments that must never appear.
 *
 * Matching is done on the lower-cased identifier so that a differently cased
 * or namespaced spelling cannot slip past.
 */
const FORBIDDEN_PERMISSION_PATTERNS: { pattern: RegExp; reason: string }[] = [
  { pattern: /^fs:/, reason: 'filesystem plugin access (INV-013)' },
  { pattern: /(^|:)fs-/, reason: 'filesystem plugin access (INV-013)' },
  { pattern: /^shell:/, reason: 'shell plugin access (INV-012)' },
  { pattern: /allow-execute/, reason: 'shell execute (INV-012)' },
  { pattern: /allow-spawn/, reason: 'shell process spawn (INV-012)' },
  { pattern: /^http:/, reason: 'arbitrary renderer HTTP egress (INV-014)' },
  { pattern: /^process:/, reason: 'process control from the renderer' },
  { pattern: /allowlist/, reason: 'legacy Tauri 1 allowlist pattern (Blueprint v2 §20.1)' },
  { pattern: /^\*$/, reason: 'wildcard permission' },
];

/** Renders a permission entry as the identifier string to match against. */
function permissionIdentifier(permission: unknown): string {
  if (typeof permission === 'string') {
    return permission;
  }
  if (typeof permission === 'object' && permission !== null) {
    const identifier = (permission as { identifier?: unknown }).identifier;
    if (typeof identifier === 'string') {
      return identifier;
    }
  }
  return JSON.stringify(permission);
}

/** All permissions across all capability files, with their source path. */
function allPermissions(): { path: string; identifier: string }[] {
  return loadCapabilities().flatMap(({ path, capability }) =>
    capability.permissions.map((permission) => ({
      path,
      identifier: permissionIdentifier(permission),
    })),
  );
}

describe('Tauri capabilities', () => {
  it('exist as an explicit definition rather than an implicit default', () => {
    expect(repoPathExists(CAPABILITIES_DIR)).toBe(true);

    const capabilities = loadCapabilities();
    expect(capabilities.length).toBeGreaterThan(0);
  });

  it('grant no filesystem, shell, process or network permission', () => {
    const violations: string[] = [];

    for (const { path, identifier } of allPermissions()) {
      const normalised = identifier.toLowerCase();
      for (const { pattern, reason } of FORBIDDEN_PERMISSION_PATTERNS) {
        if (pattern.test(normalised)) {
          violations.push(`${path}: "${identifier}" grants ${reason}`);
        }
      }
    }

    expect(violations).toEqual([]);
  });

  it('grant the G0 window no plugin permission at all', () => {
    const main = loadCapabilities().find(
      ({ capability }) => capability.identifier === 'main-window',
    );

    expect(main, 'a capability identified as "main-window" must exist').toBeDefined();
    expect(main?.capability.permissions).toEqual([]);
  });

  it('are scoped to declared windows rather than applying globally', () => {
    for (const { path, capability } of loadCapabilities()) {
      expect(capability.windows, `${path} must name the windows it applies to`).toBeDefined();
      expect(capability.windows?.length ?? 0).toBeGreaterThan(0);
      expect(capability.windows).not.toContain('*');
    }
  });

  it('do not expose any capability to a remote origin', () => {
    for (const { path, capability } of loadCapabilities()) {
      expect(
        capability.remote,
        `${path} must not grant capabilities to a remote origin`,
      ).toBeUndefined();
      expect(capability.local ?? true).toBe(true);
    }
  });

  it('are all referenced by the application configuration', () => {
    const config = loadTauriConfig();
    const declared = new Set(config.app.security.capabilities);

    for (const { path, capability } of loadCapabilities()) {
      expect(
        declared.has(capability.identifier),
        `${path} defines capability "${capability.identifier}", which tauri.conf.json does not reference`,
      ).toBe(true);
    }
  });

  it('cover every referenced capability identifier', () => {
    const config = loadTauriConfig();
    const defined = new Set(loadCapabilities().map(({ capability }) => capability.identifier));

    for (const identifier of config.app.security.capabilities) {
      expect(
        defined.has(identifier),
        `tauri.conf.json references capability "${identifier}", which no capability file defines`,
      ).toBe(true);
    }
  });
});

describe('Tauri application configuration', () => {
  it('does not expose the global Tauri object to the renderer', () => {
    expect(loadTauriConfig().app.withGlobalTauri).toBe(false);
  });

  it('freezes the prototype chain against renderer tampering', () => {
    expect(loadTauriConfig().app.security.freezePrototype).toBe(true);
  });

  it('does not disable Tauri CSP injection', () => {
    expect(loadTauriConfig().app.security.dangerousDisableAssetCspModification).toBeUndefined();
  });

  it('keeps the asset protocol disabled with an empty scope', () => {
    const assetProtocol = loadTauriConfig().app.security.assetProtocol;

    expect(assetProtocol?.enable).toBe(false);
    expect(assetProtocol?.scope).toEqual([]);
  });

  it('serves the renderer from a local bundle rather than a remote origin', () => {
    const config = loadTauriConfig();

    expect(config.build.frontendDist.startsWith('http')).toBe(false);
    expect(config.build.devUrl.startsWith('http://localhost')).toBe(true);
  });
});
