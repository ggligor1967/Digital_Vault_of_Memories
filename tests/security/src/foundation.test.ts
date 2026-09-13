/**
 * Foundation assertions: topology, version pinning, reproducibility and
 * documentation truthfulness.
 *
 * Blueprint v2 §7.1 makes reproducibility a property of the repository rather
 * than of one machine, and §50 asks that documentation be tested rather than
 * trusted. These checks are cheap, they run in CI on the same command as the
 * security checks, and they catch the failure modes that only show up in a
 * clean clone — a missing lockfile, a floating version, a README command that
 * no longer exists.
 */
import { describe, expect, it } from 'vitest';

import { readRepoFile, readRepoJson, repoPathExists } from './repository.ts';

/** Name of the aggregate verification script. */
const VERIFY_SCRIPT = 'verify:g0';

interface RootManifest {
  version: string;
  packageManager: string;
  engines: Record<string, string>;
  scripts: Record<string, string>;
  devDependencies: Record<string, string>;
}

const rootManifest = readRepoJson('package.json') as RootManifest;

describe('canonical repository topology', () => {
  /** Every path Blueprint v2 §7 requires a clean clone to reconstruct. */
  const REQUIRED_PATHS = [
    'Digital_Vault_of_Memories_Blueprint_v2.md',
    'Digital_Vault_of_Memories_Blueprint_v2_Gates.yaml',
    'README.md',
    'SECURITY.md',
    'CONTRIBUTING.md',
    'package.json',
    'pnpm-workspace.yaml',
    'pnpm-lock.yaml',
    'Cargo.toml',
    'Cargo.lock',
    'rust-toolchain.toml',
    'apps/desktop/index.html',
    'apps/desktop/package.json',
    'apps/desktop/vite.config.ts',
    'apps/desktop/tsconfig.json',
    'apps/desktop/src/app',
    'apps/desktop/src/features',
    'apps/desktop/src/components',
    'apps/desktop/src/ipc',
    'apps/desktop/src/styles',
    'apps/desktop/src-tauri/Cargo.toml',
    'apps/desktop/src-tauri/tauri.conf.json',
    'apps/desktop/src-tauri/capabilities',
    'apps/desktop/src-tauri/icons',
    'apps/desktop/src-tauri/src',
    'crates/dvm-domain',
    'crates/dvm-application',
    'crates/dvm-crypto',
    'crates/dvm-storage',
    'crates/dvm-search',
    'crates/dvm-ai',
    'crates/dvm-media',
    'crates/dvm-backup',
    'crates/dvm-observability',
    'packages/contracts',
    'packages/test-fixtures',
    'migrations',
    'tests/integration',
    'tests/crash',
    'tests/e2e',
    'tests/security',
    'tests/performance',
    'docs/architecture',
    'docs/threat-model',
    'docs/adr',
    'docs/release-evidence',
    'scripts',
  ];

  it.each(REQUIRED_PATHS)('contains %s', (path) => {
    expect(repoPathExists(path)).toBe(true);
  });

  it('keeps index.html at the Vite project root, not under public/', () => {
    expect(repoPathExists('apps/desktop/index.html')).toBe(true);
    expect(repoPathExists('apps/desktop/public/index.html')).toBe(false);
  });

  it('uses no Create React App template syntax in index.html', () => {
    const html = readRepoFile('apps/desktop/index.html');

    expect(html).not.toContain('%PUBLIC_URL%');
    expect(html).toContain('/src/main.tsx');
  });
});

describe('build reproducibility', () => {
  it('commits both lockfiles', () => {
    expect(repoPathExists('pnpm-lock.yaml')).toBe(true);
    expect(repoPathExists('Cargo.lock')).toBe(true);
  });

  it('pins the package manager to an exact version', () => {
    expect(rootManifest.packageManager).toMatch(/^pnpm@\d+\.\d+\.\d+$/);
  });

  it('pins the Node version in a file CI and contributors both read', () => {
    expect(repoPathExists('.node-version')).toBe(true);
    expect(readRepoFile('.node-version').trim()).toMatch(/^\d+\.\d+\.\d+$/);
    expect(rootManifest.engines.node).toBeTypeOf('string');
  });

  it('pins the Rust toolchain to an exact release rather than a channel', () => {
    const toolchain = readRepoFile('rust-toolchain.toml');

    expect(toolchain).toMatch(/channel\s*=\s*"\d+\.\d+\.\d+"/);
    expect(toolchain).toContain('rustfmt');
    expect(toolchain).toContain('clippy');
  });

  it('declares no floating JavaScript dependency version', () => {
    const floating: string[] = [];
    const manifests = [
      'package.json',
      'apps/desktop/package.json',
      'packages/contracts/package.json',
      'packages/test-fixtures/package.json',
      'tests/security/package.json',
    ];

    for (const manifest of manifests) {
      const parsed = readRepoJson(manifest) as Record<string, Record<string, string> | undefined>;
      for (const section of ['dependencies', 'devDependencies'] as const) {
        for (const [name, range] of Object.entries(parsed[section] ?? {})) {
          const isWorkspaceLink = range.startsWith('workspace:');
          const isExact = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(range);
          if (!isWorkspaceLink && !isExact) {
            floating.push(`${manifest}: ${name}@${range}`);
          }
        }
      }
    }

    expect(floating, 'Blueprint v2 §7.1 forbids floating production dependencies').toEqual([]);
  });

  it('declares no floating Rust dependency version', () => {
    const cargo = readRepoFile('Cargo.toml');
    const floating: string[] = [];
    let inWorkspaceDependencies = false;

    for (const rawLine of cargo.split('\n')) {
      const line = rawLine.trim();
      if (line.startsWith('[')) {
        inWorkspaceDependencies = line === '[workspace.dependencies]';
        continue;
      }
      if (!inWorkspaceDependencies || line.length === 0 || line.startsWith('#')) {
        continue;
      }
      if (line.includes('path =')) {
        continue;
      }
      const versionMatch = /version\s*=\s*"([^"]+)"/.exec(line) ?? /=\s*"([^"]+)"/.exec(line);
      const version = versionMatch?.[1];
      if (version && !version.startsWith('=')) {
        floating.push(line);
      }
    }

    expect(floating, 'workspace dependencies must pin exact versions with "="').toEqual([]);
  });

  it('normalises line endings so a Windows clone formats identically', () => {
    expect(repoPathExists('.gitattributes')).toBe(true);
    expect(readRepoFile('.gitattributes')).toContain('eol=lf');
  });

  it('does not enable dependency build scripts repository-wide', () => {
    const workspace = readRepoFile('pnpm-workspace.yaml');

    expect(workspace).toContain('onlyBuiltDependencies: []');
    expect(workspace).not.toMatch(/^\s*neverBuiltDependencies:/m);
    expect(workspace).not.toMatch(/dangerouslyAllowAllBuilds/);
  });
});

describe('documented commands exist', () => {
  const readme = readRepoFile('README.md');

  /** Extracts `pnpm <script>` invocations from fenced code blocks. */
  function documentedPnpmScripts(): string[] {
    const scripts = new Set<string>();
    const pattern = /^\s*pnpm (?:run )?([a-z][a-z0-9:-]*)\b/gm;

    let match: RegExpExecArray | null = pattern.exec(readme);
    while (match !== null) {
      const name = match[1];
      // `pnpm install` and `pnpm tauri` are the package manager and a
      // pass-through binary, not repository scripts.
      if (name && name !== 'install' && name !== 'tauri' && name !== 'exec') {
        scripts.add(name);
      }
      match = pattern.exec(readme);
    }

    return [...scripts].sort();
  }

  it('finds documented commands to check', () => {
    expect(documentedPnpmScripts().length).toBeGreaterThan(5);
  });

  it.each(documentedPnpmScripts())('README documents `pnpm %s`, which is defined', (script) => {
    expect(Object.keys(rootManifest.scripts)).toContain(script);
  });

  it('documents the single aggregate verification command', () => {
    expect(rootManifest.scripts[VERIFY_SCRIPT]).toBeTypeOf('string');
    expect(readme).toContain('pnpm verify:g0');
  });

  it('references only scripts that exist on disk', () => {
    const referenced = new Set<string>();
    const pattern = /scripts\/([A-Za-z0-9_.-]+\.mjs)/g;

    let match: RegExpExecArray | null = pattern.exec(readme + JSON.stringify(rootManifest.scripts));
    while (match !== null) {
      if (match[1]) {
        referenced.add(match[1]);
      }
      match = pattern.exec(readme + JSON.stringify(rootManifest.scripts));
    }

    expect(referenced.size).toBeGreaterThan(0);
    for (const file of referenced) {
      expect(repoPathExists('scripts', file), `scripts/${file} is referenced but missing`).toBe(
        true,
      );
    }
  });
});

describe('version consistency', () => {
  it('reports the same product version from every manifest', () => {
    const desktopManifest = readRepoJson('apps/desktop/package.json') as { version: string };
    const tauriConfig = readRepoJson('apps/desktop/src-tauri/tauri.conf.json') as {
      version: string;
    };
    const cargoWorkspace = readRepoFile('Cargo.toml');
    const cargoVersion = /\[workspace\.package\][\s\S]*?version\s*=\s*"([^"]+)"/.exec(
      cargoWorkspace,
    )?.[1];

    expect(desktopManifest.version).toBe(rootManifest.version);
    expect(tauriConfig.version).toBe(rootManifest.version);
    expect(cargoVersion).toBe(rootManifest.version);
  });
});

describe('generated contract', () => {
  it('is committed', () => {
    expect(repoPathExists('packages/contracts/src/generated/contract.ts')).toBe(true);
  });

  it('announces that it is generated so nobody edits it by hand', () => {
    const contract = readRepoFile('packages/contracts/src/generated/contract.ts');

    expect(contract.startsWith('// GENERATED FILE')).toBe(true);
    expect(contract).toContain('pnpm contracts:generate');
  });

  it('declares both sides of the G0 IPC contract', () => {
    const contract = readRepoFile('packages/contracts/src/generated/contract.ts');

    expect(contract).toContain('export interface FoundationStatus');
    expect(contract).toContain('export interface AppError');
    expect(contract).toContain("export const FOUNDATION_STATUS_COMMAND = 'foundation_status'");
  });
});
