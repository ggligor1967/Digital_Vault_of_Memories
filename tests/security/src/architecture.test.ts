/**
 * Dependency-direction assertions (Blueprint v2 §6.2, §40.1).
 *
 * ```text
 * presentation -> application -> domain/ports <- infrastructure
 * ```
 *
 * A dependency rule that lives only in a diagram is a dependency rule that
 * will be broken. These tests read the import statements in the renderer and
 * the `use` statements in the Rust crates and fail when an arrow points the
 * wrong way.
 */
import { describe, expect, it } from 'vitest';

import { readRepoFile, walkFiles } from './repository.ts';

/** Renderer source files, excluding tests and ambient declarations. */
function rendererSources(): string[] {
  return walkFiles('apps/desktop/src').filter(
    (path) =>
      (path.endsWith('.ts') || path.endsWith('.tsx')) &&
      !path.endsWith('.test.ts') &&
      !path.endsWith('.test.tsx') &&
      !path.endsWith('.d.ts'),
  );
}

/** Extracts every module specifier imported by a TypeScript source file. */
function importedModules(path: string): string[] {
  const source = readRepoFile(path);
  const specifiers: string[] = [];
  const pattern =
    /(?:import|export)[\s\S]*?from\s+['"]([^'"]+)['"]|import\s*\(\s*['"]([^'"]+)['"]/g;

  let match: RegExpExecArray | null = pattern.exec(source);
  while (match !== null) {
    const specifier = match[1] ?? match[2];
    if (specifier) {
      specifiers.push(specifier);
    }
    match = pattern.exec(source);
  }

  return specifiers;
}

/** The single renderer file permitted to import Tauri. */
const TAURI_ADAPTER = 'apps/desktop/src/ipc/tauri-adapter.ts';

describe('renderer trust boundary', () => {
  it('finds renderer sources to inspect', () => {
    expect(rendererSources().length).toBeGreaterThan(5);
  });

  it('imports Tauri from exactly one adapter module', () => {
    const importers = rendererSources().filter((path) =>
      importedModules(path).some((specifier) => specifier.startsWith('@tauri-apps/')),
    );

    expect(
      importers,
      'components must depend on the FoundationPort interface, not on Tauri',
    ).toEqual([TAURI_ADAPTER]);
  });

  it('never imports a Node built-in into the renderer', () => {
    const violations: string[] = [];

    for (const path of rendererSources()) {
      for (const specifier of importedModules(path)) {
        if (specifier.startsWith('node:')) {
          violations.push(`${path} imports ${specifier}`);
        }
      }
    }

    expect(violations, 'INV-013: the renderer has no host filesystem or process access').toEqual(
      [],
    );
  });

  it('never imports a database, crypto, filesystem or AI module into the renderer', () => {
    const forbidden = [
      'fs',
      'node:fs',
      'crypto',
      'node:crypto',
      'sqlite',
      'sql.js',
      'openai',
      'anthropic',
      'ollama',
      '@tauri-apps/plugin-fs',
      '@tauri-apps/plugin-shell',
      '@tauri-apps/plugin-http',
    ];
    const violations: string[] = [];

    for (const path of rendererSources()) {
      for (const specifier of importedModules(path)) {
        if (forbidden.includes(specifier)) {
          violations.push(`${path} imports ${specifier}`);
        }
      }
    }

    expect(violations, 'Blueprint v2 §6.2: React must not import infrastructure').toEqual([]);
  });

  it('keeps components free of direct IPC invocation', () => {
    const componentDirectories = [
      'apps/desktop/src/app',
      'apps/desktop/src/components',
      'apps/desktop/src/features',
    ];
    const violations: string[] = [];

    for (const directory of componentDirectories) {
      for (const path of walkFiles(directory)) {
        if (!path.endsWith('.ts') && !path.endsWith('.tsx')) {
          continue;
        }
        if (/\binvoke\s*\(/.test(readRepoFile(path))) {
          violations.push(`${path} calls invoke() directly`);
        }
      }
    }

    expect(violations, 'raw invocations belong in apps/desktop/src/ipc').toEqual([]);
  });
});

describe('Rust dependency direction', () => {
  /** Reads the dependency section names of a crate manifest. */
  function crateDependencies(crate: string): string[] {
    const manifest = readRepoFile(`${crate}/Cargo.toml`);
    const names: string[] = [];
    let inDependencies = false;

    for (const rawLine of manifest.split('\n')) {
      const line = rawLine.trim();
      if (line.startsWith('[')) {
        inDependencies = line === '[dependencies]';
        continue;
      }
      if (!inDependencies || line.length === 0 || line.startsWith('#')) {
        continue;
      }
      const match = /^([A-Za-z0-9_-]+)\s*=/.exec(line);
      if (match?.[1]) {
        names.push(match[1]);
      }
    }

    return names;
  }

  it('keeps the domain crate free of application and infrastructure crates', () => {
    const dependencies = crateDependencies('crates/dvm-domain');

    for (const name of dependencies) {
      expect(
        name.startsWith('dvm-'),
        `dvm-domain must not depend on the workspace crate ${name}`,
      ).toBe(false);
    }
  });

  it('keeps the domain crate free of Tauri', () => {
    expect(crateDependencies('crates/dvm-domain')).not.toContain('tauri');
  });

  it('keeps the application crate free of Tauri', () => {
    expect(
      crateDependencies('crates/dvm-application'),
      'the application layer must be usable without a desktop shell',
    ).not.toContain('tauri');
  });

  it('confines Tauri to the desktop shell', () => {
    const crates = walkFiles('crates')
      .filter((path) => path.endsWith('Cargo.toml'))
      .map((path) => path.replace(/\/Cargo\.toml$/, ''));

    for (const crate of crates) {
      expect(crateDependencies(crate), `${crate} must not depend on Tauri`).not.toContain('tauri');
    }
  });

  it('has the desktop shell depend inward only', () => {
    const dependencies = crateDependencies('apps/desktop/src-tauri');

    expect(dependencies).toContain('dvm-application');
    expect(dependencies).toContain('dvm-domain');
    expect(dependencies).toContain('tauri');
  });
});
