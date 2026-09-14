/**
 * Scope assertions: the foundation must not have quietly acquired a
 * later-gate dependency.
 *
 * G1 permits its explicitly selected native storage and crypto dependencies.
 * Other storage stacks and future-gate dependencies remain rejected. These
 * tests read every manifest in the repository and fail if such a dependency
 * appears without the corresponding gate having been opened.
 */
import { describe, expect, it } from 'vitest';

import { readRepoFile, readRepoJson, walkFiles } from './repository.ts';

/**
 * Dependency-name fragments that belong to a later gate, with the gate that
 * would authorise them.
 *
 * When that gate is implemented, the entry is removed here in the same change
 * as the dependency is added — which is the point: the removal is a visible,
 * reviewable decision rather than an unnoticed `pnpm add`.
 */
const LATER_GATE_DEPENDENCIES: { fragment: string; gate: string }[] = [
  // Unselected storage stacks remain forbidden even though G1 is current.
  { fragment: 'sqlx', gate: 'G1' },
  { fragment: 'diesel', gate: 'G1' },
  { fragment: 'sql.js', gate: 'G1' },
  { fragment: 'better-sqlite3', gate: 'G1' },
  { fragment: 'tauri-plugin-sql', gate: 'G1' },
  // G2 — cryptography and secret storage
  { fragment: 'aes-gcm', gate: 'G2' },
  { fragment: 'ring', gate: 'G2' },
  { fragment: 'tauri-plugin-stronghold', gate: 'G2' },
  // G3 — backup
  { fragment: 'zip', gate: 'G3' },
  { fragment: 'tar', gate: 'G3' },
  // G4 — search
  { fragment: 'hnsw', gate: 'G4' },
  { fragment: 'tantivy', gate: 'G4' },
  { fragment: 'faiss', gate: 'G4' },
  { fragment: 'usearch', gate: 'G4' },
  // G5 — AI providers
  { fragment: 'openai', gate: 'G5' },
  { fragment: 'anthropic', gate: 'G5' },
  { fragment: 'ollama', gate: 'G5' },
  { fragment: 'langchain', gate: 'G5' },
  { fragment: 'generative-ai', gate: 'G5' },
  { fragment: 'huggingface', gate: 'G5' },
  { fragment: 'onnxruntime', gate: 'G5' },
  { fragment: 'tokenizers', gate: 'G5' },
  // G6 — media
  { fragment: 'ffmpeg', gate: 'G6' },
  { fragment: 'image-rs', gate: 'G6' },
  { fragment: 'sharp', gate: 'G6' },
  // G8 — plugin runtimes
  { fragment: 'extism', gate: 'G8' },
  { fragment: 'wasmtime', gate: 'G8' },
  { fragment: 'wasmer', gate: 'G8' },
  { fragment: 'rhai', gate: 'G8' },
];

/**
 * Tauri plugins that would hand the renderer host authority.
 *
 * These are separate from the gate list because no later gate authorises them
 * either: Blueprint v2 §20.2 requires vault operations to be typed commands,
 * not broad plugin permissions.
 */
const FORBIDDEN_TAURI_PLUGINS = [
  'tauri-plugin-fs',
  'tauri-plugin-shell',
  'tauri-plugin-http',
  'tauri-plugin-upload',
  '@tauri-apps/plugin-fs',
  '@tauri-apps/plugin-shell',
  '@tauri-apps/plugin-http',
  '@tauri-apps/plugin-upload',
];

/** Every dependency name declared in every `package.json` in the workspace. */
function npmDependencyNames(): { manifest: string; name: string }[] {
  const found: { manifest: string; name: string }[] = [];

  for (const manifest of walkFiles('.').filter((path) => path.endsWith('package.json'))) {
    const parsed = readRepoJson(manifest) as Record<string, Record<string, string> | undefined>;
    for (const section of ['dependencies', 'devDependencies', 'optionalDependencies'] as const) {
      for (const name of Object.keys(parsed[section] ?? {})) {
        found.push({ manifest, name });
      }
    }
  }

  return found;
}

/** Every dependency name declared in every `Cargo.toml` in the workspace. */
function cargoDependencyNames(): { manifest: string; name: string }[] {
  const found: { manifest: string; name: string }[] = [];

  for (const manifest of walkFiles('.').filter((path) => path.endsWith('Cargo.toml'))) {
    let inDependencySection = false;

    for (const rawLine of readRepoFile(manifest).split('\n')) {
      const line = rawLine.trim();

      if (line.startsWith('[')) {
        inDependencySection =
          /^\[(?:target\..+\.)?(workspace\.)?(build-|dev-)?dependencies\]$/.test(line);
        const tableMatch =
          /^\[(?:target\..+\.)?(workspace\.)?(build-|dev-)?dependencies\.([A-Za-z0-9_-]+)\]$/.exec(
            line,
          );
        if (tableMatch?.[3]) {
          found.push({ manifest, name: tableMatch[3] });
        }
        continue;
      }

      if (!inDependencySection || line.startsWith('#') || line.length === 0) {
        continue;
      }

      const nameMatch = /^([A-Za-z0-9_-]+)\s*=/.exec(line);
      if (nameMatch?.[1]) {
        found.push({ manifest, name: nameMatch[1] });
      }
    }
  }

  return found;
}

/** Whether `name` matches `fragment` as a whole word or delimited segment. */
function matchesFragment(name: string, fragment: string): boolean {
  const normalised = name.toLowerCase();
  if (normalised === fragment) {
    return true;
  }
  return new RegExp(`(^|[^a-z0-9])${fragment}([^a-z0-9]|$)`).test(normalised);
}

describe('dependency scope', () => {
  const allDependencies = [...npmDependencyNames(), ...cargoDependencyNames()];

  it('finds manifests to inspect', () => {
    expect(allDependencies.length).toBeGreaterThan(10);
  });

  it('contains no dependency belonging to a later gate', () => {
    const violations: string[] = [];

    for (const { manifest, name } of allDependencies) {
      for (const { fragment, gate } of LATER_GATE_DEPENDENCIES) {
        if (matchesFragment(name, fragment)) {
          violations.push(`${manifest}: "${name}" is ${gate} scope, but G2 is the current gate`);
        }
      }
    }

    expect(violations).toEqual([]);
  });

  it('contains no AI or model-provider dependency', () => {
    const aiGates = new Set(['G5']);
    const violations: string[] = [];

    for (const { manifest, name } of allDependencies) {
      for (const { fragment, gate } of LATER_GATE_DEPENDENCIES) {
        if (aiGates.has(gate) && matchesFragment(name, fragment)) {
          violations.push(`${manifest}: "${name}"`);
        }
      }
    }

    expect(violations, 'INV-019 requires the core to work with all AI disabled').toEqual([]);
  });

  it('installs no Tauri plugin that would grant the renderer host authority', () => {
    const violations: string[] = [];

    for (const { manifest, name } of allDependencies) {
      if (FORBIDDEN_TAURI_PLUGINS.includes(name)) {
        violations.push(`${manifest}: "${name}"`);
      }
    }

    expect(violations).toEqual([]);
  });
});

describe('reserved crates', () => {
  const RESERVED = ['dvm-search', 'dvm-ai', 'dvm-media', 'dvm-backup'];

  it('declare no third-party dependency yet', () => {
    for (const crate of RESERVED) {
      const manifest = `crates/${crate}/Cargo.toml`;
      const declared = cargoDependencyNames().filter((entry) => entry.manifest === manifest);

      expect(declared, `${manifest} must stay dependency-free until its gate opens`).toEqual([]);
    }
  });

  it('contain only a documented placeholder, not an implementation', () => {
    for (const crate of RESERVED) {
      const sources = walkFiles(`crates/${crate}/src`);

      expect(sources, `${crate} must contain exactly one source file`).toEqual([
        `crates/${crate}/src/lib.rs`,
      ]);

      const body = readRepoFile(`crates/${crate}/src/lib.rs`);
      expect(body).toContain('AUTHORISED_FROM_GATE');
      expect(
        body.split('\n').filter((line) => line.trim().startsWith('fn ')),
        `${crate} must not define functions before its gate opens`,
      ).toEqual([]);
    }
  });
});

describe('G1 storage boundary', () => {
  it('keeps future-gate detection active for representative prohibited dependencies', () => {
    for (const name of [
      'hnsw',
      'tantivy',
      'openai',
      'ffmpeg',
      'zip',
      'tar',
      'extism',
      'wasmtime',
      'wasmer',
      'rhai',
    ]) {
      expect(LATER_GATE_DEPENDENCIES.some(({ fragment }) => matchesFragment(name, fragment))).toBe(
        true,
      );
    }
  });

  it('compiles crash injection only into the Rust test module', () => {
    const lib = readRepoFile('crates/dvm-storage/src/lib.rs');
    expect(lib).toMatch(/#\[cfg\(test\)\]\s*mod tests;/);
    for (const path of walkFiles('crates/dvm-storage/src').filter(
      (p) => p.endsWith('.rs') && !p.endsWith('/tests.rs'),
    )) {
      const source = readRepoFile(path);
      expect(source).not.toContain('std::env::var');
      expect(source).not.toContain('std::process::exit');
      const calls = source.match(/#\[cfg\(test\)\]\s*crate::tests::checkpoint/g) ?? [];
      expect(calls.length).toBe((source.match(/crate::tests::checkpoint/g) ?? []).length);
    }
  });

  it('keeps G1 out of renderer commands and preserves future workspace placeholders', () => {
    const commands = readRepoFile('apps/desktop/src-tauri/src/lib.rs');
    expect(commands).not.toMatch(/vault_create|vault_unlock|import_paths/);
    for (const path of walkFiles('apps/desktop/src').filter(
      (p) => p.endsWith('.ts') || p.endsWith('.tsx'),
    )) {
      expect(readRepoFile(path)).not.toMatch(/VaultMasterKey|BlobRootKey|DbKey/);
    }
  });

  it('places C6 immediately after canonical rename, before the post-rename sync', () => {
    const source = readRepoFile('crates/dvm-storage/src/vault.rs');
    expect(source).toMatch(
      /fs::rename\(&staged\.staging_path, &canonical\)[^\n]*\n\s*#\[cfg\(test\)\]\s*crate::tests::checkpoint\("C6"\);\s*OpenOptions::new\(\)/,
    );
  });
});
