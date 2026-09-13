/**
 * Shared helpers for the repository-level assertions.
 *
 * These tests read the repository as data. They deliberately do not import
 * application code: a security assertion that can be satisfied by changing an
 * export is not a security assertion.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Absolute path of the repository root. */
export const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));

/** Resolves a repository-relative path. */
export function repoPath(...segments: string[]): string {
  return join(REPO_ROOT, ...segments);
}

/** Reads a repository-relative UTF-8 file. */
export function readRepoFile(...segments: string[]): string {
  return readFileSync(repoPath(...segments), 'utf8');
}

/**
 * Reads and parses a repository-relative JSON file.
 *
 * Returns `unknown` rather than a caller-chosen generic: parsing a file cannot
 * verify its shape, and a generic parameter here would dress an assertion up
 * as a check. Callers assert the shape explicitly at the point where they know
 * what they are reading.
 */
export function readRepoJson(...segments: string[]): unknown {
  return JSON.parse(readRepoFile(...segments));
}

/** Whether a repository-relative path exists. */
export function repoPathExists(...segments: string[]): boolean {
  try {
    statSync(repoPath(...segments));
    return true;
  } catch {
    return false;
  }
}

/** Directory names never descended into when walking the repository. */
const IGNORED_DIRECTORIES = new Set([
  '.git',
  'node_modules',
  'target',
  'dist',
  'gen',
  '.dvm-local',
  'coverage',
]);

/**
 * Lists every file below `root`, as repository-relative POSIX paths.
 *
 * @param root - Repository-relative directory to walk.
 */
export function walkFiles(root: string): string[] {
  const absoluteRoot = repoPath(root);
  const found: string[] = [];

  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name)) {
          visit(join(directory, entry.name));
        }
        continue;
      }
      if (entry.isFile()) {
        found.push(relative(REPO_ROOT, join(directory, entry.name)).split(sep).join('/'));
      }
    }
  };

  visit(absoluteRoot);
  return found.sort();
}

/** The Tauri application configuration, parsed. */
export interface TauriConfig {
  version: string;
  identifier: string;
  build: { devUrl: string; frontendDist: string };
  app: {
    withGlobalTauri?: boolean;
    windows: { label: string }[];
    security: {
      csp: string;
      devCsp: string;
      capabilities: string[];
      freezePrototype?: boolean;
      dangerousDisableAssetCspModification?: unknown;
      assetProtocol?: { enable?: boolean; scope?: unknown[] };
    };
  };
}

/** A Tauri capability definition, parsed. */
export interface TauriCapability {
  identifier: string;
  windows?: string[];
  permissions: unknown[];
  local?: boolean;
  remote?: unknown;
}

/** Path of the Tauri configuration, relative to the repository root. */
export const TAURI_CONFIG_PATH = 'apps/desktop/src-tauri/tauri.conf.json';

/** Path of the capability directory, relative to the repository root. */
export const CAPABILITIES_DIR = 'apps/desktop/src-tauri/capabilities';

/** Loads the Tauri application configuration. */
export function loadTauriConfig(): TauriConfig {
  return readRepoJson(TAURI_CONFIG_PATH) as TauriConfig;
}

/** Loads every capability definition, keyed by its repository-relative path. */
export function loadCapabilities(): { path: string; capability: TauriCapability }[] {
  return walkFiles(CAPABILITIES_DIR)
    .filter((path) => path.endsWith('.json'))
    .map((path) => ({ path, capability: readRepoJson(path) as TauriCapability }));
}

/**
 * Splits a CSP string into directive name to source list.
 *
 * @param csp - A Content-Security-Policy value.
 */
export function parseCsp(csp: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();

  for (const raw of csp.split(';')) {
    const parts = raw.trim().split(/\s+/).filter(Boolean);
    const [name, ...sources] = parts;
    if (name) {
      directives.set(name, sources);
    }
  }

  return directives;
}
