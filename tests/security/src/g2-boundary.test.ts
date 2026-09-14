import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { REPO_ROOT, readRepoFile, walkFiles } from './repository.ts';

describe('G2 security boundary', () => {
  it('keeps the binding archive and download tools out of normal crypto dependencies', () => {
    const tree = spawnSync(
      'cargo',
      ['tree', '--locked', '--offline', '-p', 'dvm-crypto', '-e', 'normal', '--prefix', 'none'],
      { cwd: REPO_ROOT, encoding: 'utf8', timeout: 30_000 },
    );
    expect(tree.status, tree.stderr).toBe(0);
    expect(tree.stdout).toContain('libsodium-sys-stable v1.24.0');
    expect(tree.stdout).not.toMatch(/^(?:zip|tar|ureq|argon2|reqwest|openai|anthropic) v/m);
  });
  it('has exactly the established non-content IPC command', () => {
    const source = readRepoFile('apps/desktop/src-tauri/src/lib.rs');
    expect(source.match(/#\[tauri::command\]/g)).toHaveLength(1);
    expect(source).toMatch(/generate_handler!\[foundation_status\]/);
    expect(source).not.toMatch(/credential_read|secret_get|read_file|write_file|execute\(|shell\(/);
  });

  it('keeps every secret adapter out of renderer sources', () => {
    for (const path of walkFiles('apps/desktop/src').filter((p) => /\.tsx?$/.test(p))) {
      expect(readRepoFile(path)).not.toMatch(
        /VaultMasterKey|BlobRootKey|DbKey|DeviceKey|RecoverySecret|SecretValue|ProviderSecretStore|keyring|argon2/,
      );
    }
  });

  it('pins only the selected G2 dependencies and disables credential search', () => {
    const manifest = readRepoFile('Cargo.toml');
    expect(manifest).toContain(
      'libsodium-sys-stable = { version = "=1.24.0", default-features = false }',
    );
    expect(readRepoFile('Cargo.lock')).not.toMatch(/name = "argon2"/);
    expect(manifest).toContain('keyring-core = "=1.0.0"');
    expect(manifest).toContain(
      'windows-native-keyring-store = { version = "=1.1.0", default-features = false }',
    );
    const adapter = readRepoFile('crates/dvm-storage/src/credentials.rs');
    expect(adapter).toMatch(/\("persistence", "Local"\)/);
    expect(adapter).not.toMatch(/set_default_store|set_password|get_password|\.search\(/);
  });

  it('confines native unsafety and pins the Windows build without a moving fallback', () => {
    expect(readRepoFile('Cargo.toml')).toContain('unsafe_code = "forbid"');
    expect(readRepoFile('crates/dvm-crypto/Cargo.toml')).toContain('unsafe_code = "deny"');
    expect(readRepoFile('crates/dvm-crypto/src/lib.rs')).toContain(
      '#[allow(unsafe_code)]\nmod sodium;',
    );
    for (const path of walkFiles('crates/dvm-crypto/src').filter((p) => p.endsWith('.rs'))) {
      const source = readRepoFile(path);
      if (!path.endsWith('/sodium.rs')) expect(source).not.toMatch(/unsafe\s*\{/);
      if (!path.endsWith('/lib.rs')) expect(source).not.toMatch(/allow\(unsafe_code\)/);
    }
    const native = readRepoFile('crates/dvm-crypto/src/sodium.rs');
    expect(native).toContain('crypto_pwhash_argon2id_ALG_ARGON2ID13');
    expect(native).toContain('!= b"1.0.22"');
    expect(native).toContain('checked_mul(1024)');
    expect(readRepoFile('crates/dvm-crypto/src/keyslots.rs')).toContain('profile.parallelism != 1');
    expect(readRepoFile('.cargo/config.toml')).toContain(
      'SODIUM_LIB_DIR = { value = ".dvm-local/native/libsodium-1.0.22/lib", relative = true, force = true }',
    );
    const prepare = readRepoFile('scripts/prepare-sodium.mjs');
    expect(prepare).toContain(
      'https://download.libsodium.org/libsodium/releases/libsodium-1.0.22-msvc.zip',
    );
    expect(prepare).toContain('3e03a726fac4bc09cb61d8f29d658ef7a5eca0811de59082130414f7ca2e4279');
    expect(prepare).toContain('62815491f5ef88e83a14194358d8e9a6cd01b7f43b646fcb59a647bd12c88621');
    expect(prepare).not.toMatch(/stable-msvc|fetch-latest|Expand-Archive/);
    expect(readRepoFile('scripts/verify-g0.mjs')).toContain("args: ['scripts/prepare-sodium.mjs']");
    expect(readRepoFile('scripts/verify-g2.mjs')).toContain("['scripts/prepare-sodium.mjs']");
  });

  it('does not admit empty production slots through the G1 fixture parser', () => {
    const source = readRepoFile('crates/dvm-storage/src/header.rs');
    expect(source).toMatch(/pub fn parse\([^]*?validate_production\(&header\)\?/);
    expect(source).toContain('header.keyslots.is_empty()');
    const lifecycle = readRepoFile('crates/dvm-storage/src/security.rs');
    expect(lifecycle).toContain('header::parse(&bytes)');
    expect(lifecycle.indexOf('keyslots::unwrap_passphrase')).toBeLessThan(
      lifecycle.indexOf('Vault::open_with_injected_key'),
    );
  });
});
