/** Pinned native build input only; never imported by the application. ADR-0007. */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const directory = join(root, '.dvm-local', 'native', 'libsodium-1.0.22');
const archive = join(directory, 'libsodium-1.0.22-msvc.zip');
const library = join(directory, 'lib', 'libsodium.lib');
const archiveHash = '3e03a726fac4bc09cb61d8f29d658ef7a5eca0811de59082130414f7ca2e4279';
const libraryHash = '62815491f5ef88e83a14194358d8e9a6cd01b7f43b646fcb59a647bd12c88621';
function matches(path, expected) {
  return createHash('sha256').update(readFileSync(path)).digest('hex') === expected;
}
if (
  Object.hasOwn(process.env, 'SODIUM_SHARED') ||
  Object.hasOwn(process.env, 'SODIUM_USE_PKG_CONFIG')
) {
  throw new Error('Ambient sodium linkage overrides are prohibited by the G2 native pin.');
}
mkdirSync(join(directory, 'lib'), { recursive: true });
if (process.platform === 'linux' && process.arch === 'x64') {
  // Preserve the existing G0 Linux job using the same selected release. Windows
  // credential acceptance remains mandatory separately; this grants no runtime egress.
  const sourceArchive = join(directory, 'libsodium-1.0.22.tar.gz');
  const sourceHash = 'adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349';
  if (!existsSync(sourceArchive)) {
    const response = await fetch(
      'https://download.libsodium.org/libsodium/releases/libsodium-1.0.22.tar.gz',
      { signal: AbortSignal.timeout(120_000) },
    );
    if (!response.ok)
      throw new Error(`Pinned libsodium source download failed: HTTP ${response.status}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (createHash('sha256').update(bytes).digest('hex') !== sourceHash) {
      throw new Error('Pinned libsodium source hash mismatch; nothing installed.');
    }
    writeFileSync(sourceArchive, bytes, { flag: 'wx' });
  }
  if (!matches(sourceArchive, sourceHash))
    throw new Error('Cached libsodium source hash mismatch.');
  const source = join(directory, 'libsodium-1.0.22');
  for (const [command, args, cwd] of [
    ['tar', ['--extract', '--gzip', '--file', sourceArchive, '--no-same-owner'], directory],
    [
      'sh',
      ['./configure', '--disable-shared', '--enable-static', '--with-pic', `--prefix=${directory}`],
      source,
    ],
    ['make', ['-j2'], source],
    ['make', ['install'], source],
  ]) {
    const result = spawnSync(command, args, { cwd, stdio: 'inherit', timeout: 600_000 });
    if (result.status !== 0) throw new Error(`Pinned libsodium source build failed: ${command}`);
  }
  console.log('G0_NATIVE_PIN=PASS libsodium=1.0.22 target=x86_64-unknown-linux-gnu source-build');
  process.exit(0);
}
if (process.platform !== 'win32' || process.arch !== 'x64') {
  throw new Error(
    'Pinned native build requires Windows x64 or Linux x64. Other targets are unverified.',
  );
}
if (!existsSync(archive)) {
  const response = await fetch(
    'https://download.libsodium.org/libsodium/releases/libsodium-1.0.22-msvc.zip',
    { signal: AbortSignal.timeout(120_000) },
  );
  if (!response.ok) throw new Error(`Pinned libsodium download failed: HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (createHash('sha256').update(bytes).digest('hex') !== archiveHash) {
    throw new Error('Pinned libsodium archive hash mismatch; nothing installed.');
  }
  writeFileSync(archive, bytes, { flag: 'wx' });
}
if (!matches(archive, archiveHash)) throw new Error('Cached libsodium archive hash mismatch.');
if (!existsSync(library)) {
  // Extract exactly one known entry to a fixed application-owned path. No archive
  // paths are interpreted as destination paths, and no recursive extraction occurs.
  const extraction = spawnSync(
    'powershell.exe',
    [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$sodiumZip = [IO.Compression.ZipFile]::OpenRead($env:DVM_SODIUM_ARCHIVE)
try {
  $sodiumEntry = $sodiumZip.GetEntry('libsodium/x64/Release/v143/static/libsodium.lib')
  if ($null -eq $sodiumEntry) { throw 'Pinned sodium archive entry missing' }
  [IO.Compression.ZipFileExtensions]::ExtractToFile($sodiumEntry, $env:DVM_SODIUM_LIBRARY, $false)
} finally { $sodiumZip.Dispose() }`,
    ],
    {
      encoding: 'utf8',
      env: { ...process.env, DVM_SODIUM_ARCHIVE: archive, DVM_SODIUM_LIBRARY: library },
    },
  );
  if (extraction.status !== 0) throw new Error('Pinned libsodium extraction failed.');
}
if (!matches(library, libraryHash))
  throw new Error('Pinned libsodium static library hash mismatch.');
console.log('G2_NATIVE_PIN=PASS libsodium=1.0.22 target=x86_64-pc-windows-msvc');
