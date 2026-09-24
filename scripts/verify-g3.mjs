/** G3 acceptance composes G2 and runs every G3 recovery oracle on Windows. */
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, statfsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const args = process.argv.slice(2);
if (args.length > 1 || args.some((arg) => !['--ci', '--cleanroom'].includes(arg))) {
  console.error('Use at most one of --ci or --cleanroom.');
  process.exit(2);
}
if (process.platform !== 'win32') {
  console.error('Windows G3 destructive restore acceptance is mandatory.');
  process.exit(1);
}
const perl = 'C:\\Strawberry\\perl\\bin';
if (!existsSync(join(perl, 'perl.exe'))) {
  console.error('Required native Strawberry Perl is absent.');
  process.exit(1);
}
const env = {
  ...process.env,
  PATH: `${perl};${process.env.PATH}`,
  CARGO_BUILD_JOBS: '2',
  DVM_G3_TRIM_DEBUG_AFTER_G0: '1',
};
// G1's retained 2 GiB fixture can coexist with encrypted and recovered copies;
// allow another 1 GiB for G3 staging and a conservative build margin.
const expectedLocalBytes = 8 * 1024 ** 3;
const availableBytes = statfsSync(root).bavail * statfsSync(root).bsize;
console.log(`G3_DISK_PREFLIGHT required=${expectedLocalBytes} available=${availableBytes}`);
if (!args.includes('--ci') && availableBytes < expectedLocalBytes) {
  console.error('Insufficient free disk for the required local G1/G3 acceptance.');
  process.exit(1);
}
const knownTemps = new Set(readdirSync(tmpdir()).filter((name) => name.startsWith('dvm-g3-')));
function run(command, commandArgs, required = []) {
  const disk = statfsSync(root);
  console.log(`G3 disk free before ${command}: ${disk.bavail * disk.bsize} bytes`);
  console.log(`G3: ${command} ${commandArgs.join(' ')}`);
  const result = spawnSync(command, commandArgs, {
    cwd: root,
    env,
    shell: true,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  process.stdout.write(output);
  const code = result.status ?? 1;
  console.log(`G3 EXIT ${code}`);
  if (code !== 0 || required.some((marker) => !output.includes(marker))) {
    console.error('G3 acceptance FAIL; remaining steps NOT RUN.');
    process.exit(code || 1);
  }
}

run('node', ['scripts/prepare-sodium.mjs'], ['G2_NATIVE_PIN=PASS']);
run('node', ['scripts/g3-negative-controls.mjs'], ['G3_NEGATIVE_CONTROLS=PASS']);
run('node', ['scripts/verify-g2.mjs', ...args]);
run(
  'cargo',
  ['test', '--locked', '--release', '-p', 'dvm-storage', '--lib', 'g3_', '--', '--nocapture'],
  ['G3_MIGRATION_CRASH_MATRIX=PASS', 'G3_FUTURE_SCHEMA_NO_MUTATION=PASS'],
);
run(
  'cargo',
  ['test', '--locked', '--release', '-p', 'dvm-backup', '--lib', '--', '--nocapture'],
  [
    'G3_DVBK1_FULL=PASS',
    'G3_DESTRUCTIVE_RESTORE=PASS',
    'G3_BACKUP_CRASH_MATRIX=PASS',
    'G3_RESTORE_CRASH_MATRIX=PASS',
    'G3_ARCHIVE_PATH_TRAVERSAL_REJECTED=PASS',
    'G3_CORRUPTION_MATRIX=PASS',
    'G3_FULL_COMPLETENESS_NEGATIVE=PASS',
    'G3_PLAINTEXT_HASH_MISMATCH_NEGATIVE=PASS',
    'G3_PLAINTEXT_SNAPSHOT_NEGATIVE=PASS',
    'G3_BACKUP_DISK_FULL=PASS',
    'G3_SNAPSHOT_CONCURRENT_IMPORT_BOUNDARY=PASS',
    'G3_MAINTENANCE_COORDINATION=PASS',
    'G3_BOUNDED_MEMORY=PASS',
  ],
);
const residue = readdirSync(tmpdir()).filter(
  (name) => name.startsWith('dvm-g3-') && !knownTemps.has(name),
);
if (residue.length > 0) {
  console.error(`G3 test-owned temp residue count: ${residue.length}`);
  process.exit(1);
}
run('git', ['diff', '--check']);
run('git', ['diff', '--cached', '--check']);
if (args.includes('--ci')) {
  console.log('Inherited G1 multi-GB runtime: SKIPPED — NOT VERIFIED BY CI (verify:g2 --ci).');
  console.log('G3 destructive restore: EXECUTED IN CI.');
}
const mode = args.includes('--ci')
  ? 'CI_G3'
  : args.includes('--cleanroom')
    ? 'CLEAN_ROOM_G3'
    : 'LOCAL_G3';
console.log(`G3_TEST_RESIDUE=NONE G3_MANDATORY_SKIPS=0 ${mode}=PASS`);
