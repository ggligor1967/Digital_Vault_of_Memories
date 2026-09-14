/** Single-source G2 acceptance; G1 composes G0, including production build. */
import { spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const args = process.argv.slice(2);
if (args.some((a) => !['--ci', '--cleanroom'].includes(a)) || args.length > 1) {
  console.error('Use at most one of --ci or --cleanroom.');
  process.exit(2);
}
if (process.platform !== 'win32') {
  console.error('SKIPPED — NOT VERIFIED ON THIS PLATFORM: Windows G2 acceptance required.');
  process.exit(1);
}
const perl = 'C:\\Strawberry\\perl\\bin';
if (!existsSync(join(perl, 'perl.exe'))) {
  console.error('Required native Strawberry Perl is absent.');
  process.exit(1);
}
const evidence = join(root, '.dvm-local', 'g2');
mkdirSync(evidence, { recursive: true });
const env = { ...process.env, PATH: `${perl};${process.env.PATH}`, CARGO_BUILD_JOBS: '2' };
function run(command, commandArgs, marker) {
  console.log(`G2: ${command} ${commandArgs.join(' ')}`);
  const result = spawnSync(command, commandArgs, {
    cwd: root,
    env,
    shell: true,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  process.stdout.write(output);
  appendFileSync(join(evidence, 'gate.log'), output);
  const status = result.status ?? 1;
  console.log(`EXIT ${status}`);
  if (status !== 0 || (marker && !output.includes(marker))) {
    console.error('G2 acceptance FAIL; remaining steps NOT RUN.');
    process.exit(status || 1);
  }
}
run('node', ['scripts/prepare-sodium.mjs'], 'G2_NATIVE_PIN=PASS');
run('node', ['scripts/g2-negative-controls.mjs'], 'G2_NEGATIVE_CONTROLS=PASS');
run('node', ['scripts/verify-g1.mjs', ...args]);
run(
  'cargo',
  [
    'test',
    '--locked',
    '--release',
    '-p',
    'dvm-storage',
    '--lib',
    'security::tests',
    '--',
    '--nocapture',
  ],
  'G2_TEST_CREDENTIAL_RESIDUE=NONE',
);
run('cargo', ['test', '--locked', '--release', '-p', 'dvm-application', '--lib', 'session::tests']);
run('cargo', [
  'test',
  '--locked',
  '--release',
  '-p',
  'dvm-observability',
  '--lib',
  'g2_secret_canaries',
  '--',
  '--nocapture',
]);
// Only generated, application-owned G2 outputs are scanned. Source code and user
// data are excluded; a real synthetic credential canary must never reach a log.
for (const file of readdirSync(evidence).filter((name) => /\.(log|json|jsonl)$/.test(name))) {
  if (
    /DVM_G2_(?:PROVIDER_SECRET|(?:passphrase|recovery|vmk|passphrase-kek|recovery-kek|device-kek|db-key|blob-root|provider-secret))_[a-f0-9-]{36}/.test(
      readFileSync(join(evidence, file), 'utf8'),
    )
  ) {
    console.error('SECRET_LOG_LEAKAGE=YES; value withheld.');
    process.exit(1);
  }
}
run('git', ['diff', '--check']);
const mode = args.includes('--ci')
  ? 'CI_G2'
  : args.includes('--cleanroom')
    ? 'CLEAN_ROOM_G2'
    : 'LOCAL_G2';
console.log(`SECRET_LOG_LEAKAGE=NO ${mode}=PASS`);
