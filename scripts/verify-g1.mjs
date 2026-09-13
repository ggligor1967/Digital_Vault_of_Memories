/** G1 acceptance composes the foundation gate and explicitly required heavyweight proof. */
import { spawnSync } from 'node:child_process';
import { appendFileSync, statfsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const argv = process.argv.slice(2);
for (const argument of argv) {
  if (!['--ci', '--cleanroom'].includes(argument)) {
    console.error(`Unknown G1 argument: ${argument}`);
    process.exit(2);
  }
}
const ci = argv.includes('--ci');
if (ci && argv.includes('--cleanroom')) {
  console.error('A clean-room run cannot skip mandatory local gates.');
  process.exit(2);
}
const summary = (line) => {
  console.log(line);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${line}\n`);
};
function run(command, args) {
  const disk = statfsSync(root);
  summary(`Disk before ${command}: ${disk.bavail * disk.bsize} bytes free`);
  const started = Date.now();
  const result = spawnSync(command, args, {
    cwd: root,
    env: { ...process.env, DVM_VERIFICATION_GATE: 'G1' },
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  const code = result.status ?? 1;
  summary(
    `${command} ${args.join(' ')} -> EXIT ${code}; elapsed ${(Date.now() - started) / 1000}s`,
  );
  if (code !== 0) {
    summary('G1 LOCAL ACCEPTANCE: FAIL; remaining gates NOT RUN');
    process.exit(code);
  }
}
summary('DVM-V2 / G1 — ZERO-LOSS VAULT STORAGE');
run('node', ['scripts/verify-g0.mjs', ...(ci ? ['--no-runtime'] : [])]);
// cfg(test) child-process matrix is part of the foundation workspace Rust tests.
// Release testing separately verifies optimized crypto and the same real storage paths.
run('cargo', [
  'test',
  '--locked',
  '--release',
  '-p',
  'dvm-crypto',
  '-p',
  'dvm-storage',
  '--',
  '--nocapture',
]);
if (ci) {
  summary('Multi-GB import/recovery: SKIPPED — NOT VERIFIED BY CI');
  summary('Desktop interactive runtime: SKIPPED — NOT VERIFIED BY CI');
  summary('G1 CI checks passed; full local acceptance NOT VERIFIED BY CI.');
} else {
  if (process.platform !== 'win32') {
    summary('Mandatory measured Windows multi-GB gate unavailable: FAIL');
    process.exit(1);
  }
  run('cargo', [
    'test',
    '--locked',
    '--release',
    '-p',
    'dvm-storage',
    '--lib',
    'tests::multi_gb_bounded_memory',
    '--',
    '--exact',
    '--ignored',
    '--nocapture',
  ]);
  summary('G1 LOCAL ACCEPTANCE: PASS; multi-GB and crash gates executed');
}
