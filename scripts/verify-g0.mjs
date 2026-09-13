/**
 * Aggregate verification for `DVM-V2 / G0 — REPOSITORY FOUNDATION`.
 *
 * This is the single implementation of "is the foundation green?". Both a
 * contributor on Windows and the CI workflow run *this* script, so the two can
 * never drift into checking different things — which is the whole point of the
 * G0 requirement that CI execute the same commands as local development.
 *
 * Usage:
 *
 *   node scripts/verify-g0.mjs [--no-runtime] [--no-tauri-build] [--list]
 *
 * Every step's exact command and exit code is printed, and the summary table
 * at the end is the record that goes into the gate evidence file.
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

const argv = process.argv.slice(2);
const skipRuntime = argv.includes('--no-runtime');
const skipTauriBuild = argv.includes('--no-tauri-build');
const listOnly = argv.includes('--list');

/**
 * The gate's verification steps, in dependency order.
 *
 * `group` mirrors the structure the evidence file uses, so the summary can be
 * transcribed into it without rearranging anything.
 */
const STEPS = [
  {
    id: 'install',
    group: 'Reproducibility',
    description: 'frozen-lockfile install',
    command: 'pnpm',
    args: ['install', '--frozen-lockfile'],
  },
  {
    id: 'lockfile-pnpm',
    group: 'Reproducibility',
    description: 'pnpm-lock.yaml unchanged by the frozen install',
    command: 'git',
    args: ['diff', '--exit-code', '--', 'pnpm-lock.yaml'],
  },
  {
    id: 'cargo-metadata',
    group: 'Reproducibility',
    description: 'cargo metadata resolves against the committed lockfile',
    command: 'cargo',
    args: ['metadata', '--locked', '--format-version', '1', '--quiet'],
    quiet: true,
  },
  {
    id: 'lockfile-cargo',
    group: 'Reproducibility',
    description: 'Cargo.lock unchanged by locked resolution',
    command: 'git',
    args: ['diff', '--exit-code', '--', 'Cargo.lock'],
  },

  {
    id: 'format',
    group: 'Frontend',
    description: 'Prettier format check',
    command: 'pnpm',
    args: ['run', 'format:check'],
  },
  {
    id: 'lint',
    group: 'Frontend',
    description: 'ESLint',
    command: 'pnpm',
    args: ['run', 'lint'],
  },
  {
    id: 'typecheck',
    group: 'Frontend',
    description: 'TypeScript typecheck (all workspace packages)',
    command: 'pnpm',
    args: ['run', 'typecheck'],
  },
  {
    id: 'frontend-tests',
    group: 'Frontend',
    description: 'renderer unit tests',
    command: 'pnpm',
    args: ['--filter', '@dvm/desktop', 'run', 'test'],
  },

  {
    id: 'rust-fmt',
    group: 'Rust',
    description: 'rustfmt check',
    command: 'cargo',
    args: ['fmt', '--all', '--', '--check'],
  },
  {
    id: 'rust-clippy',
    group: 'Rust',
    description: 'Clippy with warnings denied',
    command: 'cargo',
    args: [
      'clippy',
      '--workspace',
      '--all-targets',
      '--all-features',
      '--locked',
      '--',
      '-D',
      'warnings',
    ],
  },
  {
    id: 'rust-tests',
    group: 'Rust',
    description: 'Rust unit and contract-drift tests',
    command: 'cargo',
    args: ['test', '--workspace', '--locked'],
  },

  {
    id: 'security',
    group: 'Security and scope',
    description: 'capability, CSP, dependency-scope and architecture assertions',
    command: 'pnpm',
    args: ['--filter', '@dvm/security-tests', 'run', 'test'],
  },

  {
    id: 'build',
    group: 'Build',
    description: 'production renderer bundle',
    command: 'pnpm',
    args: ['run', 'build'],
  },
  {
    id: 'tauri-build',
    group: 'Build',
    description: 'Tauri release compile smoke (no bundling)',
    command: 'pnpm',
    args: ['exec', 'tauri', 'build', '--no-bundle'],
    skip: skipTauriBuild,
    skipReason: '--no-tauri-build was passed',
  },

  {
    id: 'runtime',
    group: 'Runtime',
    description: 'launch the desktop app and capture foundation_status IPC evidence',
    command: 'node',
    args: ['scripts/runtime-evidence.mjs'],
    skip: skipRuntime,
    skipReason: '--no-runtime was passed (no interactive desktop session available)',
  },
];

/** Renders a step as the command line a human would type. */
function renderCommand(step) {
  return [step.command, ...step.args].join(' ');
}

if (listOnly) {
  for (const step of STEPS) {
    console.log(`${step.id.padEnd(16)} ${renderCommand(step)}`);
  }
  process.exit(0);
}

console.log('DVM-V2 / G0 — REPOSITORY FOUNDATION');
console.log('Aggregate verification\n');

const results = [];
let firstFailure = null;

for (const step of STEPS) {
  if (step.skip) {
    console.log(`\n─── SKIP  ${step.id}: ${step.description}`);
    console.log(`         ${step.skipReason}`);
    results.push({ ...step, status: 'SKIPPED', code: null });
    continue;
  }

  console.log(`\n─── RUN   ${step.id}: ${step.description}`);
  console.log(`         $ ${renderCommand(step)}`);

  const started = Date.now();
  const outcome = spawnSync(step.command, step.args, {
    cwd: REPO_ROOT,
    stdio: step.quiet ? ['ignore', 'ignore', 'inherit'] : 'inherit',
    shell: process.platform === 'win32',
  });
  const seconds = ((Date.now() - started) / 1000).toFixed(1);

  const code = outcome.status ?? (outcome.error ? 127 : 1);
  results.push({ ...step, status: code === 0 ? 'PASS' : 'FAIL', code, seconds });

  if (outcome.error) {
    console.error(`         could not run: ${outcome.error.message}`);
  }
  console.log(`         exit ${code} (${seconds}s)`);

  if (code !== 0) {
    firstFailure ??= step.id;
    // Stop at the first failure: later steps would report cascading noise
    // rather than new information, and the gate is already not green.
    break;
  }
}

console.log(`\n${'='.repeat(72)}`);
console.log('G0 VERIFICATION SUMMARY');
console.log('='.repeat(72));

let currentGroup = null;
for (const result of results) {
  if (result.group !== currentGroup) {
    currentGroup = result.group;
    console.log(`\n${currentGroup}`);
  }
  const code = result.code === null ? '   -' : String(result.code).padStart(4);
  console.log(`  ${result.status.padEnd(8)} exit ${code}  ${renderCommand(result)}`);
}

const notRun = STEPS.length - results.length;
const skipped = results.filter((r) => r.status === 'SKIPPED');
const failed = results.filter((r) => r.status === 'FAIL');

console.log(`\n${'-'.repeat(72)}`);
console.log(
  `steps: ${String(results.length - skipped.length)} run, ${String(skipped.length)} skipped, ` +
    `${String(failed.length)} failed, ${String(notRun)} not reached`,
);

if (failed.length > 0) {
  console.log(`\nG0 VERDICT: FAIL (first failure: ${String(firstFailure)})`);
  process.exit(1);
}

if (skipped.length > 0) {
  console.log('\nG0 VERDICT: PASS for the steps executed.');
  console.log('            Skipped steps are NOT verified and must not be reported as passing:');
  for (const step of skipped) {
    console.log(`              - ${step.id}: ${step.skipReason}`);
  }
  process.exit(0);
}

console.log('\nG0 VERDICT: PASS (all steps executed and green)');
