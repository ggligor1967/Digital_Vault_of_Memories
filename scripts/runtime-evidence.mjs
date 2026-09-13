/**
 * Autonomous runtime evidence for gate G0.
 *
 * Compiling is not proof that the IPC boundary works. This script starts the
 * real desktop application, waits for the renderer to call `foundation_status`
 * through the real Tauri transport, captures the sanitised structured event the
 * trusted backend emits when it serves that command, then shuts the process
 * down and checks that it left no crash residue.
 *
 * Usage:
 *
 *   node scripts/runtime-evidence.mjs [--timeout <seconds>]
 *
 * Exit code 0 means the evidence was captured. Any other exit code means it
 * was not, and G0 cannot be reported as PASS.
 */
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));
const EVIDENCE_DIR = join(REPO_ROOT, '.dvm-local', 'g0-runtime-evidence');
const DIAGNOSTICS_FILE = join(EVIDENCE_DIR, 'diagnostics.jsonl');
const PROCESS_LOG = join(EVIDENCE_DIR, 'tauri-dev.log');
const SUMMARY_FILE = join(EVIDENCE_DIR, 'summary.json');

/** Event the trusted backend emits once it has served `foundation_status`. */
const EXPECTED_EVENT = 'foundation_status_served';

/** Strings that indicate the process died rather than being shut down. */
const CRASH_MARKERS = [
  'panicked at',
  'STATUS_ACCESS_VIOLATION',
  'STATUS_ENTRYPOINT_NOT_FOUND',
  'STATUS_STACK_BUFFER_OVERRUN',
  'fatal runtime error',
  'Exception 0x',
];

/** How long to let the application start and answer, in milliseconds. */
const DEFAULT_TIMEOUT_MS = 240_000;

/** Grace period between asking a process to stop and forcing it. */
const GRACEFUL_SHUTDOWN_MS = 5_000;

const args = process.argv.slice(2);
const timeoutMs = readTimeout(args) ?? DEFAULT_TIMEOUT_MS;

/** Parses `--timeout <seconds>`. */
function readTimeout(argv) {
  const index = argv.indexOf('--timeout');
  if (index === -1) return undefined;
  const seconds = Number(argv[index + 1]);
  return Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : undefined;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Whether a process id still exists. */
function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Image name of the desktop application process. */
const APP_IMAGE_NAME = 'dvm-desktop.exe';

/** Whether a process with the given image name is currently running. */
function appProcessRunning() {
  if (process.platform !== 'win32') return false;

  const listed = spawnSync('tasklist', ['/FI', `IMAGENAME eq ${APP_IMAGE_NAME}`], {
    encoding: 'utf8',
  });
  return (listed.stdout ?? '').includes(APP_IMAGE_NAME);
}

/**
 * Asks the application window to close, the way a user would.
 *
 * `taskkill` without `/F` posts `WM_CLOSE` to the process's windows, so the
 * application runs its own shutdown path. It is targeted by image name rather
 * than through the supervisor's process tree: `cargo run` sits between the two
 * and the tree walk does not reliably reach the grandchild.
 *
 * Returns whether the application had exited by the end of the grace period.
 */
async function closeApplicationWindow() {
  if (process.platform !== 'win32') return false;
  if (!appProcessRunning()) return true;

  spawnSync('taskkill', ['/IM', APP_IMAGE_NAME], { stdio: 'ignore' });

  const deadline = Date.now() + GRACEFUL_SHUTDOWN_MS;
  while (Date.now() < deadline) {
    if (!appProcessRunning()) return true;
    await sleep(200);
  }

  return false;
}

/**
 * Stops the supervising process tree rooted at `pid`.
 *
 * The root is the Tauri CLI: a console process with no window, which therefore
 * has nothing for a `WM_CLOSE` to reach. Once the application itself has been
 * closed, terminating the supervisor is the normal way to end a `tauri dev`
 * session and is not a crash — which is why the evidence records the
 * application's exit and the supervisor's separately rather than collapsing
 * them into one "clean shutdown" claim.
 */
async function stopSupervisor(pid) {
  if (!isAlive(pid)) return 'already exited';

  if (process.platform === 'win32') {
    spawnSync('taskkill', ['/PID', String(pid), '/T'], { stdio: 'ignore' });
  } else {
    try {
      process.kill(-pid, 'SIGTERM');
    } catch {
      process.kill(pid, 'SIGTERM');
    }
  }

  const deadline = Date.now() + GRACEFUL_SHUTDOWN_MS;
  while (Date.now() < deadline) {
    if (!isAlive(pid)) return 'exited on request';
    await sleep(200);
  }

  if (process.platform === 'win32') {
    spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore' });
  } else {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      process.kill(pid, 'SIGKILL');
    }
  }

  await sleep(500);
  return 'terminated after the request went unanswered';
}

/** Closes the application, then stops its supervisor. */
async function shutDown(pid) {
  const appClosedGracefully = await closeApplicationWindow();
  const tree = await stopSupervisor(pid);
  return { tree, appClosedGracefully };
}

/** Reads the diagnostics sink and returns the parsed events it contains. */
function readDiagnosticEvents() {
  if (!existsSync(DIAGNOSTICS_FILE)) return [];

  return readFileSync(DIAGNOSTICS_FILE, 'utf8')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .flatMap((line) => {
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    });
}

function fail(message, details) {
  console.error(`\nRUNTIME EVIDENCE: FAILED\n  ${message}`);
  if (details) console.error(`  ${details}`);
  console.error(`\n  Process log: ${PROCESS_LOG}`);
  process.exitCode = 1;
}

async function main() {
  rmSync(EVIDENCE_DIR, { recursive: true, force: true });
  mkdirSync(EVIDENCE_DIR, { recursive: true });

  console.log('Runtime evidence for DVM-V2 / G0');
  console.log(`  diagnostics sink : ${DIAGNOSTICS_FILE}`);
  console.log(`  process log      : ${PROCESS_LOG}`);
  console.log(`  timeout          : ${timeoutMs / 1000}s`);
  console.log('\nStarting the desktop application (tauri dev)...\n');

  // The Tauri CLI is invoked through Node directly rather than through pnpm so
  // that the process id captured here is the real root of the process tree.
  const cliEntry = join(REPO_ROOT, 'node_modules', '@tauri-apps', 'cli', 'tauri.js');
  if (!existsSync(cliEntry)) {
    fail('the Tauri CLI is not installed', 'run `pnpm install --frozen-lockfile` first');
    return;
  }

  const child = spawn(process.execPath, [cliEntry, 'dev'], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      DVM_G0_DIAGNOSTICS_FILE: DIAGNOSTICS_FILE,
      // Colour codes would make the captured log harder to quote as evidence.
      NO_COLOR: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
    windowsHide: false,
  });

  let output = '';
  const capture = (chunk) => {
    const text = chunk.toString();
    output += text;
    process.stdout.write(text);
  };
  child.stdout.on('data', capture);
  child.stderr.on('data', capture);

  let exitedEarly = false;
  let earlyExitCode = null;
  child.on('exit', (code) => {
    exitedEarly = true;
    earlyExitCode = code;
  });

  const startedAt = Date.now();
  let events = [];
  let served;

  while (Date.now() - startedAt < timeoutMs) {
    events = readDiagnosticEvents();
    served = events.find((event) => event.event === EXPECTED_EVENT);
    if (served) break;
    if (exitedEarly) break;
    await sleep(500);
  }

  const elapsedMs = Date.now() - startedAt;
  const aliveWhenServed = !exitedEarly && isAlive(child.pid);

  writeFileSync(PROCESS_LOG, output, 'utf8');

  if (!served) {
    await shutDown(child.pid);

    if (exitedEarly) {
      fail(
        `the application exited before serving ${EXPECTED_EVENT}`,
        `exit code ${String(earlyExitCode)} after ${Math.round(elapsedMs / 1000)}s`,
      );
    } else {
      fail(
        `${EXPECTED_EVENT} was not observed within ${timeoutMs / 1000}s`,
        `${events.length} other diagnostic event(s) were captured`,
      );
    }
    return;
  }

  console.log(`\n\nCaptured ${EXPECTED_EVENT} after ${Math.round(elapsedMs / 1000)}s.`);
  console.log(`  ${JSON.stringify(served)}`);

  const termination = await shutDown(child.pid);
  await sleep(500);
  const appStillRunning = appProcessRunning();

  const finalOutput = output;
  writeFileSync(PROCESS_LOG, finalOutput, 'utf8');

  const crashes = CRASH_MARKERS.filter((marker) => finalOutput.includes(marker));
  const stillAlive = isAlive(child.pid);

  const summary = {
    gate: 'G0',
    launch_method: 'tauri dev (debug build, real Tauri IPC transport)',
    process_id: child.pid,
    process_alive_when_served: aliveWhenServed,
    seconds_to_first_event: Math.round(elapsedMs / 1000),
    diagnostic_events_captured: events.length,
    foundation_status_event: served,
    termination: termination.tree,
    application_closed_on_request: termination.appClosedGracefully,
    process_alive_after_termination: stillAlive,
    application_running_after_termination: appStillRunning,
    crash_markers_found: crashes,
  };
  writeFileSync(SUMMARY_FILE, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

  const problems = [];
  if (!aliveWhenServed) problems.push('the process was not alive when the event was served');
  if (served.status !== 'ok') problems.push(`status was "${String(served.status)}", expected "ok"`);
  if (typeof served.contract_version !== 'string' || served.contract_version.length === 0) {
    problems.push('the event carried no contract_version');
  }
  if (stillAlive) problems.push('the supervising process was still running after termination');
  if (appStillRunning) problems.push('the application was still running after termination');
  if (crashes.length > 0) problems.push(`crash residue found: ${crashes.join(', ')}`);

  if (problems.length > 0) {
    fail('the captured evidence is not clean', problems.join('; '));
    return;
  }

  console.log('\nRUNTIME EVIDENCE: CAPTURED');
  console.log(`  process alive when served : ${String(aliveWhenServed)}`);
  console.log(`  application closed on ask : ${String(termination.appClosedGracefully)}`);
  console.log(`  supervising tree stopped  : ${termination.tree}`);
  console.log(`  crash residue             : none`);
  console.log(`  summary                   : ${SUMMARY_FILE}`);
}

await main();
