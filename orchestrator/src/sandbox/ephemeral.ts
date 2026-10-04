/**
 * Ephemeral sandbox: run one shell command against the target, in a throwaway
 * container.
 *
 * ## Why this module exists
 *
 * The other sandbox entry point (`runner.ts`) drives a LONG-LIVED container via
 * `docker exec`. That model leaks state between steps, so a target started in
 * one call is still running for the next.
 *
 * Here, every call is a brand-new `docker run --rm` container. Two calls
 * therefore genuinely cannot see each other -- different containers, different
 * network namespaces, nothing surviving in between.
 *
 * The consequence, and the whole point: booting the app and attacking it must
 * happen in a SINGLE call. You cannot "start the app" and then "curl it" as two
 * calls, because the second call runs in a fresh container where the app is not
 * running. Put the exploit in `options.command` and let the bootstrap happen
 * around it.
 *
 * Readiness is POLLED, never slept on, so a slow start costs nothing extra and a
 * fast one is not penalised by a fixed delay.
 */
import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';
import { config } from '../config.js';
import { createLogger } from '../logger.js';

const execFileAsync = promisify(execFile);
const log = createLogger('sandbox:ephemeral');

export interface SandboxResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
  /** True once the target answered its health check. */
  ready: boolean;
  /** How many readiness probes it took. 0 when nothing was started. */
  probes: number;
  /** Milliseconds from container start to the command being allowed to run. */
  bootMs: number;
}

export interface RunSandboxOptions {
  /**
   * The real work. Runs inside the container once the target is up.
   * This is where exploits and test commands belong.
   */
  command: string;

  /**
   * How to boot the target, as a shell command. Defaults to starting the app.
   * Pass `null` to run `command` with no app at all (useful for inspecting the
   * sandbox itself, or for proving isolation).
   */
  setup?: string | null;

  /**
   * URL polled until it answers, to decide the target is really up.
   * Defaults to the target's health endpoint. Pass `null` to skip polling.
   */
  readyUrl?: string | null;

  /** Max seconds to poll before giving up. */
  readyTimeoutSec?: number;

  /** Hard cap on the whole container run. */
  timeoutMs?: number;

  /**
   * Mount the target read-only (default). An exploit should never be able to
   * rewrite the code it is attacking.
   */
  readOnly?: boolean;

  /** Label for logs. */
  label?: string;
}

/** Absolute host path of the target, resolved from the orchestrator's cwd. */
export function hostTargetPath(): string {
  return path.resolve(process.cwd(), config.sandbox.targetPath);
}

/**
 * Shell script that runs INSIDE the container.
 *
 * Written as an array of single-quoted lines rather than a template literal:
 * the script is full of `$VAR`, `${VAR}` and `$(...)` sequences, and an array
 * keeps every one of them literal, with nothing to escape.
 *
 * Every dynamic value arrives via an environment variable rather than being
 * spliced into this text, so no caller input can break out of the shell.
 */
const SANDBOX_SCRIPT: string = [
  '# No "set -e" here: cleanup must still run when the command under test fails.',
  'set -u',
  '',
  'APP_LOG=/tmp/pp-target.log',
  'APP_PID=""',
  '',
  'if [ -n "${PP_SETUP:-}" ]; then',
  '  eval "$PP_SETUP" >"$APP_LOG" 2>&1 &',
  '  APP_PID=$!',
  'fi',
  '',
  'cleanup() {',
  '  if [ -n "$APP_PID" ]; then',
  '    kill "$APP_PID" 2>/dev/null || true',
  '  fi',
  '}',
  'trap cleanup EXIT INT TERM',
  '',
  '# Poll until the target actually answers. A fixed sleep either wastes time on a',
  '# fast start or gives up on a slow one; polling is correct for both.',
  'if [ -n "${PP_READY_URL:-}" ]; then',
  '  probes=0',
  '  ready=0',
  '  while [ "$probes" -lt "${PP_READY_LIMIT}" ]; do',
  '    if curl -sS -m 2 -o /dev/null "$PP_READY_URL" 2>/dev/null; then',
  '      ready=1',
  '      echo "SANDBOX_READY probes=$probes"',
  '      break',
  '    fi',
  '    # Fail fast if the app died on startup: polling a dead process is pointless,',
  '    # and the captured log says why far more usefully than a timeout would.',
  '    if [ -n "$APP_PID" ] && ! kill -0 "$APP_PID" 2>/dev/null; then',
  '      echo "SANDBOX_TARGET_DIED" >&2',
  '      echo "--- target log ---" >&2',
  '      cat "$APP_LOG" >&2 2>/dev/null || true',
  '      echo "SANDBOX_NOT_READY" >&2',
  '      exit 1',
  '    fi',
  '    probes=$((probes + 1))',
  '    sleep 1',
  '  done',
  '',
  '  if [ "$ready" -ne 1 ]; then',
  '    echo "SANDBOX_NOT_READY after ${PP_READY_LIMIT}s" >&2',
  '    echo "--- target log ---" >&2',
  '    cat "$APP_LOG" >&2 2>/dev/null || true',
  '    exit 1',
  '  fi',
  'else',
  '  echo "SANDBOX_READY probes=0"',
  'fi',
  '',
  '# Now the command the caller actually asked for.',
  'eval "$PP_COMMAND"',
].join('\n');
/** The container's readiness marker. Stripped from stdout before the caller sees it. */
const READY_MARKER = /^\s*SANDBOX_READY probes=\d+\s*$/gm;

/** Removes the internal marker lines, leaving only the caller's own output. */
export function stripMarkers(text: string): string {
  return text.replace(READY_MARKER, '').trim();
}

/**
 * Run a command against the target in a fresh, disposable container.
 *
 * The container has no network, bounded CPU/memory/PIDs, and is removed when it
 * exits (`--rm`), so nothing persists between calls.
 */
export async function runSandboxCommand(options: RunSandboxOptions): Promise<SandboxResult> {
  const label = options.label ?? 'command';
  const setup =
    options.setup === undefined
      ? `cd ${config.sandbox.mountPath} && ${config.sandbox.startCommand}`
      : options.setup;
  const readyUrl =
    options.readyUrl === undefined ? `${config.target.baseUrl}/health` : options.readyUrl;
  const readyTimeoutSec = options.readyTimeoutSec ?? config.sandbox.readyTimeoutSec;
  const timeoutMs = options.timeoutMs ?? config.sandbox.timeoutMs;
  const readOnly = options.readOnly ?? true;

  const startedAt = Date.now();

  const args = [
    'run',
    '--rm',
    // Isolation: loopback only. No route off the host, so exploits cannot call
    // home and the target cannot be reached from outside.
    '--network', config.sandbox.network,
    // Containment: an exploit (or a fork bomb) must not take down the machine.
    '--memory', config.sandbox.memory,
    '--cpus', config.sandbox.cpus,
    '--pids-limit', String(config.sandbox.pidsLimit),
    // The target arrives as a volume rather than being baked into the image.
    '--volume', `${hostTargetPath()}:${config.sandbox.mountPath}${readOnly ? ':ro' : ''}`,
    '--workdir', config.sandbox.mountPath,
    // node:sqlite is experimental on Node 22; its warning is not interesting.
    '--env', 'NODE_NO_WARNINGS=1',
    // Passed as env vars, never spliced into the script text.
    '--env', `PP_SETUP=${setup ?? ''}`,
    '--env', `PP_COMMAND=${options.command}`,
    '--env', `PP_READY_URL=${readyUrl ?? ''}`,
    '--env', `PP_READY_LIMIT=${readyTimeoutSec}`,
    config.sandbox.image,
    'sh', '-lc', SANDBOX_SCRIPT,
  ];

  log.debug(`[${label}] setup: ${setup ?? '(none)'}`);
  log.debug(`[${label}] command: ${options.command}`);

  let result: SandboxResult;
  try {
    const { stdout, stderr } = await execFileAsync('docker', args, {
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,
      windowsHide: true,
    });
    result = { stdout, stderr, exitCode: 0, timedOut: false, ready: false, probes: 0, bootMs: 0 };
  } catch (err) {
    const e = err as NodeJS.ErrnoException & {
      stdout?: string;
      stderr?: string;
      code?: number | string;
      killed?: boolean;
    };
    result = {
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? e.message,
      exitCode: typeof e.code === 'number' ? e.code : e.killed ? 124 : 1,
      timedOut: Boolean(e.killed),
      ready: false,
      probes: 0,
      bootMs: 0,
    };
  }

  // The readiness markers come from the script; parse them back out so callers
  // get structured facts instead of scraping text.
  const output = `${result.stdout}\n${result.stderr}`;
  const readyMatch = output.match(/SANDBOX_READY probes=(\d+)/);
  const diedMatch = output.match(/SANDBOX_TARGET_DIED/);

  result.ready = Boolean(readyMatch) && !diedMatch;
  result.probes = readyMatch?.[1] ? Number.parseInt(readyMatch[1], 10) : 0;
  result.bootMs = Date.now() - startedAt;

  // Keep the machine-readable facts (`ready`, `probes`) but do not leak the
  // marker into the caller's stdout -- callers parse that as their own output,
  // and a stray line would break JSON parsing for no benefit.
  result.stdout = stripMarkers(result.stdout);

  if (!result.ready) log.warn(`[${label}] target never became ready`);
  else log.info(`[${label}] ready after ${result.probes} probe(s), ${result.bootMs}ms`);

  return result;
}