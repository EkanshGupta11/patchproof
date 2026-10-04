/**
 * Everything that touches Docker lives here.
 *
 * The sandbox is disposable by design: exploits are replayed inside it, and we
 * reset it between runs so a patch from one iteration cannot mask the next test.
 */
import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';
import { config } from '../config.js';
import { createLogger } from '../logger.js';
import {
  runSandboxCommand as runEphemeral,
  type SandboxResult,
  type RunSandboxOptions,
} from './ephemeral.js';

const execFileAsync = promisify(execFile);
const log = createLogger('sandbox');

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
}

async function runBinary(file: string, args: string[], timeoutMs: number): Promise<CommandResult> {
  try {
    const { stdout, stderr } = await execFileAsync(file, args, {
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,
      windowsHide: true,
    });
    return { stdout, stderr, exitCode: 0, timedOut: false };
  } catch (err) {
    const e = err as NodeJS.ErrnoException & {
      stdout?: string;
      stderr?: string;
      code?: number | string;
      killed?: boolean;
    };
    return {
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? e.message,
      exitCode: typeof e.code === 'number' ? e.code : e.killed ? 124 : 1,
      timedOut: Boolean(e.killed),
    };
  }
}

/** Run an arbitrary `docker` subcommand. */
export function docker(args: string[], timeoutMs = config.sandbox.timeoutMs): Promise<CommandResult> {
  log.debug(`docker ${args.join(' ')}`);
  return runBinary('docker', args, timeoutMs);
}

/** Build the sandbox image from sandbox/Dockerfile. */
export async function buildSandbox(): Promise<CommandResult> {
  log.info(`building image ${config.sandbox.image}`);
  return docker(['build', '-t', config.sandbox.image, '.'], 10 * 60_000);
}

/**
 * Absolute host path of the target, mounted into the sandbox.
 *
 * Resolved from the orchestrator's own working directory, not from the config's
 * relative default, so `docker run` receives an unambiguous path.
 */
export function hostTargetPath(): string {
  return path.resolve(process.cwd(), config.sandbox.targetPath);
}

/**
 * Start the sandbox container detached.
 *
 * The image is a bare toolbox (node + curl); the target arrives as a volume and
 * runs inside the container, so exploits can reach it over loopback while the
 * container itself has no route off the host.
 */
export async function startSandbox(): Promise<CommandResult> {
  log.info(`starting container ${config.sandbox.name}`);
  await stopSandbox();

  const args = [
    'run',
    '-d',
    '--name', config.sandbox.name,
    '--network', config.sandbox.network,
    '--memory', config.sandbox.memory,
    '--cpus', config.sandbox.cpus,
    // No published ports: nothing outside the container needs to reach the
    // target. Exploits run from the inside.
    '-v', `${hostTargetPath()}:${config.sandbox.mountPath}`,
  ];

  args.push(config.sandbox.image);
  return docker(args);
}

/**
 * Start the target app inside the running sandbox.
 *
 * The orchestrator assumes the app is already listening; if it is not, exploit
 * replay would fail for the wrong reason, so we (re)start it here.
 */
export async function startTarget(): Promise<CommandResult> {
  log.info('starting the target inside the sandbox');
  return execInSandbox(
    `cd ${config.sandbox.mountPath} && (node src/server.js > /tmp/target.log 2>&1 &)`,
    15_000,
  );
}

/** Stop the target app inside the sandbox, if it is running. */
export async function stopTarget(): Promise<CommandResult> {
  return execInSandbox(`pkill -f 'node src/server.js' || true`);
}

/**
 * Restart the sandbox so it re-reads the (possibly patched) target source from
 * the bind mount without a full image rebuild, then bring the target back up.
 */
export async function restartSandbox(): Promise<CommandResult> {
  log.info(`restarting container ${config.sandbox.name}`);
  const result = await docker(['restart', config.sandbox.name], 60_000);
  await startTarget();
  return result;
}

/** Stop and remove the sandbox container. */
export async function stopSandbox(): Promise<CommandResult> {
  return docker(['rm', '-f', config.sandbox.name], 60_000);
}

/**
 * Run a command in a FRESH, disposable container -- see `ephemeral.ts`.
 *
 * This is the entry point the exploit pipeline should use. Unlike
 * {@link execInSandbox}, it needs no pre-started container, leaks no state
 * between calls, and boots the target itself.
 */
export async function runSandboxCommand(options: RunSandboxOptions): Promise<SandboxResult> {
  return runEphemeral(options);
}

/**
 * Run a shell command INSIDE the sandbox.
 * This is how exploits are executed: never on the host.
 */
export async function execInSandbox(command: string, timeoutMs = config.sandbox.timeoutMs): Promise<CommandResult> {
  log.debug(`exec: ${command}`);
  return runBinary('docker', ['exec', config.sandbox.name, 'sh', '-lc', command], timeoutMs);
}

/** Wait until the target inside the sandbox answers its health check. */
export async function waitForTarget(attempts = 20, delayMs = 1000): Promise<boolean> {
  for (let i = 0; i < attempts; i += 1) {
    const res = await execInSandbox(
      `curl -fsS -o /dev/null -w "%{http_code}" ${config.target.baseUrl}/health`,
      10_000,
    );
    if (res.exitCode === 0 && res.stdout.trim() === '200') {
      log.info('target is healthy');
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  log.warn('target never became healthy');
  return false;
}
