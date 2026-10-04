/**
 * The functional test suite as a correctness gate.
 *
 * Replaying an exploit only proves the BUG is gone. It says nothing about
 * whether the fix broke something else -- an agent that "fixes" SQL injection by
 * deleting the endpoint passes that test and destroys the application.
 *
 * So a patch is only accepted when both hold:
 *   1. the evidence that proved the vulnerability is gone, AND
 *   2. the project's own test suite still passes.
 *
 * This is what makes the pipeline work for ANY vulnerability class rather than
 * only the ones with bespoke detectors: the gate is behavioural, not per-class.
 * It needs no knowledge of what kind of bug was being fixed.
 */
import { runSandboxCommand } from '../sandbox/ephemeral.js';
import { config } from '../config.js';
import { createLogger } from '../logger.js';

const log = createLogger('functional');

export interface FunctionalSuiteResult {
  /** The target's tests all passed. */
  passed: boolean;
  /** How many tests passed, when the output could be parsed. */
  passCount: number | null;
  /** How many failed. */
  failCount: number | null;
  exitCode: number;
  /** Raw output, for the report. */
  output: string;
  /** Why we think it failed, when it did. */
  note?: string;
}

/** `node --test` prints a summary block like "# pass 13" / "# fail 0". */
function parseCounts(output: string): { passCount: number | null; failCount: number | null } {
  const pass = output.match(/^\s*#?\s*pass\s+(\d+)\s*$/im);
  const fail = output.match(/^\s*#?\s*fail\s+(\d+)\s*$/im);
  return {
    passCount: pass?.[1] ? Number.parseInt(pass[1], 10) : null,
    failCount: fail?.[1] ? Number.parseInt(fail[1], 10) : null,
  };
}

/**
 * Run the target project's own test suite inside a throwaway sandbox.
 *
 * No target process is started: the tests boot the app themselves.
 */
export async function runFunctionalSuite(
  testCommand = 'npm test',
  label = 'functional-suite',
): Promise<FunctionalSuiteResult> {
  log.info(`running the functional suite: ${testCommand}`);

  const result = await runSandboxCommand({
    command: testCommand,
    // The suite starts the app itself, so there is nothing to wait for here.
    setup: null,
    readyUrl: null,
    label,
    timeoutMs: config.sandbox.timeoutMs * 2,
  });

  const output = `${result.stdout}\n${result.stderr}`.trim();
  const { passCount, failCount } = parseCounts(output);

  // Fall back to the exit code when the summary block is not recognised.
  const passed = result.exitCode === 0 && (failCount ?? 0) === 0;

  let note: string | undefined;
  if (!passed) {
    note =
      failCount && failCount > 0
        ? `${failCount} test(s) failed -- the fix broke existing behaviour`
        : `suite exited ${result.exitCode}`;
  }

  log.info(`functional suite ${passed ? 'passed' : 'FAILED'}${passCount !== null ? ` (${passCount} pass, ${failCount} fail)` : ''}`);

  return { passed, passCount, failCount, exitCode: result.exitCode, output: output.slice(-4000), ...(note ? { note } : {}) };
}