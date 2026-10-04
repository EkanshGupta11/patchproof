/**
 * Deterministic proof that a patch works.
 *
 * ## No language model is involved
 *
 * Nothing in this module's import graph touches the LLM layer. Every judgement
 * below is made by running commands and comparing their output. That is the
 * entire point: the AI proposed the fix, but the AI does not get to grade its own
 * homework. A patch agent that says "I fixed it" is not evidence -- this file is.
 *
 * ## Why it is differential
 *
 * Showing that an exploit fails against a patched app proves little on its own.
 * The exploit could have broken, the endpoint could have been deleted, or the app
 * could have stopped booting -- all of which make the exploit "fail" while
 * leaving things worse off.
 *
 * So the SAME exploit is replayed twice inside this function:
 *
 *   baseline - against the original code.   The exploit MUST fire.
 *   patched  - against the patched code.    The exploit MUST NOT fire.
 *
 * Only when both hold can we conclude anything. This also validates the oracle
 * itself: if the declared success signal does not appear on the vulnerable
 * build, we do not trust it on the patched one.
 *
 * ## Two independent gates
 *
 *   1. the exploit is neutralised, AND
 *   2. the project's own test suite still passes.
 *
 * Gate 2 is what blocks the degenerate fix -- disabling or deleting the endpoint
 * satisfies gate 1 while destroying the app. It is behavioural rather than
 * vulnerability-specific, so this works for any class of bug.
 */
import { overwriteSourceFile } from '../target/source.js';
import { runSandboxCommand } from '../sandbox/ephemeral.js';
import { runFunctionalSuite } from '../agents/functionalSuite.js';
import { config } from '../config.js';
import { createLogger } from '../logger.js';

const log = createLogger('prove');

export type ProofVerdict =
  /** Exploit fired before, is dead after, and the suite still passes. */
  | 'verified'
  /** The exploit still works: the patch did not fix the vulnerability. */
  | 'regression'
  /** The exploit is gone but the application no longer works correctly. */
  | 'functional-break'
  /** The exploit did not fire even on the unpatched build; nothing was proven. */
  | 'inconclusive';

export interface ProofSpec {
  findingId: string;
  /** The file the patch changes. */
  file: string;
  /** Contents before the patch. */
  originalContent: string;
  /** Contents after the patch. */
  patchedContent: string;
  /** The exploit, exactly as the exploit agent left it. */
  exploitCommand: string;
  /**
   * A literal present in output only when the vulnerability is present.
   * Validated against the baseline before being trusted on the patched build.
   */
  successSignal?: string;
  /** Optional classification, used for reporting only. */
  vulnerabilityClass?: string;
  /** How to run the project's tests. */
  testCommand?: string;
}

export interface PhaseOutcome {
  /** The exploit signal was present in the output. */
  fired: boolean;
  exitCode: number;
  output: string;
}

export interface FixProof {
  findingId: string;
  verdict: ProofVerdict;
  /** The exploit against the original code. Must fire. */
  baseline: PhaseOutcome;
  /** The same exploit against the patched code. Must not fire. */
  patched: PhaseOutcome;
  /** True when the two outputs differ, i.e. the patch changed behaviour. */
  behaviourChanged: boolean;
  /** The project's own test suite, run after the patch. */
  functional: {
    passed: boolean;
    passCount: number | null;
    failCount: number | null;
    output: string;
  };
  /** Plain-language account of why this verdict was reached. */
  reasoning: string;
  /** Always true: this module never calls a model. */
  deterministic: true;
  provenAt: string;
}
/**
 * Strip all whitespace, for comparing a claimed signal against captured output.
 *
 * Collapsing runs of whitespace is not enough. The output pads JSON keys with
 * spaces *before* the colon -- `flag               : PATCHPROOF{...}` -- so
 * collapsing yields `flag : PATCHPROOF{...}`, which still fails to contain the
 * signal `flag: PATCHPROOF{...}`. Removing whitespace entirely is what makes the
 * two comparable.
 *
 * This only removes whitespace; every other character still has to match, so it
 * cannot turn "not present" into "present". It stays case-sensitive for the same
 * reason.
 */
function normaliseWhitespace(text: string): string {
  return text.replace(/\s+/g, '');
}

/**
 * True when `signal` appears in the captured output.
 *
 * Compares on whitespace-normalised text. The signal is the exploit author's
 * claim, so a difference in spacing between their paraphrase and the target's
 * pretty-printed output must not decide the verdict -- and it must not be
 * "fixed" by loosening this into a fuzzy match, because the whole point is that
 * the literal marker is what proves the bug fired.
 */
function fired(output: string, signal: string | undefined): boolean {
  if (!signal || signal.trim().length === 0) return false;
  return normaliseWhitespace(output).includes(normaliseWhitespace(signal));
}

/** Replay the exploit once, in a throwaway container, with these contents in place. */
async function replayAgainst(
  spec: ProofSpec,
  contents: string,
  phase: string,
): Promise<PhaseOutcome> {
  await overwriteSourceFile(spec.file, contents);

  const run = await runSandboxCommand({
    command: spec.exploitCommand,
    label: `${spec.findingId}:${phase}`,
    timeoutMs: config.agents.providerTimeoutMs,
  });

  const output = `${run.stdout}\n${run.stderr}`.trim();
  return { fired: fired(output, spec.successSignal), exitCode: run.exitCode, output: output.slice(-4000) };
}

/**
 * Prove that a patch fixes a vulnerability, without asking a model anything.
 *
 * The original file contents are restored before returning, whatever happens.
 */
export async function proveFix(spec: ProofSpec): Promise<FixProof> {
  log.info(`proving fix for ${spec.findingId} (${spec.vulnerabilityClass ?? 'unclassified'})`);

  const provenAt = new Date().toISOString();
  let baseline: PhaseOutcome;
  let patched: PhaseOutcome;
  let suite: Awaited<ReturnType<typeof runFunctionalSuite>>;
  let verdict: ProofVerdict;
  let reasoning: string;

  try {
    // ---- Phase 1: the exploit MUST fire on the unpatched code ----
    baseline = await replayAgainst(spec, spec.originalContent, 'baseline');
    log.info(`baseline: exploit ${baseline.fired ? 'fired' : 'DID NOT fire'}`);

    // ---- Phase 2: the same exploit against the patched code ----
    patched = await replayAgainst(spec, spec.patchedContent, 'patched');
    log.info(`patched: exploit ${patched.fired ? 'STILL fires' : 'did not fire'}`);

    // ---- Gate 2: the application must still work ----
    suite = await runFunctionalSuite(spec.testCommand ?? 'npm test', `${spec.findingId}:suite`);
    log.info(`functional suite: ${suite.passed ? 'pass' : 'FAIL'}`);

    const changed = baseline.output !== patched.output;

    // Order matters. An unproven exploit means we can say nothing at all, and a
    // broken application is more urgent than an unfixed vulnerability.
    if (!baseline.fired) {
      verdict = 'inconclusive';
      reasoning =
        'The exploit did not fire against the unpatched code, so there is no baseline to ' +
        'compare against. Nothing can be concluded about this patch.';
    } else if (!suite.passed) {
      verdict = 'functional-break';
      reasoning =
        `The exploit is neutralised, but the project's test suite now fails ` +
        `(${suite.failCount ?? '?'} failing). The patch fixed the vulnerability by breaking ` +
        'the application, so it is rejected.';
    } else if (patched.fired) {
      verdict = 'regression';
      reasoning =
        'The exploit still fires against the patched code: the vulnerability is not fixed, ' +
        'even though the application still works.';
    } else if (!changed) {
      verdict = 'inconclusive';
      reasoning =
        'The exploit stopped firing but the output did not change at all, which suggests the ' +
        'endpoint stopped responding rather than the bug being fixed.';
    } else {
      verdict = 'verified';
      reasoning =
        `The exploit fired on the original code and no longer fires after the patch ` +
        `(${spec.successSignal ?? 'no signal declared'} is gone), the response changed, and ` +
        `the test suite still passes (${suite.passCount ?? '?'} passing).`;
    }
  } catch (error) {
    // A crash is not a pass. Report inconclusive rather than throwing, so a
    // broken target is never mistaken for a working fix.
    const message = error instanceof Error ? error.message : String(error);
    log.error(`${spec.findingId}: proof failed`, error);
    return {
      findingId: spec.findingId,
      verdict: 'inconclusive',
      baseline: { fired: false, exitCode: -1, output: message },
      patched: { fired: false, exitCode: -1, output: message },
      behaviourChanged: false,
      functional: { passed: false, passCount: null, failCount: null, output: message },
      reasoning: `The proof could not be completed: ${message}`,
      deterministic: true,
      provenAt,
    };
  } finally {
    // Always leave the target exactly as we found it.
    await overwriteSourceFile(spec.file, spec.originalContent).catch(() => undefined);
  }

  return {
    findingId: spec.findingId,
    verdict,
    baseline,
    patched,
    behaviourChanged: baseline.output !== patched.output,
    functional: {
      passed: suite.passed,
      passCount: suite.passCount,
      failCount: suite.failCount,
      output: suite.output,
    },
    reasoning,
    deterministic: true,
    provenAt,
  };
}

/** True for verdicts that mean the patch should be kept. */
export function isAcceptable(proof: FixProof): boolean {
  return proof.verdict === 'verified';
}
