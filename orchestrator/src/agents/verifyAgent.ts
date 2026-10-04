/**
 * Apply a candidate fix to the target and prove it.
 *
 * ## The verifier is an independent check
 *
 * This module makes no LLM calls. It delegates the entire decision to
 * {@link proveFix}, which replays the exploit against both the unpatched and the
 * patched build and runs the project's test suite. The agent that produced the
 * patch is never asked whether its own patch worked.
 *
 * That separation is deliberate: an agent that "fixed" the vulnerability by
 * disabling the endpoint would sail past a naive replay check (the exploit no
 * longer fires -- trivially). It fails the test suite instead. Both gates are
 * checked, on real runs.
 */
import { proveFix, type FixProof } from '../verify/proveFix.js';
import { createLogger } from '../logger.js';
import type { ConfirmedFinding, Verification, Verdict } from '../types.js';
import type { PatchPlan } from './patchAgent.js';

const log = createLogger('agent:verify');

/**
 * Verify a candidate patch by deterministic replay.
 *
 * The prover restores the original source before returning, so the target is
 * left exactly as it was found either way.
 */
export async function verifyPatch(
  finding: ConfirmedFinding,
  patch: PatchPlan,
): Promise<Verification> {
  log.info(`${finding.id}: applying patch, then proving it without an LLM`);

  const proof: FixProof = await proveFix({
    findingId: finding.id,
    file: patch.file,
    originalContent: patch.originalContent,
    patchedContent: patch.patchedContent,
    exploitCommand: finding.exploit.command,
    successSignal: finding.exploit.successSignal,
    vulnerabilityClass: finding.vulnerabilityClass,
  });

  // Map the prover's verdict onto the pipeline's vocabulary.
  const verdict: Verdict = proof.verdict;
  log.info(`${finding.id}: proof verdict = ${verdict}`);

  return {
    findingId: finding.id,
    exploitReplayed: finding.exploit.command,
    // Only a still-firing exploit is a security regression; a patch that broke
    // the app is a different (also failing) outcome.
    exploitStillSucceeds: verdict === 'regression',
    verdict,
    // Both sides of the replay, kept separately so a report can quote the real
    // before-and-after evidence instead of summarising it.
    exploitBefore: { fired: proof.baseline.fired, output: proof.baseline.output },
    exploitAfter: { fired: proof.patched.fired, output: proof.patched.output },
    functional: {
      passed: proof.functional.passed,
      passCount: proof.functional.passCount,
      failCount: proof.functional.failCount,
      ...(verdict === 'functional-break' ? { note: 'patch broke the existing test suite' } : {}),
    },
    output: [
      `exploit on ORIGINAL code : ${proof.baseline.fired ? 'FIRED (as expected)' : 'did not fire'}`,
      `exploit on PATCHED code  : ${proof.patched.fired ? 'STILL FIRED' : 'did not fire (as required)'}`,
      `response changed        : ${proof.behaviourChanged}`,
      `functional suite        : ${proof.functional.passed ? 'PASS' : 'FAIL'}`,
      '',
      proof.reasoning,
    ].join('\n'),
    verifiedAt: proof.provenAt,
  };
}