/**
 * Phase 1 - SCAN.
 *
 * Static analysis only. There used to be a second, LLM-based source review here
 * running alongside the linters, and it was removed because it never once
 * produced anything the pipeline used:
 *
 *  - it was rejected by Groq on every run for exceeding the input-token limit
 *    (the whole source is ~17KB, over the free tier's 7,000 token ITPM cap), and
 *  - when it fell through to Gemini it was content-filtered every time, because a
 *    prompt asking a model to find injection vulnerabilities reads exactly like an
 *    attack to a safety filter.
 *
 * So it failed on every single run and its output was discarded in favour of the
 * static results every time. Removing it costs no coverage and saves a full model
 * round-trip (~2 minutes) per run.
 *
 * Coverage did not drop: the one class static analysis used to miss -- SQL
 * injection -- is now covered by the local rule `patchproof/detect-sql-string-concat`.
 * Detection no longer depends on a paid API being available.
 *
 * Nothing here is trusted: every candidate must survive phase 2 (exploit) before
 * it is treated as real.
 */
import { runStaticScan } from '../scan/staticAnalysis.js';
import { sourceDigest } from '../target/source.js';
import { createLogger } from '../logger.js';
import type { Candidate } from '../types.js';

const log = createLogger('agent:scan');

export interface ScanOutcome {
  candidates: Candidate[];
  provider: string;
  usedFallback: boolean;
  /** Provenance breakdown, for the report. */
  fromStaticAnalysis: number;
  /** Always 0: the LLM review pass has been removed. */
  fromLlm: number;
}

/**
 * Run static analysis and return the candidate list.
 *
 * Candidates are numbered here so ids are stable and human-readable
 * (`VULN-1`, `VULN-2`, ...) regardless of which linter produced them.
 */
export async function scanTarget(): Promise<ScanOutcome> {
  const digest = await sourceDigest();
  log.info(`scanning target (${digest.length} chars of source)`);

  const staticResult = await runStaticScan();
  log.info(
    `static analysis (${staticResult.engine}) found ${staticResult.candidates.length} issue(s) in ${staticResult.durationMs}ms`,
  );

  const candidates: Candidate[] = staticResult.candidates.map((candidate, index) => ({
    ...candidate,
    id: `VULN-${index + 1}`,
  }));

  return {
    candidates,
    provider: 'none (static analysis only)',
    usedFallback: false,
    fromStaticAnalysis: candidates.length,
    fromLlm: 0,
  };
}
