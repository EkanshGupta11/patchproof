/**
 * Shared domain types for the PatchProof pipeline.
 *
 * Flow: Candidate -> (exploit) -> ConfirmedFinding -> (patch) -> Patch -> (replay) -> Verification
 */

export type VulnerabilityClass =
  | 'sql-injection'
  | 'command-injection'
  | 'path-traversal'
  | 'xss'
  | 'ssrf'
  | 'broken-auth'
  | 'idor'
  | 'prototype-pollution'
  | 'insecure-deserialization'
  | 'sensitive-data-exposure'
  | 'other';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

/** Where a candidate came from. Both are unproven until the exploit phase. */
export type CandidateSource = 'static-analysis' | 'llm' | 'both';

/** What the scan agent believes it found. Not yet proven. */
export interface Candidate {
  id: string;
  vulnerabilityClass: VulnerabilityClass;
  severity: Severity;
  file: string;
  line: number | null;
  /** The suspicious code, quoted from the source. */
  evidence: string;
  /** Why the agent thinks this is exploitable. */
  rationale: string;
  /** Which scanner produced this. Defaults to the LLM when omitted. */
  source?: CandidateSource;
  /** The static-analysis rule that flagged it, when there was one. */
  ruleId?: string;
}

/** A concrete, runnable proof-of-concept produced by the exploit agent. */
export interface Exploit {
  /** Shell command run inside the sandbox (e.g. a curl invocation). */
  command: string;
  /** What a vulnerable target looks like in the output. */
  successSignal: string;
  /** Raw sandbox output from the confirming run. */
  observedOutput: string;
  succeeded: boolean;
  /** How the detector judged the output, for the audit trail. */
  detection?: DetectionVerdict;
}

/** Why the detector believed (or did not believe) the bug fired. */
export interface DetectionVerdict {
  triggered: boolean;
  confidence: 'certain' | 'strong' | 'weak';
  /** The exact strings that fired, so a human can audit the decision. */
  signals: Array<{ pattern: string; matchedLine: string; detector: string; why: string }>;
  reasoning: string;
}

/** A candidate that has actually been triggered in the sandbox. */
export interface ConfirmedFinding extends Candidate {
  exploit: Exploit;
  confirmedAt: string;
}

/** A minimal code change proposed by the patch agent. */
export interface Patch {
  findingId: string;
  file: string;
  unifiedDiff: string;
  summary: string;
  createdAt: string;
  /** The agent's own closing SUMMARY: line, verbatim. */
  agentSummary?: string;
  /**
   * The patched file in full, and the file as it was before.
   *
   * Kept so an approved fix can be applied to the target later, and so it can be
   * rolled back.
   */
  patchedContent?: string;
  originalContent?: string;
}

/**
 * Verdicts.
 *
 * `functional-break` is separate from `regression` on purpose: "the exploit
 * still works" and "the fix broke the application" are different failures and
 * need different responses from whoever reads the report.
 */
export type Verdict = 'verified' | 'regression' | 'functional-break' | 'inconclusive';

/**
 * One side of the exploit replay.
 *
 * Kept as a pair so a report can quote what the exploit actually produced before
 * and after the patch, rather than paraphrasing a verdict.
 */
export interface ExploitReplay {
  /** Whether the exploit's success signal appeared in the output. */
  fired: boolean;
  /** Raw sandbox output, truncated. */
  output: string;
}

/** The result of replaying the original exploit against the patched build. */
export interface Verification {
  findingId: string;
  exploitReplayed: string;
  exploitStillSucceeds: boolean;
  verdict: Verdict;
  output: string;
  /** Exploit replayed against the ORIGINAL code. Expected to fire. */
  exploitBefore?: ExploitReplay;
  /** The same exploit against the PATCHED code. Expected not to fire. */
  exploitAfter?: ExploitReplay;
  /** Whether the project's own test suite still passes after the patch. */
  functional?: {
    passed: boolean;
    passCount: number | null;
    failCount: number | null;
    note?: string;
  };
  verifiedAt: string;
}

/**
 * A pull request opened for a verified fix.
 *
 * Recorded on the approval so a reviewer can trace a shipped change back to the
 * run and verdict that justified it.
 */
export interface PullRequestRef {
  owner: string;
  repo: string;
  number: number;
  branch: string;
  url: string;
  openedAt: string;
}

export type Phase = 'scan' | 'exploit' | 'patch' | 'verify' | 'approval' | 'run';

/**
 * Every progress event the pipeline emits.
 *
 * These names are what the SSE stream sends as the event type, so a frontend can
 * subscribe to a phase rather than filtering a generic message stream.
 */
export type PipelineEventType =
  | 'run.started'
  | 'run.completed'
  | 'run.failed'
  | 'scan.started'
  | 'scan.finding'
  | 'scan.completed'
  | 'exploit.started'
  | 'exploit.confirmed'
  | 'exploit.rejected'
  | 'patch.started'
  | 'patch.proposed'
  | 'patch.failed'
  | 'verify.started'
  | 'verify.result'
  | 'approval.requested'
  | 'approval.applied'
  | 'approval.rejected';

export interface PipelineEvent {
  /** Machine-readable event name; matches the SSE `event:` field. */
  type: PipelineEventType;
  phase: Phase;
  /** Human-readable, safe to render directly. */
  message: string;
  /** ISO timestamp. */
  at: string;
  /** Which finding this concerns, when applicable. */
  findingId?: string;
  /** Structured payload for the frontend (finding, verdict, patch, ...). */
  data?: unknown;
}

/**
 * An approval: a verified fix accepted for shipping.
 *
 * `originalContent` is retained so an approval can be undone; without it a bad
 * approval would be unrecoverable.
 */
export interface Approval {
  runId: string;
  findingId: string;
  file: string;
  approvedAt: string;
  unifiedDiff: string;
  summary: string;
  /** Content before the fix, kept for rollback. */
  originalContent: string;
  /** Set once a pull request has been opened for this fix. */
  pullRequest?: PullRequestRef;
  /** Why no pull request was opened, when one was expected. */
  pullRequestError?: string;
}

export interface PipelineResult {
  target: string;
  startedAt: string;
  finishedAt: string;
  candidates: Candidate[];
  confirmed: ConfirmedFinding[];
  patches: Patch[];
  verifications: Verification[];
}
