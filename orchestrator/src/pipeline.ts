/**
 * The PatchProof pipeline: scan -> exploit -> patch -> verify, with approvals.
 *
 * Each stage narrows the one before it:
 *   scan     proposes candidates (static analysis + LLM, merged)
 *   exploit  proves them by running a reproduction; unproven ones are dropped
 *   patch    fixes only what was proven
 *   verify   proves the fix with the deterministic prover, no LLM involved
 *
 * Every step emits an event, which is what the SSE endpoint streams. Events are
 * the product here as much as the results: a run takes minutes, and a frontend
 * that shows nothing until the end is indistinguishable from a hung one.
 */
import { randomUUID } from 'node:crypto';
import { scanTarget } from './agents/scanAgent.js';
import { confirmVulnerability } from './agents/exploitAgent.js';
import { proposePatch } from './agents/patchAgent.js';
import { verifyPatch } from './agents/verifyAgent.js';
import { overwriteSourceFile } from './target/source.js';
import {
  cleanScratchFiles,
  restoreSourceFiles,
  snapshotScratchFiles,
  snapshotSourceFiles,
} from './target/cleanup.js';
import { unifiedDiff } from './util/diff.js';
import { canOpenPullRequest, openPullRequest } from './github/openPullRequest.js';
import { currentTargetRepo } from './githubTargetRepo.js';
import type { PrEvidence } from './github/prReport.js';
import { config } from './config.js';
import { createLogger } from './logger.js';
import type {
  Approval,
  Candidate,
  ConfirmedFinding,
  Patch,
  PipelineEvent,
  PipelineEventType,
  Phase,
  Verification,
} from './types.js';

const log = createLogger('pipeline');

export type RunStatus = 'running' | 'completed' | 'failed';

export interface RunState {
  id: string;
  status: RunStatus;
  startedAt: string;
  finishedAt?: string;
  /** Every event so far, so a late subscriber can replay history. */
  events: PipelineEvent[];
  candidates: Candidate[];
  confirmed: ConfirmedFinding[];
  patches: Patch[];
  verifications: Verification[];
  error?: string;
}

export interface StartRunOptions {
  /**
   * Cap how many candidates are taken forward. Scans routinely return more than
   * is worth spending time on, and each one costs minutes of agent time.
   */
  maxFindings?: number;
  /** Only consider findings of these classes, when given. */
  onlyClasses?: string[];
}

export type EventListener = (event: PipelineEvent) => void;

export interface ApprovalResult {
  ok: boolean;
  reason?: string;
  approval?: Approval;
}

/**
 * Owns run state and event fan-out.
 *
 * Events are buffered on the run as well as pushed to live subscribers, so a
 * frontend that connects late still sees everything that already happened.
 */
export class RunManager {
  private readonly runs = new Map<string, RunState>();
  private readonly listeners = new Map<string, Set<EventListener>>();
  private readonly approvals = new Map<string, Approval>();

  listRuns(): Array<{ id: string; status: RunStatus; startedAt: string; finishedAt?: string }> {
    return [...this.runs.values()].map((run) => ({
      id: run.id,
      status: run.status,
      startedAt: run.startedAt,
      ...(run.finishedAt ? { finishedAt: run.finishedAt } : {}),
    }));
  }

  getRun(id: string): RunState | undefined {
    return this.runs.get(id);
  }

  listApprovals(): Approval[] {
    return [...this.approvals.values()];
  }

  /** Subscribe to a run's events. Returns an unsubscribe function. */
  subscribe(runId: string, listener: EventListener): () => void {
    const set = this.listeners.get(runId) ?? new Set<EventListener>();
    set.add(listener);
    this.listeners.set(runId, set);
    return () => {
      set.delete(listener);
    };
  }

  private emit(
    run: RunState,
    type: PipelineEventType,
    phase: Phase,
    message: string,
    findingId?: string,
    data?: unknown,
  ): void {
    const event: PipelineEvent = {
      type,
      phase,
      message,
      at: new Date().toISOString(),
      ...(findingId ? { findingId } : {}),
      ...(data !== undefined ? { data } : {}),
    };

    run.events.push(event);
    for (const listener of this.listeners.get(run.id) ?? []) {
      try {
        listener(event);
      } catch (error) {
        // A broken SSE client must not take the pipeline down with it.
        log.warn(`listener for run ${run.id} threw`, error);
      }
    }
  }

  /** Start a run in the background and return its id immediately. */
  start(options: StartRunOptions = {}): string {
    const run: RunState = {
      id: randomUUID(),
      status: 'running',
      startedAt: new Date().toISOString(),
      events: [],
      candidates: [],
      confirmed: [],
      patches: [],
      verifications: [],
    };

    this.runs.set(run.id, run);
    this.emit(run, 'run.started', 'run', 'pipeline run started');

    void this.execute(run, options);
    return run.id;
  }
/** The pipeline itself. */
  private async execute(run: RunState, options: StartRunOptions): Promise<void> {
    // Taken before any agent can write, so cleanup can distinguish files we
    // created from files the project already had.
    const scratchBaseline = await snapshotScratchFiles();
    // And a full copy of the target source, because the patch agent edits these
    // files in place. Without this, an interrupted run leaves the target
    // already-fixed and every later run reports a false "all clear".
    const targetSnapshot = await snapshotSourceFiles();

    try {
      // ---- scan ----
      this.emit(run, 'scan.started', 'scan', 'running static analysis and LLM review');
      const scan = await scanTarget();

      let candidates = scan.candidates;
      if (options.onlyClasses?.length) {
        const wanted = options.onlyClasses;
        candidates = candidates.filter((c) => wanted.includes(c.vulnerabilityClass));
      }
      if (options.maxFindings !== undefined) {
        candidates = candidates.slice(0, options.maxFindings);
      }

      run.candidates = candidates;
      for (const candidate of candidates) {
        this.emit(
          run,
          'scan.finding',
          'scan',
          `${candidate.id}: ${candidate.vulnerabilityClass} in ${candidate.file}:${candidate.line ?? '?'} (${candidate.severity})`,
          candidate.id,
          candidate,
        );
      }
      this.emit(
        run,
        'scan.completed',
        'scan',
        `scan found ${candidates.length} candidate(s)`,
        undefined,
        { total: scan.candidates.length, considered: candidates.length },
      );

      await this.processAllFindings(run, candidates);
      run.status = 'completed';
      run.finishedAt = new Date().toISOString();

      // Count real outcomes, not entries in the array. `verifications.length`
      // counted `inconclusive` as a success, so the headline read
      // "3 verified" while one of them proved nothing.
      const verifiedCount = run.verifications.filter((v) => v.verdict === 'verified').length;
      const unresolved = run.verifications.filter((v) => v.verdict !== 'verified').length;

      this.emit(
        run,
        'run.completed',
        'run',
        `run finished: ${run.confirmed.length} confirmed, ${run.patches.length} patch(es), ` +
          `${verifiedCount} verified` +
          (unresolved > 0 ? `, ${unresolved} not verified (${run.verifications.filter((v) => v.verdict !== 'verified').map((v) => `${v.findingId}:${v.verdict}`).join(', ')})` : ''),
      );
    } catch (error) {
      run.status = 'failed';
      run.finishedAt = new Date().toISOString();
      run.error = error instanceof Error ? error.message : String(error);
      log.error(`run ${run.id} failed`, error);
      this.emit(run, 'run.failed', 'run', `run failed: ${run.error}`);
    } finally {
      // Always, including on the failure path: a crashed run is exactly the kind
      // that leaves scratch files behind, and those would then be scanned as if
      // they were part of the target.
      //
      // Deliberately logged rather than emitted as an event. By this point the
      // terminal event has already gone out and the SSE stream has closed, so a
      // second `run.completed` would either never be delivered or, worse,
      // re-terminate a stream some clients treat as single-shot.
      await cleanScratchFiles(scratchBaseline).catch(() => undefined);
      // Restore first: a target left patched silently corrupts every future
      // run, so it matters more than tidying up scratch files.
      await restoreSourceFiles(targetSnapshot).catch(() => undefined);
    }
  }

/**
 * Process findings concurrently, grouped so independent work overlaps.
 *
 * Findings are independent in principle, but NOT in one respect: the verify
 * step writes a patched file and then restores the original. Two findings in the
 * same file running at once would clobber each other's write and could restore
 * the wrong content.
 *
 * So findings are grouped by target file. Groups run in parallel (the common
 * case -- most findings live in different files); findings within a group stay
 * sequential. Concurrency is capped so a burst of findings cannot swamp the
 * rate-limited provider and make things slower.
 */
private async processAllFindings(run: RunState, candidates: Candidate[]): Promise<void> {
  if (candidates.length === 0) return;

  const byFile = new Map<string, Candidate[]>();
  for (const candidate of candidates) {
    const group = byFile.get(candidate.file) ?? [];
    group.push(candidate);
    byFile.set(candidate.file, group);
  }

  const lanes = [...byFile.values()];
  const limit = Math.max(1, config.agents.concurrency);

  this.emit(
    run,
    'scan.completed',
    'scan',
    `processing ${candidates.length} finding(s) across ${lanes.length} file group(s), up to ${limit} at a time`,
    undefined,
    { findings: candidates.length, groups: lanes.length, concurrency: limit },
  );

  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < lanes.length) {
      const lane = lanes[cursor]!;
      cursor += 1;
      for (const candidate of lane) {
        await this.processFinding(run, candidate);
      }
    }
  };

  await Promise.all(Array.from({ length: Math.min(limit, lanes.length) }, () => worker()));
}


  /** exploit -> patch -> verify for a single candidate. */
  private async processFinding(run: RunState, candidate: Candidate): Promise<void> {
    this.emit(run, 'exploit.started', 'exploit', `${candidate.id}: attempting to reproduce`, candidate.id);

    // One finding must not be able to sink the whole run. If the agent dies --
    // rate limit, provider outage, iteration exhaustion -- the finding is treated
    // as unconfirmed and the run moves on to the next one.
    let finding: ConfirmedFinding | null;
    try {
      finding = await confirmVulnerability(candidate);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      this.emit(
        run,
        'exploit.rejected',
        'exploit',
        `${candidate.id}: exploit check failed (${reason}) - treating as unconfirmed`,
        candidate.id,
      );
      return;
    }

    if (!finding) {
      this.emit(run, 'exploit.rejected', 'exploit', `${candidate.id}: not reproducible - discarded`, candidate.id);
      return;
    }

    run.confirmed.push(finding);
    this.emit(
      run,
      'exploit.confirmed',
      'exploit',
      `${finding.id}: CONFIRMED - evidence observed in the sandbox`,
      finding.id,
      finding.exploit.detection ?? finding.exploit,
    );

    // ---- patch ----
    this.emit(run, 'patch.started', 'patch', `${finding.id}: writing a minimal fix`, finding.id);

    let plan;
    try {
      plan = await proposePatch(finding);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      this.emit(run, 'patch.failed', 'patch', `${finding.id}: patch agent failed (${reason})`, finding.id);
      return;
    }

    if (!plan) {
      this.emit(run, 'patch.failed', 'patch', `${finding.id}: no usable patch produced`, finding.id);
      return;
    }

    const patch: Patch = {
      findingId: finding.id,
      file: plan.file,
      unifiedDiff: unifiedDiff(plan.file, plan.originalContent, plan.patchedContent),
      summary: plan.summary,
      agentSummary: plan.summaryLine,
      patchedContent: plan.patchedContent,
      originalContent: plan.originalContent,
      createdAt: new Date().toISOString(),
    };
    run.patches.push(patch);
    this.emit(run, 'patch.proposed', 'patch', `${finding.id}: ${plan.summaryLine || plan.summary}`, finding.id, patch);

    // ---- verify (deterministic; no LLM is consulted) ----
    this.emit(
      run,
      'verify.started',
      'verify',
      `${finding.id}: replaying exploit and running the test suite`,
      finding.id,
    );

    const verification = await verifyPatch(finding, plan);
    run.verifications.push(verification);
    this.emit(run, 'verify.result', 'verify', `${finding.id}: ${verification.verdict}`, finding.id, verification);
  }

/**
 * Approve a verified fix for shipping.
 *
 * Only fixes the deterministic prover marked `verified` may be approved. That
 * rule is the point of the pipeline: a human approving a fix is fine, but a
 * human approving an unverified or app-breaking fix would be approving a
 * gamble.
 *
 * Delivery depends on configuration:
 *   - with a GitHub repo + token: open a pull request carrying the patch and the
 *     verification report. The working tree is left alone, because the pull
 *     request is the change under review.
 *   - without one: apply the fix locally, which is the only useful thing left.
 */
  approve(runId: string, findingId: string): ApprovalResult {
    const run = this.runs.get(runId);
    if (!run) return { ok: false, reason: 'run not found' };

    const verification = run.verifications.find((v) => v.findingId === findingId);
    if (!verification) return { ok: false, reason: `no verification for ${findingId}` };
    if (verification.verdict !== 'verified') {
      return { ok: false, reason: `fix is not verified (verdict: ${verification.verdict})` };
    }

    const patch = run.patches.find((p) => p.findingId === findingId);
    if (!patch?.patchedContent || !patch.originalContent) {
      return { ok: false, reason: 'patch content is unavailable' };
    }

    const key = `${runId}:${findingId}`;
    const existing = this.approvals.get(key);
    if (existing) return { ok: true, reason: 'already approved', approval: existing };

    const approval: Approval = {
      runId,
      findingId,
      file: patch.file,
      approvedAt: new Date().toISOString(),
      unifiedDiff: patch.unifiedDiff,
      summary: patch.agentSummary || patch.summary,
      // Retained so a bad approval can be rolled back.
      originalContent: patch.originalContent,
    };

    this.approvals.set(key, approval);
    log.info(`approved ${findingId} for shipping (${patch.file})`);

    if (canOpenPullRequest()) {
      // Deliver by pull request; the review is the point, so do not also mutate
      // the working tree.
      this.emit(
        run,
        'approval.requested',
        'approval',
        `${findingId}: opening a pull request`,
        findingId,
      );

      const evidence = buildPrEvidence(run, findingId);
      if (!evidence) {
        approval.pullRequestError = 'could not gather evidence for the pull request';
        return { ok: true, reason: approval.pullRequestError, approval };
      }

      // Named in the event so the log records which repo actually received it,
      // rather than leaving that to be inferred from config.
      const repo = currentTargetRepo();
      void openPullRequest(evidence, repo ? { repo } : {}).then(
        (result) => {
          if (result.ok && result.pullRequest) {
            approval.pullRequest = result.pullRequest;
            this.emit(
              run,
              'approval.applied',
              'approval',
              `${findingId}: pull request #${result.pullRequest.number} opened (${result.pullRequest.url})`,
              findingId,
              approval,
            );
          } else {
            approval.pullRequestError = result.reason ?? 'pull request failed';
            this.emit(
              run,
              'approval.rejected',
              'approval',
              `${findingId}: pull request failed - ${approval.pullRequestError}`,
              findingId,
              approval,
            );
          }
        },
        (error: unknown) => log.error('failed to open pull request', error),
      );

      return { ok: true, approval };
    }

    // No GitHub configured: apply locally.
    void overwriteSourceFile(patch.file, patch.patchedContent).then(
      () => {
        this.emit(
          run,
          'approval.applied',
          'approval',
          `${findingId}: approved and applied to ${patch.file} (no GitHub repo configured)`,
          findingId,
          approval,
        );
      },
      (error: unknown) => log.error('failed to apply approval', error),
    );

    return { ok: true, approval };
  }
}

/**
 * Collect everything a pull request needs from a completed run.
 *
 * Pure, so the report's inputs can be checked without touching GitHub. Returns
 * null when the run does not actually contain a verified fix for that finding --
 * callers must not fall back to inventing evidence.
 */
export function buildPrEvidence(run: RunState, findingId: string): PrEvidence | null {
  const patch = run.patches.find((p) => p.findingId === findingId);
  const verification = run.verifications.find((v) => v.findingId === findingId);
  const finding = run.confirmed.find((f) => f.id === findingId) as
    | { id: string; vulnerabilityClass: string; severity: string; exploit: { command: string; successSignal: string } }
    | undefined;

  if (!patch?.patchedContent || !verification) return null;

  return {
    runId: run.id,
    findingId,
    vulnerabilityClass: finding?.vulnerabilityClass ?? 'unknown',
    severity: finding?.severity ?? 'unknown',
    file: patch.file,
    summary: patch.agentSummary || patch.summary,
    unifiedDiff: patch.unifiedDiff,
    patchedContent: patch.patchedContent,
    exploitCommand: verification.exploitReplayed,
    successSignal: finding?.exploit?.successSignal,
    before: verification.exploitBefore ?? { fired: true, output: '' },
    after: verification.exploitAfter ?? { fired: verification.exploitStillSucceeds, output: '' },
    functional: {
      passed: verification.functional?.passed ?? false,
      passCount: verification.functional?.passCount ?? null,
      failCount: verification.functional?.failCount ?? null,
    },
    verdict: verification.verdict,
  };
}

