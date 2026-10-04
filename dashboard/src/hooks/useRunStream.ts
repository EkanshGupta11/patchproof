/**
 * Live progress from the orchestrator's SSE stream.
 *
 * ## Why every event type is registered by hand
 *
 * `EventSource.onmessage` only fires for events sent WITHOUT a name (or with
 * `event: message`). The orchestrator sends named events, so a naive
 * `onmessage` handler would sit there connected and silently receive nothing.
 * Every type therefore gets its own listener.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { EVENT_TYPES, streamUrl, type Candidate, type PipelineEvent, type RunStatus, type Verdict } from '../api';

export type ExploitState = 'pending' | 'running' | 'confirmed' | 'rejected';
export type PatchState = 'pending' | 'running' | 'proposed' | 'failed';
export type VerifyState = 'pending' | 'running' | Verdict;

/** One finding's position in the pipeline, derived purely from events. */
export interface FindingProgress {
  id: string;
  vulnerabilityClass: string;
  file: string;
  line: number | null;
  severity: string;
  ruleId?: string;
  exploit: ExploitState;
  patch: PatchState;
  verify: VerifyState;
  diff?: string;
  summary?: string;
  testSummary?: string;
  approved: boolean;
  approvedAt?: string;
}

export interface RunProgress {
  status: RunStatus;
  scanTotal: number;
  error?: string;
}

const EMPTY = (id: string, candidate?: Partial<Candidate>): FindingProgress => ({
  id,
  vulnerabilityClass: candidate?.vulnerabilityClass ?? 'unknown',
  file: candidate?.file ?? 'unknown',
  line: candidate?.line ?? null,
  severity: candidate?.severity ?? 'unknown',
  ruleId: candidate?.ruleId,
  exploit: 'pending',
  patch: 'pending',
  verify: 'pending',
  approved: false,
});

/**
 * Fold an event into the current view of the run.
 *
 * Kept pure and exported so it can be reasoned about without a browser.
 */
export function applyEvent(
  findings: FindingProgress[],
  run: RunProgress,
  event: PipelineEvent,
): { findings: FindingProgress[]; run: RunProgress } {
  const next: RunProgress = { ...run };

  switch (event.type) {
    case 'run.started':
      next.status = 'running';
      break;
    case 'run.completed':
      next.status = 'completed';
      break;
    case 'run.failed':
      next.status = 'failed';
      next.error = event.message;
      break;
    case 'scan.completed': {
      const data = event.data as { total?: number } | undefined;
      next.scanTotal = data?.total ?? next.scanTotal;
      break;
    }
    default:
      break;
  }

  // Events without a findingId are run-level.
  if (!event.findingId) return { findings, run: next };

  const id = event.findingId;
  const index = findings.findIndex((f) => f.id === id);
  const merged: FindingProgress = { ...(index === -1 ? EMPTY(id) : findings[index]!) };

  switch (event.type) {
    case 'scan.finding': {
      const candidate = event.data as Candidate | undefined;
      merged.vulnerabilityClass = candidate?.vulnerabilityClass ?? merged.vulnerabilityClass;
      merged.file = candidate?.file ?? merged.file;
      merged.line = candidate?.line ?? merged.line;
      merged.severity = candidate?.severity ?? merged.severity;
      merged.ruleId = candidate?.ruleId ?? merged.ruleId;
      break;
    }
    case 'exploit.started':
      merged.exploit = 'running';
      break;
    case 'exploit.confirmed':
      merged.exploit = 'confirmed';
      break;
    case 'exploit.rejected':
      merged.exploit = 'rejected';
      break;
    case 'patch.started':
      merged.patch = 'running';
      break;
    case 'patch.proposed': {
      const patch = event.data as { unifiedDiff?: string; agentSummary?: string; summary?: string } | undefined;
      merged.patch = 'proposed';
      merged.diff = patch?.unifiedDiff;
      merged.summary = patch?.agentSummary || patch?.summary;
      break;
    }
    case 'patch.failed':
      merged.patch = 'failed';
      break;
    case 'verify.started':
      merged.verify = 'running';
      break;
    case 'verify.result': {
      const v = event.data as
        | { verdict?: Verdict; functional?: { passed: boolean; passCount: number | null } }
        | undefined;
      merged.verify = v?.verdict ?? 'inconclusive';
      const f = v?.functional;
      merged.testSummary = f ? `${f.passCount ?? '?'} passed${f.passed ? '' : ' - FAILING'}` : undefined;
      break;
    }
    case 'approval.applied':
      merged.approved = true;
      merged.approvedAt = (event.data as { approvedAt?: string } | undefined)?.approvedAt;
      break;
    default:
      break;
  }

  const updated = [...findings];
  if (index === -1) updated.push(merged);
  else updated[index] = merged;
  return { findings: updated, run: next };
}
export interface UseRunStreamResult {
  findings: FindingProgress[];
  run: RunProgress;
  events: PipelineEvent[];
  connected: boolean;
  /** True once the terminal event has arrived. */
  finished: boolean;
}

export function useRunStream(runId: string | null): UseRunStreamResult {
  const [findings, setFindings] = useState<FindingProgress[]>([]);
  const [run, setRun] = useState<RunProgress>({ status: 'running', scanTotal: 0 });
  const [events, setEvents] = useState<PipelineEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [finished, setFinished] = useState(false);

  // Refs keep the event handler stable, so the stream is not re-subscribed on
  // every render.
  const findingsRef = useRef<FindingProgress[]>([]);
  const runRef = useRef<RunProgress>({ status: 'running', scanTotal: 0 });

  const reset = useCallback(() => {
    findingsRef.current = [];
    runRef.current = { status: 'running', scanTotal: 0 };
    setFindings([]);
    setRun({ status: 'running', scanTotal: 0 });
    setEvents([]);
    setFinished(false);
    setConnected(false);
  }, []);

  useEffect(() => {
    if (!runId) {
      reset();
      return undefined;
    }
    reset();

    const source = new EventSource(streamUrl(runId));
    let done = false;

    const ingest = (event: PipelineEvent): void => {
      setEvents((prev) => [...prev, event]);

      const result = applyEvent(findingsRef.current, runRef.current, event);
      findingsRef.current = result.findings;
      runRef.current = result.run;
      setFindings(result.findings);
      setRun(result.run);

      if (event.type === 'run.completed' || event.type === 'run.failed') {
        done = true;
        setFinished(true);
        source.close();
      }
    };

    source.onopen = () => setConnected(true);
    source.onerror = () => {
      // The browser reconnects by itself unless we closed the stream cleanly.
      if (!done) setConnected(false);
    };

    // Named events bypass onmessage, so each type needs its own listener.
    for (const type of EVENT_TYPES) {
      source.addEventListener(type, (raw) => {
        try {
          ingest(JSON.parse((raw as MessageEvent).data) as PipelineEvent);
        } catch {
          /* a malformed frame must not tear down the stream */
        }
      });
    }

    source.addEventListener('stream.open', () => setConnected(true));
    source.addEventListener('stream.end', () => {
      setConnected(false);
      source.close();
    });

    return () => {
      source.close();
    };
  }, [runId, reset]);

  return useMemo(
    () => ({ findings, run, events, connected, finished }),
    [findings, run, events, connected, finished],
  );
}

// PLACEHOLDER_HOOK