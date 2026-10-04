/**
 * Typed client for the orchestrator API.
 *
 * In dev, Vite proxies /api to http://localhost:4000 (see vite.config.ts), so
 * everything here is same-origin -- which matters for the SSE stream, since
 * EventSource cannot be pointed at a different host without CORS.
 */

export type Phase = 'scan' | 'exploit' | 'patch' | 'verify' | 'approval' | 'run';

/** Every event name the pipeline can emit. */
export const EVENT_TYPES = [
  'run.started',
  'run.completed',
  'run.failed',
  'scan.started',
  'scan.finding',
  'scan.completed',
  'exploit.started',
  'exploit.confirmed',
  'exploit.rejected',
  'patch.started',
  'patch.proposed',
  'patch.failed',
  'verify.started',
  'verify.result',
  'approval.applied',
] as const;

export type PipelineEventType = (typeof EVENT_TYPES)[number];

export interface PipelineEvent {
  type: PipelineEventType;
  phase: Phase;
  message: string;
  at: string;
  findingId?: string;
  data?: unknown;
}

export interface Candidate {
  id: string;
  vulnerabilityClass: string;
  severity: string;
  file: string;
  line: number | null;
  evidence: string;
  rationale: string;
  source?: string;
  ruleId?: string;
}

export type Verdict = 'verified' | 'regression' | 'functional-break' | 'inconclusive';

export interface Verification {
  findingId: string;
  exploitReplayed: string;
  exploitStillSucceeds: boolean;
  verdict: Verdict;
  output: string;
  functional?: {
    passed: boolean;
    passCount: number | null;
    failCount: number | null;
    note?: string;
  };
  verifiedAt: string;
}

export interface Patch {
  findingId: string;
  file: string;
  unifiedDiff: string;
  summary: string;
  agentSummary?: string;
  createdAt: string;
}

export interface Approval {
  runId: string;
  findingId: string;
  file: string;
  approvedAt: string;
  unifiedDiff: string;
  summary: string;
  originalContent: string;
}

export type RunStatus = 'running' | 'completed' | 'failed';

export interface RunState {
  id: string;
  status: RunStatus;
  startedAt: string;
  finishedAt?: string;
  events: PipelineEvent[];
  candidates: Candidate[];
  confirmed: unknown[];
  patches: Patch[];
  verifications: Verification[];
  error?: string;
}

export interface StartRunOptions {
  /** Cap how many findings are taken forward; a full run is slow. */
  maxFindings?: number;
  onlyClasses?: string[];
}

/** GitHub PR settings, as reported by the orchestrator. */
export interface GithubConfig {
  /** Repo a PR would open against right now (override, else the .env default). */
  repo: string | null;
  /** What GITHUB_DEFAULT_REPO in .env says, so the default is always visible. */
  defaultRepo: string | null;
  /** True when `repo` differs from `defaultRepo`. */
  overridden: boolean;
  /** Whether a token is configured. The token itself is never sent. */
  tokenConfigured: boolean;
  /** False when no repo or no token, i.e. approval cannot open a PR. */
  canOpenPullRequest: boolean;
}

export interface ServerConfig {
  target: { name: string; path: string; baseUrl: string };
  primaryProvider: { label: string; model: string; configured: boolean };
  backupProvider: { label: string; model: string; configured: boolean };
  fallback: { maxRetries: number; statusCodes: number[]; onContentFilter: boolean };
  github: GithubConfig;
}

/**
 * Base URL for API calls.
 *
 * Guarded rather than assumed: `import.meta.env` only exists inside Vite, and
 * this module is also imported by Node-side tests, where it is undefined.
 * Defaulting to the relative path is correct in the browser, where Vite's dev
 * proxy forwards /api to the orchestrator.
 */
const BASE = import.meta.env?.VITE_API_BASE_URL ?? '/api';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });

  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    // The orchestrator reports user-facing problems as { error: "..." } -- notably
    // the repo field's validation messages, which are written to be read. Surface
    // that text rather than making the user look at raw JSON in the UI.
    let message = detail;
    try {
      const parsed = JSON.parse(detail) as { error?: string };
      if (parsed.error) message = parsed.error;
    } catch {
      // Not JSON (a proxy error page, say): keep the raw body.
    }
    throw new Error(`${response.status} ${response.statusText}${message ? ` - ${message}` : ''}`);
  }

  return (await response.json()) as T;
}

export function getHealth(): Promise<{ ok: boolean; service: string; target: string }> {
  return request('/health');
}

export function getConfig(): Promise<ServerConfig> {
  return request('/config');
}

/**
 * Set the repo that "Approve for shipping" opens pull requests against.
 *
 * Accepts "owner/name" or any pasted GitHub URL; the server normalises it. Pass
 * null to clear the override and fall back to the .env default.
 */
export function setTargetRepo(repo: string | null): Promise<GithubConfig> {
  return request('/config/repo', {
    method: 'PUT',
    body: JSON.stringify({ repo }),
  });
}

export function listRuns(): Promise<{ runs: Array<{ id: string; status: RunStatus }> }> {
  return request('/runs');
}

export function startRun(options: StartRunOptions = {}): Promise<{ runId: string; status: RunStatus }> {
  return request('/runs', { method: 'POST', body: JSON.stringify(options) });
}

export function getRun(id: string): Promise<RunState> {
  return request(`/runs/${id}`);
}

export function listApprovals(): Promise<{ approvals: Approval[] }> {
  return request('/approvals');
}

/** Approve a verified fix for shipping. Rejects anything not marked verified. */
export function approveFinding(runId: string, findingId: string): Promise<{ ok: boolean; approval?: Approval; reason?: string }> {
  return request(`/runs/${runId}/approvals`, {
    method: 'POST',
    body: JSON.stringify({ findingId }),
  });
}

/** URL for the SSE stream. Relative, so it goes through the dev proxy. */
export function streamUrl(runId: string): string {
  return `${BASE}/runs/${runId}/stream`;
}