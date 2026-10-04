/**
 * Central configuration for the orchestrator.
 *
 * IMPORTANT: this module reads process.env at import time, so the entry file
 * must load dotenv BEFORE anything imports this file. See src/index.ts.
 */
export interface ProviderConfig {
  apiKey: string | undefined;
  model: string;
  /**
   * Optional: first-party providers (Gemini) resolve their own endpoint, while
   * OpenAI-compatible ones (OpenRouter) need an explicit base URL.
   */
  baseUrl?: string;
}

function num(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

function bool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  return value.trim().toLowerCase() === 'true';
}

function codeList(value: string | undefined, fallback: number[]): number[] {
  const raw = value ?? fallback.join(',');
  return raw
    .split(',')
    .map((part) => Number.parseInt(part.trim(), 10))
    .filter((n) => !Number.isNaN(n));
}

export const config = {
  nodeEnv: process.env.NODE_ENV ?? 'development',
  port: num(process.env.PORT, 4000),
  logLevel: (process.env.LOG_LEVEL ?? 'info').toLowerCase(),

  /** Where scan reports, generated exploits and diffs are written. */
  workspaceDir: process.env.PATCHPROOF_WORKSPACE ?? '.patchproof',

  /** The app under test. */
  target: {
    name: 'vulnerable-shop',
    path: process.env.TARGET_APP_PATH ?? '../targets/vulnerable-shop',
    /**
     * URL as seen from INSIDE the sandbox. The orchestrator drives attacks with
     * `docker exec`, so this is the in-container address, not a host one.
     */
    baseUrl: process.env.TARGET_BASE_URL ?? 'http://localhost:3000',
    sourceGlob: process.env.TARGET_SOURCE_GLOB ?? 'src/**/*.js',
  },

  /** Primary LLM provider: OpenRouter, reached through its OpenAI-compatible endpoint. */
  openrouter: {
    apiKey: process.env.OPENROUTER_API_KEY,
    model: process.env.OPENROUTER_MODEL ?? 'meta-llama/llama-3.3-70b-instruct',
    baseUrl: process.env.OPENROUTER_API_BASE_URL ?? 'https://openrouter.ai/api/v1',
  } satisfies ProviderConfig,

  /**
   * Backup provider, used when the primary is rate limited or filters content.
   *
   * Gemini by default. OpenAI was the previous default but is no longer a
   * candidate: we have no working key and no credits for it, and a backup that
   * cannot answer makes every primary failure more expensive, not cheaper.
   */
  backupProvider: (process.env.BACKUP_LLM_PROVIDER ?? 'gemini') as 'gemini' | 'anthropic',
  gemini: {
    apiKey: process.env.GEMINI_API_KEY,
    model: process.env.GEMINI_MODEL ?? 'gemini-3.8-flash',
    // No baseUrl: `providerId: 'gemini'` is a first-party provider, so the SDK
    // uses Google's own endpoint and auth handling rather than the
  // OpenAI-compatible path the OpenRouter primary needs.
  } satisfies ProviderConfig,
  anthropic: {
    apiKey: process.env.ANTHROPIC_API_KEY,
    model: process.env.ANTHROPIC_MODEL ?? 'claude-sonnet-4-6',
    baseUrl: process.env.ANTHROPIC_API_BASE_URL ?? 'https://api.anthropic.com',
  } satisfies ProviderConfig,

  /** When to give up on the primary provider and switch. */
  fallback: {
    /**
     * Extra attempts on the *same* provider before switching to the backup.
     *
     * Default 0: one attempt, then fall back immediately. Retrying a
     * rate-limited provider is self-defeating -- the failed attempt still bills
     * tokens, so the retry loop consumes the daily budget without doing any of
     * the work. That is exactly how the previous run went from 198k to the full
     * 200k/day allowance while producing zero confirmed findings. When we are
     * out of quota, the answer is a different provider, not a third try.
     */
    maxRetries: num(process.env.LLM_MAX_RETRIES, 0),
    statusCodes: codeList(process.env.LLM_FALLBACK_ON_STATUS_CODES, [429, 503]),
    onContentFilter: bool(process.env.LLM_FALLBACK_ON_CONTENT_FILTER, true),
  },

  /** GitHub integration, for reading target repos and eventually opening PRs. */
  github: {
    /**
     * Optional. Without it the client works but is limited to 60 requests/hour
     * and cannot read private repositories.
     */
    token: process.env.GITHUB_TOKEN,
    /** Default "owner/name" when the caller does not specify one. */
    defaultRepo: process.env.GITHUB_DEFAULT_REPO,
    /**
     * Deliberately NOT stored here: the dashboard override is session state, not
     * configuration, and this whole object is frozen. See `githubTargetRepo.ts`.
     */
  },

  /** Agent runtime knobs. */
  agents: {
    /**
     * Loop budget per agent run.
     *
     * Back to 12. It was briefly lowered to 6 on the theory that every finding now
     * has a prescribed exploit and would not need the room -- but that theory was
     * never actually tested, and path-traversal immediately failed with
     * "Agent runtime exceeded maxIterations (6)".
     *
     * 6 is genuinely too tight for the write-script-then-run flow the directives
     * prescribe: recon, write_test_script and run_in_sandbox each cost a step, and
     * there is no room left for the agent to read a failed result and retry. Since
     * one wasted finding costs far more than the extra steps do, the budget stays
     * wide enough for the prescribed flow to complete.
     */
    maxIterations: num(process.env.AGENT_MAX_ITERATIONS, 12),
    providerTimeoutMs: num(process.env.AGENT_PROVIDER_TIMEOUT_MS, 120_000),
    /**
     * How many findings may be in flight at once.
     *
     * 1 = strictly sequential, one finding at a time.
     *
     * This was 3, which looked attractive because the findings are independent --
     * but the real constraint is the provider's per-minute token budget, not CPU.
     * Running three agents concurrently multiplies the request rate and is what
     * actually provoked rate limiting. Sequential is both safer and
     * more predictable; throughput comes from `AGENT_THROTTLE_MS`, not fan-out.
     */
    concurrency: num(process.env.AGENT_CONCURRENCY, 1),
    /**
     * Minimum pause between agent requests, in milliseconds.
     *
     * A blunt but effective safeguard: it keeps us comfortably under the
     * provider's requests-per-minute and tokens-per-minute limits instead of
     * racing to the ceiling and being cut off mid-run.
     */
    throttleMs: num(process.env.AGENT_THROTTLE_MS, 2000),
  },

  /** Docker sandbox the exploits are replayed inside. */
  sandbox: {
    image: process.env.SANDBOX_IMAGE ?? 'patchproof-sandbox:latest',
    name: process.env.SANDBOX_CONTAINER_NAME ?? 'patchproof-sandbox',
    /**
     * Docker network mode for the sandbox.
     *
     * `none` is the default and what we want: the container gets loopback only,
     * so it can reach the target running alongside it but has no route to the
     * internet. Override only for debugging.
     */
    network: process.env.SANDBOX_NETWORK ?? 'none',
    memory: process.env.SANDBOX_MEMORY ?? '512m',
    cpus: process.env.SANDBOX_CPUS ?? '1.0',
    /** Fork-bomb guard for ephemeral containers. */
    pidsLimit: num(process.env.SANDBOX_PIDS_LIMIT, 256),
    timeoutMs: num(process.env.SANDBOX_TIMEOUT_MS, 60_000),
    /**
     * How long an ephemeral container may wait for the target to answer before
     * giving up. Polled, never slept on.
     */
    readyTimeoutSec: num(process.env.SANDBOX_READY_TIMEOUT_SEC, 60),
    /** Command that boots the target inside the sandbox. */
    startCommand: process.env.TARGET_START_COMMAND ?? 'node src/server.js',
    /** Port the app listens on INSIDE the container. */
    targetPort: num(process.env.TARGET_PORT, 3000),
    /**
     * Host path to the target, mounted into the sandbox. The image does not
     * contain the app, so this volume is how it gets there.
     */
    targetPath: process.env.TARGET_APP_PATH ?? '../targets/vulnerable-shop',
    /**
     * Where the target is mounted inside the sandbox. Exploits run against
     * http://<loopback>/... , never from the host.
     */
    mountPath: process.env.SANDBOX_MOUNT_PATH ?? '/workspace/target',
  },
} as const;

export type Config = typeof config;
