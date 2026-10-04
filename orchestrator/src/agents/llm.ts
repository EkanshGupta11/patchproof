/**
 * LLM plumbing: provider selection and the primary -> backup fallback runner.
 *
 * Primary provider is OpenRouter (reached through its OpenAI-compatible endpoint).
 * If it rate-limits, 5xx's, or filters the content, we retry a few times and
 * then transparently switch to the configured backup provider.
 */
import { Agent } from '@cline/sdk';
import { config } from '../config.js';
import { createLogger } from '../logger.js';

const log = createLogger('llm');

/**
 * Types are derived from the `Agent` class rather than imported by name,
 * because @cline/sdk only exports `Agent`/`createTool` as runtime values --
 * the type names (AgentConfig, AgentTool, ...) are not re-exported at runtime.
 */
type AgentInstance = InstanceType<typeof Agent>;
type AgentCtorConfig = ConstructorParameters<typeof Agent>[0];
export type AgentToolList = AgentCtorConfig['tools'];
export type AgentRunResult = Awaited<ReturnType<AgentInstance['run']>>;
export type AgentEvent = Parameters<Parameters<AgentInstance['subscribe']>[0]>[0];
export type AgentListener = Parameters<AgentInstance['subscribe']>[0];

export interface ModelChoice {
  /** Human-readable provider label used in logs and API responses. */
  label: string;
  providerId: string;
  modelId: string;
  apiKey: string | undefined;
  /** Undefined for first-party providers, which resolve their own endpoint. */
  baseUrl?: string;
}

/** OpenRouter via its OpenAI-compatible API. */
export function primaryModel(): ModelChoice {
  return {
    label: 'openrouter',
    providerId: 'openai-compatible',
    modelId: config.openrouter.model,
    apiKey: config.openrouter.apiKey,
    baseUrl: config.openrouter.baseUrl,
  };
}

/**
 * Whatever BACKUP_LLM_PROVIDER points at.
 *
 * Applies to both LLM call sites -- the scan reviewer and the exploit verifier
 * -- because both go through `runAgent`, so there is one place to configure.
 */
export function backupModel(): ModelChoice {
  if (config.backupProvider === 'anthropic') {
    return {
      label: 'anthropic',
      providerId: 'anthropic',
      modelId: config.anthropic.model,
      apiKey: config.anthropic.apiKey,
      baseUrl: config.anthropic.baseUrl,
    };
  }

  return {
    label: 'gemini',
    // `gemini` is a first-party provider ID (verified against the SDK's
    // exported BUILT_IN_PROVIDER_IDS). No baseUrl: unlike the OpenRouter primary,
    // which needs an OpenAI-compatible endpoint, Gemini resolves its own.
    providerId: 'gemini',
    modelId: config.gemini.model,
    apiKey: config.gemini.apiKey,
  };
}

function describe(error: unknown): string {
  if (error instanceof Error) return error.message;
  return typeof error === 'string' ? error : JSON.stringify(error);
}

function statusOf(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const candidate = error as { status?: unknown; statusCode?: unknown };
  if (typeof candidate.status === 'number') return candidate.status;
  if (typeof candidate.statusCode === 'number') return candidate.statusCode;
  return undefined;
}

/**
 * A run that "succeeded" but produced no text is a failure, not an answer.
 *
 * This is the quiet one: a content-filtered or truncated response can come back
 * with status "completed" and an empty string. Accepting it means the agent
 * silently declines and the caller concludes there was nothing to find.
 */
export class EmptyAgentResult extends Error {
  constructor(provider: string) {
    super(`agent returned an empty result from ${provider}`);
    this.name = 'EmptyAgentResult';
  }
}

/**
 * Should we give up on the primary provider and try the backup?
 *
 * True for rate limits, overloaded/5xx responses, quota exhaustion, retired
 * models, (when enabled) provider content filtering, and empty results. False for
 * real bugs and bad input, which must surface instead of being masked by a
 * fallback that would only hit the same wall.
 */
export function isFallbackWorthy(error: unknown): boolean {
  // An empty result is retryable: providers occasionally return a
  // successful-looking run with no content.
  if (error instanceof EmptyAgentResult) return true;

  const message = describe(error);

  // Local failures first: our own Docker daemon or orchestrator being
  // unreachable. A different LLM provider would hit exactly the same wall, and
  // retrying would only burn the rate limit while hiding the real problem.
  if (/(ECONNREFUSED|ECONNRESET|EHOSTUNREACH|spawn ENOENT)/i.test(message)) {
    return false;
  }

  const status = statusOf(error);
  if (status !== undefined && config.fallback.statusCodes.includes(status)) return true;

  if (/(rate.?limit|too many requests|\b429\b|quota|overloaded|\b503\b|capacity)/i.test(message)) {
    return true;
  }

  // Rate limits expressed in tokens rather than requests. OpenRouter reports these as
  // "Request too large ... (ITPM): Limit N", which matches none of the usual
  // wording but is still a throttling problem, not a bad request.
  if (/(request too large|input tokens per minute|\bITPM\b|context_length_exceeded|maximum context length)/i.test(message)) {
    return true;
  }

  // A retired or inaccessible model. Retrying the
  // same model cannot help, but switching provider can -- which is exactly what
  // the fallback is for.
  if (/(model.?not.?found|does not exist or you do not have access|model_deprecated|unknown model)/i.test(message)) {
    return true;
  }

  if (config.fallback.onContentFilter) {
    // Covers OpenAI-style codes, Anthropic refusals and generic moderation text.
    if (
      /(content.?filter|content.?polic|content_policy|content_filter|safety|refus|blocked|flagged|responsible_ai|moderation)/i.test(
        message,
      )
    ) {
      return true;
    }
  }

  return false;
}

export interface RunAgentOptions {
  systemPrompt: string;
  prompt: string;
  tools?: AgentToolList;
  maxIterations?: number;
  /** Receives every runtime event; handy for streaming progress to the UI. */
  listener?: AgentListener;
}

export interface RunAgentOutcome {
  result: AgentRunResult;
  provider: string;
  model: string;
  usedFallback: boolean;
}

/**
 * The SDK's result field is `outputText`, and a failed run resolves rather than
 * rejecting. Silently accepting that would mean a dead API key or a retired model
 * looks exactly like an agent that declined to answer, so failures are turned
 * back into exceptions here and the fallback path can see them.
 */
class AgentRunFailure extends Error {
  constructor(
    readonly status: string,
    readonly detail: string,
  ) {
    super(`agent run ${status}: ${detail}`);
    this.name = 'AgentRunFailure';
  }
}

/** The assistant's final text, tolerating either result shape. */
export function agentText(result: AgentRunResult): string {
  const record = result as unknown as { outputText?: string; text?: string };
  return record.outputText ?? record.text ?? '';
}

/**
 * Minimum gap between agent requests.
 *
 * The provider's limits are per-minute, so the simple, reliable way to stay
 * under them is to never fire two requests close together. Deliberately coarse:
 * it trades a little wall-clock time for not being throttled mid-run.
 */
let lastRequestAt = 0;

async function throttle(): Promise<void> {
  const gap = config.agents.throttleMs;
  if (gap <= 0) return;

  const since = Date.now() - lastRequestAt;
  if (lastRequestAt > 0 && since < gap) {
    await new Promise((resolve) => setTimeout(resolve, gap - since));
  }
  lastRequestAt = Date.now();
}

async function attempt(model: ModelChoice, options: RunAgentOptions): Promise<AgentRunResult> {
  await throttle();

  const agent = new Agent({
    providerId: model.providerId,
    modelId: model.modelId,
    apiKey: model.apiKey,
    baseUrl: model.baseUrl,
    systemPrompt: options.systemPrompt,
    tools: options.tools ?? [],
    maxIterations: options.maxIterations ?? config.agents.maxIterations,
    apiTimeoutMs: config.agents.providerTimeoutMs,
  });

  if (options.listener) agent.subscribe(options.listener);

  const result = await agent.run(options.prompt);

  const status = (result as unknown as { status?: string }).status;
  if (status && status !== 'completed') {
    const detail = describe((result as unknown as { error?: unknown }).error) || 'no detail';
    throw new AgentRunFailure(status, detail);
  }

  // A completed run that produced no text is treated as a failure so the backup
  // provider gets a chance. Silently returning "" would look like "nothing to
  // report" rather than "the provider gave us nothing".
  if (agentText(result).trim().length === 0) {
    throw new EmptyAgentResult(model.label);
  }

  return result;
}

/**
 * Run an agent on one provider, retrying failures that a retry could fix.
 *
 * Genuine bugs (bad schema, unreachable host) are rethrown immediately -- a
 * second attempt would only hit the same wall and just wastes the rate limit.
 */
async function attemptWithRetries(
  model: ModelChoice,
  options: RunAgentOptions,
  maxAttempts: number,
): Promise<AgentRunResult> {
  let lastError: unknown;

  for (let attemptNo = 0; attemptNo < maxAttempts; attemptNo += 1) {
    try {
      return await attempt(model, options);
    } catch (error) {
      lastError = error;
      if (!isFallbackWorthy(error)) throw error;

      if (attemptNo < maxAttempts - 1) {
        log.warn(`${model.label} attempt ${attemptNo + 1}/${maxAttempts} failed: ${describe(error)}`);
      }
    }
  }

  throw lastError;
}

/**
 * Run an agent on the primary provider, falling back to the backup provider.
 *
 * The backup is tried when the primary fails, is rate limited, is content
 * filtered, has a retired model, or returns an empty result -- and the backup
 * gets its own retries before the whole thing gives up.
 */
export async function runAgent(options: RunAgentOptions): Promise<RunAgentOutcome> {
  const primary = primaryModel();
  const maxAttempts = Math.max(1, config.fallback.maxRetries + 1);

  if (!primary.apiKey) {
    log.warn('OPENROUTER_API_KEY is not set - the primary provider will fail and we will fall back.');
  }

  try {
    const result = await attemptWithRetries(primary, options, maxAttempts);
    return { result, provider: primary.label, model: primary.modelId, usedFallback: false };
  } catch (error) {
    if (!isFallbackWorthy(error)) throw error;

    const backup = backupModel();
    if (!backup.apiKey) {
      throw new Error(
        `Primary provider '${primary.label}' failed and backup '${backup.label}' has no API key configured.`,
      );
    }

    log.warn(`switching to backup provider '${backup.label}' (${describe(error)})`);

    try {
      const result = await attemptWithRetries(backup, options, maxAttempts);
      return { result, provider: backup.label, model: backup.modelId, usedFallback: true };
    } catch (backupError) {
      throw new Error(
        `Both providers failed. ${primary.label}: ${describe(error)} | ${backup.label}: ${describe(backupError)}`,
      );
    }
  }
}
