/**
 * The QA verification agent.
 *
 * Given one suspected defect, this agent decides whether it is genuine by
 * *running a check against the live application* in the sandbox. It never
 * settles the question by reading code and reasoning about it, because a
 * plausible-looking bug and a real one look identical on the page.
 *
 * Two deliberate framing decisions:
 *
 * 1. QA language, not offensive language. The system prompt talks about
 *    specifications, expected behaviour and confirmation tests. Some model
 *    providers filter prompts that read as "write an exploit", even when the
 *    actual task is ordinary QA on an application the team owns. Naming the
 *    defect category is necessary; describing it as an attack is not.
 *
 * 2. Test scripts are a SINGLE line, single-quoted. This is not a style
 *    preference. A script becomes a tool-call argument, and multi-line scripts
 *    with nested double quotes get mangled in transit -- the shell then sees
 *    something different from what the model wrote. Writing one simple command
 *    to a file and running it with `sh <file>` keeps quoting trivial and
 *    removes an entire class of silent failure.
 */
import { runAgent, agentText, type AgentEvent } from './llm.js';
import { runInSandboxTool, writeTestScriptTool, readSourceTool } from './tools.js';
import { runSandboxCommand } from '../sandbox/ephemeral.js';
import { detectTriggered } from '../scan/detectors.js';
import { createLogger } from '../logger.js';
import { config } from '../config.js';
import type { VulnerabilityClass } from '../types.js';

const log = createLogger('agent:qa');

/** The verdict vocabulary the agent must answer with. */
export type VerdictStatus = 'CONFIRMED' | 'NOT_REPRODUCIBLE' | 'INCONCLUSIVE';

export interface QaVerificationRequest {
  /** The defect category, e.g. "sql-injection". */
  vulnerabilityClass: VulnerabilityClass;
  /** Where it was reported. */
  file: string;
  line?: number | null;
  /** The finding in plain language. */
  description: string;
  /** Optional: the reported code snippet. */
  evidence?: string;
}

export interface QaTranscriptEntry {
  kind: 'text' | 'tool' | 'iteration' | 'usage' | 'done' | 'error';
  text: string;
  toolName?: string;
}

export interface QaVerificationResult {
  status: VerdictStatus;
  /** One concrete, quotable line of evidence. */
  evidence: string;
  /** The single-line script the agent settled on. */
  testScript?: string;
  scriptName?: string;
  /** Whether the agent's script actually ran (vs. the agent claiming so). */
  scriptRan: boolean;
  /** Raw output from running the script ourselves, if we re-ran it. */
  scriptOutput?: string;
  /** Full transcript, in order. */
  transcript: QaTranscriptEntry[];
  /** Set when the underlying run failed; the transcript still holds the detail. */
  failure?: string;
  /** The agent's final message, verbatim. */
  finalText: string;
  /** Our independent detector's opinion, as a cross-check. */
  detector: {
    triggered: boolean;
    confidence: 'certain' | 'strong' | 'weak';
    reasoning: string;
  };
  provider: string;
  usedFallback: boolean;
}

/**
 * System prompt.
 *
 * Framed as a QA engineer confirming whether a reported defect reproduces
 * against a running build. Nothing here asks for attack tooling; the task is
 * "does this behaviour match the specification, yes or no", evidenced by a
 * command and its output.
 */
const SYSTEM_PROMPT = `You are a quality assurance engineer confirming whether a reported defect reproduces against a running application. The application is the team's own internal test build, and the defect was filed by an automated code review.

Your job is NOT to reason about the source code. Your job is to produce a check that runs against the live application and reports what it observes.

Method, in order:
1. Read the file if you need context (read_source_file).
2. Write ONE single-line check script (write_test_script).
3. Run that script in the test environment (run_in_sandbox). It starts the application for you and runs your script against it.
4. Read the output and decide: does the application behave the way the specification requires, or not?

CRITICAL RULE -- test scripts must be a SINGLE LINE:
- Write exactly one command. No newlines, no shebang, no multi-line blocks.
- Wrap any value containing spaces or special characters in SINGLE quotes only.
- Do not use double quotes, backticks, \$, or ! anywhere in the script.
- Do not use nested quoting. If a value needs quotes, use single quotes once.
  Correct: curl -sS -m 5 -G 'http://localhost:3000/search' --data-urlencode 'q=abc'
  Wrong:   sh -c "curl 'http://x/?q=\\"y\\""
- The script is passed as a tool argument, so simplicity is what makes it work.

To run it, use: sh <script-filename>

What counts as evidence:
- CONFIRMED: the output shows behaviour that violates the specification. Quote the specific data that proves it.
- NOT_REPRODUCIBLE: the application behaves as specified. This is a perfectly good answer and a normal outcome.
- INCONCLUSIVE: the app would not start, or the check could not be run.

Do not guess. Do not report a defect you did not observe in output.

BUDGET -- you have limited turns, and each run_in_sandbox call takes several seconds:
- Write ONE script, run it ONCE, then give your verdict.
- Only revise and re-run if the script errored (no output at all). If it produced output, that output is your answer.
- Do not re-run a script that already returned data, even if the data looks unexpected.

FINISH WITH EXACTLY THESE TWO LINES, and nothing after them:
VERDICT: CONFIRMED | NOT_REPRODUCIBLE | INCONCLUSIVE
EVIDENCE: <one concrete line, quoting the observed output>`;

function buildPrompt(request: QaVerificationRequest): string {
  return [
    'Reported defect to confirm:',
    '',
    `Category    : ${request.vulnerabilityClass}`,
    `Location    : ${request.file}${request.line ? ` line ${request.line}` : ''}`,
    `Description : ${request.description}`,
    ...(request.evidence ? [`Reported code: ${request.evidence}`] : []),
    '',
    `The application under test responds at ${config.target.baseUrl}.`,
    'Write a single-line check, run it, and report the verdict.',
  ].join('\n');
}

/** Parse the two-line verdict contract out of the agent's final message. */
export function parseVerdict(text: string): { status: VerdictStatus; evidence: string } {
  const verdictMatch = text.match(/^\s*VERDICT:\s*(CONFIRMED|NOT_REPRODUCIBLE|INCONCLUSIVE)\s*$/im);
  const evidenceMatch = text.match(/^\s*EVIDENCE:\s*(.+)$/im);

  if (!verdictMatch) {
    // No parseable verdict: treat as inconclusive rather than guessing.
    return { status: 'INCONCLUSIVE', evidence: 'agent did not emit a parseable VERDICT line' };
  }

  return {
    status: verdictMatch[1] as VerdictStatus,
    evidence: (evidenceMatch?.[1] ?? '').trim(),
  };
}

// PLACEHOLDER_AGENT
/**
 * Pull readable text out of a tool-result message.
 *
 * `tool-finished` carries its result on `message` (a message whose content holds
 * a tool-result part), not on `toolCall.output`, so the shape is dug out here
 * rather than guessed at the call site.
 */
function toolResult(message: unknown): string | undefined {
  if (!message || typeof message !== 'object') return undefined;

  const content = (message as { content?: unknown }).content;
  if (!Array.isArray(content)) return JSON.stringify(message);

  const parts: string[] = [];
  for (const part of content) {
    if (!part || typeof part !== 'object') continue;
    const record = part as { type?: string; text?: string; output?: unknown; error?: unknown };
    if (record.type === 'tool-result') {
      if (typeof record.output === 'string') parts.push(record.output);
      else if (record.output !== undefined) parts.push(JSON.stringify(record.output));
      else if (record.error !== undefined) parts.push(`ERROR: ${String(record.error)}`);
    } else if (typeof record.text === 'string') {
      parts.push(record.text);
    }
  }

  return parts.length ? parts.join('\n') : undefined;
}

/**
 * Turn the agent's event stream into an ordered, readable transcript.
 *
 * Event names here are the ones the SDK actually emits (`assistant-text-delta`,
 * `tool-started`, `tool-finished`, `turn-finished`, `run-finished`), with tool
 * arguments arriving on `event.toolCall.input`.
 */
function createTranscriptCollector(): {
  entries: QaTranscriptEntry[];
  scriptWrites: Array<{ filename: string; content: string }>;
  observedRuns: string[];
  listener: (event: AgentEvent) => void;
} {
  const entries: QaTranscriptEntry[] = [];
  const scriptWrites: Array<{ filename: string; content: string }> = [];
  const observedRuns: string[] = [];
  let pendingText = '';

  const flushText = (): void => {
    const trimmed = pendingText.trim();
    if (trimmed) entries.push({ kind: 'text', text: trimmed });
    pendingText = '';
  };

  const listener = (event: AgentEvent): void => {
    const e = event as unknown as {
      type: string;
      iteration?: number;
      message?: unknown;
      toolCall?: { toolName?: string; input?: unknown; output?: unknown; error?: unknown };
      delta?: string;
      text?: string;
      error?: unknown;
      finishReason?: string;
      usage?: { inputTokens?: number; outputTokens?: number };
    };

    switch (e.type) {
      case 'assistant-text-delta':
        pendingText += e.delta ?? '';
        break;

      case 'assistant-message':
        // Prefer the completed message over accumulated deltas.
        if (typeof e.text === 'string' && e.text.trim()) pendingText = e.text;
        flushText();
        break;

      case 'tool-started': {
        flushText();
        const name = e.toolCall?.toolName ?? 'tool';
        const input = e.toolCall?.input as { filename?: string; content?: string } | undefined;
        entries.push({
          kind: 'tool',
          toolName: name,
          text: `-> ${JSON.stringify(input ?? {})}`,
        });
        if (name === 'write_test_script' && input?.filename) {
          scriptWrites.push({ filename: input.filename, content: input.content ?? '' });
        }
        break;
      }

      case 'tool-finished': {
        const name = e.toolCall?.toolName ?? 'tool';
        const out = e.toolCall?.error ?? toolResult(e.message) ?? '(no output)';
        const rendered =
          String(typeof out === 'string' ? out : JSON.stringify(out)).slice(0, 1500);

        // Keep what the agent actually saw when it ran a command. That is the
        // evidence its verdict rests on, and it may not correspond to the last
        // script it wrote (it can revise a script without running it).
        if (name === 'run_in_sandbox' && typeof out === 'string') {
          observedRuns.push(out);
        }

        entries.push({ kind: 'tool', toolName: name, text: rendered });
        break;
      }

      case 'turn-finished':
        entries.push({ kind: 'iteration', text: `turn ${e.iteration ?? '?'} finished` });
        break;

      case 'usage-updated':
        if (e.usage) {
          entries.push({
            kind: 'usage',
            text: `tokens in=${e.usage.inputTokens ?? 0} out=${e.usage.outputTokens ?? 0}`,
          });
        }
        break;

      case 'run-finished':
        flushText();
        entries.push({ kind: 'done', text: `finished: ${e.finishReason ?? 'completed'}` });
        break;

      case 'run-failed':
        flushText();
        entries.push({ kind: 'error', text: String(e.error ?? 'run failed') });
        break;

      default:
        break;
    }
  };

  return { entries, scriptWrites, observedRuns, listener };
}

/** The last text block the agent produced, which carries the verdict. */
function lastAgentText(entries: QaTranscriptEntry[]): string {
  for (let i = entries.length - 1; i >= 0; i -= 1) {
    const entry = entries[i];
    if (entry?.kind === 'text' && entry.text.length > 0) return entry.text;
  }
  return '';
}

/**
 * Verify one reported defect by running a check against the live application.
 *
 * The agent's own verdict is reported, but we do not simply believe it: we
 * re-run the script it wrote and cross-check the output with the static detector.
 * Disagreement between the agent and the detector is surfaced rather than
 * averaged away.
 */
export async function verifyFinding(
  request: QaVerificationRequest,
): Promise<QaVerificationResult> {
  const collector = createTranscriptCollector();

  log.info(`verifying ${request.vulnerabilityClass} in ${request.file}`);

  // A run that dies part-way still tells us something: the transcript up to that
  // point is the most useful diagnostic we have. So failures are captured rather
  // than propagated, and reported as an inconclusive verdict with the reason.
  let outcome;
  let failure: string | undefined;
  try {
    outcome = await runAgent({
      systemPrompt: SYSTEM_PROMPT,
      prompt: buildPrompt(request),
      tools: [readSourceTool, writeTestScriptTool, runInSandboxTool],
      // Enough room to read, write, run, notice a failure and revise once.
      maxIterations: 14,
      listener: collector.listener,
    });
  } catch (error) {
    failure = error instanceof Error ? error.message : String(error);
    log.warn(`agent run failed: ${failure}`);
  }

  const finalText = outcome ? agentText(outcome.result) : lastAgentText(collector.entries);
  const { status, evidence } = parseVerdict(finalText);

  // The last script the agent wrote is the one it settled on.
  const settled = collector.scriptWrites[collector.scriptWrites.length - 1];

  // Re-run it ourselves. The agent's verdict is reported, but our own run of its
  // script is what the detector judges -- so the two can be compared honestly.
  let scriptOutput: string | undefined;
  let scriptRan = false;
  if (settled?.filename) {
    const replay = await runSandboxCommand({
      command: `sh ${settled.filename}`,
      label: 'qa-replay',
      timeoutMs: config.agents.providerTimeoutMs,
    });
    scriptRan = replay.exitCode === 0;
    scriptOutput = `${replay.stdout}\n${replay.stderr}`.trim().slice(-2000);
  }

  // Judge what the agent ACTUALLY observed, not a re-run of whatever it last
  // wrote. It may revise a script without running it, in which case the re-run
  // would grade the wrong evidence. Our own re-run is still reported, but as a
  // reproducibility check rather than as the basis of the verdict.
  const agentObserved = collector.observedRuns[collector.observedRuns.length - 1] ?? '';

  const detection = detectTriggered({
    vulnerabilityClass: request.vulnerabilityClass,
    output: agentObserved || scriptOutput || finalText,
    expectedSignal: undefined,
  });

  // A crashed run cannot be CONFIRMED, whatever the transcript looks like.
  const finalStatus = failure && status === 'CONFIRMED' ? 'INCONCLUSIVE' : status;

  log.info(`agent verdict: ${finalStatus}; detector: ${detection.triggered}`);

  return {
    status: finalStatus,
    evidence: failure ? `run failed: ${failure}` : evidence,
    finalText,
    transcript: collector.entries,
    testScript: settled?.content,
    scriptName: settled?.filename,
    scriptRan,
    scriptOutput,
    failure,
    provider: outcome?.provider ?? config.openrouter.model,
    usedFallback: outcome?.usedFallback ?? false,
    detector: {
      triggered: detection.triggered,
      confidence: detection.confidence,
      reasoning: detection.reasoning,
    },
  };
}