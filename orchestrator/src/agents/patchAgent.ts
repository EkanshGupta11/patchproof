/**
 * The patch agent.
 *
 * Takes ONE confirmed vulnerability -- including the evidence that proved it --
 * and writes the smallest change that removes it without breaking anything.
 *
 * ## Why this is not a table of fixes
 *
 * An earlier version mapped vulnerability class to a canned fix ("sql-injection
 * -> use bound parameters"). That only works for the classes someone thought of
 * in advance, which is exactly the limitation this agent is meant to remove.
 *
 * Instead the agent is given the same things a developer fixing a production
 * incident would have: what the bug is, the code, a working reproduction, and
 * what the program is supposed to do. It derives the fix from those. An
 * unfamiliar vulnerability class is handled the same way a familiar one is --
 * because nothing in the prompt branches on the class.
 *
 * Correctness is not taken on trust. The caller replays the reproduction and runs
 * the project's own test suite; see verifyAgent.ts.
 */
import { runAgent, agentText, type AgentEvent } from './llm.js';
import { readSourceFile } from '../target/source.js';
import { tryExtractJson } from '../util/json.js';
import { config } from '../config.js';
import { createLogger } from '../logger.js';
import type { ConfirmedFinding } from '../types.js';

const log = createLogger('agent:patch');

const SYSTEM_PROMPT = `You are a software engineer fixing ONE confirmed defect in an application you own.

You will be given the vulnerable file, an explanation of the defect, and a reproduction that has already been observed working against the running application.

Rules:
1. SMALLEST POSSIBLE CHANGE. Fix the defect and nothing else. Do not refactor, rename, reformat, or tidy unrelated code.
2. KEEP EVERY EXISTING COMMENT. Comments are documentation, not clutter. Leaving them costs nothing and removing them is not a minimal change -- an earlier run deleted the whole file's documentation and turned a two-line fix into a 59-line diff.
3. PRESERVE BEHAVIOUR. The routes, status codes, response shapes and public interface must stay exactly as they are for legitimate input. The application has an existing automated test suite that must still pass; your change must not break any of it.
4. Fix the ROOT CAUSE, not the symptom. Do not blocklist one magic input, and do not simply return an error where the endpoint used to work.
5. Use the mechanism the platform is designed for, not a workaround: the standard library or an already-installed dependency. Do not add new dependencies.
6. Match the surrounding code style, including whether the file uses ESM or CommonJS.

Change as few lines as you possibly can. If the fix is one line, make it one line.

Think about what the correct general behaviour is, then implement that.

Respond with a JSON object and then a summary line, exactly like this:
{"file":"<path exactly as given>","patchedContent":"<the ENTIRE file after your fix, newlines escaped as \\n>","summary":"<one sentence>"}
SUMMARY: <one plain line describing precisely what you changed and why>`;

export interface PatchPlan {
  file: string;
  originalContent: string;
  patchedContent: string;
  summary: string;
}

export interface PatchProposal extends PatchPlan {
  /** The agent's closing SUMMARY: line, parsed verbatim. */
  summaryLine: string;
  transcript: PatchTranscriptEntry[];
  provider: string;
  usedFallback: boolean;
  /** Diff quality: a fix should change very few lines and keep all comments. */
  quality: PatchQuality;
}

/**
 * Whether the patch really was minimal.
 *
 * A patch that is correct but sprawling is still a bad patch: it is harder to
 * review and harder to revert. These are cheap signals that catch the common
 * failure where an agent rewrites a file instead of fixing it.
 */
export interface PatchQuality {
  addedLines: number;
  removedLines: number;
  /** Comment lines present before and absent after. Should be 0. */
  commentsDropped: number;
  /** A rough verdict for reporting. */
  minimal: boolean;
}

const COMMENT_LINE = /^\s*(?:\/\/|\/\*|\*)/;

function countComments(source: string): number {
  return source.split(/\r?\n/).filter((line) => COMMENT_LINE.test(line)).length;
}

/** Measure how much the patch actually disturbed the file. */
export function measurePatchQuality(original: string, patched: string): PatchQuality {
  const before = original.split(/\r?\n/);
  const after = patched.split(/\r?\n/);

  const beforeComments = countComments(original);
  const afterComments = countComments(patched);
  const commentsDropped = Math.max(0, beforeComments - afterComments);

  // Lines removed that were not comments, compared with lines added.
  const removedNonComment = Math.max(0, before.filter((l) => !COMMENT_LINE.test(l)).length - after.filter((l) => !COMMENT_LINE.test(l)).length);
  const addedLines = after.length - before.length;

  return {
    addedLines: Math.max(0, addedLines),
    removedLines: removedNonComment,
    commentsDropped,
    // "Minimal" means a handful of code lines and no deleted documentation.
    minimal: commentsDropped === 0 && Math.abs(addedLines) <= 12,
  };
}

export interface PatchTranscriptEntry {
  kind: 'text' | 'tool' | 'turn' | 'done' | 'error';
  text: string;
}

interface RawPatch {
  file?: string;
  patchedContent?: string;
  summary?: string;
}

/** Parse the trailing `SUMMARY:` line the agent is asked to emit. */
export function parseSummaryLine(text: string): string {
  const match = text.match(/^\s*SUMMARY:\s*(.+)$/im);
  return (match?.[1] ?? '').trim();
}

/** Collect the agent's reasoning and tool activity for display and auditing. */
function createCollector(): { entries: PatchTranscriptEntry[]; listener: (event: AgentEvent) => void } {
  const entries: PatchTranscriptEntry[] = [];

  const listener = (event: AgentEvent): void => {
    const e = event as unknown as {
      type: string;
      delta?: string;
      text?: string;
      iteration?: number;
      toolCall?: { toolName?: string; input?: unknown };
      error?: unknown;
    };

    switch (e.type) {
      case 'assistant-text-delta':
        entries.push({ kind: 'text', text: e.delta ?? '' });
        break;
      case 'tool-started':
        entries.push({
          kind: 'tool',
          text: `${e.toolCall?.toolName ?? 'tool'} ${JSON.stringify(e.toolCall?.input ?? {})}`,
        });
        break;
      case 'tool-finished':
        entries.push({ kind: 'tool', text: '(tool returned)' });
        break;
      case 'turn-finished':
        entries.push({ kind: 'turn', text: `turn ${e.iteration ?? '?'} finished` });
        break;
      case 'run-finished':
        entries.push({ kind: 'done', text: 'run finished' });
        break;
      case 'run-failed':
        entries.push({ kind: 'error', text: String(e.error ?? 'run failed') });
        break;
      default:
        break;
    }
  };

  return { entries, listener };
}

/**
 * Propose a minimal fix for a confirmed vulnerability.
 *
 * Returns null only when the agent produced nothing usable. The patch is NOT
 * written to disk here -- the caller decides, because verification has to run
 * first.
 */
export async function proposePatch(finding: ConfirmedFinding): Promise<PatchProposal | null> {
  const originalContent = await readSourceFile(finding.file);
  const collector = createCollector();

  const prompt = [
    'Confirmed defect to fix.',
    '',
    `Type      : ${finding.vulnerabilityClass}`,
    `File      : ${finding.file}${finding.line ? ` line ${finding.line}` : ''}`,
    `Why it is exploitable: ${finding.rationale}`,
    '',
    'Reproduction (already observed working against the running application):',
    `  command: ${finding.exploit.command}`,
    ...(finding.exploit.successSignal ? [`  proof  : ${finding.exploit.successSignal}`] : []),
    ...(finding.exploit.detection?.reasoning
      ? [`  detector: ${finding.exploit.detection.reasoning}`]
      : []),
    '',
    'Current contents of the file:',
    '```',
    originalContent,
    '```',
    '',
    'Return the patched file as the JSON object, then the SUMMARY line.',
  ].join('\n');

  const outcome = await runAgent({
    systemPrompt: SYSTEM_PROMPT,
    prompt,
    maxIterations: config.agents.maxIterations,
    listener: collector.listener,
  });

  const finalText = agentText(outcome.result);
  const summaryLine = parseSummaryLine(finalText);
  const raw = tryExtractJson<RawPatch>(finalText);
  let patchedContent = raw?.patchedContent;

  // Fallback: some models emit the file inside a fenced code block instead of
  // the JSON envelope. Accept that rather than failing the whole patch stage.
  if (!patchedContent || typeof patchedContent !== 'string') {
    const fenced = finalText.match(/```(?:javascript|js|typescript|ts)?\s*([\s\S]*?)```/i);
    if (fenced?.[1]) {
      patchedContent = fenced[1];
      log.warn(`${finding.id}: JSON envelope missing — extracted patch from fenced code block`);
    }
  }

  if (!patchedContent || typeof patchedContent !== 'string') {
    log.warn(`${finding.id}: agent returned no patched content`);
    return null;
  }

  if (patchedContent.trim() === originalContent.trim()) {
    log.warn(`${finding.id}: agent returned the file unchanged`);
    return null;
  }

  log.info(`${finding.id}: patch proposed via ${outcome.provider}`);

  return {
    file: finding.file,
    originalContent,
    patchedContent,
    summary: raw?.summary ?? summaryLine ?? `Fix ${finding.vulnerabilityClass} in ${finding.file}`,
    summaryLine: summaryLine || (raw?.summary ?? ''),
    transcript: collector.entries,
    provider: outcome.provider,
    usedFallback: outcome.usedFallback,
    quality: measurePatchQuality(originalContent, patchedContent),
  };
}