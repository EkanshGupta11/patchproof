/**
 * Turning a verified fix into a pull request.
 *
 * ## Why this file is split
 *
 * `prReport.ts` is pure: it builds branch names, commit messages and the PR body
 * from data we already hold. `openPullRequest.ts` does the network I/O.
 *
 * The split matters because the interesting part -- does the report actually
 * show the before/after evidence and the test results -- is exactly the part
 * that is painful to check against a live GitHub API. Pure functions mean it can
 * be asserted directly, with no token and no network.
 */
import type { ExploitReplay } from '../types.js';

/** Everything needed to describe a fix in a pull request. */
export interface PrEvidence {
  runId: string;
  findingId: string;
  vulnerabilityClass: string;
  severity: string;
  file: string;
  summary: string;
  unifiedDiff: string;
  /** The full patched file, which is what actually gets committed. */
  patchedContent: string;
  exploitCommand: string;
  /** The literal that only appears when the vulnerability is present. */
  successSignal?: string;
  /** Exploit replayed against the original code. Should have fired. */
  before: ExploitReplay;
  /** Same exploit against the patched code. Should not have fired. */
  after: ExploitReplay;
  functional: { passed: boolean; passCount: number | null; failCount: number | null };
  verdict: string;
}

/** Longest code block we embed; GitHub renders fine and bodies stay readable. */
const MAX_OUTPUT = 1200;

/**
 * A branch name that is safe as a git ref: no spaces, no "~^:?*[\", no leading
 * dot or dash, and short enough to stay legible in a UI.
 */
export function branchNameFor(evidence: PrEvidence): string {
  const slug = evidence.summary
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40)
    .replace(/-+$/g, '');

  const finding = evidence.findingId.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  return `patchproof/${finding}${slug ? `-${slug}` : ''}`;
}

export function commitMessageFor(evidence: PrEvidence): string {
  return [
    `fix(${evidence.vulnerabilityClass}): ${evidence.summary}`,
    '',
    `Finding: ${evidence.findingId} (${evidence.severity}) in ${evidence.file}`,
    `Verified by differential exploit replay: the exploit fired before the patch and is`,
    `blocked after it, with the project's test suite still passing.`,
  ].join('\n');
}

export function prTitleFor(evidence: PrEvidence): string {
  return `[patchproof] fix ${evidence.vulnerabilityClass} in ${evidence.file}`;
}

/** Trim output for embedding, marking that it was cut. */
function fence(body: string, lang = ''): string {
  const trimmed = body.length > MAX_OUTPUT ? `${body.slice(0, MAX_OUTPUT)}\n… (truncated)` : body || '(no output)';
  // Use a longer fence if the content itself contains a backtick fence.
  const ticks = trimmed.includes('```') ? '````' : '```';
  return `${ticks}${lang}\n${trimmed}\n${ticks}`;
}

function yesNo(fired: boolean): string {
  return fired ? '**YES** — the exploit succeeded' : '**no** — the exploit was blocked';
}

/**
 * Build the pull request body.
 *
 * Structured as evidence, not narrative: a reviewer should be able to check the
 * claim without trusting anyone, including us.
 */
export function renderPrBody(evidence: PrEvidence): string {
  const tests = evidence.functional.passCount !== null
    ? `${evidence.functional.passCount} passing, ${evidence.functional.failCount ?? 0} failing`
    : 'no counts reported';

  return [
    '## What this fixes',
    '',
    evidence.summary || `Fix for ${evidence.vulnerabilityClass} in ${evidence.file}.`,
    '',
    `| | |`,
    `|---|---|`,
    `| Finding | \`${evidence.findingId}\` |`,
    `| Class | \`${evidence.vulnerabilityClass}\` |`,
    `| Severity | \`${evidence.severity}\` |`,
    `| File | \`${evidence.file}\` |`,
    `| Verdict | \`${evidence.verdict}\` |`,
    `| Source run | \`${evidence.runId}\` |`,
    '',
    '## Why this is safe to merge',
    '',
    'This was not accepted on an AI\'s say-so. The same exploit was replayed against',
    'both the unpatched and the patched build, and the project\'s own test suite was',
    're-run afterwards:',
    '',
    `1. Against the **original** code: ${yesNo(evidence.before.fired)}.`,
    `2. Against the **patched** code: ${yesNo(evidence.after.fired)}.`,
    `3. The test suite still passes — ${tests}${evidence.functional.passed ? '' : ' **FAILING**'}.`,
    '',
    'Step 3 is what rules out the cheap "fix" that just disables the vulnerable',
    'endpoint: that stops the exploit too, but it breaks the tests.',
    '',
    '### Before the patch — exploit evidence',
    '',
    'Reproduction command:',
    '',
    fence(evidence.exploitCommand, 'bash'),
    '',
    `Result against the **original** code: ${yesNo(evidence.before.fired)}.`,
    ...(evidence.successSignal ? [`Success signal looked for: \`${evidence.successSignal}\``] : []),
    '',
    'Output:',
    '',
    fence(evidence.before.output),
    '',
    '### After the patch — same exploit replayed',
    '',
    `Result against the **patched** code: ${yesNo(evidence.after.fired)}.`,
    '',
    'Output:',
    '',
    fence(evidence.after.output),
    '',
    '### Test results',
    '',
    `- Functional suite: **${evidence.functional.passed ? 'PASS' : 'FAIL'}** (${tests})`,
    ...(evidence.functional.failCount ? [`- ${evidence.functional.failCount} test(s) failing`] : []),
    '',
    '### The change',
    '',
    fence(evidence.unifiedDiff, 'diff'),
    '',
    '---',
    '',
    '_Opened by PatchProof. The fix was written by an AI agent and verified by',
    'deterministic replay against a running instance; the commit message and this',
    'description are generated from that verification._',
  ].join('\n');
}