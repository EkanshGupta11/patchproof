// Must be first: config.ts reads process.env at import time.
import 'dotenv/config';

import fs from 'node:fs/promises';
import path from 'node:path';
import { proposePatch } from '../src/agents/patchAgent.js';
import { verifyPatch } from '../src/agents/verifyAgent.js';
import { runFunctionalSuite } from '../src/agents/functionalSuite.js';
import { replayExploit } from '../src/agents/verifyAgent.js';
import { overwriteSourceFile, targetRoot } from '../src/target/source.js';
import { unifiedDiff } from '../src/util/diff.js';
import { config } from '../src/config.js';
import type { ConfirmedFinding } from '../src/types.js';

function rule(title = ''): void {
  console.log(title ? `\n${'='.repeat(78)}\n${title}\n${'='.repeat(78)}` : '='.repeat(78));
}

/**
 * The already-confirmed SQL injection finding from the verification step,
 * including the evidence that proved it.
 */
const FINDING: ConfirmedFinding = {
  id: 'VULN-1',
  vulnerabilityClass: 'sql-injection',
  severity: 'critical',
  file: 'src/routes/search.js',
  line: 30,
  evidence:
    "const statement = db.prepare(`SELECT id, name, description, price FROM products WHERE name LIKE '%${q}%'`);",
  rationale: 'The q parameter is interpolated into the SQL string instead of being bound.',
  exploit: {
    command:
      "curl -sS -m 5 -G 'http://localhost:3000/search' --data-urlencode \"q=%' UNION SELECT id, username, password, email FROM users--\"",
    successSignal: 'S3cr3t-Adm1n-P@ss',
    observedOutput:
      '{"count":8,"results":[{"name":"alice","description":"alice-password"},{"name":"admin","description":"S3cr3t-Adm1n-P@ss"}]}',
    succeeded: true,
    detection: {
      triggered: true,
      confidence: 'certain',
      signals: [],
      reasoning: 'response contains credential rows that the products table does not hold',
    },
  },
  confirmedAt: new Date().toISOString(),
};

async function main(): Promise<void> {
  rule('BASELINE -- functional suite BEFORE the patch');
  const before = await runFunctionalSuite('npm test', 'before-patch');
  console.log(`passed: ${before.passed} (${before.passCount} pass / ${before.failCount} fail)`);

  rule('INPUT -- the confirmed finding handed to the patch agent');
  console.log(`id      : ${FINDING.id}`);
  console.log(`type    : ${FINDING.vulnerabilityClass}`);
  console.log(`file    : ${FINDING.file}:${FINDING.line}`);
  console.log(`proof   : ${FINDING.exploit.successSignal}`);
  console.log(`command : ${FINDING.exploit.command}`);

  rule('PATCH AGENT -- live run');
  console.log(`provider: ${config.openrouter.model}`);
  const started = Date.now();
  const patch = await proposePatch(FINDING);
  if (!patch) {
    console.log('the agent produced no usable patch');
    process.exitCode = 1;
    return;
  }
  const elapsed = ((Date.now() - started) / 1000).toFixed(1);

  for (const entry of patch.transcript) {
    if (entry.kind === 'text' && entry.text.trim()) {
      rule('assistant');
      console.log(entry.text.trim());
    } else if (entry.kind === 'tool') {
      console.log(`[tool] ${entry.text}`);
    } else if (entry.kind === 'turn') {
      console.log(`[${entry.text}]`);
    }
  }

  rule('SUMMARY LINE (parsed by the caller)');
  console.log(patch.summaryLine || '(none emitted)');

  rule('DIFF -- the actual change');
  const diff = unifiedDiff(patch.file, patch.originalContent, patch.patchedContent);
  console.log(diff);

  const added = diff.split('\n').filter((l) => l.startsWith('+') && !l.startsWith('+++')).length;
  const removed = diff.split('\n').filter((l) => l.startsWith('-') && !l.startsWith('---')).length;
  console.log(`\n(+${added} / -${removed} lines in ${patch.file})`);
  console.log(`minimal-change check: ${patch.quality.minimal ? 'OK' : 'TOO BIG'}`);
  console.log(
    `  code lines added=${patch.quality.addedLines} removed=${patch.quality.removedLines}, comments dropped=${patch.quality.commentsDropped}`,
  );

  rule('VERIFY GATE 1 -- replay the original exploit against the patched build');
  await overwriteSourceFile(patch.file, patch.patchedContent);
  let gate1 = 'not run';
  try {
    const replayed = await replayExploit(FINDING);
    gate1 = replayed.triggered ? `STILL EXPLOITABLE (${replayed.confidence})` : 'evidence gone';
    console.log(`exploit still succeeds: ${replayed.triggered}`);
    console.log(`detector: ${replayed.reasoning}`);
  } finally {
    // Gate 2 runs against the patched tree too, so hold the patch until it is done.
  }

  rule('VERIFY GATE 2 -- the project test suite must still pass');
  const after = await runFunctionalSuite('npm test', 'after-patch');
  console.log(`passed: ${after.passed} (${after.passCount} pass / ${after.failCount} fail)`);
  console.log('(tests exercise: search matching, case-insensitivity, empty results, missing q, column shape)');

  // Restore the target.
  await overwriteSourceFile(patch.file, patch.originalContent);
  rule();
  console.log(`gate 1 (exploit)  : ${gate1}`);
  console.log(`gate 2 (tests)    : ${after.passed ? 'PASS' : 'FAIL'}`);
  console.log(
    `overall           : ${gate1 === 'evidence gone' && after.passed ? 'VERIFIED' : 'REJECTED'}`,
  );
  console.log(`elapsed           : ${elapsed}s`);
  console.log(`restored          : ${patch.file}`);
}
main().catch(async (error: unknown) => {
  console.error('FAILED:', error instanceof Error ? error.stack : error);
  process.exit(1);
});