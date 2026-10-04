/**
 * Run the QA verification agent against ONE reported defect and print the full
 * transcript.
 *
 *   npm run check:qa
 *
 * Uses the SQL injection finding from src/routes/search.js as the case study.
 * The agent is given only (type, file, description) -- no exploit, no hint about
 * what to look for -- and must work it out by running the application.
 *
 * Everything the agent did is printed: each step, each tool call and its output,
 * the script it wrote, our independent re-run of that script, and the final
 * verdict line.
 */
// Must be first: config.ts reads process.env at import time, so dotenv has to
// evaluate before any module in the graph.
import 'dotenv/config';

import fs from 'node:fs/promises';
import path from 'node:path';
import { verifyFinding, parseVerdict } from '../src/agents/verificationAgent.js';
import { targetRoot } from '../src/target/source.js';
import { config } from '../src/config.js';

function rule(title = ''): void {
  console.log(title ? `\n${'='.repeat(78)}\n${title}\n${'='.repeat(78)}` : '='.repeat(78));
}

async function main(): Promise<void> {
  // The finding under test, exactly as a scanner would report it.
  const finding = {
    vulnerabilityClass: 'sql-injection' as const,
    file: 'src/routes/search.js',
    line: 30,
    description:
      'The /search endpoint builds its database query by concatenating the caller-supplied ' +
      'q parameter directly into the SQL string instead of binding it as a parameter. The ' +
      'specification requires that all caller input is bound, never interpolated.',
    evidence:
      "const statement = db.prepare(`SELECT id, name, description, price FROM products WHERE name LIKE '%${q}%'`);",
  };

  rule('INPUT -- the finding handed to the agent');
  console.log(`category    : ${finding.vulnerabilityClass}`);
  console.log(`location    : ${finding.file}:${finding.line}`);
  console.log(`description : ${finding.description}`);
  console.log(`evidence    : ${finding.evidence}`);

  rule('AGENT -- live run (transcript)');
  console.log(`provider    : openrouter / ${config.openrouter.model}`);
  console.log(`target      : ${config.target.baseUrl}`);
  console.log(`sandbox     : ${config.sandbox.image} (${config.sandbox.network} network)`);

  const started = Date.now();
  const result = await verifyFinding(finding);
  const elapsed = ((Date.now() - started) / 1000).toFixed(1);

  for (const entry of result.transcript) {
    if (entry.kind === 'text') {
      rule('assistant');
      console.log(entry.text);
    } else if (entry.kind === 'tool') {
      rule(`tool: ${entry.toolName}`);
      console.log(entry.text);
    } else if (entry.kind === 'iteration') {
      console.log(`\n--- ${entry.text} ---`);
    } else if (entry.kind === 'usage') {
      console.log(`[${entry.text}]`);
    } else if (entry.kind === 'done') {
      console.log(`[${entry.text}]`);
    } else if (entry.kind === 'error') {
      console.log(`[error] ${entry.text}`);
    }
  }

  rule('SCRIPT -- what the agent wrote');
  console.log(`filename : ${result.scriptName ?? '(none captured)'}`);
  console.log('contents :');
  console.log(result.testScript ?? '(none)');

  rule('RE-RUN -- the same script, executed independently by us');
  console.log(`ran ok   : ${result.scriptRan}`);
  console.log('output   :');
  console.log(result.scriptOutput ?? '(none)');

  rule('VERDICT -- agent (parseable contract)');
  console.log(`VERDICT: ${result.status}`);
  console.log(`EVIDENCE: ${result.evidence}`);

  rule('CROSS-CHECK -- our static detector on the re-run output');
  console.log(`triggered : ${result.detector.triggered}`);
  console.log(`confidence: ${result.detector.confidence}`);
  console.log(`reasoning : ${result.detector.reasoning}`);

  const agree = (result.status === 'CONFIRMED') === result.detector.triggered;
  rule('AGREEMENT');
  console.log(
    `agent says ${result.status}; detector says ${result.detector.triggered ? 'triggered' : 'not triggered'}`,
  );
  console.log(agree ? '-> the two agree.' : '-> the two DISAGREE; the detector is the tiebreaker.');

  rule();
  console.log(`provider : ${result.provider}${result.usedFallback ? ' (fell back)' : ''}`);
  console.log(`elapsed  : ${elapsed}s`);

  // Leave the repo as we found it.
  if (result.scriptName) {
    await fs.rm(path.join(targetRoot(), result.scriptName), { force: true });
    console.log(`cleaned up ${result.scriptName}`);
  }

  // The verdict line must parse; that is the whole contract.
  const parsed = parseVerdict(result.finalText);
  if (parsed.status === 'INCONCLUSIVE' && !/VERDICT:/i.test(result.finalText)) {
    console.log('\nWARNING: the agent did not emit a parseable VERDICT line.');
    process.exitCode = 1;
  }
}

main().catch(async (error: unknown) => {
  console.error('FAILED:', error instanceof Error ? error.stack : error);
  await sweepStrays();
  process.exit(1);
});

/**
 * Remove any scripts this check left behind.
 *
 * The agent writes into the target repo, so a run that throws part-way would
 * otherwise leave test scripts behind and pollute the next scan.
 */
async function sweepStrays(): Promise<void> {
  const { readdir } = await import('node:fs/promises');
  try {
    const entries = await readdir(targetRoot());
    for (const name of entries) {
      if (name.endsWith('.sh') && (name.startsWith('verify') || name.startsWith('probe'))) {
        await fs.rm(path.join(targetRoot(), name), { force: true });
        console.log(`swept stray ${name}`);
      }
    }
  } catch {
    /* nothing to sweep */
  }
}