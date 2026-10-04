/**
 * Isolated test for one finding class (path-traversal by default).
 *
 * Scoped to a single finding on purpose: the full pipeline also runs the LLM
 * scan pass and the other findings, and those dominate the wall-clock time.
 * This exercises exactly the path that was failing -- static analysis ->
 * exploit agent -> independent replay -> detector -- so the result says
 * something about the fix rather than about provider latency.
 *
 * Usage: tsx scripts/check-one-finding.ts [vulnerability-class]
 */
import 'dotenv/config';
import { runStaticScan } from '../src/scan/staticAnalysis.js';
import { confirmVulnerability } from '../src/agents/exploitAgent.js';
import type { Candidate } from '../src/types.js';

const target = process.argv[2] ?? 'path-traversal';

const scan = await runStaticScan();
const candidate = scan.candidates.find((c) => c.vulnerabilityClass === target);

if (!candidate) {
  console.error(`FAIL: static analysis produced no ${target} finding`);
  console.error(`found: ${scan.candidates.map((c) => c.vulnerabilityClass).join(', ') || '(none)'}`);
  process.exit(1);
}

console.log(`candidate: ${candidate.id} ${candidate.vulnerabilityClass} ` +
  `${candidate.file}:${candidate.line} (${candidate.severity})`);
console.log(`rule:      ${candidate.ruleId}`);
console.log(`budget:    ${process.env.AGENT_MAX_ITERATIONS ?? 'default'} iterations\n`);

const startedAt = Date.now();
const result = (await confirmVulnerability(candidate as Candidate)) ?? null;
const elapsedMs = Date.now() - startedAt;

console.log(`\n--- result after ${(elapsedMs / 1000).toFixed(1)}s ---`);

if (!result) {
  console.log('RESULT: NOT CONFIRMED');
  process.exit(1);
}

console.log('RESULT: CONFIRMED');
console.log(`command:       ${result.exploit.command}`);
console.log(`successSignal: ${result.exploit.successSignal}`);
console.log(`confidence:    ${result.exploit.detection.confidence}`);
console.log(`reasoning:     ${result.exploit.detection.reasoning}`);
console.log(`signals:`);
for (const signal of result.exploit.detection.signals) {
  console.log(`  - [${signal.detector}] ${signal.why}`);
  console.log(`    matched: ${signal.matchedLine}`);
}
console.log(`observedOutput:\n${result.exploit.observedOutput.trim()}`);