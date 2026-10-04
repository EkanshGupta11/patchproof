/**
 * Unit tests for the event reducer.
 *
 *   npm test
 *
 * The reducer is the piece most likely to break silently: if it mis-maps an
 * event type, the timeline renders plausible-looking but wrong states and nothing
 * throws. These feed real backend event shapes through it and assert the result.
 */
import assert from 'node:assert/strict';
import { applyEvent, type FindingProgress, type RunProgress } from '../src/hooks/useRunStream';
import type { PipelineEvent } from '../src/api';

const emptyRun: RunProgress = { status: 'running', scanTotal: 0 };
let findings: FindingProgress[] = [];

function feed(...events: PipelineEvent[]): void {
  for (const event of events) {
    ({ findings } = applyEvent(findings, emptyRun, event));
  }
}

function only(): FindingProgress {
  assert.equal(findings.length, 1, 'expected exactly one finding');
  return findings[0]!;
}

const t0 = '2026-01-01T00:00:00.000Z';

const scanFinding: PipelineEvent = {
  type: 'scan.finding',
  phase: 'scan',
  at: t0,
  findingId: 'VULN-1',
  message: 'found',
  data: {
    id: 'VULN-1',
    vulnerabilityClass: 'command-injection',
    severity: 'critical',
    file: 'src/routes/convert.js',
    line: 48,
    ruleId: 'security/detect-child-process',
  },
};

console.log('reducer: happy path scan -> exploit -> patch -> verify');

feed(scanFinding);
assert.equal(only().vulnerabilityClass, 'command-injection');
assert.equal(only().file, 'src/routes/convert.js');
assert.equal(only().line, 48);
assert.equal(only().exploit, 'pending');

feed({ type: 'exploit.started', phase: 'exploit', at: t0, findingId: 'VULN-1', message: 'trying' });
assert.equal(only().exploit, 'running');

feed({ type: 'exploit.confirmed', phase: 'exploit', at: t0, findingId: 'VULN-1', message: 'confirmed' });
assert.equal(only().exploit, 'confirmed');

feed({ type: 'patch.started', phase: 'patch', at: t0, findingId: 'VULN-1', message: 'writing' });
assert.equal(only().patch, 'running');

feed({
  type: 'patch.proposed',
  phase: 'patch',
  at: t0,
  findingId: 'VULN-1',
  message: 'done',
  data: { unifiedDiff: '--- a\n+++ b\n-old\n+new', agentSummary: 'switched to execFile' },
});
assert.equal(only().patch, 'proposed');
assert.equal(only().summary, 'switched to execFile');
assert.ok(only().diff?.includes('+new'));

feed({ type: 'verify.started', phase: 'verify', at: t0, findingId: 'VULN-1', message: 'proving' });
assert.equal(only().verify, 'running');

feed({
  type: 'verify.result',
  phase: 'verify',
  at: t0,
  findingId: 'VULN-1',
  message: 'verified',
  data: { verdict: 'verified', functional: { passed: true, passCount: 13, failCount: 0 } },
});
assert.equal(only().verify, 'verified');
assert.equal(only().testSummary, '13 passed');
assert.equal(only().approved, false, 'not approved until the user acts');

console.log('  ok  full path lands on verified');

console.log('reducer: approval flips the flag and records the time');
feed({
  type: 'approval.applied',
  phase: 'approval',
  at: t0,
  findingId: 'VULN-1',
  message: 'approved',
  data: { approvedAt: t0 },
});
assert.equal(only().approved, true);
assert.equal(only().approvedAt, t0);
console.log('  ok  approved');

console.log('reducer: rejected exploit');
findings = [];
feed(scanFinding);
feed({ type: 'exploit.started', phase: 'exploit', at: t0, findingId: 'VULN-1', message: 'trying' });
feed({ type: 'exploit.rejected', phase: 'exploit', at: t0, findingId: 'VULN-1', message: 'nope' });
assert.equal(only().exploit, 'rejected');
assert.equal(only().patch, 'pending', 'patch must not start after a rejection');
assert.equal(only().verify, 'pending');
console.log('  ok  rejected, downstream phases untouched');

console.log('reducer: functional-break is not treated as verified');
findings = [];
feed(scanFinding);
feed({ type: 'exploit.confirmed', phase: 'exploit', at: t0, findingId: 'VULN-1', message: 'c' });
feed({
  type: 'verify.result',
  phase: 'verify',
  at: t0,
  findingId: 'VULN-1',
  message: 'broke',
  data: { verdict: 'functional-break', functional: { passed: false, passCount: 8, failCount: 5 } },
});
assert.equal(only().verify, 'functional-break');
assert.ok(only().testSummary?.includes('FAILING'));
console.log('  ok  functional-break flagged');

console.log('reducer: run-level events do not create a finding');
findings = [];
let run = emptyRun;
({ findings, run } = applyEvent(findings, run, { type: 'run.started', phase: 'run', at: t0, message: 'go' }));
({ findings, run } = applyEvent(findings, run, {
  type: 'scan.completed',
  phase: 'scan',
  at: t0,
  message: 'scan done',
  data: { total: 7, considered: 1 },
}));
assert.equal(findings.length, 0, 'run-level events must not fabricate findings');
assert.equal(run.scanTotal, 7);
({ findings, run } = applyEvent(findings, run, { type: 'run.completed', phase: 'run', at: t0, message: 'done' }));
assert.equal(run.status, 'completed');
console.log('  ok  run-level events handled separately');

console.log('reducer: two findings stay independent');
findings = [];
feed(scanFinding);
feed({ ...scanFinding, findingId: 'VULN-2', data: { ...(scanFinding.data as object), id: 'VULN-2', vulnerabilityClass: 'path-traversal' } as never });
feed({ type: 'exploit.confirmed', phase: 'exploit', at: t0, findingId: 'VULN-1', message: 'c' });
assert.equal(findings.length, 2, 'both findings are tracked');
assert.equal(findings[0]!.exploit, 'confirmed', 'VULN-1 advanced');
assert.equal(findings[1]!.exploit, 'pending', 'VULN-2 untouched');
assert.equal(findings[1]!.vulnerabilityClass, 'path-traversal');
console.log('  ok  independent');

console.log('\nAll reducer tests passed.');