/**
 * Tests for pull-request generation.
 *
 *   npm run check:pr
 *
 * Two halves, neither needing a token or network:
 *   1. the report content -- does it show the before/after evidence and the test
 *      results, which is the whole point of the PR body;
 *   2. the GitHub call sequence, driven through a recording stub.
 */
import assert from 'node:assert/strict';
import {
  branchNameFor,
  commitMessageFor,
  prTitleFor,
  renderPrBody,
  type PrEvidence,
} from '../src/github/prReport.js';
import { openPullRequest, type GitHubApi } from '../src/github/openPullRequest.js';
import { buildPrEvidence, type RunState } from '../src/pipeline.js';

export const evidence: PrEvidence = {
  runId: 'run-123',
  findingId: 'VULN-1',
  vulnerabilityClass: 'sql-injection',
  severity: 'critical',
  file: 'src/routes/search.js',
  summary: 'Bound the q parameter instead of interpolating it into SQL',
  unifiedDiff: '--- a/src/routes/search.js\n+++ b/src/routes/search.js\n-old\n+new',
  patchedContent: 'const x = 1;\n',
  exploitCommand:
    "curl -sS -m 5 -G 'http://localhost:3000/search' --data-urlencode \"q=%' UNION SELECT id, username, password, email FROM users--\"",
  successSignal: 'S3cr3t-Adm1n-P@ss',
  before: {
    fired: true,
    output: '{"count":8,"results":[{"name":"admin","description":"S3cr3t-Adm1n-P@ss"}]}',
  },
  after: { fired: false, output: '{"count":0,"results":[]}' },
  functional: { passed: true, passCount: 13, failCount: 0 },
  verdict: 'verified',
};

interface Call {
  name: string;
  args: unknown;
}

/** A recording stand-in for Octokit. */
export function stubApi(): { api: GitHubApi; calls: Call[] } {
  const calls: Call[] = [];
  const ok = (name: string) => (args: unknown) => {
    calls.push({ name, args });
    return Promise.resolve({ data: {} });
  };

  const api = {
    repos: {
      get: async (args: unknown) => {
        calls.push({ name: 'repos.get', args });
        return { data: { default_branch: 'main' } };
      },
      getContent: async (args: unknown) => {
        calls.push({ name: 'repos.getContent', args });
        return { data: { sha: 'olde3e' } };
      },
      createOrUpdateFileContents: ok('repos.createOrUpdateFileContents'),
    },
    git: {
      getRef: async (args: unknown) => {
        calls.push({ name: 'git.getRef', args });
        return { data: { object: { sha: 'baseSha123' } } };
      },
      createRef: ok('git.createRef'),
      deleteRef: ok('git.deleteRef'),
    },
    pulls: {
      create: async (args: unknown) => {
        calls.push({ name: 'pulls.create', args });
        return { data: { number: 42, html_url: 'https://github.com/acme/shop/pull/42' } };
      },
    },
  } as unknown as GitHubApi;

  return { api, calls };
}

function testReport(): void {
  console.log('report body');
  const body = renderPrBody(evidence);

  assert.ok(body.includes('Before the patch'), 'has a before section');
  assert.ok(body.includes('After the patch'), 'has an after section');
  assert.ok(body.includes('Test results'), 'has a test-results section');
  assert.ok(body.includes(evidence.exploitCommand), 'quotes the reproduction command');
  assert.ok(body.includes('S3cr3t-Adm1n-P@ss'), 'quotes the success signal');
  assert.ok(body.includes('"name":"admin"'), 'includes the before output');
  assert.ok(body.includes('"count":0'), 'includes the after output');
  assert.ok(body.includes('13 passing'), 'includes the test counts');
  assert.ok(body.includes('**PASS**'), 'test outcome is stated');
  assert.ok(body.includes('sql-injection'), 'names the vulnerability class');
  assert.ok(body.includes('run-123'), 'traces back to the run');
  assert.ok(body.includes('--- a/src/routes/search.js'), 'includes the diff');
  console.log('  ok  body carries before evidence, after evidence and test results');

  console.log('report body: a failing run is not dressed up as a pass');
  const failed = renderPrBody({
    ...evidence,
    after: { fired: true, output: 'still leaking' },
    functional: { passed: false, passCount: 8, failCount: 5 },
    verdict: 'functional-break',
  });
  assert.ok(failed.includes('**FAILING**'), 'flags failing tests');
  assert.ok(failed.includes('5 failing'), 'reports the failure count');
  assert.ok(failed.includes('**YES**'), 'does not claim the exploit was blocked when it was not');
  console.log('  ok  failing evidence is reported honestly');

  console.log('branch / title / message');
  const branch = branchNameFor(evidence);
  assert.ok(branch.startsWith('patchproof/vuln-1'), `unexpected branch: ${branch}`);
  assert.ok(/^[A-Za-z0-9._\/-]+$/.test(branch), `not a safe git ref: ${branch}`);
  assert.ok(!branch.includes('..'), 'no traversal characters');
  assert.ok(prTitleFor(evidence).includes('sql-injection'));
  assert.ok(commitMessageFor(evidence).includes('VULN-1'));
  console.log(`  ok  branch=${branch}`);

  console.log('long output is truncated, and marked as such');
  const long = renderPrBody({ ...evidence, before: { fired: true, output: 'x'.repeat(5000) } });
  assert.ok(long.includes('(truncated)'), 'marks truncation');
  assert.ok(long.length < 6000, `body stays bounded (${long.length})`);
  console.log('  ok  truncated');
}

async function testApi(): Promise<void> {
  console.log('github call sequence');
  const { api, calls } = stubApi();
  const result = await openPullRequest(evidence, { repo: 'acme/shop', client: api });

  assert.ok(result.ok, `expected success, got: ${result.reason}`);
  assert.equal(result.pullRequest?.number, 42);
  assert.equal(result.pullRequest?.url, 'https://github.com/acme/shop/pull/42');
  console.log(`  ok  PR #${result.pullRequest?.number} ${result.pullRequest?.url}`);

  const order = calls.map((c) => c.name);
  assert.deepEqual(order, [
    'repos.get',
    'git.getRef',
    'git.createRef',
    'repos.getContent',
    'repos.createOrUpdateFileContents',
    'pulls.create',
  ]);
  console.log(`  ok  call order: ${order.join(' -> ')}`);

  const commit = calls.find((c) => c.name === 'repos.createOrUpdateFileContents')!.args as Record<string, unknown>;
  assert.equal(commit.path, 'src/routes/search.js');
  assert.equal(commit.branch, branchNameFor(evidence));
  assert.equal(
    Buffer.from(String(commit.content), 'base64').toString('utf8'),
    evidence.patchedContent,
    'the committed blob must be the patched content, base64 encoded',
  );
  assert.equal(commit.sha, 'olde3e', 'existing file sha sent for an update');
  console.log('  ok  commits the patched file as base64');

  const pr = calls.find((c) => c.name === 'pulls.create')!.args as Record<string, unknown>;
  assert.equal(pr.head, branchNameFor(evidence));
  assert.equal(pr.base, 'main');
  assert.ok(String(pr.body).includes('Before the patch'), 'PR body carries the evidence');
  console.log('  ok  PR targets the new branch from main');

  console.log('github: an existing branch is recreated rather than wedging the run');
  const existing = stubApi();
  let attempts = 0;
  // Real behaviour: the first createRef is rejected because the ref exists,
  // the second succeeds. A stub that always fails would test nothing.
  (existing.api.git as unknown as { createRef: unknown }).createRef = async (args: unknown) => {
    existing.calls.push({ name: 'git.createRef', args });
    attempts += 1;
    if (attempts === 1) {
      const error = new Error('Reference already exists') as Error & { status: number };
      error.status = 422;
      throw error;
    }
    return { data: {} };
  };
  const retry = await openPullRequest(evidence, { repo: 'acme/shop', client: existing.api });
  assert.ok(retry.ok, `expected success on retry, got: ${retry.reason}`);
  const names = existing.calls.map((c) => c.name);
  assert.ok(names.includes('git.deleteRef'), 'deletes the stale branch');
  assert.equal(names.filter((n) => n === 'git.createRef').length, 2, 'retries creation');
  console.log('  ok  branch recreated');

  console.log('github: a new file is created without a sha');
  const fresh = stubApi();
  (fresh.api.repos as unknown as { getContent: unknown }).getContent = async () => {
    const error = new Error('Not Found') as Error & { status: number };
    error.status = 404;
    throw error;
  };
  const created = await openPullRequest(
    { ...evidence, file: 'src/new/route.js' },
    { repo: 'acme/shop', client: fresh.api },
  );
  assert.ok(created.ok, `expected success, got: ${created.reason}`);
  const freshArgs = fresh.calls.find((c) => c.name === 'repos.createOrUpdateFileContents')!.args as Record<string, unknown>;
  assert.equal(freshArgs.sha, undefined, 'no sha for a new file');
  assert.equal(freshArgs.create, true, 'flagged as a create');
  console.log('  ok  new file handled');

  console.log('evidence gathering refuses to invent anything');
  const bareRun = { id: 'r', confirmed: [], patches: [], verifications: [] } as unknown as RunState;
  assert.equal(buildPrEvidence(bareRun, 'VULN-1'), null, 'no evidence without a patch');
  console.log('  ok  returns null rather than a half-filled report');
}

async function main(): Promise<void> {
  testReport();
  await testApi();
  console.log('\nAll pull request checks passed.');
}

void main();
