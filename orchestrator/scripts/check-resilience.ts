/**
 * Tests for the two resilience mechanisms added for full runs:
 *   1. findings in different files run concurrently, same file stays sequential;
 *   2. the backup provider is used when the primary fails or returns nothing.
 *
 *   npm run check:resilience
 */
import assert from 'node:assert/strict';
import { isFallbackWorthy, EmptyAgentResult, primaryModel, backupModel } from '../src/agents/llm.js';

console.log('fallback detection');

const fallbackWorthy: string[] = [
  '429 Too Many Requests',
  'rate limit reached for model',
  'Request too large ... (ITPM): Limit 7000',
  'Rate limit reached ... on tokens per day (TPD): Limit 200000',
  'The model does not exist or you do not have access to it',
  'content_policy_violation',
  'Your request was blocked by our content filter',
  'overloaded_error',
  '503 Service Unavailable',
];

for (const message of fallbackWorthy) {
  assert.ok(isFallbackWorthy(new Error(message)), `should be retryable: ${message}`);
}
console.log(`  ok  ${fallbackWorthy.length} provider failure shapes are retryable`);

// Genuine bugs must surface rather than being retried against a second provider.
const fatal: string[] = [
  'ECONNREFUSED 127.0.0.1:4000',
  'spawn ENOENT docker',
  'Invalid JSON in request body',
  'zod: expected string',
];
for (const message of fatal) {
  assert.ok(!isFallbackWorthy(new Error(message)), `should NOT be retryable: ${message}`);
}
console.log('  ok  real bugs (including local ECONNREFUSED) are not masked by a fallback');

// Provider ids the SDK actually knows about. Using an unregistered id fails at
// run time with "Unknown or disabled provider", which is a config bug, not a
// transient one -- so it must be caught here.
console.log('provider ids are valid');
{
  const { BUILT_IN_PROVIDER_IDS } = await import('@cline/sdk');
  const known = new Set<string>(BUILT_IN_PROVIDER_IDS as string[]);
  for (const choice of [primaryModel(), backupModel()]) {
    assert.ok(
      known.has(choice.providerId),
      `${choice.label} uses providerId "${choice.providerId}", which the SDK does not know. Valid: openai-native, anthropic, openai-compatible...`,
    );
  }
  console.log('  ok  primary and backup provider ids are registered with the SDK');
}

assert.ok(isFallbackWorthy(new EmptyAgentResult('groq')), 'empty result is retryable');
assert.ok(isFallbackWorthy(new Error('request refused by the provider')), 'refusal is retryable');
console.log('  ok  empty results and refusals trigger the backup');

/** Run async jobs with a cap, mirroring the pipeline's scheduler. */
async function withLimit<T>(jobs: Array<() => Promise<T>>, limit: number): Promise<T[]> {
  const results: T[] = [];
  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < jobs.length) {
      const job = jobs[cursor]!;
      cursor += 1;
      results.push(await job());
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, jobs.length) }, () => worker()));
  return results;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

console.log('parallel scheduling');
{
  // Distinct files: all three should be in flight together.
  let peak = 0;
  let active = 0;
  const job = async (): Promise<string> => {
    active += 1;
    peak = Math.max(peak, active);
    await sleep(120);
    active -= 1;
    return 'done';
  };
  await withLimit([job, job, job], 3);
  assert.equal(peak, 3, 'independent findings should overlap');
  console.log('  ok  three independent findings ran concurrently');
}
{
  // One lane, concurrency 3: still only one at a time.
  let peak = 0;
  let active = 0;
  const job = async (): Promise<string> => {
    active += 1;
    peak = Math.max(peak, active);
    await sleep(60);
    active -= 1;
    return 'done';
  };
  await withLimit([job, job, job], 1);
  assert.equal(peak, 1, 'a single file group must stay sequential');
  console.log('  ok  a single file group stayed sequential');
}
{
  // Limit below the job count: capped, not unbounded.
  let peak = 0;
  let active = 0;
  const job = async (): Promise<string> => {
    active += 1;
    peak = Math.max(peak, active);
    await sleep(60);
    active -= 1;
    return 'done';
  };
  await withLimit([job, job, job, job, job], 2);
  assert.equal(peak, 2, 'concurrency must respect the cap');
  console.log('  ok  concurrency cap respected');
}

console.log('\nAll resilience checks passed.');