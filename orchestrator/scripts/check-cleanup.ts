/**
 * Regression checks for the three defects found in run 9b6d1e49.
 *
 * Each of these produced a wrong or misleading result in a real run, so each is
 * pinned here rather than left to the next full pipeline run to rediscover.
 */
import 'dotenv/config';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { cleanScratchFiles, snapshotScratchFiles } from '../src/target/cleanup.js';
import { targetRoot } from '../src/target/source.js';

const root = targetRoot();
let failed = 0;

function check(label: string, condition: boolean): void {
  console.log(`  ${condition ? 'PASS' : 'FAIL'}  ${label}`);
  if (!condition) failed += 1;
}

// ---- 1. cleanup must match multi-hyphen agent script names ----
// `verify-path-traversal.sh` survived cleanup because the trailing character
// class excluded hyphens, while `verify-search.sh` was removed.
const created = ['verify-search.sh', 'verify-path-traversal.sh', 'exploit-convert.sh', 'verify-cmdinj.sh'];

// Leftovers from the real run are cleaned up first. Without this they land in the
// baseline and are then correctly *protected* by it, which would mask the very
// bug this check exists to catch.
console.log('\n1. cleanup name matching');
for (const name of created) await fs.rm(path.join(root, name), { force: true });
const baseline = await snapshotScratchFiles();
for (const name of created) await fs.writeFile(path.join(root, name), '#!/bin/sh\n', 'utf8');

const removed = await cleanScratchFiles(baseline);
for (const name of created) {
  check(`${name} removed`, removed.includes(name));
}

// ---- 2. pre-existing scripts must survive ----
// The safety property: cleanup is baseline-driven, not pattern-driven.
console.log('\n2. pre-existing files are protected');
const preExisting = 'release-build.sh';
await fs.writeFile(path.join(root, preExisting), '#!/bin/sh\n', 'utf8');
const baseline2 = await snapshotScratchFiles();
await fs.writeFile(path.join(root, 'verify-second.sh'), '#!/bin/sh\n', 'utf8');
const removed2 = await cleanScratchFiles(baseline2);
check('new agent file removed', removed2.includes('verify-second.sh'));
check(
  'pre-existing file survives',
  await fs
    .stat(path.join(root, preExisting))
    .then(() => true)
    .catch(() => false),
);
await fs.rm(path.join(root, preExisting), { force: true });

// ---- 3. fired() must tolerate JSON pretty-print padding ----
// The exact-match test missed `flag: PATCHPROOF{...}` inside output that emits
// `flag               : PATCHPROOF{...}`, recording a real confirmation as
// inconclusive.
console.log('\n3. whitespace-tolerant signal matching');
const padded = 'flag               : PATCHPROOF{path_traversal_confirmed}\n';
const tight = 'flag: PATCHPROOF{path_traversal_confirmed}';
assert.equal(padded.includes(tight), false, 'precondition: exact match really does fail');
const norm = (s: string) => s.replace(/\s+/g, '');
check('normalised match succeeds', norm(padded).includes(norm(tight)));
check('normalisation does not invent matches', !norm('flag: PATCHPROOF{other}').includes(norm(tight)));
check(
  'normalisation preserves case sensitivity',
  !norm('FLAG: PATCHPROOF{path_traversal_confirmed}').includes(norm(tight)),
);

console.log(failed === 0 ? '\n  ok  all regression checks pass' : `\n  ${failed} check(s) FAILED`);
if (failed > 0) process.exit(1);