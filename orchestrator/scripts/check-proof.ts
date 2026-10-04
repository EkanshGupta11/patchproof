// Must be first: config.ts reads process.env at import time.
import 'dotenv/config';

import fs from 'node:fs/promises';
import path from 'node:path';
import { proveFix, isAcceptable } from '../src/verify/proveFix.js';
import { readSourceFile, targetRoot } from '../src/target/source.js';
import { unifiedDiff } from '../src/util/diff.js';

function rule(title = ''): void {
  console.log(title ? `\n${'='.repeat(78)}\n${title}\n${'='.repeat(78)}` : '='.repeat(78));
}

/** The confirmed SQL injection finding, with the exploit the exploit agent left. */
const SPEC_BASE = {
  findingId: 'VULN-1',
  file: 'src/routes/search.js',
  exploitCommand:
    "curl -sS -m 5 -G 'http://localhost:3000/search' --data-urlencode \"q=%' UNION SELECT id, username, password, email FROM users--\"",
  successSignal: 'S3cr3t-Adm1n-P@ss',
  vulnerabilityClass: 'sql-injection',
};

/** The real fix: bind the parameter instead of interpolating it. */
const GOOD_FIX = (original: string): string =>
  original
    .replace(
      '`SELECT id, name, description, price FROM products WHERE name LIKE \'%${q}%\'`',
      "`SELECT id, name, description, price FROM products WHERE name LIKE ?`",
    )
    .replace('const results = statement.all();', 'const results = statement.all(`%${q}%`);');

/**
 * The degenerate "fix": make the exploit stop working by removing the endpoint.
 * This is the case a naive replay check cannot catch, and the reason the
 * functional suite is a second, independent gate.
 */
const DELETE_ENDPOINT_FIX = (original: string): string =>
  original.replace(
    "router.get('/search', (req, res) => {",
    "router.get('/search', (req, res) => {\n    return res.status(501).json({ error: 'not implemented' });",
  );

async function report(label: string, spec: Parameters<typeof proveFix>[0]): Promise<void> {
  rule(`${label}`);
  const started = Date.now();
  const proof = await proveFix(spec);
  const elapsed = ((Date.now() - started) / 1000).toFixed(1);

  console.log(`exploit on ORIGINAL code : ${proof.baseline.fired ? 'FIRED (as expected)' : 'did not fire'}`);
  console.log(`exploit on PATCHED code  : ${proof.patched.fired ? 'STILL FIRED' : 'did not fire (as required)'}`);
  console.log(`response changed        : ${proof.behaviourChanged}`);
  console.log(`functional suite        : ${proof.functional.passed ? 'PASS' : 'FAIL'}` +
    (proof.functional.passCount !== null ? ` (${proof.functional.passCount} pass / ${proof.functional.failCount} fail)` : ''));
  console.log(`deterministic           : ${proof.deterministic}`);
  console.log(`VERDICT                 : ${proof.verdict.toUpperCase()}`);
  console.log(`reasoning               : ${proof.reasoning}`);
  console.log(`elapsed                 : ${elapsed}s`);
  return proof;
}

async function main(): Promise<void> {
  const original = await readSourceFile(SPEC_BASE.file);
  const goodFix = GOOD_FIX(original);

  if (goodFix === original) {
    console.log('FATAL: the fixture fix did not change the file; the target source moved.');
    process.exitCode = 1;
    return;
  }

  console.log('CASE A -- the real fix (bound parameter)');
  console.log('');
  console.log(unifiedDiff(SPEC_BASE.file, original, goodFix)
    .split('\n')
    .filter((l) => l.startsWith('+') || l.startsWith('-'))
    .filter((l) => !l.startsWith('+++') && !l.startsWith('---'))
    .map((l) => `  ${l}`)
    .join('\n'));

  const good = await report('PROOF A', {
    ...SPEC_BASE,
    originalContent: original,
    patchedContent: goodFix,
  });

  console.log('');
  console.log('CASE B -- the degenerate fix (endpoint disabled instead of repaired)');
  console.log('         a naive replay check would call this a success.');
  const bad = await report('PROOF B', {
    ...SPEC_BASE,
    originalContent: original,
    patchedContent: DELETE_ENDPOINT_FIX(original),
  });

  rule('RESULTS');
  console.log(`A  real fix            -> ${good.verdict.toUpperCase()}  ${isAcceptable(good) ? '(accepted)' : '(rejected)'}`);
  console.log(`B  endpoint disabled   -> ${bad.verdict.toUpperCase()}  ${isAcceptable(bad) ? '(accepted)' : '(rejected)'}`);

  console.log('');
  const allGood = isAcceptable(good) && !isAcceptable(bad);
  if (allGood) {
    console.log('The prover accepts the real fix and rejects the degenerate one,');
    console.log('with no language model involved at any point.');
  } else {
    console.log('UNEXPECTED: the prover did not separate the real fix from the degenerate one.');
    process.exitCode = 1;
  }

  void path.join;
  void fs;
}

main().catch((error: unknown) => {
  console.error('FAILED:', error instanceof Error ? error.stack : error);
  process.exit(1);
});