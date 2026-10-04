/**
 * Check static analysis + evidence detection.
 *
 *   npm run check:scan
 *
 * Part 1 runs the real static analyser over the target and asserts it locates
 * the planted bugs. Part 2 feeds recorded exploit output to the detector,
 * including the negative cases that matter most: output a *patched* target would
 * also produce must never be mistaken for evidence.
 */
import { runStaticScan, SCANNER_NAME } from '../src/scan/staticAnalysis.js';
import { detectTriggered, isAmbiguousSignal } from '../src/scan/detectors.js';

let failures = 0;

function check(label: string, ok: boolean, detail = ''): void {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ` -- ${detail}` : ''}`);
  if (!ok) failures += 1;
}

// ---------- recorded outputs from the demo target ----------
const SQLI_FIRED =
  '{"count":3,"results":[{"name":"alice","description":"alice-password"},' +
  '{"name":"admin","description":"S3cr3t-Adm1n-P@ss"}]}';
const SQLI_PATCHED = '{"count":0,"results":[]}';
const SQLI_NORMAL = '{"query":"hub","count":1,"results":[{"name":"USB-C Hub"}]}';

const TRAVERSAL_FIRED =
  '{"file":"../secret.txt","content":"flag : PATCHPROOF{path_traversal_confirmed} admin : S3cr3t-Adm1n-P@ss"}';
const TRAVERSAL_PATCHED = '{"error":"no such file: ../secret.txt"}';

const CMD_FIRED = '{"output":"PATCHPROOF_PWNED\\nconverted report.txt -> pdf\\nroot:x:0:0"}';
const CMD_PATCHED = '{"output":"converted report.txt -> pdf\\n","exitCode":0}';

async function main(): Promise<void> {
  // ================= 1. static analysis =================
  console.log(`1. static analysis (${SCANNER_NAME}) over the target\n`);
  const scan = await runStaticScan();

  console.log(`   ${scan.candidates.length} finding(s) in ${scan.durationMs}ms\n`);
  for (const candidate of scan.candidates.slice(0, 12)) {
    console.log(
      `   ${candidate.file}:${candidate.line ?? '?'}  [${candidate.ruleId}] ${candidate.vulnerabilityClass}`,
    );
  }
  console.log('');

  check('scanner ran and produced findings', scan.candidates.length > 0, `${scan.candidates.length} found`);
  check('every finding carries a rule id', scan.candidates.every((c) => Boolean(c.ruleId)));
  check(
    'every finding is marked as static analysis',
    scan.candidates.every((c) => c.source === 'static-analysis'),
  );
  check(
    'every finding path is inside the target',
    scan.candidates.every((c) => !c.file.includes('..') && c.file.length > 0),
  );
  check('every finding has evidence', scan.candidates.every((c) => c.evidence.length > 0));

  const hasRule = (rule: string) => scan.candidates.some((c) => c.ruleId === rule);
  check('flagged command injection (child_process)', hasRule('security/detect-child-process'));
  check('flagged path traversal (non-literal fs)', hasRule('security/detect-non-literal-fs-filename'));

  // SQL injection, covered by a local rule.
  //
  // This used to be an asserted gap: no upstream security rule covers
  // string-interpolated SQL, so the /search finding only appeared when the LLM
  // scan pass happened to work. A provider outage silently dropped us from
  // three findings to two. `patchproof/detect-sql-string-concat` closes it, so
  // detection no longer depends on a paid API being available.
  const sqlFinding = scan.candidates.find((c) => c.file === 'src/routes/search.js');
  check(
    'flagged SQL injection (string-concatenated query)',
    Boolean(sqlFinding),
    'the local rule should match db.prepare(`...${x}...`)',
  );
  check(
    'the SQLi finding is classified as sql-injection',
    sqlFinding?.vulnerabilityClass === 'sql-injection',
    `got ${sqlFinding?.vulnerabilityClass ?? 'nothing'}`,
  );
  check(
    'the SQLi finding came from our rule, not the LLM',
    sqlFinding?.source === 'static-analysis' && sqlFinding?.ruleId === 'patchproof/detect-sql-string-concat',
    `got source=${sqlFinding?.source ?? 'nothing'} rule=${sqlFinding?.ruleId ?? 'nothing'}`,
  );
  check(
    'the SQLi finding carries evidence',
    Boolean(sqlFinding?.evidence && sqlFinding.evidence.length > 0),
  );

  // Cross-check against the files the target's own VULN comments point at.
  for (const [file, vulnClass] of [
    ['src/routes/convert.js', 'command-injection'],
    ['src/routes/files.js', 'path-traversal'],
  ] as Array<[string, string]>) {
    const inFile = scan.candidates.filter((c) => c.file === file);
    check(
      `located an issue in ${file}`,
      inFile.length > 0,
      inFile.map((c) => c.ruleId).join(', ').slice(0, 70),
    );
    check(
      `classified ${file} as ${vulnClass}`,
      inFile.some((c) => c.vulnerabilityClass === vulnClass),
      inFile.map((c) => c.vulnerabilityClass).join(', ').slice(0, 60),
    );
  }
  console.log('');

  // ================= 2. detectors =================
  console.log('2. detector: SQL injection\n');
  const sqli = detectTriggered({ vulnerabilityClass: 'sql-injection', output: SQLI_FIRED });
  check('detects leaked credentials', sqli.triggered, sqli.confidence);
  check('reaches "certain" with multiple signals', sqli.confidence === 'certain', `${sqli.signals.length} signals`);
  check('cites the credential as evidence', sqli.signals.some((s) => s.pattern.includes('S3cr3t')));
  check('reasoning mentions the leak', sqli.reasoning.toLowerCase().includes('credential'));
  check(
    'silent on a patched response',
    !detectTriggered({ vulnerabilityClass: 'sql-injection', output: SQLI_PATCHED }).triggered,
  );
  check(
    'rejects a product name as proof',
    !detectTriggered({
      vulnerabilityClass: 'sql-injection',
      output: SQLI_NORMAL,
      expectedSignal: 'USB-C Hub',
    }).triggered,
    'a patched /search still returns products',
  );
  console.log('');

  console.log('3. detector: path traversal\n');
  const trav = detectTriggered({ vulnerabilityClass: 'path-traversal', output: TRAVERSAL_FIRED });
  check('detects the out-of-tree file', trav.triggered, trav.confidence);
  check('cites the planted flag', trav.signals.some((s) => s.pattern.includes('PATCHPROOF{')));
  check(
    'silent on a 404',
    !detectTriggered({ vulnerabilityClass: 'path-traversal', output: TRAVERSAL_PATCHED }).triggered,
  );
  console.log('');

  console.log('4. detector: command injection\n');
  const cmd = detectTriggered({ vulnerabilityClass: 'command-injection', output: CMD_FIRED });
  check('detects the injected marker', cmd.triggered, cmd.confidence);
  check('reaches "certain"', cmd.confidence === 'certain', `${cmd.signals.length} signals`);
  check('cites the marker', cmd.signals.some((s) => s.pattern === 'PATCHPROOF_PWNED'));
  check(
    'silent on a normal conversion',
    !detectTriggered({ vulnerabilityClass: 'command-injection', output: CMD_PATCHED }).triggered,
  );
  console.log('');

  console.log('5. detector: ambiguous signals are never proof\n');
  for (const ambiguous of ['200', 'results', 'ok', 'USB-C Hub', 'converted']) {
    const r = detectTriggered({
      vulnerabilityClass: 'other',
      output: `some output containing ${ambiguous}`,
      expectedSignal: ambiguous,
    });
    check(`rejects "${ambiguous}"`, !r.triggered, r.reasoning.slice(0, 66));
    check(`isAmbiguousSignal("${ambiguous}")`, isAmbiguousSignal(ambiguous));
  }
  check(
    'empty output is not a trigger',
    !detectTriggered({ vulnerabilityClass: 'sql-injection', output: '' }).triggered,
  );
  console.log('');

  console.log('6. round trip: the same detector confirms then clears\n');
  const before = detectTriggered({ vulnerabilityClass: 'sql-injection', output: SQLI_FIRED });
  const after = detectTriggered({ vulnerabilityClass: 'sql-injection', output: SQLI_PATCHED });
  check('fires on vulnerable output', before.triggered);
  check('silent on patched output', !after.triggered);
  check(
    'decisions differ, so verification is meaningful',
    before.triggered !== after.triggered,
  );

  console.log('');
  if (failures === 0) console.log('All scan/detector checks passed.');
  else {
    console.log(`${failures} check(s) FAILED.`);
    process.exitCode = 1;
  }
}
main().catch((error: unknown) => {
  console.error('FAILED:', error instanceof Error ? error.stack : error);
  process.exit(1);
});