/**
 * Print a rendered pull request body, for eyeballing the report a reviewer
 * would actually see.
 *
 *   npm run show:pr
 */
import { renderPrBody, type PrEvidence } from '../src/github/prReport.js';

const evidence: PrEvidence = {
  runId: 'run-123',
  findingId: 'VULN-1',
  vulnerabilityClass: 'sql-injection',
  severity: 'critical',
  file: 'src/routes/search.js',
  summary: 'Bound the q parameter instead of interpolating it into SQL',
  unifiedDiff: [
    '--- a/src/routes/search.js',
    '+++ b/src/routes/search.js',
    '-        `SELECT ... FROM products WHERE name LIKE \'%${q}%\'`,',
    '+        `SELECT ... FROM products WHERE name LIKE ?`,',
    '-      const results = statement.all();',
    '+      const results = statement.all(`%${q}%`);',
  ].join('\n'),
  patchedContent: '...',
  exploitCommand:
    "curl -sS -m 5 -G 'http://localhost:3000/search' --data-urlencode \"q=%' UNION SELECT id, username, password, email FROM users--\"",
  successSignal: 'S3cr3t-Adm1n-P@ss',
  before: {
    fired: true,
    output:
      '{"query":"%\' UNION SELECT ...","count":8,"results":[{"id":1,"name":"alice","description":"alice-password"},' +
      '{"id":3,"name":"admin","description":"S3cr3t-Adm1n-P@ss","price":"admin@example.com"}]}',
  },
  after: { fired: false, output: '{"query":"%\' UNION SELECT ...","count":0,"results":[]}' },
  functional: { passed: true, passCount: 13, failCount: 0 },
  verdict: 'verified',
};

console.log(renderPrBody(evidence));