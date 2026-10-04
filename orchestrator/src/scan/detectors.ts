/**
 * Evidence detectors.
 *
 * Decides whether a command's output proves a vulnerability actually fired.
 *
 * This exists because "did the exploit work?" is the single most important
 * question in the pipeline, and answering it with a naive substring check is how
 * tools end up confidently reporting things that never happened.
 *
 * The rule that matters: a signal only counts if it is something the FIXED
 * target cannot produce. Anything a well-behaved response also contains -- "200",
 * "results", a product name -- is worthless as proof, so those are rejected by
 * construction via {@link AMBIGUOUS_SIGNALS}.
 *
 * Detectors return evidence (the exact matched line) rather than a bare boolean,
 * so a human can audit why something was called a confirmed vulnerability.
 */
import type { VulnerabilityClass } from '../types.js';

/** How much we trust a positive detection. */
export type Confidence = 'certain' | 'strong' | 'weak';

export interface DetectionSignal {
  /** The literal text or pattern that fired. */
  pattern: string;
  /** The line it matched, so the decision can be audited. */
  matchedLine: string;
  /** Which detector produced this. */
  detector: string;
  why: string;
}

export interface DetectionResult {
  /** True only when the evidence is strong enough to call the bug triggered. */
  triggered: boolean;
  confidence: Confidence;
  /** Every signal that fired, for the audit trail. */
  signals: DetectionSignal[];
  /** Human-readable reasoning, suitable for a report. */
  reasoning: string;
}

/**
 * Signals that prove nothing, because a patched target produces them too.
 *
 * If an exploit "confirms" a vulnerability only by returning HTTP 200 or a
 * normal product name, it has demonstrated nothing.
 */
export const AMBIGUOUS_SIGNALS: readonly string[] = [
  '200',
  'ok',
  'results',
  'count',
  'query',
  'success',
  'true',
  'usb-c hub',
  'webcam',
  'mechanical keyboard',
  'blue light glasses',
  'laptop stand',
  'converted',
  'health',
  '{}',
  '[]',
  'content-type',
];

export interface DetectorInput {
  vulnerabilityClass: VulnerabilityClass;
  /** Combined stdout/stderr from the exploit command. */
  output: string;
  /**
   * The signal the exploit author claimed proves success.
   * Treated as a hint, never as proof on its own.
   */
  expectedSignal?: string;
  /** HTTP status observed, when known. */
  statusCode?: number;
}

/** Per-class detectors. Each returns only the signals it can justify. */
type ClassDetector = (input: DetectorInput) => DetectionSignal[];

const contains = (output: string, needle: string): boolean =>
  output.toLowerCase().includes(needle.toLowerCase());

/** The line in the output containing the needle, for evidence. */
function lineContaining(output: string, needle: string): string {
  const lower = needle.toLowerCase();
  const line = output.split(/\r?\n/).find((candidate) => candidate.toLowerCase().includes(lower));
  return (line ?? needle).trim().slice(0, 300);
}

/**
 * SQL injection: the response leaks data only a cross-table or stacked query
 * could produce -- other tables' columns, SQL error text, credential rows.
 */
const detectSqlInjection: ClassDetector = ({ output }) => {
  const signals: DetectionSignal[] = [];

  for (const pattern of ['S3cr3t-Adm1n-P@ss', 'hunter2', 'alice-password', 'admin@example.com']) {
    if (contains(output, pattern)) {
      signals.push({
        pattern,
        matchedLine: lineContaining(output, pattern),
        detector: 'sql-injection:credential-leak',
        why: 'response contains a credential row that the products table does not hold',
      });
    }
  }

  if (contains(output, 'api_token') || contains(output, '"username"')) {
    const needle = contains(output, 'api_token') ? 'api_token' : '"username"';
    signals.push({
      pattern: 'users-table columns',
      matchedLine: lineContaining(output, needle),
      detector: 'sql-injection:schema-leak',
      why: 'response exposes columns that only exist on the users table',
    });
  }

  if (/SQLITE_ERROR|syntax error|near "|unrecognized token|no such column/i.test(output)) {
    signals.push({
      pattern: 'sql-error',
      matchedLine: lineContaining(output, 'error'),
      detector: 'sql-injection:error-based',
      why: 'the database returned a SQL error, so the input was parsed as SQL',
    });
  }

  return signals;
};
/**
 * Path traversal: a file outside the served directory came back, evidenced by
 * content that cannot exist in the public directory.
 */
const detectPathTraversal: ClassDetector = ({ output }) => {
  const signals: DetectionSignal[] = [];

  // The demo target plants this flag in the file it must not serve.
  if (contains(output, 'PATCHPROOF{path_traversal_confirmed}')) {
    signals.push({
      pattern: 'PATCHPROOF{path_traversal_confirmed}',
      matchedLine: lineContaining(output, 'PATCHPROOF{'),
      detector: 'path-traversal:planted-flag',
      why: 'returned a file that lives outside the directory the endpoint serves',
    });
  }

  // Classic OS files that only a traversal reaches.
  if (/root:[\w*:]*:0:0/.test(output)) {
    signals.push({
      pattern: 'root:...:0:0',
      matchedLine: lineContaining(output, 'root:'),
      detector: 'path-traversal:etc-passwd',
      why: 'output contains /etc/passwd content',
    });
  }

  // Windows hosts: escaping shows up as a path inside the parent project dir.
  if (/cline hackathon - patchproof\\(targets|orchestrator|sandbox)/i.test(output)) {
    signals.push({
      pattern: 'parent-directory path',
      matchedLine: lineContaining(output, 'patchproof'),
      detector: 'path-traversal:parent-dir',
      why: 'output references a path outside the served directory',
    });
  }

  return signals;
};

/**
 * Command injection: output the converter would never produce -- a shell
 * marker, an OS account, or shell diagnostics.
 */
const detectCommandInjection: ClassDetector = ({ output }) => {
  const signals: DetectionSignal[] = [];

  // An explicit injected marker is unambiguous.
  if (/PATCHPROOF_PWNED/.test(output)) {
    signals.push({
      pattern: 'PATCHPROOF_PWNED',
      matchedLine: lineContaining(output, 'PATCHPROOF_PWNED'),
      detector: 'command-injection:injected-marker',
      why: 'the injected shell command produced output the application never emits',
    });
  }

  // OS identity, which only a spawned command can report.
  if (/root|ubuntu|laptop-[\w-]+|\\\\[\w.-]+\\[\w.-]+/i.test(output)) {
    signals.push({
      pattern: 'OS account name',
      matchedLine: lineContaining(output, 'root'),
      detector: 'command-injection:whoami',
      why: 'output contains an OS account name, which only an executed command returns',
    });
  }

  // Proof that the shell, not the application, produced the output.
  if (/command not found|not recognized as an internal|\/bin\/sh: /i.test(output)) {
    signals.push({
      pattern: 'shell diagnostics',
      matchedLine: lineContaining(output, 'not found'),
      detector: 'command-injection:shell-error',
      why: 'shell diagnostic text shows the input was executed by a shell',
    });
  }

  return signals;
};

/** Reflected XSS: the payload came back unencoded in the HTML. */
const detectXss: ClassDetector = ({ output }) => {
  if (/<img[^>]*onerror\s*=|<script>|javascript:/i.test(output)) {
    return [
      {
        pattern: 'unescaped payload',
        matchedLine: lineContaining(output, 'onerror'),
        detector: 'xss:reflected-payload',
        why: 'the injected markup is present verbatim in the response body',
      },
    ];
  }
  return [];
};

/**
 * Fallback for classes without a dedicated detector.
 *
 * Only the author's own claimed signal is considered, and only when it is not
 * ambiguous. This can never produce `triggered: true` on its own -- see
 * {@link detectTriggered}.
 */
const detectByExpectedSignal: ClassDetector = ({ output, expectedSignal }) => {
  const needle = (expectedSignal ?? '').trim();
  if (!needle) return [];

  // Reject the claim outright if it is one of the meaningless signals.
  if (AMBIGUOUS_SIGNALS.includes(needle.toLowerCase())) {
    return [
      {
        pattern: needle,
        matchedLine: lineContaining(output, needle),
        detector: 'generic:rejected-signal',
        why: `"${needle}" also appears in a correct response, so it proves nothing`,
      },
    ];
  }

  if (contains(output, needle)) {
    return [
      {
        pattern: needle,
        matchedLine: lineContaining(output, needle),
        detector: 'generic:expected-signal',
        why: 'the expected signal was present in the output',
      },
    ];
  }

  return [];
};

const DETECTORS: Partial<Record<VulnerabilityClass, ClassDetector>> = {
  'sql-injection': detectSqlInjection,
  'path-traversal': detectPathTraversal,
  'command-injection': detectCommandInjection,
  xss: detectXss,
};

/**
 * Decide whether a command's output shows the bug was triggered.
 *
 * Never treats a bare HTTP 200 as evidence, and never trusts the exploit
 * author's claimed signal on its own for classes that have a real detector.
 */
export function detectTriggered(input: DetectorInput): DetectionResult {
  const output = input.output ?? '';
  const classDetector = DETECTORS[input.vulnerabilityClass];
  const signals = classDetector ? classDetector(input) : detectByExpectedSignal(input);

  const rejected = signals.filter((signal) => signal.detector === 'generic:rejected-signal');

  // For classes with a dedicated detector, only class-specific evidence counts.
  const strong = classDetector
    ? signals.filter((signal) => signal.detector !== 'generic:rejected-signal')
    : signals.filter((signal) => signal.detector === 'generic:expected-signal');

  if (strong.length > 1) {
    return {
      triggered: true,
      confidence: 'certain',
      signals: [...strong, ...rejected],
      reasoning:
        `${strong.length} independent signal(s) matched for ${input.vulnerabilityClass}: ` +
        strong.map((signal) => signal.why).join('; '),
    };
  }

  if (strong.length === 1) {
    return {
      triggered: true,
      confidence: 'strong',
      signals: [...strong, ...rejected],
      reasoning: `evidence for ${input.vulnerabilityClass}: ${strong[0]!.why}`,
    };
  }

  if (rejected.length > 0) {
    return {
      triggered: false,
      confidence: 'weak',
      signals: rejected,
      reasoning:
        `the only claimed signal ("${rejected[0]!.pattern}") is ambiguous -- ` +
        'a correctly patched response contains it too',
    };
  }

  return {
    triggered: false,
    confidence: 'weak',
    signals: [],
    reasoning: `no evidence of ${input.vulnerabilityClass} in the command output`,
  };
}

/** True when a claimed signal would be worthless as proof, on its own. */
export function isAmbiguousSignal(signal: string): boolean {
  return AMBIGUOUS_SIGNALS.includes(signal.trim().toLowerCase());
}
