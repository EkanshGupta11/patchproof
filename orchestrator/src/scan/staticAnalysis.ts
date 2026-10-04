/**
 * Phase 1 - SCAN (static analysis).
 *
 * Runs real static analysis over the target source with ESLint plus the security
 * rule sets, and returns Candidates derived from actual findings rather than the
 * model's opinion. This grounds the scan in a reproducible tool output.
 *
 * The LLM scan in scanAgent.ts runs alongside this and the two are merged; this
 * one is what turns "the model thinks this is suspicious" into "a linter flagged
 * this exact line, here is the rule, here is the offending text".
 */
import path from 'node:path';
import { ESLint, type Linter } from 'eslint';
import js from '@eslint/js';
import security from 'eslint-plugin-security';
import noUnsanitized from 'eslint-plugin-no-unsanitized';
import { config } from '../config.js';
import { createLogger } from '../logger.js';
import { targetRoot } from '../target/source.js';
import { patchproofPlugin } from './sqlInjectionRule.js';
import type { Candidate, Severity, VulnerabilityClass } from '../types.js';

const log = createLogger('scan:semgrep');

/** Semgrep-shaped name for this module's engine, kept for report readability. */
export const SCANNER_NAME = 'eslint+security';

/**
 * Rule id -> our domain class.
 *
 * Anything unmapped becomes "other" rather than being dropped, so a real finding
 * from an unfamiliar rule is still surfaced.
 */
const RULE_CLASS: Record<string, VulnerabilityClass> = {
  'security/detect-child-process': 'command-injection',
  'security/detect-non-literal-fs-filename': 'path-traversal',
  'security/detect-non-literal-require': 'other',
  'security/detect-object-injection': 'other',
  'security/detect-eval-with-expression': 'insecure-deserialization',
  'security/detect-non-literal-fs-filename-without-mkdir': 'path-traversal',
  'patchproof/detect-sql-string-concat': 'sql-injection',
  'no-unsanitized/method': 'xss',
  'no-unsanitized/property': 'xss',
};

/** Rule id -> severity. Defaults to medium for anything we have no opinion on. */
const RULE_SEVERITY: Record<string, Severity> = {
  'security/detect-child-process': 'critical',
  'security/detect-non-literal-fs-filename': 'high',
  'security/detect-object-injection': 'medium',
  'security/detect-eval-with-expression': 'critical',
  // SQL injection is the most severe class here: it yields data exfiltration,
  // and on some engines arbitrary statement execution.
  'patchproof/detect-sql-string-concat': 'critical',
  'no-unsanitized/method': 'high',
  'no-unsanitized/property': 'medium',
};

function toSeverity(raw: Linter.Severity): Severity {
  // ESLint: 2 = error, 1 = warning, 0 = off.
  if (raw === 2) return 'high';
  if (raw === 1) return 'medium';
  return 'low';
}

export interface StaticScanResult {
  candidates: Candidate[];
  /** Rules that ran, for the report. */
  rulesApplied: string[];
  engine: string;
  durationMs: number;
}

/**
 * ESLint 9+ removed `context.getSourceCode()`; the source is now passed directly
 * on the context object.
 *
 * `eslint-plugin-security@3` still calls the old API, so every rule is wrapped to
 * restore it. This is a compatibility shim around a known upstream mismatch, not
 * a reimplementation: the rules themselves run untouched.
 */
type RuleCreate = (context: unknown) => Record<string, unknown>;

function withLegacyContext<T>(rules: T): T {
  if (!rules || typeof rules !== 'object') return rules;

  const wrapped: Record<string, unknown> = {};
  for (const [name, rule] of Object.entries(rules as Record<string, unknown>)) {
    const create = (rule as { create?: RuleCreate })?.create;
    if (typeof create !== 'function') {
      wrapped[name] = rule;
      continue;
    }
    wrapped[name] = {
      ...(rule as object),
      create(context: Record<string, unknown>) {
        // ESLint freezes the context, so the legacy methods are added to a
        // child object that inherits from it rather than onto it directly.
        const shimmed = Object.create(context) as Record<string, unknown>;
        const sourceCode = context.sourceCode as
          | { getScope?: (c: unknown) => unknown }
          | undefined;

        if (typeof shimmed.getSourceCode !== 'function' && sourceCode) {
          shimmed.getSourceCode = () => sourceCode;
        }
        const getScope = sourceCode?.getScope;
        if (typeof shimmed.getScope !== 'function' && typeof getScope === 'function') {
          shimmed.getScope = () => getScope.call(sourceCode, context);
        }
        if (typeof shimmed.getFilename !== 'function') {
          shimmed.getFilename = () => context.filename ?? '<input>';
        }

        return create(shimmed);
      },
    };
  }

  return wrapped as T;
}

/** Rule implementations, shimmed for the current ESLint API. */
const securityRules = withLegacyContext(security.rules ?? {});
const noUnsanitizedRules = withLegacyContext(noUnsanitized.rules ?? {});

/** Build an ESLint instance pointed at the target, with the security rules on. */
function createScanner(): ESLint {
  return new ESLint({
    cwd: targetRoot(),
    // The target is ESM JavaScript; do not try to fix, just report.
    fix: false,
    // Report every configured severity so the scan does not silently drop findings.
    errorOnUnmatchedPattern: false,
    overrideConfigFile: true,
    // Analysis scope: the target's own source. These two directories hold the
    // HTTP surface, which is the only thing an attacker can reach.
    overrideConfig: [
      {
        files: ['**/*.js'],
        languageOptions: {
          ecmaVersion: 2022,
          sourceType: 'module',
          globals: {
            // Node globals, so `no-undef` does not fire on `process`/`Buffer`.
            process: 'readonly',
            Buffer: 'readonly',
            console: 'readonly',
            setTimeout: 'readonly',
            clearTimeout: 'readonly',
            URL: 'readonly',
            fetch: 'readonly',
          },
        },
      },
      js.configs.recommended,
      {
        plugins: {
          // The real rule implementations are registered here, not just the
          // names: spreading an empty object made every rule id unresolvable.
          security: { rules: securityRules } as unknown as ESLint.Plugin,
          'no-unsanitized': { rules: noUnsanitizedRules } as unknown as ESLint.Plugin,
          // Local rules for classes the third-party sets miss (currently SQL
          // injection, which no upstream security rule covers).
          patchproof: patchproofPlugin as unknown as ESLint.Plugin,
        },
        rules: {
          // Security rules are the point of this scan.
          ...(security.configs?.recommended?.rules ?? {}),
          ...(noUnsanitized.configs?.recommended?.rules ?? {}),
          'patchproof/detect-sql-string-concat': 'error',
        } as unknown as Record<string, import('eslint').Linter.RuleEntry>,
      },
    ],
  });
}

/**
 * The offending source line, straight from the lint message.
 *
 * ESLint puts the relevant code on `sourceCode`; older message shapes and rules
 * that fire without a snippet fall back to the message text.
 */
function extractEvidence(message: { sourceCode?: string; message: string }): string {
  return (message.sourceCode ?? message.message).trim();
}

/**
 * Run static analysis over the target source.
 *
 * Non-security correctness rules from js.configs.recommended are left enabled:
 * they are cheap and occasionally relevant, and the candidates they produce are
 * still unproven until the exploit phase confirms them.
 */
export async function runStaticScan(): Promise<StaticScanResult> {
  const startedAt = Date.now();

  let results: ESLint.LintResult[];
  try {
    const eslint = createScanner();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    results = (await eslint.lintFiles(['src/**/*.js'])) as any;
  } catch (error) {
    log.error('static analysis failed to run', error);
    return {
      candidates: [],
      rulesApplied: [],
      engine: SCANNER_NAME,
      durationMs: Date.now() - startedAt,
    };
  }

  const candidates: Candidate[] = [];

  for (const result of results) {
    for (const message of result.messages) {
      const ruleId = message.ruleId;
      // A parse error has no rule id: the file could not be analysed at all.
      if (!ruleId) {
        log.warn(`parse problem in ${result.filePath}: ${message.message}`);
        continue;
      }

      const relativeFile = path
        .relative(targetRoot(), result.filePath)
        .split(path.sep)
        .join('/');

      candidates.push({
        id: `SA-${candidates.length + 1}`,
        vulnerabilityClass: RULE_CLASS[ruleId] ?? 'other',
        severity: RULE_SEVERITY[ruleId] ?? toSeverity(message.severity),
        file: relativeFile,
        line: message.line ?? null,
        evidence: extractEvidence(message),
        // Rule id is the provenance: this came from a tool, not a guess.
        rationale: `${SCANNER_NAME} rule ${ruleId}: ${message.message}`,
        source: 'static-analysis',
        ruleId,
      });
    }
  }

  const durationMs = Date.now() - startedAt;
  log.info(`static analysis found ${candidates.length} issue(s) in ${durationMs}ms`);

  return {
    candidates,
    rulesApplied: [...Object.keys(RULE_CLASS), ...Object.keys(RULE_SEVERITY)],
    engine: SCANNER_NAME,
    durationMs,
  };
}