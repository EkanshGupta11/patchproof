/**
 * Local ESLint rule: `patchproof/detect-sql-string-concat`.
 *
 * Why this exists: the security rulesets we run cover command injection and
 * path traversal, but neither has a rule for SQL injection. Interpolated SQL was
 * therefore invisible to static analysis, and the finding only appeared when the
 * LLM scan pass happened to succeed -- so a provider outage silently reduced us
 * from three findings to two. Detection that depends on a paid API being up is
 * not detection.
 *
 * The rule flags the actual defect shape rather than the vulnerability name:
 * a SQL-executing method whose query argument is assembled at runtime by string
 * interpolation or concatenation. A bound-parameter call
 * (`db.prepare('... WHERE name LIKE ?').all(`%${q}%`)`) is a template literal in
 * the source, but it is passed to `.all()`, which takes no query argument, so
 * it does not match. The real fix passes the interpolated value as a parameter,
 * not as query text.
 */
import type { Rule } from 'eslint';

/** Methods whose first argument is a SQL statement. */
const SQL_METHODS = new Set(['prepare', 'query', 'execute', 'raw']);

/** Render `db.prepare(...)` for the report message. */
function calleeText(callee: unknown): string | null {
  if (typeof callee !== 'object' || callee === null) return null;

  const node = callee as {
    type?: string;
    name?: string;
    property?: { type?: string; name?: string; value?: unknown };
    computed?: boolean;
  };

  if (node.type === 'Identifier') return node.name ?? null;

  if (node.type === 'MemberExpression') {
    // `db.prepare` -> "db.prepare"; a computed `db['prepare']` -> "db.prepare" too,
    // since that is the same call just written differently.
    const property =
      node.property?.type === 'Identifier'
        ? node.property.name
        : typeof node.property?.value === 'string'
          ? node.property.value
          : undefined;
    if (!property || node.computed === true && node.property?.type !== 'Literal') return property ?? null;

    const object = (callee as { object?: { type?: string; name?: string } }).object;
    const objectName =
      object?.type === 'Identifier'
        ? object.name
        : object?.type === 'ThisExpression'
          ? 'this'
          : null;

    return objectName ? `${objectName}.${property}` : property;
  }

  return null;
}

/** How the query string was built, if it was built at runtime. */
function concatenationKind(argument: unknown): 'template interpolation' | 'concatenation' | null {
  if (typeof argument !== 'object' || argument === null) return null;

  const node = argument as {
    type?: string;
    expressions?: unknown[];
    operator?: string;
  };

  // `` `SELECT ... WHERE name LIKE '%${q}%'` ``
  if (node.type === 'TemplateLiteral' && (node.expressions?.length ?? 0) > 0) {
    return 'template interpolation';
  }

  // `'SELECT ... ' + q`
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return 'concatenation';
  }

  return null;
}

export const detectSqlStringConcat: Rule.RuleModule = {
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow SQL statements assembled by string interpolation or concatenation',
      recommended: true,
    },
    messages: {
      sqlConcat:
        'Found {{callee}}() called with a SQL query built by {{kind}} instead of bound parameters ({{preview}})',
    },
    schema: [],
  },
  create(context) {
    return {
      CallExpression(node) {
        const call = node as unknown as {
          callee?: unknown;
          arguments?: unknown[];
        };

        const method = calleeText(call.callee);
        if (!method) return;

        const methodName = method.split('.').pop();
        if (!methodName || !SQL_METHODS.has(methodName)) return;

        const [firstArgument] = call.arguments ?? [];
        const kind = concatenationKind(firstArgument);
        if (!kind) return;

        const sourceCode = (context as unknown as { sourceCode?: { getText?: (n: unknown) => string } })
          .sourceCode;
        const text =
          typeof sourceCode?.getText === 'function' ? sourceCode.getText(firstArgument) : '';

        context.report({
          // Report on the query argument: that is the line that has to change.
          node: firstArgument as never,
          messageId: 'sqlConcat',
          data: {
            callee: method,
            kind,
            preview: text.length > 60 ? `${text.slice(0, 57)}...` : text,
          },
        });
      },
    };
  },
};

/** Plugin wrapper so it can be registered like the third-party rule sets. */
export const patchproofPlugin = {
  rules: {
    'detect-sql-string-concat': detectSqlStringConcat,
  },
};