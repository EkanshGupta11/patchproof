/**
 * Minimal, dependency-free unified diff (LCS based).
 * Target files are small, so the O(n*m) table is fine; we guard the worst case.
 */

function lcsTable(a: string[], b: string[]): number[][] {
  const n = a.length;
  const m = b.length;
  const table: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));

  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      table[i]![j] = a[i] === b[j] ? table[i + 1]![j + 1]! + 1 : Math.max(table[i + 1]![j]!, table[i]![j + 1]!);
    }
  }

  return table;
}

export function unifiedDiff(filePath: string, oldText: string, newText: string): string {
  if (oldText === newText) return '';

  const a = oldText.split('\n');
  const b = newText.split('\n');

  // Guard the quadratic path for very large files.
  if (a.length * b.length > 4_000_000) {
    return `--- a/${filePath}\n+++ b/${filePath}\n@@ whole file replaced (too large to diff line-by-line) @@`;
  }

  const table = lcsTable(a, b);
  const lines: string[] = [];
  let i = 0;
  let j = 0;

  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      lines.push(` ${a[i]}`);
      i += 1;
      j += 1;
    } else if (table[i + 1]![j]! >= table[i]![j + 1]!) {
      lines.push(`-${a[i]}`);
      i += 1;
    } else {
      lines.push(`+${b[j]}`);
      j += 1;
    }
  }

  while (i < a.length) lines.push(`-${a[i++]}`);
  while (j < b.length) lines.push(`+${b[j++]}`);

  return [`--- a/${filePath}`, `+++ b/${filePath}`, ...lines].join('\n');
}
