/**
 * Models often wrap JSON in prose or fenced code blocks. These helpers dig the
 * JSON back out so agent output can be parsed into our domain types.
 */

/** Extract the first balanced JSON object or array from a blob of text. */
export function extractJson<T>(text: string): T {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const source = (fenced?.[1] ?? text).trim();

  const start = source.search(/[[{]/);
  if (start === -1) throw new Error(`No JSON found in model output: ${text.slice(0, 300)}`);

  const openChar = source[start];
  const closeChar = openChar === '{' ? '}' : ']';
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = start; i < source.length; i += 1) {
    const ch = source[i]!;

    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }

    if (ch === '"') inString = true;
    else if (ch === openChar) depth += 1;
    else if (ch === closeChar) {
      depth -= 1;
      if (depth === 0) {
        const candidate = source.slice(start, i + 1);
        return JSON.parse(candidate) as T;
      }
    }
  }

  throw new Error('Unbalanced JSON in model output');
}

/** Same as extractJson, but returns null instead of throwing. */
export function tryExtractJson<T>(text: string): T | null {
  try {
    return extractJson<T>(text);
  } catch {
    return null;
  }
}

/** Slugify a string for use in artifact filenames. */
export function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
}
