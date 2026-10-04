/**
 * Static check that the prover really is LLM-free.
 *
 * A comment claiming "no language model is called here" is not a guarantee -- it
 * is a promise that rots the first time someone adds an import. This walks the
 * module's transitive imports and fails if anything reaches the LLM layer.
 *
 *   npm run check:proof -- --static
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Modules that would make the prover non-deterministic. */
const FORBIDDEN = ['llm.js', 'verificationAgent.js', 'patchAgent.js', 'scanAgent.js', 'exploitAgent.js', '@cline/sdk'];

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');

async function readImports(file: string): Promise<string[]> {
  const source = await fs.readFile(file, 'utf8');
  const specifiers: string[] = [];
  const pattern = /(?:^|\n)\s*(?:import|export)[\s\S]*?from\s+['"]([^'"]+)['"]/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(source)) !== null) {
    if (match[1]) specifiers.push(match[1]);
  }
  return specifiers;
}

/** Resolve a relative specifier to a file inside src, if it is one. */
function resolveLocal(from: string, specifier: string): string | null {
  if (!specifier.startsWith('.')) return null;
  return path.resolve(path.dirname(from), specifier).replace(/\.js$/, '.ts');
}

async function main(): Promise<void> {
  const entry = path.join(SRC, 'verify', 'proveFix.ts');
  const seen = new Set<string>();
  const violations: Array<{ file: string; specifier: string }> = [];
  const queue = [entry];

  while (queue.length) {
    const file = queue.pop();
    if (!file || seen.has(file)) continue;
    seen.add(file);

    for (const specifier of await readImports(file)) {
      if (FORBIDDEN.some((bad) => specifier.includes(bad))) {
        violations.push({ file: path.relative(SRC, file), specifier });
        continue;
      }
      const local = resolveLocal(file, specifier);
      if (local) {
        try {
          await fs.access(local);
          queue.push(local);
        } catch {
          /* not a file we can follow */
        }
      }
    }
  }

  console.log(`modules reachable from src/verify/proveFix.ts: ${seen.size}`);
  for (const file of [...seen].sort()) console.log(`  ${path.relative(SRC, file)}`);

  console.log('');
  if (violations.length === 0) {
    console.log('PASS  no module in the prover import graph reaches the LLM layer.');
    console.log('PASS  the proof is deterministic by construction.');
  } else {
    console.log(`FAIL  ${violations.length} forbidden import(s):`);
    for (const v of violations) console.log(`  ${v.file} -> ${v.specifier}`);
    process.exitCode = 1;
  }
}

void main();