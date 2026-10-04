/**
 * Check the three custom agent tools.
 *
 *   npm run check:tools
 *
 * Exercises the real tools -- not the functions behind them -- so the SDK wiring
 * is covered too. The refusals are the feature here: these tools write to disk
 * on behalf of a language model, so proving they refuse bad paths matters more
 * than proving they can write.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import {
  overwriteSourceFileTool,
  runInSandboxTool,
  writeTestScriptTool,
} from '../src/agents/tools.js';
import { targetRoot } from '../src/target/source.js';
import { config } from '../src/config.js';

let failures = 0;

function check(label: string, ok: boolean, detail = ''): void {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ` -- ${detail}` : ''}`);
  if (!ok) failures += 1;
}

async function call(tool: unknown, input: unknown): Promise<Record<string, unknown>> {
  const execute = (tool as { execute: (i: unknown) => Promise<unknown> }).execute;
  return (await execute.call(tool, input)) as Record<string, unknown>;
}

const SCRIPT = '#!/bin/sh\ncurl -sS -m 5 "http://localhost:3000/health"\n';

const BAD_NAMES: Array<[string, string]> = [
  ['../escape.sh', 'parent traversal'],
  ['nested/dir.sh', 'subfolder'],
  ['a/b/../../../../etc/passwd.sh', 'traversal + depth'],
  ['..\\windows.sh', 'backslash traversal'],
  ['no-extension', 'missing .sh'],
  ['script.txt', 'wrong extension'],
  ['/absolute.sh', 'absolute path'],
  ['', 'empty filename'],
];

const BAD_PATHS: Array<[string, string]> = [
  ['../outside.js', 'parent traversal'],
  ['src/../../outside.js', 'traversal mid-path'],
  ['..\\..\\windows-system32\\evil.js', 'backslash traversal'],
  ['src/routes/../../../../../../etc/passwd', 'deep traversal to /etc'],
  ['C:/Windows/System32/evil.js', 'windows drive'],
  ['/etc/passwd', 'absolute unix path'],
  ['node_modules/evil/index.js', 'protected directory'],
  ['.git/config', 'protected directory'],
];

async function main(): Promise<void> {
  const root = targetRoot();
  console.log(`target repo: ${root}\n`);

  // ---------- 1. write_test_script: accepts ----------
  console.log('1. write_test_script accepts a flat .sh filename');
  const written = await call(writeTestScriptTool, { filename: 'check-tools.sh', content: SCRIPT });
  console.log(`   ${JSON.stringify(written)}`);
  check('accepted the write', !('refused' in written));
  check('reports the filename', written.filename === 'check-tools.sh');
  const onDisk = await fs.readFile(path.join(root, 'check-tools.sh'), 'utf8');
  check('content landed on disk', onDisk === SCRIPT);

  // ---------- 2. write_test_script: refuses ----------
  console.log('\n2. write_test_script rejects bad filenames');
  for (const [filename, why] of BAD_NAMES) {
    const r = await call(writeTestScriptTool, { filename, content: SCRIPT });
    const refused = 'refused' in r;
    check(`rejects ${why}`, refused, refused ? String(r.error).slice(0, 55) : `ACCEPTED: ${filename}`);
  }
  const escaped = await fs
    .stat(path.resolve(root, '..', 'escape.sh'))
    .then(() => true)
    .catch(() => false);
  check('nothing was created outside the repo', !escaped);
  console.log('');

  // ---------- 3. overwrite_source_file: applies ----------
  console.log('3. overwrite_source_file applies the change and reports it');
  const victim = 'src/routes/search.js';
  const original = await fs.readFile(path.join(root, victim), 'utf8');
  const patched = `${original}\n// patched by check-tools\n`;

  const result = await call(overwriteSourceFileTool, { relativePath: victim, content: patched });
  console.log(`   changed=${String(result.changed)} bytes=${String(result.bytesWritten)}`);
  check('accepted the write', !('refused' in result));
  check('reports a change', result.changed === true);
  check('new content is on disk', (await fs.readFile(path.join(root, victim), 'utf8')) === patched);
  check('previous content returned for rollback', result.previousContent === original);

  // ---------- 4. overwrite_source_file: refuses ----------
  console.log('\n4. overwrite_source_file rejects escaping paths');
  for (const [relativePath, why] of BAD_PATHS) {
    const r = await call(overwriteSourceFileTool, { relativePath, content: 'pwned' });
    const refused = 'refused' in r;
    check(`rejects ${why}`, refused, refused ? String(r.error).slice(0, 55) : `ACCEPTED: ${relativePath}`);
  }
  check(
    'the real source file was untouched by rejected paths',
    (await fs.readFile(path.join(root, victim), 'utf8')) === patched,
  );
  console.log('');

  // ---------- 5. run_in_sandbox ----------
  console.log('5. run_in_sandbox boots the target and runs a command in one call');
  const sandbox = await call(runInSandboxTool, {
    command: `curl -sS -m 5 "${config.target.baseUrl}/search?q=hub"`,
  });
  console.log(`   stdout: ${String(sandbox.stdout).slice(0, 130)}`);
  check('command succeeded', sandbox.exitCode === 0);
  check('target reported ready', sandbox.targetReady === true);
  check('search returned the product', String(sandbox.stdout).includes('USB-C Hub'));
  console.log('');

  // ---------- restore ----------
  console.log('6. restoring files this check modified');
  await fs.writeFile(path.join(root, victim), original, 'utf8');
  await fs.rm(path.join(root, 'check-tools.sh'), { force: true });
  check('source file restored', (await fs.readFile(path.join(root, victim), 'utf8')) === original);
  const gone = await fs
    .stat(path.join(root, 'check-tools.sh'))
    .then(() => false)
    .catch(() => true);
  check('test script removed', gone);

  console.log('');
  if (failures === 0) console.log('All tool checks passed.');
  else {
    console.log(`${failures} check(s) FAILED.`);
    process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  console.error('FAILED:', error instanceof Error ? error.stack : error);
  process.exit(1);
});