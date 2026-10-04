/**
 * Standalone check for the ephemeral sandbox runner.
 *
 *   npm run check:ephemeral
 *
 * Calls runSandboxCommand() directly and curls the target's /search endpoint,
 * proving the whole contract in one call: fresh container, no network, bounded
 * resources, target mounted, app booted AND queried without a fixed sleep.
 */
import { runSandboxCommand } from '../src/sandbox/ephemeral.js';
import { config } from '../src/config.js';

let failures = 0;

function check(label: string, condition: boolean, detail = ''): void {
  console.log(`  ${condition ? 'PASS' : 'FAIL'}  ${label}${detail ? ` -- ${detail}` : ''}`);
  if (!condition) failures += 1;
}

async function main(): Promise<void> {
  console.log(`image    : ${config.sandbox.image}`);
  console.log(`target   : ${config.sandbox.mountPath} (from ${config.sandbox.targetPath})`);
  console.log(`network  : ${config.sandbox.network}`);
  console.log(`limits   : ${config.sandbox.memory} / ${config.sandbox.cpus} cpu / ${config.sandbox.pidsLimit} pids`);
  console.log(`baseUrl  : ${config.target.baseUrl}`);
  console.log('');

  // The checkpoint: one call boots the app and curls /search against it.
  console.log('1. single call boots the target and curls /search');
  const result = await runSandboxCommand({
    label: 'search',
    command: `curl -sS -m 5 "${config.target.baseUrl}/search?q=hub"`,
  });

  console.log(`   stdout: ${result.stdout.trim()}`);
  if (result.stderr.trim()) console.log(`   stderr: ${result.stderr.trim()}`);
  console.log(
    `   exit=${result.exitCode} ready=${result.ready} probes=${result.probes} boot=${result.bootMs}ms`,
  );
  console.log('');

  check('target reached readiness by polling', result.ready, `${result.probes} probe(s)`);
  check('command exited cleanly', result.exitCode === 0, `exit ${result.exitCode}`);
  check('did not time out', !result.timedOut);

  // /search?q=hub should return the single matching product.
  let parsed: { count?: number; results?: Array<{ name?: string }> } = {};
  try {
    parsed = JSON.parse(result.stdout) as typeof parsed;
  } catch {
    /* reported by the assertion below */
  }
  check('response was valid JSON', Object.keys(parsed).length > 0, result.stdout.slice(0, 120));
  check('returned exactly one match', parsed.count === 1, `count=${parsed.count}`);
  check('match is the expected product', parsed.results?.[0]?.name === 'USB-C Hub', parsed.results?.[0]?.name);

  console.log('');
  console.log('2. a second call must NOT see the first call\'s app (fresh container each time)');
  const isolated = await runSandboxCommand({
    label: 'isolation',
    // Deliberately skip the app boot: nothing should be listening on loopback.
    setup: null,
    readyUrl: null,
    command: `curl -sS -m 3 "${config.target.baseUrl}/health" || echo "NOTHING_LISTENING"`,
  });
  const isolatedOut = `${isolated.stdout}\n${isolated.stderr}`;
  console.log(`   ${isolated.stdout.trim() || isolated.stderr.trim()}`);
  console.log('');
  check(
    'no state leaked between calls',
    isolatedOut.includes('NOTHING_LISTENING') || isolated.exitCode !== 0,
    isolatedOut.includes('NOTHING_LISTENING') ? 'connection refused' : `exit ${isolated.exitCode}`,
  );

  console.log('');
  console.log('3. the sandbox has no outbound network');
  const netless = await runSandboxCommand({
    label: 'no-network',
    setup: null,
    readyUrl: null,
    command: 'curl -sS -m 8 https://api.groq.com -o /dev/null && echo REACHED || echo BLOCKED',
  });
  const netOut = `${netless.stdout}\n${netless.stderr}`;
  console.log(`   ${netless.stdout.trim() || netless.stderr.trim()}`);
  check('outbound request blocked', netOut.includes('BLOCKED') || !netOut.includes('REACHED'));

  console.log('');
  console.log('4. a slow-starting app is still caught (no fixed sleep)');
  // Boot with a deliberate 5s delay. A hard-coded sleep of 2s or 3s would fail
  // this; polling waits it out and still finishes promptly.
  const slow = await runSandboxCommand({
    label: 'slow-start',
    setup: 'sleep 5 && cd /workspace/target && node src/server.js',
    command: `curl -sS -m 5 "${config.target.baseUrl}/search?q=webcam"`,
    readyTimeoutSec: 45,
  });
  console.log(`   stdout: ${slow.stdout.trim()}`);
  console.log(`   exit=${slow.exitCode} ready=${slow.ready} probes=${slow.probes} boot=${slow.bootMs}ms`);
  check('slow app still reached readiness', slow.ready, `${slow.probes} probe(s)`);
  check('slow-start command succeeded', slow.exitCode === 0);
  check('polled for real (>1s of startup)', slow.bootMs > 1000, `${slow.bootMs}ms`);
  check('did not waste time beyond the delay', slow.bootMs < 20_000, `${slow.bootMs}ms`);

  console.log('');
  console.log('5. a broken target fails fast with its log, not a silent timeout');
  const broken = await runSandboxCommand({
    label: 'broken-target',
    setup: 'echo "boom: cannot start" >&2; exit 7',
    command: 'echo SHOULD_NOT_RUN',
    readyTimeoutSec: 30,
  });
  const brokenOut = `${broken.stdout}\n${broken.stderr}`;
  console.log(`   ${brokenOut.trim().split('\n').slice(-3).join(' | ')}`);
  check('reported as not ready', !broken.ready);
  check('captured the target log', brokenOut.includes('boom: cannot start'));
  check('did not run the command', !brokenOut.includes('SHOULD_NOT_RUN'));

  console.log('');
  if (failures === 0) {
    console.log('All ephemeral sandbox checks passed.');
  } else {
    console.log(`${failures} check(s) FAILED.`);
    process.exitCode = 1;
  }
}

main().catch((error: unknown) => {
  console.error('FAILED:', error instanceof Error ? error.stack : error);
  process.exit(1);
});