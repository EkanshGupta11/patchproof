/**
 * Tools handed to the agents.
 *
 * These are the only ways an agent can touch the target. Two of them write to
 * disk, so both funnel every path through `resolveInsideTarget` first: an agent
 * is a language model, and "write this file" plus "../" must never become
 * "write outside the repo". The guard is applied here rather than trusted to
 * the agent, because that is the whole point.
 */
import { createTool } from '@cline/sdk';
import { z } from 'zod';
import fs from 'node:fs/promises';
import path from 'node:path';
import { runSandboxCommand } from '../sandbox/ephemeral.js';
import { listSourceFiles, overwriteSourceFile, readSourceFile, targetRoot } from '../target/source.js';
import { config } from '../config.js';

const MAX_OUTPUT = 6000;

/**
 * Turn a guard rejection into a structured, agent-readable failure.
 *
 * Returning this instead of throwing matters: a thrown error aborts the agent's
 * run, whereas a refusal lets it read the reason and try a different path.
 */
async function guard<T>(operation: () => Promise<T>): Promise<T | { error: string; refused: true }> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof Error && error.name === 'PathEscapeError') {
      return { error: error.message, refused: true };
    }
    throw error;
  }
}

export const readSourceTool = createTool({
  name: 'read_source_file',
  description:
    'Read a single file from the target application source tree. Returns the file contents.',
  inputSchema: z.object({
    relativePath: z
      .string()
      .describe('Path relative to the target app root, e.g. "src/routes/admin.js".'),
  }),
  async execute(input: { relativePath: string }) {
    const content = await readSourceFile(input.relativePath);
    return { relativePath: input.relativePath, content };
  },
});

export const listSourceTool = createTool({
  name: 'list_source_files',
  description: 'List every source file in the target application, as relative paths.',
  inputSchema: z.object({
    extensions: z
      .array(z.string())
      .optional()
      .describe('File extensions to include. Defaults to [".js"].'),
  }),
  async execute(input: { extensions?: string[] }) {
    const requested = input.extensions;
    const files = await listSourceFiles(requested?.length ? requested : ['.js']);
    return { count: files.length, files };
  },
});

export const runInSandboxTool = createTool({
  name: 'run_in_sandbox',
  description:
    'Execute a shell command INSIDE the sandbox container against the target app. Use this to run ' +
    'curl against the target, run a verification script, or replay an exploit. Commands never ' +
    `execute on the host. The target is started automatically and is reachable at ${config.target.baseUrl}, ` +
    'so one call can both boot the app and attack it. The container is thrown away afterwards, ' +
    'so nothing persists into your next call.',
  inputSchema: z.object({
    command: z.string().describe('Shell command to execute inside the sandbox.'),
    setup: z
      .string()
      .nullable()
      .optional()
      .describe(
        'How to boot the target before running the command. Defaults to starting the app. ' +
          'Pass null to run the command with no target running.',
      ),
    timeoutMs: z.number().optional().describe('Optional hard timeout in milliseconds.'),
  }),
  async execute(input: { command: string; setup?: string | null; timeoutMs?: number }) {
    const result = await runSandboxCommand({
      command: input.command,
      setup: input.setup,
      timeoutMs: input.timeoutMs,
      label: 'tool',
    });

    return {
      exitCode: result.exitCode,
      timedOut: result.timedOut,
      // Whether the target was up before the command ran.
      targetReady: result.ready,
      readinessProbes: result.probes,
      bootMs: result.bootMs,
      stdout: result.stdout.slice(-MAX_OUTPUT),
      stderr: result.stderr.slice(-MAX_OUTPUT),
    };
  },
});

export const targetHealthTool = createTool({
  name: 'target_health',
  description:
    'Check whether the target application is healthy, by booting it in a throwaway sandbox ' +
    'and probing its health endpoint. The sandbox is discarded afterwards.',
  inputSchema: z.object({}),
  async execute() {
    const result = await runSandboxCommand({
      command: `curl -sS -m 5 "${config.target.baseUrl}/health"`,
      label: 'health',
    });

    return {
      healthy: result.ready && result.exitCode === 0,
      targetReady: result.ready,
      readinessProbes: result.probes,
      bootMs: result.bootMs,
      response: result.stdout,
      baseUrl: config.target.baseUrl,
    };
  },
});

/** Filename only: no directory separators allowed at all. */
const FLAT_FILENAME = /^[A-Za-z0-9._-]+$/;

export const writeTestScriptTool = createTool({
  name: 'write_test_script',
  description:
    'Write a verification/test shell script into the target repo. The filename must be flat ' +
    '(no subfolders) and must end in .sh. Use this to leave a reproducible check in the repo, ' +
    'then run it with run_in_sandbox. Any path containing "/" or ".." is rejected.',
  inputSchema: z.object({
    filename: z
      .string()
      .describe('Flat filename ending in .sh, e.g. "verify-search.sh". No directories allowed.'),
    content: z.string().describe('Full contents of the script.'),
  }),
  async execute(input: { filename: string; content: string }) {
    const { filename, content } = input;

    // Enforced here as well as in the path guard, so the agent gets a specific
    // reason rather than a generic "outside the repo".
    if (!FLAT_FILENAME.test(filename) || filename.includes('/') || filename.includes('\\')) {
      return {
        error: `Filename must be flat and contain no directory separators: "${filename}"`,
        refused: true,
      };
    }
    if (!filename.endsWith('.sh')) {
      return { error: `Filename must end in .sh: "${filename}"`, refused: true };
    }

    return guard(async () => {
      const written = await overwriteSourceFile(filename, content);
      // 0o755 so the script is directly executable inside the sandbox.
      await fs.chmod(path.join(targetRoot(), filename), 0o755).catch(() => {
        // Windows hosts do not honour POSIX modes; harmless there.
      });
      return {
        filename: written.relativePath,
        bytesWritten: written.bytesWritten,
        overwritten: written.previous !== null,
        executable: true,
      };
    });
  },
});

export const overwriteSourceFileTool = createTool({
  name: 'overwrite_source_file',
  description:
    'Overwrite a source file in the target repo with new content. Use this to apply a patch. ' +
    'The path must stay inside the repo: absolute paths and any path containing ".." are refused. ' +
    'The previous contents are returned so you can undo your change if the fix does not verify.',
  inputSchema: z.object({
    relativePath: z
      .string()
      .describe('Path relative to the target repo root, e.g. "src/routes/search.js".'),
    content: z.string().describe('The complete new contents of the file.'),
  }),
  async execute(input: { relativePath: string; content: string }) {
    return guard(async () => {
      const result = await overwriteSourceFile(input.relativePath, input.content);
      return {
        relativePath: result.relativePath,
        bytesWritten: result.bytesWritten,
        changed: result.changed,
        // Returned so a caller can restore the file exactly.
        previousContent: result.previous,
      };
    });
  },
});

/** Tools for the agents that need to inspect the target's source. */
export const reconTools = [readSourceTool, listSourceTool];

/**
 * Tools for the exploit agent: recon plus the ability to actually attack.
 *
 * Includes writeTestScriptTool because the command-injection directive tells the
 * agent to write the known-good curl line to a script and run it. A prompt that
 * names a tool the agent does not have is worse than no prompt: the agent burns
 * iterations trying to call it, which is the exact failure this directive was
 * written to stop.
 */
export const exploitTools = [...reconTools, writeTestScriptTool, runInSandboxTool];

/** Tools for the patch agent: read, rewrite, and prove the fix with a script. */
export const patchTools = [
  readSourceTool,
  listSourceTool,
  overwriteSourceFileTool,
  writeTestScriptTool,
  runInSandboxTool,
];
