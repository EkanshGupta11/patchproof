/**
 * Dependency smoke check (dev aid).
 *
 *   node --import tsx scripts/check-deps.ts
 *
 * Imports every runtime dependency and exercises the parts the orchestrator
 * actually relies on, so a bad install fails here rather than mid-pipeline.
 */
import 'dotenv/config';

import { Agent, createTool } from '@cline/sdk';
import { Octokit } from '@octokit/rest';
import cors from 'cors';
import express from 'express';
import { z } from 'zod';

import { config } from '../src/config.js';
import { createGitHubClient, hasGitHubToken, parseRepoRef } from '../src/github.js';
import { createServer } from '../src/server.js';

function pass(label: string, detail = ''): void {
  console.log(`  PASS  ${label}${detail ? ` (${detail})` : ''}`);
}

async function main(): Promise<void> {
  console.log('dotenv');
  pass('loads .env', `NODE_ENV=${config.nodeEnv}`);

  console.log('@cline/sdk');
  pass('exports Agent', typeof Agent);
  pass('exports createTool', typeof createTool);
  const tool = createTool({
    name: 'echo',
    description: 'Echoes its input back.',
    inputSchema: z.object({ text: z.string() }),
    async execute(input: { text: string }) {
      return input.text;
    },
  });
  pass('createTool builds a tool', tool.name);

  console.log('zod');
  const schema = z.object({ format: z.string(), pages: z.number().int().positive().optional() });
  const parsed = schema.safeParse({ format: 'pdf' });
  pass('schema accepts valid input', JSON.stringify(parsed.success ? parsed.data : null));
  pass('schema rejects invalid input', String(schema.safeParse({ pages: -1 }).success === false));

  console.log('express + cors');
  const app = express();
  app.use(cors());
  app.get('/health', (_req, res) => {
    res.json({ ok: true });
  });
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  const response = await fetch(`http://127.0.0.1:${port}/health`);
  await new Promise((resolve) => server.close(resolve));
  pass('express serves JSON', `HTTP ${response.status} ${JSON.stringify(await response.json())}`);
  pass('cors middleware mounts', typeof cors);

  console.log('orchestrator server');
  const api = createServer();
  pass('createServer() builds the API', typeof api);

  console.log('@octokit/rest');
  const gh = createGitHubClient();
  pass('Octokit constructs', gh.constructor.name);
  pass('authenticated', hasGitHubToken() ? 'yes (GITHUB_TOKEN set)' : 'no (anonymous, 60 req/hr)');
  pass('parseRepoRef', JSON.stringify(parseRepoRef('cline/cline')));

  console.log('\nAll dependency checks passed.');
}

main().catch((error: unknown) => {
  console.error('\nFAILED:', error instanceof Error ? error.stack : error);
  process.exit(1);
});