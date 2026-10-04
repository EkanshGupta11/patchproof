/**
 * Express application factory for the PatchProof demo target.
 *
 * Kept separate from server.js so tests can boot the app on an ephemeral port
 * in-process, with a fresh in-memory database each time.
 *
 * Every vulnerability is marked with a VULN comment. See README.md.
 */
import express from 'express';
import { createDb } from './db.js';
import { createSearchRouter } from './routes/search.js';
import { createFilesRouter } from './routes/files.js';
import { createConvertRouter } from './routes/convert.js';

export function createApp() {
  const db = createDb();
  const app = express();

  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  // Endpoint index. Handy during a demo, and a reminder of the intended surface.
  app.get('/', (_req, res) => {
    res.json({
      app: 'Vulnerable Shop',
      warning: 'Intentionally vulnerable. Sandbox use only.',
      endpoints: [
        'GET  /search?q=<term>',
        'GET  /files/:name',
        'POST /convert  { "format": "pdf", "input": "report.txt" }',
        'GET  /health',
      ],
    });
  });

  app.get('/health', (_req, res) => res.json({ ok: true }));

  app.use(createSearchRouter(db));
  app.use(createFilesRouter());
  app.use(createConvertRouter());

  app.use((_req, res) => res.status(404).json({ error: 'not found' }));

  return app;
}
