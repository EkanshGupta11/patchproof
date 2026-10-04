/**
 * HTTP API.
 *
 * Three things matter here:
 *   POST /api/runs               start a run
 *   GET  /api/runs/:id/stream    live progress over Server-Sent Events
 *   POST /api/runs/:id/approvals approve a verified fix for shipping
 *
 * SSE rather than WebSockets: the traffic is one-directional (server to browser),
 * it is plain HTTP so it works through anything, and the browser reconnects on
 * its own. The run lives in the RunManager, not in the connection, so a dropped
 * stream loses nothing.
 */
import cors from 'cors';
import express, { type Express, type Request, type Response } from 'express';
import { config } from './config.js';
import { createLogger } from './logger.js';
import { RunManager, type StartRunOptions } from './pipeline.js';
import { backupModel, primaryModel } from './agents/llm.js';
import { hasGitHubToken, normaliseRepoInput } from './github.js';
import { canOpenPullRequest } from './github/openPullRequest.js';
import {
  clearTargetRepo,
  currentTargetRepo,
  isTargetRepoOverridden,
  setTargetRepo,
} from './githubTargetRepo.js';

const log = createLogger('api');

/** One manager for the process; runs survive reconnects and dropped streams. */
export const runs = new RunManager();

/** Comment-frame interval, so idle streams are not dropped by intermediaries. */
const SSE_HEARTBEAT_MS = 15_000;

export function createServer(): Express {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '2mb' }));

  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ ok: true, service: 'patchproof-orchestrator', target: config.target.name });
  });

  /** Non-secret view of configuration, for the dashboard header. */
  app.get('/api/config', (_req: Request, res: Response) => {
    const primary = primaryModel();
    const backup = backupModel();
    res.json({
      target: config.target,
      sandbox: { image: config.sandbox.image, name: config.sandbox.name, network: config.sandbox.network },
      primaryProvider: { label: primary.label, model: primary.modelId, configured: Boolean(primary.apiKey) },
      backupProvider: { label: backup.label, model: backup.modelId, configured: Boolean(backup.apiKey) },
      fallback: config.fallback,
      // Whether a token exists, never the token itself.
      github: {
        repo: currentTargetRepo() ?? null,
        // From .env, shown so the user can see what the default is.
        defaultRepo: config.github.defaultRepo ?? null,
        // True when the dashboard value differs from .env.
        overridden: isTargetRepoOverridden(),
        tokenConfigured: hasGitHubToken(),
        canOpenPullRequest: canOpenPullRequest(),
      },
    });
  });

  /**
   * Set the repository that "Approve for shipping" opens pull requests against.
   *
   * Accepts a bare "owner/name" or any pasted GitHub URL; both are normalised to
   * the canonical slug before being stored, so what is saved is always something
   * we could have derived ourselves.
   *
   * Validation is syntactic only -- no API call is made to confirm the repository
   * exists. That keeps saving instant and avoids spending rate limit on a typo,
   * and a wrong repo fails loudly at PR time with GitHub's own error.
   */
  app.put('/api/config/repo', (req: Request, res: Response) => {
    const { repo } = (req.body ?? {}) as { repo?: string };

    // An explicit null clears the override and restores the .env default.
    if (repo === null) {
      clearTargetRepo();
      res.json({
        repo: currentTargetRepo() ?? null,
        defaultRepo: config.github.defaultRepo ?? null,
        overridden: false,
        canOpenPullRequest: canOpenPullRequest(),
      });
      return;
    }

    try {
      const slug = normaliseRepoInput(String(repo ?? ''));
      setTargetRepo(slug);
      log.info(`target repository for PRs set to ${slug}`);
      res.json({
        repo: slug,
        defaultRepo: config.github.defaultRepo ?? null,
        overridden: isTargetRepoOverridden(),
        canOpenPullRequest: canOpenPullRequest(slug),
      });
    } catch (error) {
      // 400, not 500: the user typed something wrong, and the message is for them.
      res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  // ---------------------------------------------------------------- runs ----

  app.get('/api/runs', (_req: Request, res: Response) => {
    res.json({ runs: runs.listRuns() });
  });

  /**
   * Start a run.
   *
   * Returns immediately with the run id; progress is on the stream. The body is
   * optional and can cap how much work is done, which matters because a full run
   * over many findings is slow.
   */
  app.post('/api/runs', (req: Request, res: Response) => {
    const body = (req.body ?? {}) as StartRunOptions;

    const options: StartRunOptions = {};
    if (typeof body.maxFindings === 'number' && body.maxFindings > 0) {
      options.maxFindings = body.maxFindings;
    }
    if (Array.isArray(body.onlyClasses) && body.onlyClasses.length > 0) {
      options.onlyClasses = body.onlyClasses.map(String);
    }

    const id = runs.start(options);
    log.info(`started run ${id} (${JSON.stringify(options)})`);
    res.status(202).json({ runId: id, status: 'running', options });
  });

  app.get('/api/runs/:id', (req: Request<{ id: string }>, res: Response) => {
    const run = runs.getRun(req.params.id);
    if (!run) {
      res.status(404).json({ error: 'run not found' });
      return;
    }
    res.json(run);
  });

  // PLACEHOLDER_SSE
/**
   * Live progress over Server-Sent Events.
   *
   * On connect the whole backlog is replayed first, so a client that attaches
   * late still sees the history; live events then follow. The stream closes
   * itself when the run ends, which tells the client it is finished rather than
   * leaving it hanging on an idle connection.
   */
  app.get('/api/runs/:id/stream', (req: Request<{ id: string }>, res: Response) => {
    const run = runs.getRun(req.params.id);
    if (!run) {
      res.status(404).json({ error: 'run not found' });
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      // Defeats proxy buffering, which otherwise delivers the stream all at once.
      'X-Accel-Buffering': 'no',
    });
    res.flushHeaders?.();

    const write = (event: { type: string; message: string; at: string }): void => {
      res.write(`event: ${event.type}\n`);
      res.write(`data: ${JSON.stringify(event)}\n\n`);
    };

    // 1. replay history, so a late subscriber is not left guessing.
    res.write(
      `event: stream.open\ndata: ${JSON.stringify({ runId: run.id, replaying: run.events.length })}\n\n`,
    );
    for (const event of run.events) write(event);

    // 2. follow live events.
    let closed = false;

    const cleanup = (): void => {
      if (closed) return;
      closed = true;
      clearInterval(heartbeat);
      unsubscribe();
    };

    const unsubscribe = runs.subscribe(run.id, (event) => {
      write(event);
      if (event.type === 'run.completed' || event.type === 'run.failed') {
        // Let the client see the terminal event, then close cleanly.
        res.write('event: stream.end\ndata: {}\n\n');
        cleanup();
        res.end();
      }
    });

    // Keep intermediaries from dropping an idle stream.
    const heartbeat = setInterval(() => {
      if (!closed) res.write(': keep-alive\n\n');
    }, SSE_HEARTBEAT_MS);

    req.on('close', cleanup);
  });

  // ----------------------------------------------------------- approvals ----

  /** Fixes approved for shipping. */
  app.get('/api/approvals', (_req: Request, res: Response) => {
    res.json({ approvals: runs.listApprovals() });
  });

  /**
   * Approve a verified fix for shipping.
   *
   * Refuses anything the deterministic prover did not mark `verified`, so this
   * endpoint cannot be used to ship an unproven or app-breaking change.
   */
  app.post('/api/runs/:id/approvals', (req: Request<{ id: string }>, res: Response) => {
    const { findingId } = (req.body ?? {}) as { findingId?: string };

    if (!findingId) {
      res.status(400).json({ error: 'findingId is required' });
      return;
    }

    const result = runs.approve(req.params.id, findingId);
    if (!result.ok) {
      res.status(409).json({ error: result.reason });
      return;
    }
    res.status(202).json(result);
  });

  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: 'not found' });
  });

  return app;
}