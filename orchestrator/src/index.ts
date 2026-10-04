/**
 * PatchProof orchestrator — entry point.
 *
 * `dotenv/config` is imported FIRST and on its own line: ES modules evaluate
 * their imports in order, so this guarantees process.env is populated before
 * config.ts (or anything that imports it) is evaluated.
 */
import 'dotenv/config';

import { backupModel, primaryModel } from './agents/llm.js';
import { config } from './config.js';
import { createLogger } from './logger.js';
import { createServer } from './server.js';

const log = createLogger('boot');

function main(): void {
  const app = createServer();

  app.listen(config.port, () => {
    const primary = primaryModel();
    const backup = backupModel();

    log.info(`listening on http://localhost:${config.port}`);
    log.info(`primary provider : ${primary.label} / ${primary.modelId}${primary.apiKey ? '' : '  (NO API KEY SET)'}`);
    log.info(`backup provider  : ${backup.label} / ${backup.modelId}${backup.apiKey ? '' : '  (NO API KEY SET)'}`);
    log.info(`target           : ${config.target.name} -> ${config.target.baseUrl}`);
    log.info(`sandbox          : ${config.sandbox.image} (container ${config.sandbox.name})`);
  });
}

main();
