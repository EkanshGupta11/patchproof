/**
 * Test helpers.
 *
 * Boots the real Express app on an ephemeral port in-process, so tests exercise
 * the actual HTTP surface (routing, body parsing, status codes) rather than
 * calling route handlers directly. No test framework beyond node:test, and no
 * supertest dependency -- Node's global fetch does the work.
 */
import { once } from 'node:events';
import { createApp } from '../src/app.js';

export async function startTestServer() {
  const server = createApp().listen(0, '127.0.0.1');
  await once(server, 'listening');

  const { port } = server.address();

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise((resolve, reject) => {
        // fetch() keeps connections alive, so close() would otherwise wait for
        // them to time out and the test process would appear to hang.
        server.closeAllConnections();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}
