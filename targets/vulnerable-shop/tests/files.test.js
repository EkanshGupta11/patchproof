/**
 * Functional tests for GET /files/:name.
 *
 * Only legitimate behaviour is asserted: public documents are served, and
 * missing files 404. The traversal itself is deliberately NOT tested here --
 * these tests must still pass once the traversal is fixed.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer } from './helpers.js';

describe('GET /files/:name', () => {
  let server;

  before(async () => {
    server = await startTestServer();
  });

  after(async () => {
    await server.close();
  });

  test('serves a document that lives in the public directory', async () => {
    const response = await fetch(`${server.baseUrl}/files/readme.txt`);
    assert.equal(response.status, 200);

    const body = await response.json();
    assert.equal(body.file, 'readme.txt');
    assert.match(body.content, /Vulnerable Shop/);
  });

  test('serves a second public document', async () => {
    const response = await fetch(`${server.baseUrl}/files/terms.txt`);
    assert.equal(response.status, 200);

    const body = await response.json();
    assert.match(body.content, /Terms of Service/);
  });

  test('reports the size of the returned document', async () => {
    const response = await fetch(`${server.baseUrl}/files/terms.txt`);
    const body = await response.json();

    assert.equal(typeof body.bytes, 'number');
    assert.equal(body.bytes, body.content.length);
  });

  test('responds 404 for a file that does not exist', async () => {
    const response = await fetch(`${server.baseUrl}/files/does-not-exist.txt`);
    assert.equal(response.status, 404);

    const body = await response.json();
    assert.match(body.error, /no such file/);
  });
});
