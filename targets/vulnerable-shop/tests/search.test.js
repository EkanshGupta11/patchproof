/**
 * Functional tests for GET /search.
 *
 * These describe how the endpoint SHOULD behave for normal users. They pass
 * against the vulnerable code as written, and must keep passing after the SQL
 * injection is patched -- a fix that breaks ordinary search is a regression, not
 * a fix. They deliberately do not test the vulnerability itself.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer } from './helpers.js';

describe('GET /search', () => {
  let server;

  before(async () => {
    server = await startTestServer();
  });

  after(async () => {
    await server.close();
  });

  test('finds a product by a lower-case substring of its name', async () => {
    const response = await fetch(`${server.baseUrl}/search?q=hub`);
    assert.equal(response.status, 200);

    const body = await response.json();
    assert.equal(body.count, 1);
    assert.equal(body.results.length, 1);
    assert.equal(body.results[0].name, 'USB-C Hub');
  });

  test('is case-insensitive', async () => {
    const response = await fetch(`${server.baseUrl}/search?q=WEBCAM`);
    const body = await response.json();

    assert.equal(body.count, 1);
    assert.equal(body.results[0].name, 'Webcam 1080p');
  });

  test('returns an empty result set when nothing matches', async () => {
    const response = await fetch(`${server.baseUrl}/search?q=nothing-matches-this`);
    assert.equal(response.status, 200);

    const body = await response.json();
    assert.equal(body.count, 0);
    assert.deepEqual(body.results, []);
  });

  test('does not fail when the query parameter is omitted', async () => {
    const response = await fetch(`${server.baseUrl}/search`);
    assert.equal(response.status, 200);

    const body = await response.json();
    assert.ok(Array.isArray(body.results));
  });

  test('echoes the query back and exposes only the product columns', async () => {
    const response = await fetch(`${server.baseUrl}/search?q=webcam`);
    const body = await response.json();

    assert.equal(body.query, 'webcam');
    assert.deepEqual(Object.keys(body.results[0]).sort(), [
      'description',
      'id',
      'name',
      'price',
    ]);
  });
});
