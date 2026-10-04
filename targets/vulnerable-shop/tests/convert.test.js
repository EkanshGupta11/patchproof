/**
 * Functional tests for POST /convert.
 *
 * These assert the conversion contract only. They must keep passing after the
 * command injection is fixed -- for example if the route switches from exec() to
 * execFile(), the converted output is unchanged.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { startTestServer } from './helpers.js';

async function convert(baseUrl, payload) {
  return fetch(`${baseUrl}/convert`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

describe('POST /convert', () => {
  let server;

  before(async () => {
    server = await startTestServer();
  });

  after(async () => {
    await server.close();
  });

  test('converts a document to the requested format', async () => {
    const response = await convert(server.baseUrl, { format: 'pdf', input: 'report.txt' });
    assert.equal(response.status, 200);

    const body = await response.json();
    assert.equal(body.format, 'pdf');
    assert.equal(body.input, 'report.txt');
    assert.equal(body.exitCode, 0);
    assert.match(body.output, /converted report\.txt -> pdf/);
  });

  test('defaults the output format to pdf when none is given', async () => {
    const response = await convert(server.baseUrl, { input: 'report.txt' });
    assert.equal(response.status, 200);

    const body = await response.json();
    assert.equal(body.format, 'pdf');
    assert.match(body.output, /converted report\.txt -> pdf/);
  });

  test('honours a different target format', async () => {
    const response = await convert(server.baseUrl, { format: 'png', input: 'logo.svg' });
    const body = await response.json();

    assert.equal(body.format, 'png');
    assert.match(body.output, /converted logo\.svg -> png/);
  });

  test('rejects a request with no input', async () => {
    const response = await convert(server.baseUrl, { format: 'pdf' });
    assert.equal(response.status, 400);

    const body = await response.json();
    assert.equal(body.error, 'input is required');
  });
});
