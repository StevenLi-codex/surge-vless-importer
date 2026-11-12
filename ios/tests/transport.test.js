'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createFetcher } = require('../transport');

test('Surge transport disables cookies redirects and TLS bypass and follows validated HTTPS redirects only', async () => {
  const calls = [];
  const fetch = createFetcher({ get(options, done) {
    calls.push(options);
    if (calls.length === 1) done(null, { status: 302, headers: { Location: 'https://cdn.example.com/feed' } }, '');
    else done(null, { status: 200, headers: {} }, 'nodes');
  } });
  assert.equal(await fetch('https://subscription.example.com/feed'), 'nodes');
  assert.equal(calls.length, 2);
  for (const options of calls) {
    assert.equal(options['auto-cookie'], false);
    assert.equal(options['auto-redirect'], false);
    assert.notEqual(options.insecure, true);
    assert.equal(options.timeout, 10);
    assert.equal(options.headers['User-Agent'], 'clash.meta');
    assert.ok(!options.headers.Authorization);
  }
});

test('Surge transport rejects downgrade, local redirects, oversized data, errors and redirect loops without URL leaks', async () => {
  for (const [status, headers, body] of [
    [302, { Location: 'http://example.com/' }, ''],
    [302, { Location: 'https://127.0.0.1/' }, ''],
    [302, { Location: 'https://example.com/loop' }, ''],
    [403, {}, 'private secret'],
    [200, {}, 'x'.repeat(2 * 1024 * 1024 + 1)],
  ]) {
    let calls = 0;
    const fetch = createFetcher({ get(options, done) { calls++; done(null, { status, headers }, body); } });
    await assert.rejects(fetch('https://example.com/?token=private-secret'), error => !error.message.includes('secret') && !error.message.includes('https://'));
    assert.ok(calls <= 4);
  }
});
