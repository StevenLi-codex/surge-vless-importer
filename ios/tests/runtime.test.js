'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../runtime');

function fixture(overrides = {}) {
  let state = null;
  const app = createApp({
    read: () => state,
    write: value => { state = value; return true; },
    convert: source => ({ content: '# example\nTest = vless, example.com, 443, username=test\n', count: 1, warnings: [], notes: [], duplicates: 0 }),
    fetch: async () => 'vless://test@example.com:443',
    random: () => 'a'.repeat(64),
    now: () => 1000000,
    ...overrides,
  });
  return { app, state: () => state };
}

test('local page is self-contained, no credentials and no permissive CORS', async () => {
  const f = fixture();
  const r = await f.app({ url: 'http://surge-vless.invalid/', method: 'GET', headers: {} });
  assert.equal(r.status, 200);
  assert.match(r.headers['Content-Type'], /text\/html/);
  assert.match(r.body, /VLESS/);
  assert.ok(!r.headers['Access-Control-Allow-Origin']);
  assert.match(r.headers['Content-Security-Policy'], /default-src 'none'/);
  assert.equal(f.state(), null);
});

const localHeaders = { 'X-Vless-Local': '1', Origin: 'http://surge-vless.invalid', 'Content-Type': 'application/json' };
const request = (path, method = 'GET', body, headers = localHeaders) => ({ url: 'http://surge-vless.invalid' + path, method, headers, body: body === undefined ? undefined : JSON.stringify(body) });

test('import converts before atomically storing private source and a randomized download token', async () => {
  const f = fixture();
  const r = await f.app(request('/api/import', 'POST', { source: 'https://subscription.example/feed?token=private-secret' }));
  assert.equal(r.status, 200);
  const result = JSON.parse(r.body);
  assert.equal(result.count, 1);
  assert.match(result.downloadURL, /^http:\/\/surge-vless\.invalid\/list\/[a-f0-9]{64}\.list$/);
  assert.ok(!r.body.includes('private-secret'));
  const saved = JSON.parse(f.state());
  assert.equal(saved.source, 'https://subscription.example/feed?token=private-secret');
  assert.equal(saved.count, 1);
});

test('untrusted origins and simple cross-site POST cannot overwrite local data', async () => {
  const f = fixture();
  for (const headers of [{}, { ...localHeaders, Origin: 'https://evil.example' }, { ...localHeaders, 'Sec-Fetch-Site': 'cross-site' }]) {
    const r = await f.app(request('/api/import', 'POST', { source: 'https://example.com/' }, headers));
    assert.equal(r.status, 403);
    assert.equal(f.state(), null);
  }
  assert.equal((await f.app(request('/api/status', 'OPTIONS', undefined, { Origin: 'https://evil.example' }))).status, 403);
});

test('invalid source and conversion failures preserve state and redact secrets', async () => {
  const f = fixture({ convert: () => { throw new Error('secret upstream failure'); } });
  const r = await f.app(request('/api/import', 'POST', { source: 'https://example.com/feed?token=private-secret' }));
  assert.equal(r.status, 400);
  assert.ok(!r.body.includes('secret'));
  assert.equal(f.state(), null);
  for (const source of ['http://example.com/feed', 'https://user:pass@example.com/', 'https://127.0.0.1/', 'https://192.168.1.1/', 'https://[::1]/', 'https://surge-vless.invalid/', 'https://example.com/#fragment']) {
    assert.equal((await fixture().app(request('/api/import', 'POST', { source }))).status, 400, source);
  }
  assert.equal((await f.app({ ...request('/api/import', 'POST'), body: 'not-json' })).status, 400);
});

test('status returns only safe metadata and persists a stable download link across replacement', async () => {
  const f = fixture();
  assert.deepEqual(JSON.parse((await f.app(request('/api/status'))).body), { configured: false });
  const first = JSON.parse((await f.app(request('/api/import', 'POST', { source: 'https://example.com/?secret=one' }))).body);
  const second = JSON.parse((await f.app(request('/api/import', 'POST', { source: 'https://example.org/?secret=two' }))).body);
  assert.equal(first.downloadURL, second.downloadURL);
  const status = await f.app(request('/api/status'));
  const metadata = JSON.parse(status.body);
  assert.equal(metadata.configured, true);
  assert.ok(!status.body.includes('secret'));
  assert.ok(!status.body.includes('username='));
  assert.equal(metadata.policyGroup, `VLESS订阅 = select, policy-path=${first.downloadURL}, update-interval=3600`);
});

test('token-authenticated list serves cached policies and rejects other methods or bad tokens', async () => {
  const f = fixture();
  const saved = JSON.parse((await f.app(request('/api/import', 'POST', { source: 'https://example.com/' }))).body);
  const path = new URL(saved.downloadURL).pathname;
  const r = await f.app(request(path, 'GET', undefined, {}));
  assert.equal(r.status, 200);
  assert.match(r.headers['Content-Type'], /text\/plain/);
  assert.match(r.body, /Test = vless/);
  assert.equal((await f.app(request('/list/' + 'b'.repeat(64) + '.list', 'GET', undefined, {}))).status, 404);
  assert.equal((await f.app(request(path, 'POST', {}, {}))).status, 405);
});

test('list refreshes stale remote data and retains last valid cache after upstream failure', async () => {
  let now = 1000000, broken = false, calls = 0;
  const f = fixture({ now: () => now, fetch: async () => { calls++; if (broken) throw new Error('private URL secret'); return 'source'; } });
  const saved = JSON.parse((await f.app(request('/api/import', 'POST', { source: 'https://example.com/' }))).body);
  const path = new URL(saved.downloadURL).pathname;
  assert.equal(calls, 1);
  now += 3600001;
  assert.equal((await f.app(request(path, 'GET', undefined, {}))).status, 200);
  assert.equal(calls, 2);
  assert.equal(JSON.parse(f.state()).updatedAt, now);
  now += 3600001; broken = true;
  const previous = f.state();
  const r = await f.app(request(path, 'GET', undefined, {}));
  assert.equal(r.status, 200);
  assert.equal(r.headers['X-Vless-Cache'], 'stale');
  assert.ok(!r.body.includes('secret'));
  assert.equal(f.state(), previous);
});

test('manual refresh and clear are explicit authenticated operations', async () => {
  const f = fixture();
  assert.equal((await f.app(request('/api/refresh', 'POST', {}))).status, 409);
  const saved = JSON.parse((await f.app(request('/api/import', 'POST', { source: 'https://example.com/' }))).body);
  assert.equal((await f.app(request('/api/refresh', 'POST', {}))).status, 200);
  assert.equal((await f.app(request('/api/clear', 'POST', {}))).status, 200);
  assert.equal((await f.app(request(new URL(saved.downloadURL).pathname, 'GET', undefined, {}))).status, 404);
  assert.deepEqual(JSON.parse((await f.app(request('/api/status'))).body), { configured: false });
});

test('pasted local source is converted without networking and not auto-refreshed', async () => {
  let calls = 0;
  const f = fixture({ fetch: async () => { calls++; throw new Error('must not fetch'); } });
  const r = await f.app(request('/api/import', 'POST', { source: 'vless://test@example.com:443' }));
  assert.equal(r.status, 200);
  assert.equal(calls, 0);
  assert.equal(JSON.parse(f.state()).remote, false);
});

test('clear during a pending refresh cannot restore deleted credentials', async () => {
  let release;
  const f = fixture();
  await f.app(request('/api/import', 'POST', { source: 'https://example.com/' }));
  const pendingApp = createApp({
    read: f.state,
    write: value => { throw new Error('must not write after clear'); },
    fetch: () => new Promise(resolve => { release = resolve; }),
    convert: () => ({ content: 'sensitive', count: 1, warnings: [], notes: [], duplicates: 0 }),
    now: () => 2000000,
    random: () => 'b'.repeat(64),
  });
  const pending = pendingApp(request('/api/refresh', 'POST', {}));
  await f.app(request('/api/clear', 'POST', {}));
  release('source');
  assert.equal((await pending).status, 400);
  assert.equal(f.state(), 'null');
});

test('pending list refresh never serves a cleared or replaced generation', async () => {
  for (const replacement of [false, true]) {
    let now = 1000000, release, conversions = 0;
    const f = fixture({ now: () => now, convert: () => ({ content: ++conversions === 1 ? 'OLD_NODES' : 'NEW_NODES', count: 1, warnings: [], notes: [], duplicates: 0 }) });
    const saved = JSON.parse((await f.app(request('/api/import', 'POST', { source: 'https://example.com/old' }))).body);
    now += 3600001;
    const pendingApp = createApp({ read: f.state, write: () => { throw new Error('no write'); }, now: () => now,
      random: () => 'b'.repeat(64), convert: () => ({ content: 'UPSTREAM_OLD', count: 1, warnings: [], notes: [], duplicates: 0 }),
      fetch: () => new Promise(resolve => { release = resolve; }) });
    const pending = pendingApp(request(new URL(saved.downloadURL).pathname, 'GET', undefined, {}));
    if (replacement) await f.app(request('/api/import', 'POST', { source: 'https://example.com/new' }));
    else await f.app(request('/api/clear', 'POST', {}));
    release('old upstream');
    const r = await pending;
    assert.equal(r.status, replacement ? 200 : 404);
    if (replacement) assert.equal(r.body, JSON.parse(f.state()).content);
  }
});

test('terminal-dot local hostnames are rejected without normalizing submitted URL', async () => {
  for (const source of ['https://localhost./', 'https://router.local./', 'https://router.internal./']) {
    assert.equal((await fixture().app(request('/api/import', 'POST', { source }))).status, 400);
  }
});

test('state exceeding iOS persistent-store limit is rejected before writing', async () => {
  const f = fixture({ convert: () => ({ content: 'x'.repeat(4 * 1024 * 1024), count: 1, warnings: [], notes: [], duplicates: 0 }) });
  assert.equal((await f.app(request('/api/import', 'POST', { source: 'https://example.com/' }))).status, 400);
  assert.equal(f.state(), null);
});

test('import requires JSON and all local requests reject URL credentials or query secrets', async () => {
  const f = fixture();
  assert.equal((await f.app(request('/api/import', 'POST', { source: 'https://example.com/' }, { 'X-Vless-Local': '1', 'Content-Type': 'text/plain' }))).status, 415);
  for (const url of ['http://user:pass@surge-vless.invalid/', 'http://surge-vless.invalid/?source=secret']) {
    assert.equal((await f.app({ url, method: 'GET', headers: {} })).status, 404);
  }
});
