'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../ui.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];

function browser() {
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      id, value: '', disabled: false, hidden: false, textContent: '', className: '', children: [], events: {},
      setAttribute() {}, addEventListener(name, fn) { this.events[name] = fn; },
      appendChild(child) { this.children.push(child); },
      focus() { this.focused = true; }, select() { this.selected = true; }, setSelectionRange() {},
    });
    return elements.get(id);
  }
  const calls = [];
  let configured = false;
  const state = () => ({ configured, count: configured ? 2 : 0, updatedAt: 1000000,
    warnings: ['<img src=x onerror=alert(1)>'], notes: [], duplicates: 0,
    downloadURL: 'http://surge-vless.invalid/list/' + 'a'.repeat(64) + '.list', policyGroup: 'VLESS订阅 = select' });
  let failRefresh = false;
  vm.runInNewContext(script, {
    document: { getElementById: element, createElement: () => element('child-' + Math.random()), execCommand: () => false },
    window: { isSecureContext: false, confirm: () => true }, navigator: {}, AbortController, setTimeout, clearTimeout,
    fetch: async (url, options) => {
      calls.push({ url, options });
      if (url === '/api/import') configured = true;
      if (url === '/api/clear') configured = false;
      if (url === '/api/refresh' && failRefresh) return { ok: false, json: async () => ({ error: '更新失败，保留原节点' }) };
      return { ok: true, json: async () => state() };
    },
  });
  return { element, calls, setFailRefresh: () => { failRefresh = true; } };
}
const settle = () => new Promise(resolve => setImmediate(resolve));

test('phone page imports without browser persistence and safely renders upstream text', async () => {
  const b = browser(); await settle();
  assert.equal(b.calls[0].url, '/api/status');
  const source = b.element('source'); source.value = 'https://example.com/?token=secret';
  b.element('import-form').events.submit({ preventDefault() {} }); await settle();
  assert.equal(source.value, '');
  assert.equal(b.element('node-count').textContent, '2');
  assert.equal(b.element('warnings').children.at(-1).textContent, '<img src=x onerror=alert(1)>');
  const imported = b.calls.find(call => call.url === '/api/import');
  assert.equal(imported.options.headers['X-Vless-Local'], '1');
  assert.equal(imported.options.headers['Content-Type'], 'application/json');
  assert.equal(imported.options.redirect, 'error');
  assert.equal(imported.options.credentials, 'omit');
  b.setFailRefresh(); b.element('refresh-button').events.click(); await settle();
  assert.match(b.element('feedback').textContent, /更新失败/);
  assert.equal(b.element('node-count').textContent, '2');
  b.element('copy-url').events.click(); await settle();
  assert.equal(b.element('download-url').selected, true);
  assert.match(b.element('feedback').textContent, /已选中/);
  b.element('clear-button').events.click(); await settle();
  assert.equal(b.element('node-count').textContent, '0');
  assert.equal(b.element('download-url').value, '');
  assert.ok(!/localStorage|sessionStorage|indexedDB|innerHTML|document\.cookie|serviceWorker/.test(script));
  assert.ok(!/<(?:script[^>]+src|link[^>]+href)\s*=/i.test(html));
});
