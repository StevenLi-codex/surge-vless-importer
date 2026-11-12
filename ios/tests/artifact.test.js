'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto').webcrypto;
const path = require('node:path');

test('installable bundled script uses Surge globals for local import and policy list delivery', async () => {
  const bundle = fs.readFileSync(path.join(__dirname, '../../module/surge-vless.js'), 'utf8');
  const storage = new Map();
  const run = (url, method = 'GET', body, headers = {}) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('script did not finish')), 4000);
    const context = { URL, TextEncoder, TextDecoder, atob, btoa, Uint8Array, crypto, setTimeout, clearTimeout,
      $request: { url, method, body: body && JSON.stringify(body), headers },
      $persistentStore: { read: key => storage.get(key) || null, write: (value, key) => { storage.set(key, value); return true; } },
      $httpClient: { get: () => reject(new Error('local input must not request network')) },
      $notification: { post() {} },
      $done: result => { clearTimeout(timer); resolve(result.response); },
    };
    vm.runInNewContext(bundle, context, { timeout: 3000 });
  });
  const page = await run('http://surge-vless.invalid/');
  assert.equal(page.status, 200);
  assert.match(page.body, /textarea/);
  const imported = await run('http://surge-vless.invalid/api/import', 'POST',
    { source: 'vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls#Demo' },
    { 'X-Vless-Local': '1', 'Content-Type': 'application/json', Origin: 'http://surge-vless.invalid' });
  assert.equal(imported.status, 200, imported.body);
  const data = JSON.parse(imported.body);
  assert.equal(data.count, 1);
  const list = await run(data.downloadURL);
  assert.equal(list.status, 200);
  assert.match(list.body, /Demo = vless, example.com, 443/);
  const moduleText = fs.readFileSync(path.join(__dirname, '../../module/surge-vless.sgmodule'), 'utf8');
  assert.match(moduleText, /surge-vless\.invalid = 127\.0\.0\.1/);
  assert.match(moduleText, /DOMAIN,surge-vless\.invalid,REJECT/);
  assert.ok(!moduleText.includes('[MITM]'));
  assert.ok(!moduleText.includes('[Proxy Group]'));
  assert.ok(!moduleText.includes('[Proxy]'));
  assert.match(moduleText, /engine=webview/);
});
