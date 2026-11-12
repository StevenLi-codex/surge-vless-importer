'use strict';
const { createApp } = require('./runtime');
const { createFetcher } = require('./transport');
const { convert } = require('./converter');
const page = require('./ui.html');
const KEY = 'surge-vless-importer.v2';
const app = createApp({
  read: () => $persistentStore.read(KEY),
  write: value => $persistentStore.write(value, KEY),
  convert,
  fetch: createFetcher($httpClient),
  random: () => Array.from(crypto.getRandomValues(new Uint8Array(32)), n => n.toString(16).padStart(2, '0')).join(''),
  now: () => Date.now(),
  notify: message => $notification.post('VLESS 订阅导入', '', message),
  page,
});
app($request).then(response => $done({ response })).catch(() => $done({ response: {
  status: 500,
  headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
  body: '本机转换未完成，请检查模块与脚本版本；未向外部转发此请求。',
} }));
