'use strict';
function response(status, body, contentType = 'application/json') {
  return { status, headers: {
    'Content-Type': contentType + '; charset=utf-8',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
  }, body: typeof body === 'string' ? body : JSON.stringify(body) };
}
const LOCAL_ORIGIN = 'http://surge-vless.invalid';
function validateRemote(source) {
  if (typeof source !== 'string' || source.length > 8192 || /[\u0000-\u0020\u007f]/.test(source)) throw new Error('URL');
  const url = new URL(source);
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || host.includes(':') || !host.includes('.') || /(?:^|\.)(?:localhost|local|invalid|test|internal)$/.test(host)) throw new Error('URL');
  if (/^[\d.]+$/.test(host)) {
    const parts = host.split('.').map(Number);
    const [a, b] = parts;
    if (parts.length !== 4 || parts.some(n => n > 255) || a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19))) throw new Error('URL');
  }
  return url.href;
}
function createApp(deps) {
  function load() { try { return JSON.parse(deps.read() || 'null'); } catch (_) { return null; } }
  function metadata(state) {
    if (!state) return { configured: false };
    const downloadURL = LOCAL_ORIGIN + '/list/' + state.token + '.list';
    return { configured: true, count: state.count, warnings: state.warnings, notes: state.notes, duplicates: state.duplicates, updatedAt: state.updatedAt, downloadURL,
      policyGroup: 'VLESS订阅 = select, policy-path=' + downloadURL + ', update-interval=3600' };
  }
  async function update(source, previous) {
    if (typeof source !== 'string' || !source.trim() || new TextEncoder().encode(source).length > 2 * 1024 * 1024) throw new Error('source');
    source = source.trim();
    const remote = /^https?:/i.test(source);
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(source) && !remote && !source.startsWith('vless://')) throw new Error('scheme');
    if (remote) source = validateRemote(source);
    const result = deps.convert(remote ? await deps.fetch(source) : source);
    const saved = { source, remote, token: previous ? previous.token : deps.random(), ...result, updatedAt: deps.now() };
    if (!/^[a-f0-9]{64}$/.test(saved.token)) throw new Error('random');
    const current = load();
    if (JSON.stringify(current) !== JSON.stringify(previous)) throw new Error('concurrent change');
    const serialized = JSON.stringify(saved);
    if (new TextEncoder().encode(serialized).length > 3.5 * 1024 * 1024) throw new Error('storage limit');
    if (!deps.write(serialized)) throw new Error('storage');
    return saved;
  }
  return async function handle(request) {
    let url;
    try { url = new URL(request.url); } catch (_) { return response(404, { error: '地址无效' }); }
    if (url.origin !== LOCAL_ORIGIN || url.username || url.password || url.search || url.hash) return response(404, { error: '地址无效' });
    if ((request.method || 'GET') === 'GET' && url.pathname === '/') {
      return response(200, deps.page || '<!doctype html><html lang="zh-CN"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VLESS 订阅导入</title><h1>VLESS 订阅导入</h1></html>', 'text/html');
    }
    const headers = Object.fromEntries(Object.entries(request.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
    if (url.pathname.startsWith('/api/') && (headers['x-vless-local'] !== '1' || (headers.origin && headers.origin !== LOCAL_ORIGIN) || headers['sec-fetch-site'] === 'cross-site' || request.method === 'OPTIONS')) return response(403, { error: '仅允许本机管理页访问' });
    if (url.pathname.startsWith('/api/') && request.method === 'POST' && !/^application\/json(?:\s*;|$)/i.test(headers['content-type'] || '')) return response(415, { error: '需要 JSON 请求' });
    const state = load();
    if (url.pathname === '/api/status' && request.method === 'GET') return response(200, metadata(state));
    if (url.pathname.startsWith('/list/')) {
      if (request.method !== 'GET') return response(405, { error: '只允许 GET' });
      if (!state || url.pathname !== '/list/' + state.token + '.list') return response(404, { error: '地址无效' });
      if (state.remote && deps.now() - state.updatedAt >= 3600000) {
        try { return response(200, (await update(state.source, state)).content, 'text/plain'); }
        catch (_) {
          const current = load();
          if (!current || current.token !== state.token) return response(404, { error: '订阅已清除或链接已失效' });
          if (JSON.stringify(current) !== JSON.stringify(state)) return response(200, current.content, 'text/plain');
          const stale = response(200, current.content, 'text/plain');
          stale.headers['X-Vless-Cache'] = 'stale';
          stale.headers.Warning = '110 - "Serving last valid local subscription"';
          if (deps.notify) deps.notify('订阅更新失败，继续使用上次有效节点。请打开本机管理页检查。');
          return stale;
        }
      }
      return response(200, state.content, 'text/plain');
    }
    if (request.method === 'POST' && url.pathname === '/api/clear') {
      if (!deps.write('null')) return response(500, { error: '清除失败' });
      return response(200, { configured: false });
    }
    if (request.method === 'POST' && url.pathname === '/api/refresh') {
      if (!state) return response(409, { error: '请先导入订阅' });
      try { return response(200, metadata(await update(state.source, state))); }
      catch (_) { return response(400, { error: '更新失败，保留上次有效节点。请检查网络或原始订阅。' }); }
    }
    if (request.method === 'POST' && url.pathname === '/api/import') {
      try {
        const input = JSON.parse(request.body);
        return response(200, metadata(await update(input.source, state)));
      } catch (_) {
        return response(400, { error: '导入失败：请检查 HTTPS 原始订阅、网络及节点兼容性；原数据未替换' });
      }
    }
    return response(404, { error: '地址无效' });
  };
}
module.exports = { createApp, validateRemote };
