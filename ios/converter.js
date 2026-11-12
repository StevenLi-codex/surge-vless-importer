'use strict';
const YAML = require('yaml');

class ConversionError extends Error {
  constructor(message) { super(message); this.name = 'ConversionError'; }
}
const fail = message => { throw new ConversionError(message); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function scalar(value) {
  if (!['string', 'number'].includes(typeof value) || (typeof value === 'number' && !Number.isFinite(value))) fail('参数必须为文本或数字');
  const text = String(value);
  if (/[\x00-\x1f\x7f]/.test(text)) fail('参数包含控制字符');
  // encodeURIComponent rejects lone UTF-16 surrogates instead of replacing credentials.
  try { encodeURIComponent(text); } catch (_) { fail('参数不是有效 UTF-8 文本'); }
  return text;
}
function boolean(value) {
  if (typeof value === 'string') value = value.toLowerCase();
  if (value === true || value === 'true' || value === '1' || value === 1) return true;
  if (value === false || value === 'false' || value === '0' || value === 0) return false;
  fail('布尔参数必须是 true/false 或 1/0');
}
function quote(value) {
  const text = scalar(value);
  return !text || /[,"\\#;]/.test(text) || text !== text.trim() || text.includes(' //') ? JSON.stringify(text) : text;
}
function nameFor(value) {
  const from = ',="\\#;/[]', to = '，＝＂＼＃；／［］';
  return scalar(value).trim().replace(/[,="\\#;/\[\]]/g, c => to[from.indexOf(c)]) || 'VLESS';
}
function parseURI(text) {
  scalar(text);
  try { decodeURIComponent(text); } catch (_) { fail('VLESS 链接编码无效'); }
  const authority = text.match(/^vless:\/\/([^/?#]*)/i);
  if (!authority || authority[1].split('@')[0].includes(':')) fail('VLESS 用户信息无效');
  const url = new URL(text);
  if (url.pathname && url.pathname !== '/') fail('VLESS 链接含有不支持的路径');
  if (url.protocol.toLowerCase() !== 'vless:' || !url.hostname || !url.username || url.password || !url.port) fail('VLESS 链接的地址、端口或用户 ID 不完整');
  const allowed = new Set(['security', 'type', 'sni', 'flow', 'encryption', 'pbk', 'sid', 'fp', 'spx', 'alpn', 'allowInsecure', 'udp', 'path', 'host', 'serviceName', 'authority', 'mode', 'packetEncoding']);
  const keys = new Set();
  for (const [key] of url.searchParams) {
    if (!allowed.has(key) || keys.has(key)) fail('不支持或重复的 URI 参数，未降级转换');
    keys.add(key);
  }
  const q = Object.fromEntries(url.searchParams);
  const security = (q.security ?? 'none').toLowerCase();
  if (!['none', 'tls', 'reality'].includes(security)) fail('不支持此 security 参数');
  const node = {name: decodeURIComponent(url.hash.slice(1)) || 'VLESS', type: 'vless', server: url.hostname.replace(/^\[|\]$/g, ''),
    port: url.port, uuid: decodeURIComponent(url.username), network: q.type ?? 'tcp',
    tls: security !== 'none', servername: q.sni ?? '', flow: q.flow ?? '', encryption: q.encryption ?? 'none'};
  if (security === 'reality') node['reality-opts'] = {'public-key': q.pbk ?? '', 'short-id': q.sid ?? ''};
  if ('fp' in q || 'spx' in q) node['client-fingerprint'] = q.fp ?? '';
  if ('alpn' in q) node.alpn = q.alpn.split(',');
  if ('allowInsecure' in q) node['skip-cert-verify'] = q.allowInsecure;
  if ('udp' in q) node.udp = q.udp;
  const network = node.network.toLowerCase();
  if (network !== 'ws' && ['path', 'host'].some(key => key in q)) fail('URI 参数不适用于此传输方式');
  if (network !== 'grpc' && ['serviceName', 'authority', 'mode'].some(key => key in q)) fail('URI 参数不适用于此传输方式');
  if (security !== 'reality' && ['pbk', 'sid'].some(key => key in q)) fail('REALITY 参数与 security 不匹配');
  if ('packetEncoding' in q) node['packet-encoding'] = q.packetEncoding;
  if (network === 'ws') node['ws-opts'] = {path: q.path ?? '/', headers: q.host ? {Host: q.host} : {}};
  if (network === 'grpc') node['grpc-opts'] = {'grpc-service-name': q.serviceName ?? '', 'grpc-authority': q.authority ?? '', 'grpc-mode': q.mode ?? 'gun'};
  return node;
}
function validIPv4(text) {
  const parts = text.split('.');
  return parts.length === 4 && parts.every(p => /^(0|[1-9][0-9]{0,2})$/.test(p) && Number(p) <= 255);
}
function validIPv6(text) {
  if (!/^[0-9a-f:.]+$/i.test(text)) return false;
  if (text.includes('.')) {
    const index = text.lastIndexOf(':');
    if (!validIPv4(text.slice(index + 1))) return false;
    text = text.slice(0, index + 1) + '0:0';
  }
  const halves = text.split('::');
  if (halves.length > 2) return false;
  const groups = halves.flatMap(half => half ? half.split(':') : []);
  if (!groups.every(group => /^[0-9a-f]{1,4}$/i.test(group))) return false;
  return halves.length === 2 ? groups.length < 8 : groups.length === 8;
}
function serverFor(value) {
  const server = scalar(value).trim();
  if (server.includes(':')) {
    if (!validIPv6(server)) fail('IPv6 地址无效');
  } else {
    const labels = server.replace(/\.$/, '').split('.');
    if (!server || server.length > 253 || !labels.every(label => /^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/.test(label))) fail('服务器地址无效');
    if (/^[0-9.]+$/.test(server) && !validIPv4(server)) fail('IPv4 地址无效');
  }
  return server;
}
function normalize(node) {
  const server = serverFor(node.server ?? '');
  const port = scalar(node.port ?? '');
  if (!/^[0-9]+$/.test(port) || Number(port) < 1 || Number(port) > 65535) fail('端口必须介于 1 和 65535');
  const uid = scalar(node.uuid ?? '');
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(uid)) {
    const bytes = new TextEncoder().encode(uid).length;
    if (bytes < 1 || bytes > 30) fail('用户 ID 必须为 UUID 或 1–30 字节的字符串');
  }
  const params = [['username', uid]];
  const network = scalar(node.network ?? 'tcp').toLowerCase();
  if (!['tcp', 'raw', 'ws', 'grpc'].includes(network)) fail('不支持的传输方式');
  if (scalar(node.encryption ?? 'none').toLowerCase() !== 'none') fail('不支持 VLESS Encryption');
  for (const key of ['smux', 'multiplex']) {
    if (key in node && (!object(node[key]) || boolean(node[key].enabled ?? false))) fail('不支持此节点的多路复用选项');
  }
  if ('mux' in node && boolean(node.mux)) fail('不支持此节点的多路复用选项');
  if (!['', 'xudp'].includes(node['packet-encoding'] ?? 'xudp')) fail('仅支持 XUDP 封装');
  const notes = [];
  const tls = boolean(node.tls ?? false);
  const reality = node['reality-opts'];
  if (reality != null && !object(reality)) fail('reality-opts 必须为对象');
  const flow = scalar(node.flow ?? '');
  if (flow && !['xtls-rprx-vision', 'xtls-rprx-vision-udp443'].includes(flow)) fail('不支持此 flow');
  if (flow && (!['tcp', 'raw'].includes(network) || !(tls || reality != null))) fail('Vision 需要 TCP + TLS/REALITY');
  if (flow) params.push(['flow', flow]);
  if (network === 'grpc' && !(tls || reality != null)) fail('gRPC 需要 TLS 或 REALITY');
  if (network === 'ws' && reality != null) fail('Surge 不支持 WebSocket + REALITY');
  const sni = scalar(node.servername ?? node.sni ?? '');
  if (sni) params.push(['sni', sni]);
  if ('client-fingerprint' in node) notes.push('Surge 使用自己的 TLS 栈；未输出 client-fingerprint/fp/spx。');
  if (reality != null) {
    const key = scalar(reality['public-key'] ?? '');
    try {
      if (/\s/.test(key) || decodeBytes(key).length !== 32) fail('公钥无效');
    } catch (_) { fail('REALITY 公钥必须为 32 字节 Base64'); }
    if (!sni) fail('REALITY 缺少 servername/SNI');
    const sid = scalar(reality['short-id'] ?? '');
    if (!/^[0-9a-f]{0,16}$/i.test(sid)) fail('REALITY short-id 必须为最多 16 位十六进制文本');
    params.push(['reality-public-key', key], ['reality-short-id', sid]);
    if ('support-x25519mlkem768' in reality) notes.push('未输出 support-x25519mlkem768；Surge 没有对应配置项，不保证此握手选项兼容。');
  } else if (tls) params.push(['tls', 'true']);
  if ('skip-cert-verify' in node && reality == null) params.push(['skip-cert-verify', String(boolean(node['skip-cert-verify']))]);
  if ('alpn' in node) params.push(['alpn', Array.isArray(node.alpn) ? node.alpn.map(scalar).join(',') : scalar(node.alpn)]);
  if ('udp' in node) params.push(['udp-relay', String(boolean(node.udp))]);
  if (network === 'ws') {
    const opts = node['ws-opts'] ?? {};
    if (!object(opts) || !object(opts.headers ?? {})) fail('ws-opts/headers 必须为对象');
    if (![undefined, null, '0', 0].includes(opts['max-early-data']) || opts['early-data-header-name']) fail('不支持 WebSocket early-data，未降级转换');
    const path = scalar(opts.path ?? '/');
    if (/[?&]ed=/i.test(path)) fail('不支持 WebSocket early-data，未降级转换');
    params.push(['ws', 'true'], ['ws-path', path]);
    const headers = Object.entries(opts.headers ?? {});
    if (headers.length) params.push(['ws-headers', headers.map(([key, value]) => {
      if (!/^[A-Za-z0-9-]+$/.test(key)) fail('WebSocket Header 名称无效');
      const text = scalar(value);
      if (text.includes('|')) fail('WebSocket Header 值不能包含 |');
      return `${key}:${text}`;
    }).join('|')]);
  }
  if (network === 'grpc') {
    const opts = node['grpc-opts'] ?? {};
    if (!object(opts)) fail('grpc-opts 必须为对象');
    const mode = opts['grpc-mode'] ?? (boolean(opts['multi-mode'] ?? false) ? 'multi' : 'gun');
    if (!['gun', 'multi'].includes(mode)) fail('不支持此 gRPC mode');
    params.push(['grpc', 'true'], ['grpc-service-name', opts['grpc-service-name'] ?? ''], ['grpc-mode', mode]);
    if (opts['grpc-authority']) params.push(['grpc-authority', opts['grpc-authority']]);
  }
  const tail = ['vless', quote(server), String(Number(port)), ...params.map(([k, v]) => `${k}=${quote(v)}`)].join(', ');
  return {name: nameFor(node.name ?? 'VLESS'), tail, notes};
}
function decodeBytes(text) {
  const raw = text.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(raw) || raw.replace(/=+$/, '').length % 4 === 1) fail('Base64 格式无效');
  try {
    const binary = atob(raw.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, ''));
    return Uint8Array.from(binary, c => c.charCodeAt(0));
  } catch (_) { fail('Base64 格式无效'); }
}
function convert(text) {
  if (typeof text !== 'string') fail('订阅必须为 UTF-8 文本');
  if (text.length > 2 * 1024 * 1024 || new TextEncoder().encode(text).length > 2 * 1024 * 1024) fail('订阅超过 2 MiB，未处理');
  text = text.replace(/^\ufeff+/, '').trim();
  if (!text) fail('订阅内容为空');
  if (!text.includes(':') && !/^[{\[]/.test(text)) {
    try { text = new TextDecoder('utf-8', {fatal: true}).decode(decodeBytes(text)).trim(); }
    catch (_) { fail('无法识别订阅格式；支持 YAML/JSON、VLESS 和 Base64 订阅'); }
  }
  let nodes = [];
  const warnings = [], notes = new Set(), names = new Set(), seen = new Set(), lines = [];
  const uriLines = text.split(/\r?\n/);
  if (uriLines.some(line => /^vless:\/\//i.test(line.trim()))) {
    if (uriLines.filter(line => /^vless:\/\//i.test(line.trim())).length > 5000) fail('节点数量超过 5000，未处理');
    uriLines.forEach((line, index) => {
      if (!/^vless:\/\//i.test(line.trim())) return;
      try { nodes.push(parseURI(line.trim())); }
      catch (error) { warnings.push(`第 ${index + 1} 行：${error instanceof ConversionError ? error.message : 'VLESS 链接格式错误'}`); }
    });
  } else {
    let data;
    try {
      const doc = YAML.parseDocument(text, {schema: 'failsafe', maxAliasCount: 0, prettyErrors: false, uniqueKeys: true});
      if (doc.errors.length || doc.warnings.length) fail('YAML/JSON 语法或标签无效');
      YAML.visit(doc, (_key, value) => {
        if (YAML.isPair(value) && !YAML.isScalar(value.key)) fail('YAML 对象键必须为标量');
        if (YAML.isAlias(value) || (value && typeof value === 'object' && (value.tag || value.anchor))) fail('不支持 YAML 标签、锚点或别名');
      });
      data = doc.toJS({maxAliasCount: 0});
    } catch (_) { fail('YAML/JSON 语法错误，未输出节点'); }
    nodes = Array.isArray(data) ? data : object(data) ? data.proxies : undefined;
    if (!Array.isArray(nodes)) fail('未找到 proxies 节点列表');
    if (nodes.length > 5000) fail('节点数量超过 5000，未处理');
    nodes = nodes.filter(n => object(n) && typeof n.type === 'string' && n.type.toLowerCase() === 'vless');
  }
  let duplicates = 0;
  nodes.forEach((n, index) => {
    try {
      const result = normalize(n);
      if (seen.has(result.tail)) { duplicates++; return; }
      seen.add(result.tail);
      let name = result.name, counter = 2;
      while (names.has(name)) name = `${result.name} (${counter++})`;
      names.add(name);
      result.notes.forEach(note => notes.add(note));
      lines.push(`${name} = ${result.tail}`);
    } catch (error) {
      warnings.push(`第 ${index + 1} 个 VLESS 节点：${error instanceof ConversionError ? error.message : '节点参数格式错误'}`);
    }
  });
  if (!lines.length) fail('没有可转换的 VLESS 节点。' + warnings.slice(0, 3).join('；'));
  return {content: '# Surge VLESS policy list; generated locally. Contains credentials.\n' + lines.join('\n') + '\n',
    count: lines.length, warnings, notes: [...notes].sort(), duplicates};
}

module.exports = {convert, ConversionError};
