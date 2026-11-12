'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const UUID = '00000000-0000-4000-8000-000000000001';
const KEY = Buffer.alloc(32).toString('base64url');
const URI = `vless://${UUID}@192.0.2.1:443#Example`;
const node = (overrides = {}) => ({name: 'Example', type: 'vless', server: '192.0.2.1', port: 443, uuid: UUID, tls: true, ...overrides});
const api = () => require('../converter.js');
const converted = (...nodes) => api().convert(JSON.stringify({proxies: nodes}));

test('JSON objects and arrays support TLS raw nodes and safe scalars', () => {
  const n = node({name: 'A, B = C # D; E', network: 'raw', alpn: ['h2', 'http/1.1'], udp: false, 'skip-cert-verify': true});
  for (const source of [JSON.stringify({proxies: [n]}), JSON.stringify([n])]) {
    const result = api().convert(source);
    assert.equal(result.count, 1);
    assert.match(result.content, /A， B ＝ C ＃ D； E = vless/);
    assert.match(result.content, /tls=true, skip-cert-verify=true, alpn="h2,http\/1.1", udp-relay=false/);
  }
  assert.doesNotMatch(converted(node({tls: false})).content, /tls=/);
});

test('URI REALITY Vision retains zero SID and reports ignored fingerprints', () => {
  const uri = URI.replace('#Example', `?security=reality&type=tcp&sni=www.example.com&pbk=${KEY}&sid=001122&flow=xtls-rprx-vision&fp=chrome&spx=%2F#Example`);
  const result = api().convert(uri);
  assert.match(result.content, new RegExp(`flow=xtls-rprx-vision, sni=www.example.com, reality-public-key=${KEY}, reality-short-id=001122`));
  assert.doesNotMatch(result.content, /tls=true|fingerprint|spx=/);
  assert.equal(result.notes.length, 1);
  assert.match(converted(node({flow: 'xtls-rprx-vision-udp443'})).content, /flow=xtls-rprx-vision-udp443, tls=true/);
});

test('WS and gRPC URI and JSON options map to Surge with Python quoting', () => {
  const ws = converted(node({network: 'ws', alpn: ['h2', 'http/1.1'], 'ws-opts': {path: '/a,b', headers: {Host: 'cdn.example.com', 'X-Token': 'a,b'}}}));
  assert.match(ws.content, /ws=true, ws-path="\/a,b", ws-headers="Host:cdn.example.com\|X-Token:a,b"/);
  const wsUri = api().convert(URI.replace('#Example', '?type=ws&security=tls&path=%2Fa%23b&host=cdn.example.com&alpn=h2%2Chttp%2F1.1&allowInsecure=1&udp=0#WS'));
  assert.match(wsUri.content, /ws-path="\/a#b", ws-headers=Host:cdn.example.com/);
  assert.match(wsUri.content, /skip-cert-verify=true/);
  const grpc = api().convert(URI.replace('#Example', '?type=grpc&security=tls&serviceName=hello&mode=multi&authority=cdn.example.com#GRPC'));
  assert.match(grpc.content, /grpc=true, grpc-service-name=hello, grpc-mode=multi, grpc-authority=cdn.example.com/);
  assert.match(converted(node({network: 'grpc', 'grpc-opts': {'multi-mode': true}})).content, /grpc-mode=multi/);
});

test('mixed node lists deduplicate connections and rename colliding labels', () => {
  const result = converted(node(), node({port: 444}), node({name: 'Another label'}), {type: 'ss'}, null, node({uuid: {secret: 'do-not-echo'}}));
  assert.equal(result.count, 2);
  assert.equal(result.duplicates, 1);
  assert.equal(result.warnings.length, 1);
  assert.match(result.content, /Example \(2\) =/);
  assert.doesNotMatch(result.warnings.join(''), /do-not-echo/);
  const uris = api().convert(`trojan://other@example.com:443\n${URI}\nvless://broken\n${URI.replace(':443', ':444')}\n`);
  assert.equal(uris.count, 2);
  assert.equal(uris.warnings.length, 1);
  assert.match(uris.warnings[0], /3/);
});

test('Base64 and URL-safe subscriptions decode UTF8 and preserve mixed protocols', () => {
  const source = `trojan://other@example.com:443\n${URI.replace('Example', encodeURIComponent('测试😀'))}`;
  for (const encoding of ['base64', 'base64url']) {
    const encoded = Buffer.from('\ufeff' + source).toString(encoding).replace(/=+$/, '');
    const result = api().convert(encoded.match(/.{1,37}/g).join('\n'));
    assert.match(result.content, /测试😀 =/);
    assert.equal(result.count, 1);
  }
});

test('YAML failsafe schema preserves numeric credentials and hexadecimal SID strings', () => {
  const source = `proxies:\n- name: YAML\n  type: vless\n  server: example.com\n  port: 443\n  uuid: 000123\n  tls: true\n  udp: false\n  servername: www.example.com\n  reality-opts:\n    public-key: ${KEY}\n    short-id: 001234\n`;
  const result = api().convert(source);
  assert.match(result.content, /username=000123/);
  assert.match(result.content, /reality-short-id=001234, udp-relay=false/);
  assert.equal(api().convert(Buffer.from(source).toString('base64')).content, result.content);
});

test('malicious or malformed YAML is rejected without exposing secrets', () => {
  const secret = 'PRIVATE-SUBSCRIPTION-TOKEN';
  for (const source of [
    `proxies: [${secret}`, `proxies: !!python/object/apply:os.system ['${secret}']`,
    `proxies: &a [*a] # ${secret}`, `proxies: [!custom ${secret}]`,
    `proxies: [!!str ${secret}]`, `a: &x ${secret}\nproxies: [*x]`,
    `proxies: []\nproxies: [${secret}]`, `---\nproxies: []\n---\n${secret}`
  ]) {
    assert.throws(() => api().convert(source), error => {
      assert.equal(error instanceof api().ConversionError, true);
      assert.doesNotMatch(error.message, new RegExp(secret));
      return true;
    });
  }
});

test('server port and UTF8 ID validation rejects malformed nodes without credential echo', () => {
  const secret = 'PRIVATE-CREDENTIAL-SECRET';
  for (const update of [
    {server: 'x\n[Rule]'}, {server: 'example.com/evil'}, {server: '-bad.example'},
    {server: 'x..example'}, {server: '1.2.3.999'}, {server: '2001:::1'}, {server: '::ffff:999.1.1.1'},
    {port: 0}, {port: 65536}, {port: '443x'}, {port: true}, {port: 1.5},
    {uuid: ''}, {uuid: '界'.repeat(11)}, {uuid: secret + '\n'}, {uuid: {secret}},
    {name: secret + '\n'}, {alpn: ['h2', '\r']}, {'skip-cert-verify': 'yes'},
    {servername: {secret}}, {uuid: '\ud800'}
  ]) {
    assert.throws(() => converted(node(update)), error => {
      assert.equal(error instanceof api().ConversionError, true);
      assert.doesNotMatch(error.message, new RegExp(secret));
      return true;
    }, JSON.stringify(update));
  }
  for (const uid of [UUID, '界'.repeat(10), 'a', '0'.repeat(30)]) assert.equal(converted(node({uuid: uid})).count, 1);
  assert.match(api().convert(URI.replace('192.0.2.1', '[2001:db8::1]')).content, /vless, 2001:db8::1, 443/);
  assert.equal(converted(node({server: '::ffff:192.0.2.1'})).count, 1);
});

test('unsupported security transports multiplexing and Vision combinations never downgrade', () => {
  const bad = [
    {network: 'xhttp'}, {network: {secret: 'PRIVATE'}}, {encryption: 'mlkem768x25519plus.test'},
    {flow: 'xtls-rprx-direct'}, {flow: 'xtls-rprx-vision', tls: false},
    {network: 'ws', flow: 'xtls-rprx-vision'}, {network: 'grpc', tls: false},
    {network: 'ws', servername: 'example.com', 'reality-opts': {'public-key': KEY}},
    {smux: {enabled: true}}, {multiplex: {enabled: '1'}}, {smux: false},
    {'packet-encoding': 'packetaddr'}, {mux: true}
  ].map(update => node(update));
  const result = converted(node(), ...bad);
  assert.equal(result.count, 1);
  assert.equal(result.warnings.length, bad.length);
  assert.equal(converted(node({network: 'raw', smux: {enabled: false}, multiplex: {enabled: 'false'}, 'packet-encoding': 'xudp'})).count, 1);
});

test('REALITY validates 32-byte key SNI and hex SID without losing leading zeroes', () => {
  for (const update of [
    {'reality-opts': []}, {'reality-opts': 'secret'},
    {'reality-opts': {'public-key': KEY}},
    {servername: 'example.com', 'reality-opts': {'public-key': 'bad'}},
    {servername: 'example.com', 'reality-opts': {'public-key': Buffer.alloc(31).toString('base64url')}},
    {servername: 'example.com', 'reality-opts': {'public-key': KEY, 'short-id': 'xyz'}},
    {servername: 'example.com', 'reality-opts': {'public-key': KEY, 'short-id': '0'.repeat(17)}}
  ]) assert.throws(() => converted(node(update)), api().ConversionError);
  for (const sid of ['', '0', '001234', 'aF'.repeat(8)]) {
    const result = converted(node({network: 'grpc', tls: false, servername: 'example.com', 'client-fingerprint': 'chrome', 'reality-opts': {'public-key': KEY, 'short-id': sid, 'support-x25519mlkem768': true}}));
    assert.match(result.content, /grpc=true/);
    assert.ok(result.content.includes(`reality-short-id=${sid || '""'}`));
    assert.equal(result.notes.length, 2);
  }
});

test('WS early data invalid headers option objects and unsupported gRPC modes are rejected', () => {
  const bad = [
    {network: 'ws', 'ws-opts': []}, {network: 'ws', 'ws-opts': {headers: []}},
    {network: 'ws', 'ws-opts': {path: '\n[Rule]'}},
    {network: 'ws', 'ws-opts': {'max-early-data': 2048}},
    {network: 'ws', 'ws-opts': {'early-data-header-name': 'Sec-WebSocket-Protocol'}},
    {network: 'ws', 'ws-opts': {path: '/?ed=2048'}},
    {network: 'ws', 'ws-opts': {headers: {'X Token': 'value'}}},
    {network: 'ws', 'ws-opts': {headers: {'X-Token': 'value|Injected:yes'}}},
    {network: 'grpc', 'grpc-opts': []}, {network: 'grpc', 'grpc-opts': {'grpc-mode': 'strange'}},
    {network: 'grpc', 'grpc-opts': {'grpc-authority': {bad: 'secret'}}}
  ];
  const result = converted(node(), ...bad.map(update => node(update)));
  assert.equal(result.count, 1);
  assert.equal(result.warnings.length, bad.length);
  assert.equal(converted(node({network: 'ws', 'ws-opts': {'max-early-data': 0}})).count, 1);
});

test('unsupported URI transport and security query fields cannot be silently dropped', () => {
  const options = [
    'security=xtls', 'encryption=mlkem', 'type=xhttp', 'mux=1', 'packetEncoding=packetaddr',
    'type=ws&ed=2048', 'type=ws&max-early-data=2048', 'type=tcp&headerType=http',
    'type=grpc&security=tls&mode=bad', 'security=tls&ech=SECRET', 'security=tls&insecure=1',
    'type=tcp&path=%2Fhidden', 'type=tcp&host=hidden', 'pbk=hidden', 'sid=123',
    'type=ws&serviceName=hidden', 'type=grpc&security=tls&path=%2Fhidden',
    'security=tls&security=none', 'type=ws&path=%2F%3Fed%3D2048', 'unknownTransportOption=SECRET'
  ];
  for (const query of options) assert.throws(() => api().convert(URI.replace('#Example', `?${query}#Example`)), error => {
    assert.equal(error instanceof api().ConversionError, true);
    assert.doesNotMatch(error.message, /SECRET|hidden/);
    return true;
  }, query);
  assert.equal(api().convert(URI.replace('#Example', '?packetEncoding=xudp#Example')).count, 1);
  assert.throws(() => api().convert(`vless://${UUID}:password@example.com:443`), api().ConversionError);
});

test('input and node caps apply before parsing including invalid and non-VLESS entries', () => {
  const limit = 2 * 1024 * 1024;
  const exact = URI + '\n#' + 'x'.repeat(limit - Buffer.byteLength(URI) - 2);
  assert.equal(api().convert(exact).count, 1);
  for (const source of [exact + 'x', '界'.repeat(700000), URI.repeat(40000)]) {
    assert.throws(() => api().convert(source), error => error instanceof api().ConversionError && /2 MiB/.test(error.message));
  }
  assert.equal(api().convert(Array(5000).fill(URI).join('\n')).duplicates, 4999);
  for (const source of [Array(5001).fill(URI).join('\n'), URI + '\n' + Array(5000).fill('vless://bad').join('\n'), JSON.stringify([node(), ...Array(5000).fill({type: 'ss'})])]) {
    assert.throws(() => api().convert(source), error => error instanceof api().ConversionError && /5000/.test(error.message));
  }
  for (const source of ['', ' ', null, 5, {}, '<html>Denied</html>', '%%%%', 'proxies: null', 'proxies: []', '!!!', Buffer.from([0xff]).toString('base64')]) {
    assert.throws(() => api().convert(source), api().ConversionError);
  }
});

test('URI parsing refuses hidden control characters discarded paths malformed escapes and empty password', () => {
  for (const source of [
    URI.replace(UUID, 'my\tuser'), URI.replace(':443#', ':443/ignored#'),
    URI.replace(UUID, 'my%ZZuser'), URI.replace('#Example', '?type=ws&path=%FF#Example'),
    `vless://${UUID}:@example.com:443`, URI.replace('#Example', '?udp=%00#Example')
  ]) assert.throws(() => api().convert(source), api().ConversionError);
  assert.equal(api().convert(' \ufeff' + URI.toUpperCase().replace('EXAMPLE', '%E6%B5%8B%E8%AF%95') + ' ').count, 1);
});

test('case-insensitive YAML booleans and networks retain Python compatibility', () => {
  const result = converted(node({tls: 'TRUE', udp: 'False', network: 'WS', 'skip-cert-verify': 'FALSE'}));
  assert.match(result.content, /tls=true, skip-cert-verify=false, udp-relay=false, ws=true/);
});

test('untrusted protocol descriptors are ignored without invoking coercion hooks', () => {
  const result = converted(node(), {type: {toString: 'SECRET'}}, {type: ['vless']});
  assert.equal(result.count, 1);
  assert.equal(result.warnings.length, 0);
});

test('YAML complex mapping keys are rejected rather than coerced with diagnostics', () => {
  const source = `proxies:\n- type: vless\n  server: example.com\n  port: 443\n  uuid: safe\n  ws-opts:\n    headers:\n      ? [PRIVATE, SECRET]\n      : value\n`;
  assert.throws(() => api().convert(source), error => error instanceof api().ConversionError && !/PRIVATE|SECRET/.test(error.message));
});

test('plain TCP URI produces only a local Surge policy list', () => {
  assert.deepEqual(api().convert(URI), {
    content: `# Surge VLESS policy list; generated locally. Contains credentials.\nExample = vless, 192.0.2.1, 443, username=${UUID}\n`,
    count: 1, warnings: [], notes: [], duplicates: 0
  });
});
