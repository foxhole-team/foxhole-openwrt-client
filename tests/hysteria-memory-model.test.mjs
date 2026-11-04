import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { functionBody } from './helpers.mjs';

const root = '../package/foxhole-openwrt-client/root/usr/share/foxhole/';
const modelSource = readFileSync(new URL(root + 'model.uc', import.meta.url), 'utf8');
const runtimeSource = readFileSync(new URL(root + 'runtime-model.uc', import.meta.url), 'utf8');
const bindings = {
  type: value => value == null ? 'null' : Array.isArray(value) ? 'array' :
    Number.isInteger(value) ? 'int' : typeof value === 'boolean' ? 'bool' : typeof value,
  length: value => typeof value === 'string' ? Buffer.byteLength(value) : value.length,
  split: (value, separator, maximum) => value.split(separator, maximum),
  match: (value, pattern) => value.match(pattern), index: (value, item) => value.indexOf(item),
  substr: (value, start, count) => value.substr(start, count), trim: value => value.trim(),
  replace: (value, pattern, replacement) => value.replace(pattern, replacement),
  lc: value => value.toLowerCase(), int: (value, base = 10) => Number.parseInt(value, base),
  chr: value => String.fromCharCode(value), ord: value => value.charCodeAt(0),
  exists: (value, key) => Object.hasOwn(value, key), keys: Object.keys,
  push: (values, value) => values.push(value), pop: values => values.pop(),
  json: JSON.parse, sprintf: (format, value) => {
    assert.equal(format, '%J'); return JSON.stringify(value);
  },
  die: code => { throw Error(code); },
  iptoarr: () => { throw Error('IPv6 is outside this focused fixture'); },
  arrtoip: () => { throw Error('IPv6 is outside this focused fixture'); },
};
const parserFunctions = ['fail', 'object', 'text', 'only', 'decode', 'dns', 'endpoint',
  'from_uri', 'scalar', 'from_yaml', 'parse_config'].map(name => {
  let body = functionBody(modelSource, name);
  if (name === 'parse_config') {
    // The generic brace helper treats the URI-regex terminator as a line comment.
    const start = modelSource.indexOf('{', modelSource.indexOf('export function parse_config('));
    const end = modelSource.indexOf('\nexport function config_uri(', start);
    assert.ok(start >= 0 && end > start);
    body = modelSource.slice(start, end).trim().replace(/;$/, '');
  }
  body = body.replaceAll('[[:cntrl:]]', '[\\x00-\\x1f\\x7f]');
  if (name !== 'only') body = body
    .replace(/for \(let (\w+), (\w+) in ([^)]+)\)/g, 'for (let [$1, $2] of Object.entries($3))')
    .replace(/for \(let (\w+) in /g, 'for (let $1 of ');
  const args = { fail: 'code', object: 'value', text: 'value, limit, code', only: 'value, fields, code',
    decode: 'value', dns: 'value', endpoint: 'value', from_uri: 'raw', scalar: 'value',
    from_yaml: 'raw', parse_config: 'raw' }[name];
  return `function ${name}(${args}) ${body};`;
}).join('\n');
const model = new Function(...Object.keys(bindings), parserFunctions + ';return {parse_config};')(...Object.values(bindings));
const runtimeCode = runtimeSource.replace(/^import .*;\n/gm, '').replace(/^export /gm, '')
  .replace(/for \(let (\w+) in /g, 'for (let $1 of ');
const runtime = new Function(...Object.keys(bindings), 'model', runtimeCode +
  ';return {hysteria_config,client_quic_defaults};')(...Object.values(bindings), model);
const expected = { initStreamReceiveWindow: 1048576, maxStreamReceiveWindow: 2097152,
  initConnReceiveWindow: 2097152, maxConnReceiveWindow: 8388608 };
const profile = () => ({ server: 'vpn.example.com:443', auth: 'synthetic-password',
  tls: { sni: 'vpn.example.com', insecure: false, pinSHA256: 'a'.repeat(64) },
  bandwidth: { up: '100 Mbps', down: '200 Mbps' }, congestion: { type: 'bbr', bbrProfile: 'standard' },
  obfs: { type: 'salamander', salamander: { password: 'synthetic-obfs' } }, fastOpen: true,
  socks5: { listen: '127.0.0.1:1080', disableUDP: false, username: 'synthetic-user', password: 'synthetic-pass' } });
const state = config => ({ activeServerId: 'server-000000000001', servers: [
  { id: 'server-000000000001', name: 'Example', config: typeof config === 'string' ? config : JSON.stringify(config) }
] });

test('real JSON profile parser and client generator emit the bounded receive-credit wire keys', () => {
  const result = runtime.hysteria_config(state(profile()), null, { preserveSocks: true });
  assert.deepEqual(result.config.quic, expected);
});

test('real URI profile parser also receives only the internal client defaults', () => {
  const result = runtime.hysteria_config(state('hy2://synthetic@vpn.example.com:443/?sni=vpn.example.com#Example'));
  assert.deepEqual(result.config.quic, expected);
  assert.equal(result.config.auth, 'synthetic');
  assert.equal(result.config.tls.sni, 'vpn.example.com');
});

test('client generation preserves security and transport choices without rewriting the saved profile', () => {
  const input = profile(); const current = state(input); const saved = JSON.stringify(current);
  const result = runtime.hysteria_config(current, null, { preserveSocks: true });
  for (const key of ['server', 'auth', 'tls', 'bandwidth', 'congestion', 'obfs', 'fastOpen', 'socks5']) {
    assert.equal(JSON.stringify(result.config[key]), JSON.stringify(input[key]), key);
  }
  assert.equal(JSON.stringify(current), saved);
});

test('public top-level QUIC profile admission remains rejected for zero and positive windows', () => {
  for (const quic of [{}, { initStreamReceiveWindow: 0 }, { maxConnReceiveWindow: 4194304 }]) {
    assert.throws(() => runtime.hysteria_config(state({ ...profile(), quic })), /unsupported_config/);
  }
});

test('internal runtime object only defaults absent or integer-zero receive fields and preserves other settings', () => {
  for (const quic of [{ internalSetting: 'preserved' }, { ...Object.fromEntries(Object.keys(expected).map(key => [key, 0])), internalSetting: 'preserved' }]) {
    const value = { quic: structuredClone(quic), auth: 'unchanged' };
    runtime.client_quic_defaults(value);
    assert.deepEqual(value.quic, { internalSetting: 'preserved', ...expected });
    assert.equal(value.auth, 'unchanged');
  }
});

test('internal runtime object with any explicit positive window remains wholly unchanged', () => {
  for (const key of Object.keys(expected)) {
    const value = { quic: { [key]: 65536, internalSetting: 'preserved',
      ...Object.fromEntries(Object.keys(expected).filter(other => other !== key).map(other => [other, 0])) }, auth: 'unchanged' };
    const before = structuredClone(value);
    runtime.client_quic_defaults(value);
    assert.deepEqual(value, before);
  }
});
