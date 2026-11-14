import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../package/foxhole-openwrt-client/root/', import.meta.url);
const read = name => readFileSync(new URL(name, root), 'utf8');
const builtin = {
  type: x => x == null ? 'null' : Array.isArray(x) ? 'array' : Number.isInteger(x) ? 'int' : typeof x,
  length: x => x?.length ?? 0, index: (a, x) => a.indexOf(x),
  match: (x, re) => x.match(re), push: (a, x) => a.push(x),
  join: (s, a) => a.join(s), filter: (a, f) => a.filter(f),
  json: JSON.parse, sprintf: (_f, x) => JSON.stringify(x),
  die: x => { throw Error(x); },
  iptoarr: x => typeof x === 'string' && /^\d+\.\d+\.\d+\.\d+$/.test(x) &&
    x.split('.').every(p => +p >= 0 && +p <= 255) ? x.split('.').map(Number) : null,
  arrtoip: x => x.join('.')
};
const adapt = x => x.replace(/^import .*;\n/gm, '').replace(/^export /gm, '')
  .replace(/for \(let (\w+) in /g, 'for (let $1 of ');
const networkSource = read('usr/share/foxhole/mobile-network.uc');
const network = new Function(...Object.keys(builtin), `${adapt(networkSource)}; return {management_addresses};`)(...Object.values(builtin));
const source = read('usr/share/foxhole/inbound.uc');
const inbound = new Function(...Object.keys(builtin), 'model', 'observation', 'network',
  `${adapt(source)}; return {config,shared_config};`)(...Object.values(builtin),
  { normalize_address: x => x }, {}, network);
const bindings = [{ device: 'br-lan', address: '192.168.8.1' }];
const base = { listenerMode: 'per-client', allowedLan: [], template: {} };
const client = { id: 'client-000000000001', secret: 'a'.repeat(64), inbound: true,
  port: 14443, allowLan: false };
const state = { activeServerId: null, servers: [], settings: { clientRules: true } };
const rules = (allowLan, endpoints = bindings) => inbound.config(base, state,
  { ...client, allowLan }, false, [], null, endpoints).acl.inline;

test('explicit client permission grants only TCP8443 at the owned management address', () => {
  const value = rules(true);
  assert.equal(value[0], 'direct(192.168.8.1, tcp/8443)');
  assert.ok(value.includes('reject(192.168.0.0/16)'));
  assert.ok(!value.includes('direct(192.168.8.1)'));
  assert.equal(value.at(-1), 'direct(all)');
});

test('disabled permission or absent listeners never add a private management exception', () => {
  for (const value of [rules(false), rules(true, []), rules(true, null)]) {
    assert.ok(!value.some(x => x.startsWith('direct(192.168.')));
    assert.ok(value.includes('reject(192.168.0.0/16)'));
  }
});

test('a public address or private CIDR cannot become a management exception', () => {
  for (const address of ['1.1.1.1', '192.168.8.0/24', '127.0.0.1'])
    assert.throws(() => rules(true, [{ device: 'br-lan', address }]), /lan_unavailable/);
});

test('shared mode uses the explicit shared permission instead of an individual grant', () => {
  for (const allowLan of [false, true]) {
    const value = inbound.shared_config({ ...base, sharedAllowLan: allowLan }, state,
      [{ ...client, allowLan: true }], false, [], null, bindings);
    assert.equal(value.acl.inline.includes('direct(192.168.8.1, tcp/8443)'), allowLan);
  }
});
