import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { functionBody } from './helpers.mjs';

const root = new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/', import.meta.url);
const source = readFileSync(new URL('remote.uc', root), 'utf8');
const handoff = readFileSync(new URL('handoff.uc', root), 'utf8');
const builtins = {
  type: value => value == null ? 'null' : Array.isArray(value) ? 'array' : Number.isInteger(value) ? 'int' : typeof value,
  length: value => typeof value === 'string' || Array.isArray(value) ? value.length : Object.keys(value).length,
  index: (value, item) => value.indexOf(item), push: (value, item) => value.push(item),
  match: (value, expression) => value.match(expression),
  iptoarr: value => typeof value === 'string' && /^\d+\.\d+\.\d+\.\d+$/.test(value) &&
    value.split('.').every(part => +part >= 0 && +part <= 255) ? value.split('.').map(Number) : null,
  die: reason => { throw Error(reason); },
};
const model = { host_address: value => builtins.iptoarr(value) ? value : null };
const publicAddress = new Function(...Object.keys(builtins), 'model',
  `return function public_address(address) ${functionBody(handoff, 'public_address')}`)(...Object.values(builtins), model);
const code = source.slice(source.indexOf('export function wan_address'), source.indexOf('export function template'))
  .replace(/^export /gm, '').replace(/for\s*\(let\s+(\w+)\s+in\s+/g, 'for (let $1 of ');
const uplink = new Function(...Object.keys(builtins), 'handoff', `${code};return uplink;`)(...Object.values(builtins), { public_address: publicAddress });
const physical = (address = '8.8.8.8', metric = 0) => ({ interface: 'pppoe', proto: 'pppoe', up: true,
  l3_device: 'pppoe-pppoe', 'ipv4-address': [{ address }], route: [{ target: '0.0.0.0', mask: 0, metric }] });

test('a default PPPoE uplink is detected without a logical interface named wan', () => {
  const input = [physical()], before = structuredClone(input);
  assert.deepEqual(uplink(input), { publicIpv4Available: true, address: '8.8.8.8' });
  assert.deepEqual(input, before);
});
test('private, CGNAT, loopback, link-local, documentation and multicast addresses are never direct IPv4', () => {
  for (const address of ['10.0.0.2', '100.64.0.1', '172.16.1.2', '192.168.1.1', '127.0.0.1',
    '169.254.1.1', '0.0.0.0', '192.0.2.1', '198.51.100.1', '203.0.113.1', '198.18.0.1', '224.1.1.1', '255.255.255.255'])
    assert.deepEqual(uplink([physical(address)]), { publicIpv4Available: false, address: null }, address);
});
test('LAN addresses, VPN exits and policy-table defaults cannot establish direct access', () => {
  const lan = { ...physical(), interface: 'lan', proto: 'static', l3_device: 'br-lan', route: [] };
  const vpn = { ...physical('1.1.1.1'), interface: 'tunnel', proto: 'wireguard', l3_device: 'wg0' };
  const disguisedVpn = { ...physical('1.1.1.1'), proto: 'static', l3_device: 'tun0' };
  const policy = physical(); policy.route[0].table = 201;
  for (const input of [[lan], [vpn], [disguisedVpn], [policy], [{ ...physical(), up: false }]])
    assert.deepEqual(uplink(input), { publicIpv4Available: false, address: null });
  assert.equal(uplink([vpn, physical()]).address, '8.8.8.8');
});
test('active default metric wins over a public backup and equal-priority endpoints remain unknown', () => {
  assert.deepEqual(uplink([physical('10.0.0.2'), physical('8.8.8.8', 10)]), { publicIpv4Available: false, address: null });
  assert.equal(uplink([physical(), physical('1.1.1.1', 10)]).address, '8.8.8.8');
  assert.deepEqual(uplink([physical(), physical('1.1.1.1')]), { publicIpv4Available: null, address: null });
  assert.equal(uplink([physical(), physical()]).publicIpv4Available, true);
});
test('malformed interface data and metrics fail as unavailable rather than positive evidence', () => {
  for (const input of [null, {}, Array(65).fill(physical()), [{ ...physical(), route: {} }],
    [{ ...physical(), route: [{ target: '0.0.0.0', mask: 0, metric: -1 }] }]]) assert.throws(() => uplink(input));
});
