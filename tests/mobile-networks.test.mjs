import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/mobile-network.uc', import.meta.url), 'utf8');
const context = vm.createContext({
  die: reason => { throw new Error(reason); },
  type: value => Array.isArray(value) ? 'array' : value === null ? 'null' :
    Number.isInteger(value) ? 'int' : typeof value === 'boolean' ? 'bool' : typeof value,
  length: value => value.length, match: (value, pattern) => value.match(pattern),
  index: (values, value) => values.indexOf(value), push: (values, value) => values.push(value),
  join: (separator, values) => values.join(separator),
  split: (value, separator) => value.split(separator),
  substr: (value, start, count) => count == null ? value.slice(start) : value.slice(start, start + count),
  sprintf: (_format, value) => JSON.stringify(value),
  keys: Object.keys,
  iptoarr: value => /^\d+\.\d+\.\d+\.\d+$/.test(value) &&
    value.split('.').every(part => +part >= 0 && +part <= 255) ? value.split('.').map(Number) : null,
  arrtoip: values => values.join('.')
});
vm.runInContext(source.replaceAll('export function ', 'function '), context);
const lan = (name, device, addresses = ['192.168.8.1']) => ({
  interface: name, l3_device: device, up: true, route: [],
  'ipv4-address': addresses.map(address => ({ address, mask: 24 }))
});
const plan = (statuses, devices = null) => JSON.parse(JSON.stringify(context.listeners(statuses, devices)));

test('default management remains restricted to the primary LAN', () => {
  assert.deepEqual(plan([lan('lan', 'br-lan'), lan('guest', 'br-guest')]),
    [{ address: '192.168.8.1', device: 'br-lan' }]);
});
test('explicit management devices bind every private local alias', () => {
  const result = plan([lan('lan', 'br-lan'), lan('lanvpn', 'br-vpn', ['10.23.4.1', '10.23.4.2'])], ['br-lan', 'br-vpn']);
  assert.deepEqual(result, [{ address: '192.168.8.1', device: 'br-lan' },
    { address: '10.23.4.1', device: 'br-vpn' }, { address: '10.23.4.2', device: 'br-vpn' }]);
  assert.match(context.firewall_elements(result), /"br-vpn" \. 10\.23\.4\.2/);
});
test('upstream/default-route devices cannot become management interfaces', () => {
  for (const network of ['wan', 'wan6', 'pppoe'])
    assert.throws(() => plan([lan(network, 'eth1')], ['eth1']), /lan_unavailable/);
  const upstream = lan('uplink', 'eth1');
  upstream.route = [{ target: '0.0.0.0', mask: 0 }];
  assert.throws(() => plan([upstream], ['eth1']), /lan_unavailable/);
  const shared = lan('uplink', 'br-lan'); shared.route = [{ target: '::', mask: 0 }];
  assert.throws(() => plan([lan('lan', 'br-lan'), shared], ['br-lan']), /lan_unavailable/);
});
test('malformed, empty and duplicate device policies fail closed', () => {
  for (const value of [[], 'br-lan', ['br-lan', 'br-lan'], ['*'], ['br-lan" accept'], ['../wan']])
    assert.throws(() => plan([lan('lan', 'br-lan')], value), /lan_unavailable/);
});
test('offline selected devices do not prevent another allowed LAN from starting', () => {
  const vpn = lan('lanvpn', 'br-vpn', ['10.23.4.1']); vpn.up = false;
  assert.deepEqual(plan([lan('lan', 'br-lan'), vpn], ['br-lan', 'br-vpn']),
    [{ address: '192.168.8.1', device: 'br-lan' }]);
  assert.throws(() => plan([vpn], ['br-vpn']), /lan_unavailable/);
});
test('public/loopback addresses are refused and repeated ubus rows are deduplicated', () => {
  const good = lan('lan', 'br-lan');
  assert.equal(plan([good, good]).length, 1);
  for (const address of ['1.1.1.1', '127.0.0.1', '169.254.1.1', '224.0.0.1'])
    assert.throws(() => plan([lan('lan', 'br-lan', [address])]), /lan_unavailable/);
});
test('socket addresses are unique while interface/address firewall tuples remain distinct', () => {
  const bindings = plan([lan('lan', 'br-lan'), lan('other', 'br-other')], ['br-lan', 'br-other']);
  assert.equal(bindings.length, 2);
  assert.deepEqual(JSON.parse(JSON.stringify(context.socket_addresses(bindings))), ['192.168.8.1']);
  assert.match(context.firewall_elements(bindings), /"br-other" \. 192\.168\.8\.1/);
});
test('mutable public set accepts only bounded canonical private endpoint tuples', () => {
  for (const bindings of [[], plan([lan('lan', 'br-lan')])]) {
    const raw = context.firewall_set(bindings);
    assert.deepEqual(JSON.parse(JSON.stringify(context.parse_firewall_set(raw))), bindings);
    for (const changed of [raw + '\n', raw.replace('ifname', 'inet_service'),
      raw.replace('192.168.8.1', '1.1.1.1'), raw.replace(' }\n', ' accept }\n')])
      if (changed !== raw) assert.throws(() => context.parse_firewall_set(changed), /lan_unavailable/);
  }
  const duplicate = [{ address: '192.168.8.1', device: 'br-lan' }, { address: '192.168.8.1', device: 'br-lan' }];
  assert.throws(() => context.parse_firewall_set(context.firewall_set(duplicate)), /lan_unavailable/);
  const devices = Array.from({ length: 9 }, (_, i) => ({ device: `br-${i}`, address: `10.0.0.${i + 1}` }));
  assert.throws(() => context.parse_firewall_set(context.firewall_set(devices)), /lan_unavailable/);
  const addresses = Array.from({ length: 17 }, (_, i) => ({ device: 'br-lan', address: `10.0.0.${i + 1}` }));
  assert.throws(() => context.parse_firewall_set(context.firewall_set(addresses)), /lan_unavailable/);
  assert.throws(() => context.parse_firewall_set('x'.repeat(4097)), /lan_unavailable/);
});

const apiExpression = () => [
  { match: { op: '==', left: { concat: [{ meta: { key: 'iifname' } },
    { payload: { protocol: 'ip', field: 'daddr' } }] }, right: '@foxhole_mobile_endpoints' } },
  { match: { op: '==', left: { payload: { protocol: 'tcp', field: 'dport' } }, right: 8443 } },
  { accept: null }
];
const apiRule = () => ({ rule: { family: 'inet', table: 'fw4', chain: 'input', handle: 7,
  comment: 'FoxHole mobile API', expr: apiExpression() } });
test('mobile API accepts only one exact owned fw4 rule and ignores foreign comments', () => {
  assert.equal(context.api_accept_present({ nftables: [] }), false);
  assert.equal(context.api_accept_present({ nftables: [apiRule()] }), true);
  const foreign = apiRule(); foreign.rule.comment = 'another service'; foreign.rule.expr = [{ drop: null }];
  assert.equal(context.api_accept_present({ nftables: [foreign] }), false);
  assert.equal(context.api_accept_present({ nftables: [foreign, apiRule()] }), true);
  assert.throws(() => context.api_accept_present({ nftables: [apiRule(), apiRule()] }), /lan_unavailable/);
});
test('conflicting owned port, set, expression or chain is refused without widening ownership', () => {
  for (const change of [
    r => { r.rule.expr[1].match.right = 8444; },
    r => { r.rule.expr[0].match.right = '@another_set'; },
    r => { r.rule.expr[0].match.left.concat.reverse(); },
    r => { r.rule.expr.push({ counter: { packets: 0, bytes: 0 } }); },
    r => { r.rule.expr[2] = { drop: null }; },
    r => { r.rule.chain = 'forward'; },
    r => { r.rule.table = 'another_table'; }
  ]) {
    const rule = apiRule(); change(rule);
    assert.throws(() => context.api_accept_present({ nftables: [rule] }), /lan_unavailable/);
  }
  const rule = apiRule();
  rule.rule.expr[1].match = { right: 8443, left: { payload: { field: 'dport', protocol: 'tcp' } }, op: '==' };
  assert.equal(context.api_accept_present({ nftables: [rule] }), true, 'object member order is not a wire rule change');
});
test('mobile API rule literal is byte-identical to the canonical packaged fw4 include', async () => {
  const canonical = await readFile(new URL('../package/foxhole-openwrt-client/root/usr/share/nftables.d/chain-pre/input/30-foxhole-mobile.nft', import.meta.url), 'utf8');
  assert.equal(context.api_accept_rule(), canonical);
});
