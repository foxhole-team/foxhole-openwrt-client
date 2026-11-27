import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

test('rpcd binds the session principal before any handler calls it', () => {
  const plugin = readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/rpcd/ucode/foxhole.uc', import.meta.url), 'utf8');
  const declaration = /^function engine_principal\(request\) \{/m.exec(plugin);
  assert.ok(declaration, 'missing engine_principal declaration');
  // ucode resolves functions in source order, including calls
  // inside handler bodies.
  assert.doesNotMatch(plugin.slice(0, declaration.index), /\bengine_principal\s*\(/);
  assert.match(plugin.slice(declaration.index + declaration[0].length), /\bengine_principal\s*\(request\)/);
});

test('Home VPN Server jobs bind progress and service control before the worker uses them', () => {
  const service = readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/server-install-service.uc', import.meta.url), 'utf8');
  const worker = service.indexOf('function run_disable(value) {');
  assert.notEqual(worker, -1, 'missing disable worker');
  for (const name of ['progress', 'managed']) {
    const definition = new RegExp('^function ' + name + '\\(', 'm').exec(service);
    assert.ok(definition && definition.index < worker, name + ' must be declared before the disable worker');
  }
});

test('disable verifies its exact read-only nftables set query through the bounded command helper', () => {
  const root = new URL('../package/foxhole-openwrt-client/root/', import.meta.url);
  const module = readFileSync(new URL('usr/share/foxhole/server-install-service.uc', root), 'utf8');
  const caller = module.match(/registry\.capture\(\[('\/usr\/sbin\/nft',.*?)\],(\d+),(\d+)\)/);
  assert.ok(caller);
  const argv = caller[1].split(',').map(arg => arg.trim().slice(1, -1));
  const [limit, timeout] = caller.slice(2);
  assert.deepEqual(argv, ['/usr/sbin/nft', '-j', 'list', 'set', 'inet', 'fw4', 'foxhole_inbound_ports']);
  assert.equal(limit, '8192');
  assert.equal(timeout, '5000');
  const helper = readFileSync(new URL('usr/libexec/foxhole-engine-command-v2', root), 'utf8');
  const gate = helper.match(/^case "\$\{1-\}" in\n[\s\S]*?^esac$/m);
  assert.ok(gate);
  // Exercise the stock dispatch check without starting nft or
  // accessing a host firewall.
  const check = (args, bytes = limit, millis = timeout) => spawnSync('sh',
    ['-c', 'set -eu; limit=$1; timeout=$2; shift 2\n' + gate[0], 'role-check', bytes, millis, ...args]).status;
  assert.equal(check(argv), 0);
  assert.equal(check([...argv, 'extra']), 1);
  assert.equal(check([...argv.slice(0, -1), 'other_set']), 1);
  assert.equal(check([argv[0], argv[1], 'flush', ...argv.slice(3)]), 1);
  assert.equal(check(argv, '16384'), 1);
  assert.equal(check(argv, limit, '6000'), 1);
});

test('first client creation binds WAN lookup before save_client', () => {
  const source = readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/rpcd/ucode/foxhole.uc', import.meta.url), 'utf8');
  const lookup = source.indexOf('function remote_wan_address()');
  assert.ok(lookup > source.indexOf('function remote_uplink()'));
  assert.ok(lookup < source.indexOf('function save_client(request)'));
});
