import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { functionBody, packageRoot, read } from './helpers.mjs';

const source = await read(`${packageRoot}/root/usr/share/foxhole/remote.uc`);
const fingerprint = 'a'.repeat(64);

function prepareFirstClient(component) {
  const writes = [];
  const scope = vm.createContext({
    store: {
      read: path => path === '/etc/foxhole/inbound.json' ? null : JSON.stringify({ schema: 1, certificateSha256: fingerprint }),
      directory: () => {},
      write: (path, value) => writes.push([path, JSON.parse(value)]),
    },
    server_install: { installed: () => component },
    fs: { readfile: () => '0'.repeat(12), unlink: () => {} },
    wan_address: () => {}, length: x => x.length, hexenc: () => '0'.repeat(24),
    system: () => 0, json: JSON.parse, sprintf: (_, x) => JSON.stringify(x),
    template: (address, pin) => ({ address, pin }), die: message => { throw Error(message); },
  });
  vm.runInContext(`function prepare(address) ${functionBody(source, 'prepare')}`, scope);
  return { create: () => scope.prepare('192.0.2.1'), writes };
}

test('a verified managed server creates the first client even without a legacy executable path', () => {
  const setup = prepareFirstClient({ kind: 'verified-managed-server' });
  assert.equal(setup.create().pin, fingerprint);
  assert.deepEqual(setup.writes, [['/etc/foxhole/inbound.json', { address: '192.0.2.1', pin: fingerprint }]]);
});

test('an absent server cannot initialize incoming clients', () => {
  const setup = prepareFirstClient(null);
  assert.throws(setup.create, /inbound_required/);
  assert.deepEqual(setup.writes, []);
});
