import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import { functionBody } from './helpers.mjs';

const rpc = await readFile(new URL('../package/foxhole-openwrt-client/root/usr/share/rpcd/ucode/foxhole.uc', import.meta.url), 'utf8');

function fixture(auth, license) {
  const records = { auth, license }, writes = [];
  const context = vm.createContext({
    AUTH_PATH: 'auth', PAIRING_PATH: 'pairs', LICENSE_RECORD_PATH: 'license', LICENSE_VERSION: 1,
    sessions: {}, records, writes,
    type: value => typeof value === 'boolean' ? 'bool' : Number.isInteger(value) ? 'int' : typeof value,
    match: (value, pattern) => value.match(pattern),
    read_json: path => records[path],
    write_json: (path, value) => { writes.push(path); records[path] = value; },
    fail: code => { throw new Error(code); },
    random_hex: bytes => 'a'.repeat(bytes * 2),
    pin_hash: () => 'b'.repeat(64),
    revoke_handoff: () => writes.push('handoff'),
    pairing: { defaults: () => ({ schema: 1, devices: [] }) }
  });
  const names = [['auth_record', 'allow_missing'], ['license_record', ''], ['license_required', 'auth'],
    ['license_choice', 'auth, acceptance'], ['store_pin', 'pin, acceptance']];
  const source = names.filter(([name]) => rpc.includes(`function ${name}(`))
    .map(([name, args]) => `function ${name}(${args}) ${functionBody(rpc, name)};`).join('\n');
  vm.runInContext(source, context);
  return { records, writes, store: acceptance => context.store_pin('6789', acceptance) };
}

const fresh = extra => ({ schema: 1, changed: false, salt: 'a'.repeat(32), hash: 'b'.repeat(64), ...extra });

test('first PIN refuses missing or mistyped consent before every write', () => {
  for (const value of [undefined, null, {}, { licenseAccepted: false, licenseVersion: 1 },
    { licenseAccepted: 'true', licenseVersion: 1 }, { licenseAccepted: true, licenseVersion: '1' },
    { licenseAccepted: true, licenseVersion: 0 }, { licenseAccepted: true, licenseVersion: 2 }]) {
    const f = fixture(fresh());
    assert.throws(() => f.store(value), /license_required/);
    assert.deepEqual(f.writes, []);
    assert.equal(f.records.auth.changed, false);
  }
});

test('first PIN persists explicit versioned consent with the new authentication record', () => {
  const f = fixture(fresh());
  f.store({ licenseAccepted: true, licenseVersion: 1 });
  assert.equal(f.records.auth.changed, true);
  assert.equal(f.records.auth.licenseAccepted, true);
  assert.equal(f.records.auth.licenseVersion, 1);
});

test('existing configured router needs no retrospective consent and creates no acceptance claim', () => {
  const f = fixture(fresh({ changed: true }));
  f.store({});
  assert.equal(f.records.auth.changed, true);
  assert.equal(f.records.auth.licenseAccepted, undefined);
  assert.equal(f.records.auth.licenseVersion, undefined);
});

test('previously accepted terms survive a PIN change and a restricted reset session', () => {
  for (const changed of [false, true]) {
    const f = fixture(fresh({ changed, licenseAccepted: true, licenseVersion: 1 }));
    f.store({});
    assert.equal(f.records.auth.licenseAccepted, true);
    assert.equal(f.records.auth.licenseVersion, 1);
  }
});

test('recorded explicit CLI consent carries into the first web or phone PIN', () => {
  const f = fixture(fresh(), { schema: 1, licenseAccepted: true, licenseVersion: 1 });
  f.store({});
  assert.equal(f.records.auth.licenseAccepted, true);
  assert.equal(f.records.auth.licenseVersion, 1);
});

test('corrupted CLI consent cannot be overwritten by a new PIN request', () => {
  const f = fixture(fresh(), { schema: 1, licenseAccepted: 'true', licenseVersion: 1 });
  assert.throws(() => f.store({ licenseAccepted: true, licenseVersion: 1 }), /storage_error/);
  assert.deepEqual(f.writes, []);
});

const app = await readFile(new URL('../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/app.js', import.meta.url), 'utf8');

async function webPin(required, accepted, version = 1) {
  const calls = [], notices = [];
  const form = { classList: { remove() {}, add() {} }, reset() {}, offsetWidth: 0 };
  const context = vm.createContext({
    pinSetupRequired: required, licenseRequired: required, licenseRequiredVersion: version,
    LICENSE_VERSION: 1, token: 'old',
    $: selector => selector === '[data-pin-change-form]' ? form :
      selector === '[data-license-accept]' ? { checked: accepted } : { value: '6789' },
    t: key => key, toast: key => notices.push(key),
    operation: async fn => fn(),
    api: async (method, args) => { calls.push(JSON.parse(JSON.stringify({ method, args }))); return { token: 'new' }; },
    openView: async () => {}, back: async () => {}, poll() {}
  });
  vm.runInContext(`async function savePin() ${functionBody(app, 'savePin')};`, context);
  await context.savePin();
  return { calls, notices };
}

test('web first PIN refuses an unchecked agreement before its request', async () => {
  const result = await webPin(true, false);
  assert.equal(result.calls.length, 0);
  assert.ok(result.notices.includes('error.license_required'));
});

test('web first PIN sends only explicit Boolean acceptance and the supported integer version', async () => {
  const result = await webPin(true, true);
  assert.deepEqual(result.calls, [{ method: 'pin.change', args: {
    newPin: '6789', licenseAccepted: true, licenseVersion: 1
  } }]);
});

test('web existing configured router keeps ordinary PIN change available', async () => {
  const result = await webPin(false, false);
  assert.equal(result.calls.length, 1);
  assert.equal(result.calls[0].args.newPin, '6789');
  assert.notEqual(result.calls[0].args.licenseAccepted, true);
});

test('web cannot accept a server agreement version that the displayed text does not cover', async () => {
  const result = await webPin(true, true, 2);
  assert.equal(result.calls.length, 0);
});
