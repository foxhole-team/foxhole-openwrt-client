import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import vm from 'node:vm';
import { functionBody, plain, read, rpcPath } from './helpers.mjs';

const rpc = await read(rpcPath);
const pair = { id: `pair-${'a'.repeat(32)}`, verifier: 'not-exported' };
const clientId = 'client-123456abcdef';
const uri = 'hy2://fixture@router.invalid:443/#Phone';
const sha = value => createHash('sha256').update(value, 'utf8').digest('hex');

function harness({ paired = pair, inbound = true, revoke = false } = {}) {
  let revoked = false;
  const calls = [];
  const context = vm.createContext({
    digest: { sha256: sha },
    type: value => value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value,
    match: (value, regex) => String(value).match(regex),
    ord: (value, index) => Buffer.from(value, 'utf8')[index],
    length: value => typeof value === 'string' ? Buffer.byteLength(value) : value.length,
    fail: code => { throw new Error(code); },
    sessions: { issued: { pairing: paired } },
    session: () => {
      if (revoked) throw new Error('unauthorized');
      calls.push('session');
      return 'issued';
    },
    state_record: () => ({ clients: [{ id: clientId, inbound }] }),
    model: { client_profile: () => ({ uri, config: uri, inactive: false }) },
    inbound: { profile: () => ({ uri, config: uri, inactive: false }) },
    read_json: () => ({}),
    qr_svg: value => {
      assert.equal(value, uri);
      calls.push('qr');
      revoked = revoke;
      return '<svg />';
    },
  });
  for (const [name, args] of [
    ['profile_app_metadata', 'paired, client_id, uri'],
    ['client_export', 'state, client'], ['get_client', 'request'],
  ]) {
    let body = functionBody(rpc, name);
    body = body.replace('for (let client in state.clients)',
      'for (const client of state.clients)');
    vm.runInContext(`function ${name}(${args}) ${body}`, context, { timeout: 100 });
  }
  return { context, calls, get: id => context.get_client({ args: { id } }) };
}

test('paired inbound export binds only bounded nonsecret app metadata', () => {
  const h = harness();
  const result = plain(h.get(clientId));
  assert.deepEqual(result.export.appMetadata, {
    schema: 1, kind: 'foxhole-openwrt-client', pairingId: pair.id,
    clientId, uriSha256: sha(uri),
  });
  assert.equal(result.export.uri, uri);
  assert.equal(result.export.config, uri);
  assert.equal(result.export.qrSvg, '<svg />');
  assert.deepEqual(h.calls, ['session', 'qr', 'session']);
  assert.ok(Buffer.byteLength(JSON.stringify(result.export.appMetadata)) <= 256);
  assert.ok(!JSON.stringify(result.export.appMetadata).includes('not-exported'));
});

test('web and copied upstream profiles keep native exports unmarked', () => {
  for (const options of [{ paired: null }, { inbound: false }]) {
    const result = plain(harness(options).get(clientId));
    assert.equal(result.export.uri, uri);
    assert.equal(result.export.config, uri);
    assert.equal(Object.hasOwn(result.export, 'appMetadata'), false);
  }
});

test('revoked pairing cannot receive metadata after QR work', () => {
  const h = harness({ revoke: true });
  assert.throws(() => h.get(clientId), /unauthorized/);
});

test('foreign client ID never returns a profile or marker', () => {
  assert.throws(() => harness().get('client-ffffffffffff'), /not_found/);
});

test('URI tampering and foreign pairing cannot retain the old binding', () => {
  const { context } = harness();
  const original = plain(context.profile_app_metadata(pair, clientId, uri));
  const changed = plain(context.profile_app_metadata(pair, clientId, `${uri}changed`));
  const foreign = plain(context.profile_app_metadata({ id: `pair-${'b'.repeat(32)}` }, clientId, uri));
  assert.notEqual(original.uriSha256, changed.uriSha256);
  assert.equal(changed.uriSha256, sha(`${uri}changed`));
  assert.notEqual(original.pairingId, foreign.pairingId);
});

test('malformed identities and overlong or control-bearing URI have no marker', () => {
  const { context } = harness();
  for (const id of ['', 'pair-AAAA', `${pair.id}extra`, `${pair.id}\u0000foreign`,
    `${pair.id}\n`, `pair-${'A'.repeat(32)}`])
    assert.equal(context.profile_app_metadata({ id }, clientId, uri), null);
  for (const id of ['', 'server-123456abcdef', `${clientId}extra`, `${clientId}\u0000foreign`, `${clientId}\n`])
    assert.equal(context.profile_app_metadata(pair, id, uri), null);
  for (const raw of ['', 'x'.repeat(16385), `hy2://x\nforeign`, `hy2://x\u0000foreign`, `hy2://x\u007fforeign`])
    assert.equal(context.profile_app_metadata(pair, clientId, raw), null);
  assert.equal(context.profile_app_metadata(pair, clientId, 'я'.repeat(8193)), null);
  assert.equal(context.profile_app_metadata(pair, clientId, 'я'.repeat(8192)).uriSha256,
    sha('я'.repeat(8192)));
});

function phoneHarness({ remote = true, revoke = false } = {}) {
  const h = harness();
  const writes = [];
  let revoked = false;
  const phone = { pairId: pair.id, verifier: pair.verifier,
    lanDeviceId: 'device-123456abcdef', remoteClientId: remote ? clientId : null };
  Object.assign(h.context, {
    STATE_PATH: '/memory/state', MOBILE_PATH: '/memory/mobile',
    phone_session: () => {
      if (revoked) throw new Error('unauthorized');
      return pair;
    },
    phone_address: () => '192.0.2.1', resolve_mac: () => '02:00:00:00:00:01',
    locked: action => action(), pairing_record: () => ({}),
    random_hex: bytes => 'a'.repeat(bytes * 2),
    mobile: { prune: () => ({}), prepare: () => ({ phone, record: {} }),
      apply: () => ({ state: { revision: 4, clients: [{ id: clientId }] }, changed: false }) },
    write_json: (path, value) => writes.push({ path, value: plain(value) }),
    restart_runtime: () => { revoked = revoke; return true; },
    system: () => 0,
  });
  const body = functionBody(rpc, 'phone_provision').replace(
    'for (let client in applied.state.clients)', 'for (const client of applied.state.clients)');
  vm.runInContext(`function phone_provision(request) ${body}`, h.context, { timeout: 100 });
  return { run: () => plain(h.context.phone_provision({ args: {} })), writes };
}

test('phone provisioning carries the same marker without changing URI or readiness', () => {
  const h = phoneHarness();
  const response = h.run();
  assert.equal(response.profileUri, uri);
  assert.equal(response.remoteReady, false);
  assert.deepEqual(response.appMetadata, {
    schema: 1, kind: 'foxhole-openwrt-client', pairingId: pair.id,
    clientId, uriSha256: sha(uri),
  });
  assert.ok(h.writes.every(row => !Object.hasOwn(row.value, 'appMetadata')));
});

test('phone registration without a remote profile does not acquire a marker', () => {
  const response = phoneHarness({ remote: false }).run();
  assert.equal(response.profileUri, null);
  assert.equal(Object.hasOwn(response, 'appMetadata'), false);
});

test('pairing revoked during provisioning cannot return a marked profile', () => {
  assert.throws(() => phoneHarness({ revoke: true }).run(), /unauthorized/);
});
