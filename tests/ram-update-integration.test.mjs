import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { functionBody, packageRoot, read, rpcMethods, plain } from './helpers.mjs';

const source = await read(`${packageRoot}/root/usr/share/foxhole/update-service.uc`);
const names = ['ram_selected', 'ram_deployment', 'deployment', 'status', 'settings', 'check', 'plan', 'apply', 'job',
  'device_begin', 'device_chunk', 'device_status', 'device_finish', 'tick', 'run', 'cohort_kind', 'base_request'];
const argumentsFor = { ram_selected: '', ram_deployment: '', deployment: '', status: 'principal',
  settings: 'request,principal', check: 'request,principal', plan: 'request,principal', apply: 'request,principal',
  job: 'id,principal', device_begin: 'request,principal', device_chunk: 'request,principal',
  device_status: 'request,principal', device_finish: 'request,principal', tick: '', run: 'id',
  cohort_kind: 'request', base_request: 'request' };

function harness() {
  const calls = [], environment = { marker: true, pending: null };
  const ram = Object.fromEntries(names.filter(name => !['ram_selected', 'ram_deployment'].includes(name))
    .map(name => [name, (...args) => { calls.push({ name, args }); return { delegated: name }; }]));
  const context = vm.createContext({ ram, JOB: 'job', calls, environment,
    fs: { lstat: () => environment.marker ? { type: 'file' } : null },
    read: () => environment.pending,
    blocked: value => value != null && !['SUCCEEDED', 'FAILED'].includes(value.state),
    index: (rows,value)=>rows.indexOf(value),
    model: { fail: reason => { throw new Error(reason); } }
  });
  for (const name of names)
    vm.runInContext(`function ${name}(${argumentsFor[name]}) ${functionBody(source, name)}`, context);
  return { context, calls, environment };
}

test('every existing update entry delegates RAM without entering host/native FLASH path', () => {
  const { context, calls } = harness(), request = { fixture: true }, principal = { fixture: 'owner' };
  for (const name of ['status', 'settings', 'check', 'plan', 'apply', 'job', 'device_begin', 'device_chunk', 'device_status', 'device_finish', 'tick', 'run']) {
    const args = name === 'status' ? [principal] : name === 'job' ? ['job-id', principal]
      : name === 'run' ? ['job-id'] : name === 'tick' ? [] : [request, principal];
    assert.equal(context[name](...args).delegated, name);
    assert.equal(calls.at(-1).name, name);
    assert.deepEqual(plain(calls.at(-1).args), args);
  }
  assert.doesNotMatch(source, /fail\('UNSUPPORTED'\)/);
});
test('paired phones can query guarded package updates on either storage mode', async () => {
  const rpc = await read(`${packageRoot}/root/usr/share/rpcd/ucode/foxhole.uc`);
  for (const storage of ['RAM', 'FLASH']) {
    const context = vm.createContext({ phone_session: () => {},
      server_install: { installed: () => null }, protocol_facts: { server: () => null }, server_mode: { enabled: () => false }, state_record: () => ({ settings: {} }),
      core_adapter: { receipt: () => null }, fs: { stat: () => null },
      read_json: () => null, ram_deployment: () => storage === 'RAM' });
    vm.runInContext(`function phone_capabilities(request) ${functionBody(rpc, 'phone_capabilities')}`, context);
    assert.equal(context.phone_capabilities({}).packageUpdates, true);
    assert.equal(context.phone_capabilities({}).phoneRemoteProvisioning, false);
  }
});
test('RAM job dispatch survives marker absence and never enters global database worker', () => {
  const f = harness(); f.environment.marker = false;
  f.environment.pending = { deployment: 'RAM_BASE', jobId: 'job-id', state: 'QUEUED' };
  assert.equal(f.context.run('job-id').delegated, 'run'); assert.equal(f.context.status({}).delegated, 'status');
  f.environment.pending.state = 'SUCCEEDED';
  assert.equal(f.context.job('job-id', {}).delegated, 'job');
});
test('device transport is unsupported on FLASH and cannot silently select another updater', () => {
  const f = harness(); f.environment.marker = false;
  for (const name of ['device_begin', 'device_chunk', 'device_status', 'device_finish'])
    assert.throws(() => f.context[name]({}, {}), /UNSUPPORTED_TARGET/);
  assert.equal(f.calls.length, 0);
});
test('device RPC wire fields, HTTPS and access scopes match the shared controller', async () => {
  const methods = await rpcMethods(), gateway = await read(`${packageRoot}/root/www/cgi-bin/foxhole`);
  const expected = {
    'updates.deviceBegin': ['token', 'cohortKind', 'assetId', 'uploadId', 'expectedRevision', 'requestId', 'releaseTag', 'version', 'fileSha256', 'fileBytes'],
    'updates.deviceChunk': ['token', 'cohortKind', 'assetId', 'uploadId', 'offset', 'dataBase64', 'chunkSha256'],
    'updates.deviceStatus': ['token', 'cohortKind', 'assetId', 'uploadId'], 'updates.deviceFinish': ['token', 'cohortKind', 'assetId', 'uploadId']
  };
  const tls = gateway.slice(gateway.indexOf('pairing.requires_tls'));
  const acl = JSON.parse(await read(`${packageRoot}/root/usr/share/rpcd/acl.d/luci-app-foxhole.json`))['luci-app-foxhole'];
  for (const [name, fields] of Object.entries(expected)) {
    assert.deepEqual(Object.keys(methods[name].args), fields); assert.ok(tls.includes(`'${name}'`));
    assert.ok(acl[name === 'updates.deviceStatus' ? 'read' : 'write'].ubus.foxhole.includes(name));
  }
  const rpc = await read(`${packageRoot}/root/usr/share/rpcd/ucode/foxhole.uc`);
  assert.doesNotMatch(functionBody(rpc, 'call'), /update_unsupported/);
  assert.match(functionBody(rpc, 'package_status'), /update_service\.deployment\(\)/);
  assert.doesNotMatch(functionBody(rpc, 'package_status'), /1\.0\.1/);
});
test('pairing and public status cannot overwrite storage-specific owner policy', async () => {
  for (const [name, namespace] of [['update-service', 'model'], ['ram-update-service', 'updates']]) {
    const backend = await read(`${packageRoot}/root/usr/share/foxhole/${name}.uc`), calls = [];
    const context = vm.createContext({ POLICY: 'policy', saved: null, owner: { changed: true },
      read(path) { calls.push(path); return path === 'policy' ? context.saved : context.owner; },
      [namespace]: { policy: (saved, owner) => ({ saved, owner }) } });
    vm.runInContext(`function policy() ${functionBody(backend, 'policy')}`, context);
    assert.deepEqual(plain(context.policy()), { saved: null, owner: { changed: true } });
    assert.deepEqual(calls, ['policy','/etc/foxhole/auth.json']);
    calls.length = 0;
    context.saved = { enabled: false, revision: 3 };
    assert.deepEqual(plain(context.policy()), { saved: context.saved, owner: null });
    assert.deepEqual(calls, ['policy']);
  }
  const rpc = await read(`${packageRoot}/root/usr/share/rpcd/ucode/foxhole.uc`);
  for (const name of ['pair_create', 'pair_unlock', 'phone_provision'])
    assert.doesNotMatch(functionBody(rpc, name), /update_service\.settings|autoUpdateEnabled|update-policy\.json/);
  const publicStatus = functionBody(rpc, 'package_status');
  assert.doesNotMatch(publicStatus, /write_json|update_service\.settings|fs\.(?:writefile|unlink|rename)|store\.write/);
  const setup = await read(`${packageRoot}/root/usr/libexec/foxhole-bootstrap-enroll`);
  assert.doesNotMatch(setup, /autoUpdate|update-policy\.json/);
});
test('SDK installs both RAM modules and fixed bounded workers', async () => {
  const makefile = await read(`${packageRoot}/Makefile`);
  for (const name of ['ram-update-model.uc', 'ram-update-service.uc', 'foxhole-ram-update-job', 'foxhole-ram-update-command'])
    assert.ok(makefile.includes(name), name);
});
