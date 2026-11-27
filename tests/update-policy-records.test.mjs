import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import test from 'node:test';

const root = new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/', import.meta.url);
const failure = { fail: why => { throw Error(why); } };
const builtins = {
  updates: failure, digest: {},
  type: v => v == null ? 'null' : Array.isArray(v) ? 'array' : typeof v === 'boolean' ? 'bool' : Number.isInteger(v) ? 'int' : typeof v,
  length: v => v?.length ?? Object.keys(v).length, keys: Object.keys,
  index: (a, v) => a.indexOf(v), match: (v, r) => v.match(r),
  split: (v, s) => v.split(s), replace: (v, a, b) => v.replace(a, b),
  substr: (v, a, b) => v.substr(a, b), sprintf: (_f, v) => JSON.stringify(v)
};
const model = vm.createContext(builtins);
vm.runInContext(readFileSync(new URL('ram-update-model.uc', root), 'utf8')
  .replace(/^import .*;\n/gm, '').replace(/^export /gm, '')
  .replace(/for\(let (\w+) in /g, 'for(let $1 of '), model);
const legacy = () => ({ schema: 1, transactionAbi: 1, stateAbi: 1, osRelease: '25.12.5',
  packageVersion: '1.0.9-r1', releaseTag: 'v1.0.9', targets: ['x86/64', 'mediatek/filogic'] });
const modern = () => { const { osRelease, ...value } = legacy(); return { ...value, schema: 2, supportedOpenWrt: ['25.12.5', '25.12.6'] }; };
const read = (a, b, os) => model.policy_records(a, b, '1.0.9-r1', 'v1.0.9', os);

test('separate truthful legacy and modern records admit their exact tested firmware', () => {
  const a = legacy(), b = modern(), frozen = JSON.stringify([a, b]);
  for (const os of ['25.12.5', '25.12.6']) assert.equal(read(a, b, os).schema, 2);
  assert.equal(JSON.stringify([a, b]), frozen);
});
test('single legacy and single modern formats retain their original meanings', () => {
  assert.equal(read(legacy(), null, '25.12.5').schema, 1);
  assert.throws(() => read(legacy(), null, '25.12.6'));
  assert.equal(read(modern(), null, '25.12.6').schema, 2);
});
test('a malformed or conflicting modern record cannot fall back to legacy', () => {
  for (const patch of [{}, { schema: 1 }, { packageVersion: '1.0.8-r2' }, { releaseTag: 'v1.0.8' },
    { stateAbi: 2 }, { transactionAbi: 2 }, { targets: ['mediatek/filogic', 'x86/64'] },
    { supportedOpenWrt: ['25.12.5', '25.12.7'] }, { extra: true }]) {
    const b = Object.keys(patch).length ? { ...modern(), ...patch } : {};
    assert.throws(() => read(legacy(), b, '25.12.5'));
  }
  assert.throws(() => read(modern(), modern(), '25.12.6'));
  for (const os of ['25.12.7', '25.12.50', '25.12', '']) assert.throws(() => read(legacy(), modern(), os));
});
test('the actual published1.0.6 reader accepts the legacy path without altered fields', () => {
  const value = legacy();
  const old = vm.createContext({ ...builtins, guard: failure, decode: JSON.parse, public_raw: () => JSON.stringify(value) });
  vm.runInContext(readFileSync(new URL('fixtures/legacy106-policy.fixture.txt', import.meta.url), 'utf8'), old);
  assert.equal(old.legacy_policy('/signed/update-policy.json', '1.0.9-r1').osRelease, '25.12.5');
  Object.assign(value, modern()); delete value.osRelease;
  assert.throws(() => old.legacy_policy('/signed/update-policy.json', '1.0.9-r1'));
});
test('native reader chooses the authenticated companion and refuses a broken companion', () => {
  const source = readFileSync(new URL('update-native.uc', root), 'utf8');
  const start = source.indexOf('export function policy(');
  const end = source.indexOf('\n};', start) + 3;
  assert.ok(start >= 0 && end > start);
  const records = { '/signed/update-policy.json': legacy(), '/signed/update-policy-v2.json': modern() };
  const context = vm.createContext({ ...builtins, guard: failure, ram_updates: model, decode: JSON.parse,
    target: () => ({ release: '25.12.6' }), fs: { lstat: path => records[path] ? { type: 'file' } : null },
    public_raw: path => JSON.stringify(records[path]) });
  vm.runInContext(source.slice(start, end).replace('export function', 'function'), context);
  assert.equal(context.policy('/signed/update-policy.json', '1.0.9-r1').schema, 2);
  records['/signed/update-policy-v2.json'] = {};
  assert.throws(() => context.policy('/signed/update-policy.json', '1.0.9-r1'));
  delete records['/signed/update-policy-v2.json'];
  assert.throws(() => context.policy('/signed/update-policy.json', '1.0.9-r1'));
});


test('the compatibility source records match before role-specific BASE assembly', () => {
  const a = JSON.parse(readFileSync(new URL('update-policy.json', root), 'utf8'));
  const b = JSON.parse(readFileSync(new URL('update-policy-v2.json', root), 'utf8'));
  const release = readFileSync(new URL('../config/release-version.txt', import.meta.url), 'utf8').trim();
  const makefile = readFileSync(new URL('../package/foxhole-openwrt-client/Makefile', import.meta.url), 'utf8');
  assert.match(makefile, /^ifeq \(\$\(FOXHOLE_BASE_ROLE\),flash\)\nPKG_RELEASE:=1\nelse ifeq \(\$\(FOXHOLE_BASE_ROLE\),managed-ram\)\nPKG_RELEASE:=2$/m);
  assert.equal(a.schema, 1);
  assert.equal(a.osRelease, '25.12.5');
  assert.equal(a.packageVersion, `${release}-r1`);
  assert.equal(a.releaseTag, `v${release}`);
  for (const os of ['25.12.5', '25.12.6'])
    assert.equal(model.policy_records(a, b, a.packageVersion, a.releaseTag, os).schema, 2);
  assert.match(makefile, /install-base-policies\.py --role "\$\(FOXHOLE_BASE_ROLE\)" --version "\$\(PKG_VERSION\)"/);
});

test('the actual two BASE roles supply the records their respective older reader opens', () => {
 const release = readFileSync(new URL('../config/release-version.txt', import.meta.url), 'utf8').trim();
 for (const [role, revision] of [['flash', 1], ['managed-ram', 2]]) {
  const dir = mkdtempSync(join(tmpdir(), 'foxhole-reader-'));
  try {
   const generated = spawnSync('python3', [fileURLToPath(new URL('../tools/install-base-policies.py', import.meta.url)),
    '--source', fileURLToPath(root), '--output', dir, '--role', role, '--revision', String(revision), '--version', release]);
   assert.equal(generated.status, 0, generated.stderr.toString());
   const primary = JSON.parse(readFileSync(join(dir, 'update-policy.json')));
   const version = `${release}-r${revision}`, tag = `v${release}`;
   assert.equal(primary.packageVersion, version);
   const companionPath = join(dir, 'update-policy-v2.json');
   assert.equal(existsSync(companionPath), role === 'managed-ram');
   if (role === 'flash') {
    assert.equal(primary.schema, 2);
    assert.equal(model.policy_records(primary, null, version, tag, '25.12.6').schema, 2);
   } else {
    assert.equal(primary.schema, 1);
    assert.equal(model.policy_records(primary, null, version, tag, '25.12.5').schema, 1);
    assert.throws(() => model.policy_records(primary, null, version, tag, '25.12.6'));
    const companion = JSON.parse(readFileSync(companionPath));
    assert.equal(model.policy_records(primary, companion, version, tag, '25.12.5').schema, 2);
    assert.throws(() => model.policy_records(primary, companion, `${release}-r1`, tag, '25.12.5'));
   }
  } finally { rmSync(dir, { recursive: true }); }
 }
});
