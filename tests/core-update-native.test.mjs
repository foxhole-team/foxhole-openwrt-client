import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createHash } from 'node:crypto';
import { read, functionBody, packageRoot, plain } from './helpers.mjs';

const modelSource = await read(`${packageRoot}/root/usr/share/foxhole/core-update-model.uc`);
const nativeSource = await read(`${packageRoot}/root/usr/share/foxhole/core-update-native.uc`);
const hash = raw => createHash('sha256').update(raw).digest('hex');
const now = 1_793_000_000_000, H = 'a'.repeat(64), C = 'c'.repeat(40);
const payload = {
 schema: 1, feedAbi: 1, channel: 'stable', sequence: 1, coreVersion: '1.0.4', releaseTag: 'v1.0.4',
 publishedAtUnixMs: now - 1, expiresAtUnixMs: now + 86_400_000,
 compatibility: { stateAbi: 1, transactionAbi: 1, routerContractVersion: 1, osRelease: '25.12.5',
  targets: ['x86/64', 'mediatek/filogic'], minimumBaseVersion: '1.0.6-r1' },
 source: { producerCommit: C, publisherCommit: C, publisherTree: C, sourceContentSha256: H,
  sourceManifestSha256: H, signatureReceiptSha256: H, contentJoinReceiptSha256: H },
 catalog: { schema: 1, entries: [{ id: 'vless', storage: 'FLASH', architecture: 'x86_64',
  version: '1.0.4', sourceCommit: C }] }
};
const raw = JSON.stringify(payload), bodyHash = hash(raw), archiveHash = hash('synthetic metadata APK'), indexHash = hash('synthetic signed index');
const acl = mode => ({ mode, user: 'root', group: 'root' });
function document() {
 return { info: { name: 'foxcore-update-catalog', arch: 'noarch', version: '1.0.4-r1', 'installed-size': 4096 },
  paths: [{ acl: acl(0o755) }, { name: 'usr/share/foxhole-core-catalog', acl: acl(0o755),
   files: [{ name: 'core-update.json', acl: acl(0o644), size: raw.length, hash: bodyHash }] }] };
}
function model() {
 const scope = vm.createContext({
  type: value => value === null ? 'null' : Array.isArray(value) ? 'array' :
   typeof value === 'number' && Number.isInteger(value) ? 'int' : typeof value,
  length: value => typeof value === 'string' || Array.isArray(value) ? value.length : Object.keys(value).length,
  keys: Object.keys, index: (values, value) => values.indexOf(value), match: (text, expression) => text.match(expression),
  substr: (value, start, count) => count == null ? value.slice(start) : value.slice(start, start + count),
  sprintf: (_format, value) => JSON.stringify(value), json: JSON.parse,
  die: reason => { throw new Error(reason); }
 });
 vm.runInContext(modelSource.replaceAll('export function ', 'function ').replaceAll('export const ', 'const '), scope);
 return scope;
}
function verification(options = {}) {
 const commands = [], requests = [], cached = [];
 let bodyReads = 0;
 const doc = options.document || document();
 const row = { name: 'foxcore-update-catalog', arch: 'noarch', version: '1.0.4-r1',
  hashes: H, 'file-size': 500, ...(options.row || {}) };
 const models = model();
 const scope = vm.createContext({
  ORIGIN: 'https://github.com/foxhole-team/foxhole-core/releases/download/',
  CACHE: '/etc/foxhole/update-cache',
  length: value => value.length,
  substr: (value, start, count) => count == null ? value.slice(start) : value.slice(start, start + count),
  type: value => Array.isArray(value) ? 'array' : typeof value === 'number' && Number.isInteger(value) ? 'int' : typeof value,
  match: (text, expression) => text.match(expression), time: () => now / 1000,
  fs: { lstat: path => ({ size: path === '/fixture/index' ? 100 : 500 }),
   readfile: () => `MemAvailable: ${options.noSpace ? 1 : 65536} kB\n` },
  store: { directory() {}, write() {} }, guard: { fail: reason => { throw new Error(reason); } },
  digest: { sha256: hash }, model: models,
  engines: { catalog: value => value },
  native: {
   fetch(url, maximum) { requests.push({ url, maximum }); return url.endsWith('.adb') ? '/fixture/index' : '/fixture/archive'; },
   decode: JSON.parse,
   target: () => ({ release: '25.12.5', target: 'x86/64', architecture: 'x86_64' }),
   compare: () => '=', public_raw: () => { bodyReads++; return raw; },
   prepare_keys: () => '/fixture/keys',
   cache_asset: (...args) => cached.push(args)
  },
  registry: { hash_file: path => path === '/fixture/index' ? indexHash :
   path.includes('/fetched/') && options.wrongRoundtrip ? H : archiveHash },
  system(argv) { commands.push(argv); return 0; },
  packages: { apk(argv) {
   commands.push(argv);
   if (argv.includes('verify') && options.badSignature) throw new Error('native-signature-refused');
   if (argv[0] === 'adbdump') return JSON.stringify(argv.at(-1) === '/fixture/index'
    ? { packages: options.duplicateIndex ? [row, row] : [row] } : doc);
   return '';
  } }
 });
 vm.runInContext(`function capacity(bytes) ${functionBody(nativeSource, 'capacity')}`, scope);
 vm.runInContext(`function metadata_asset(url,maximum,provided,index) ${functionBody(nativeSource, 'metadata_asset')}`, scope);
 vm.runInContext(`function verify_catalog(tag,directory,keys,active_version,previous,provided) ${functionBody(nativeSource, 'verify_catalog')}`, scope);
 return { run: () => scope.verify_catalog('v1.0.4', '/fixture/work', '/fixture/keys', '1.0.6-r1', null),
  facts: () => ({ commands, requests, cached, bodyReads }) };
}

test('metadata APK admits exactly one bounded data file and optional native list', () => {
 assert.deepEqual(plain(model().metadata_layout(document(), '1.0.4-r1')),
  { path: 'usr/share/foxhole-core-catalog/core-update.json', sha256: bodyHash, bytes: raw.length });
});
test('metadata scripts, arbitrary payload, unsafe ACL and links are rejected', () => {
 for (const change of [doc => { doc.scripts = { 'post-install': 'untrusted' }; },
  doc => { doc.paths[1].files[0].name = '../escape'; },
  doc => { doc.paths[1].files[0].acl.mode = 0o666; },
  doc => { doc.paths[1].files[0].target = '/arbitrary'; },
  doc => { doc.info.depends = ['unrelated-package']; }]) {
  const doc = document(); change(doc);
  assert.throws(() => model().metadata_layout(doc, '1.0.4-r1'), /update_/);
 }
});
test('signed index and APK are verified before bounded metadata becomes visible', () => {
 const current = verification(), result = plain(current.run()), facts = current.facts();
 assert.equal(result.reference.bodySha256, bodyHash); assert.equal(facts.bodyReads, 1);
 const verify = facts.commands.findIndex(row => row.includes('verify'));
 const dump = facts.commands.findIndex(row => row[0] === 'adbdump');
 const extraction = facts.commands.findIndex(row => row.includes('extract'));
 const fetch = facts.commands.find(row => row.includes('fetch'));
 assert.ok(verify >= 0 && verify < dump && extraction > dump);
 assert.equal(fetch.at(-1), 'foxcore-update-catalog'); assert.ok(!fetch.includes('--link'));
 assert.equal(facts.cached.length, 3);
 assert.ok(facts.requests.every(row => row.url.startsWith('https://github.com/foxhole-team/foxhole-core/releases/download/v1.0.4/')));
});
test('signature failure and duplicate or foreign index identity stop before metadata read', () => {
 for (const options of [{ badSignature: true }, { duplicateIndex: true }, { row: { name: 'foreign' } }]) {
  const current = verification(options); assert.throws(current.run);
  assert.equal(current.facts().bodyReads, 0); assert.equal(current.facts().cached.length, 0);
 }
});
test('NAME-only fetched-byte mismatch and unsafe data layout cannot populate cache', () => {
 const invalid = document(); invalid.scripts = { 'post-install': 'unsafe' };
 for (const options of [{ wrongRoundtrip: true }, { document: invalid }]) {
  const current = verification(options); assert.throws(current.run, /PACKAGE_VERIFICATION_FAILED|update_/);
  assert.equal(current.facts().cached.length, 0); assert.equal(current.facts().bodyReads, 0);
 }
});
test('low memory refuses catalog APK download after the bounded index check', () => {
 const current = verification({ noSpace: true }); assert.throws(current.run, /NO_SPACE/);
 assert.equal(current.facts().requests.length, 1); assert.equal(current.facts().bodyReads, 0);
});
