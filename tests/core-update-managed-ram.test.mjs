import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { posix } from 'node:path';
import { createHash } from 'node:crypto';
import { read, functionBody, packageRoot, plain } from './helpers.mjs';

const service = await read(`${packageRoot}/root/usr/share/foxhole/ram-switch-service.uc`);
const model = await read(`${packageRoot}/root/usr/share/foxhole/ram-switch-model.uc`);
const H = 'a'.repeat(64), hash = raw => createHash('sha256').update(raw).digest('hex');
const adapt = value => value
 .replace(/for\s*\(let (\w+) in keys\(([^)]+)\)\)/g, 'for(let $1 of keys($2))')
 .replace(/for\s*\(let (\w+) in ([A-Za-z0-9_.]+(?:\([^)]*\))?)\)/g, 'for(let $1 of $2)');
function managed(options = {}) {
 const stage = '/tmp/foxhole-ram-stage-fixture', root = stage + '/root';
 const markerPath = '/tmp/foxhole-ram-active.json';
 const ledgerPath = '/etc/foxhole/ram-update/generations/generation-' + 'b'.repeat(32) + '.json';
 const database = 'synthetic-managed-APK-database';
 const marker = { schema: 1, storage: 'RAM', phase: 'active', stage,
  baseSha256: H, stageDbSha256: options.badDatabase ? H : hash(database),
  mountLedger: ledgerPath, version: '1.0.6-r1' };
 if (options.missingGeneration) delete marker.stageDbSha256;
 const mount = { target: '/usr/share/foxhole', source: root + '/usr/share/foxhole',
  type: 'directory', dev: { major: 0, minor: 2 }, inode: 10, sha256: null, role: 'base' };
 const ledger = { schema: 1, abi: 1, kind: 'foxhole-ram-mount-ledger-v1', stage, baseSha256: H, mounts: [mount] };
 const texts = { [markerPath]: JSON.stringify(marker), [ledgerPath]: JSON.stringify(ledger),
  [root + '/lib/apk/db/installed']: database, '/etc/apk/arch': 'x86_64\n' };
 let race = 0, queries = 0;
 const basics = {
  type: value => value === null ? 'null' : Array.isArray(value) ? 'array' :
   typeof value === 'number' && Number.isInteger(value) ? 'int' : typeof value,
  length: value => typeof value === 'string' || Array.isArray(value) ? value.length : Object.keys(value).length,
  keys: Object.keys, index: (values, value) => values.indexOf(value),
  match: (value, regex) => value.match(regex), split: (value, separator) => value.split(separator),
  join: (separator, values) => values.join(separator), slice: (value, start) => value.slice(start),
  push: (values, value) => values.push(value), filter: (values, fn) => values.filter(fn),
  sort: values => values.sort(), trim: value => value.trim(),
  sprintf: (_format, value) => JSON.stringify(value), json: JSON.parse,
  die: reason => { throw new Error(reason); }
 };
 const models = vm.createContext(basics);
 vm.runInContext(adapt(model.replaceAll('export function ', 'function ')), models);
 const scope = vm.createContext({ ...basics, model: models, MARKER: markerPath, BASE: 'foxhole-openwrt-client',
  update_model: { version: value => /^[0-9]+\.[0-9]+\.[0-9]+-r[1-9][0-9]*$/.test(value) },
  digest: { sha256: hash },
  native(action, args) {
   assert.equal(action, 'query'); assert.equal(args[0], root); queries++;
   return JSON.stringify([{ name: 'foxhole-openwrt-client', version: '1.0.6-r1', arch: 'noarch', status: ['installed'] }]);
  },
  fs: { dirname: posix.dirname,
   lstat(path) {
    if (path === mount.source || path === mount.target) return { type: 'directory', uid: 0, gid: 0,
     mode: 0o755, inode: options.wrongMountIdentity && path === mount.target ? 11 : 10,
     dev: { major: 0, minor: 2 } };
    if (Object.hasOwn(texts, path)) return { type: 'file', uid: 0, gid: 0, mode: 0o600,
     inode: path === markerPath ? 20 + race : 30, nlink: 1, size: texts[path].length, mtime: 1, ctime: 1,
     dev: { major: 0, minor: 2 } };
    return { type: 'directory', uid: 0, gid: 0, mode: path === '/tmp' ? 0o1777 : 0o755 };
   },
   readfile(path) {
    if (path === markerPath && options.concurrentMarker) race++;
    if (path === '/proc/self/mountinfo') return '1 0 0:1 / / rw - ext4 /dev/root rw\n' +
     `2 1 0:2 / /tmp rw - ${options.diskStage ? 'ext4' : 'tmpfs'} tmpfs rw\n` +
     `3 1 0:2 / /usr/share/foxhole ${options.writableMount ? 'rw' : 'ro'} - tmpfs tmpfs rw\n` +
     (options.nestedMount ? '4 3 0:2 / /usr/share/foxhole/hidden ro - tmpfs tmpfs rw\n' : '');
    return texts[path];
   }
  },
  system() { assert.fail('managed admission must never mutate mounts, packages or services'); }
 });
 for (const [name, args] of [['fail', ''], ['same', 'a,b'], ['facts', 'value'], ['parents', 'path'],
  ['raw', 'path,maximum,empty'], ['mount_rows', ''], ['covering', 'rows,path'],
  ['ram_backing', 'rows,path,depth'], ['verify_mount', 'row,readonly'], ['core_context', '']])
  vm.runInContext(`function ${name}(${args}) ${adapt(functionBody(service, name))}`, scope);
 return { run: () => scope.core_context(), queries: () => queries };
}
test('managed RAM admission binds exact immutable BASE generation and read-only ledger', () => {
 const current = managed(), proof = plain(current.run());
 assert.equal(proof.storage, 'RAM'); assert.equal(proof.version, '1.0.6-r1');
 assert.equal(proof.stageDbSha256, hash('synthetic-managed-APK-database'));
 assert.equal(current.queries(), 1);
});
test('missing generation or another managed database cannot use the RAM Core path', () => {
 for (const options of [{ missingGeneration: true }, { badDatabase: true }])
  assert.throws(managed(options).run, /RAM_SWITCH_VALIDATION_FAILED/);
});
test('writable, mismatched or nested public binds fail before package work', () => {
 for (const options of [{ writableMount: true }, { wrongMountIdentity: true }, { nestedMount: true }]) {
  const current = managed(options); assert.throws(current.run, /RAM_SWITCH_VALIDATION_FAILED/);
  assert.equal(current.queries(), 0);
 }
});
test('disk-backed or concurrently replaced RAM stage metadata is refused', () => {
 for (const options of [{ diskStage: true }, { concurrentMarker: true }])
  assert.throws(managed(options).run, /RAM_SWITCH_VALIDATION_FAILED/);
});
