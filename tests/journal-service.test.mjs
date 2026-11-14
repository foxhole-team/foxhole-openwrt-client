import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/', import.meta.url);
const modelSource = readFileSync(new URL('journal-model.uc', root), 'utf8');
const serviceSource = readFileSync(new URL('journal-service.uc', root), 'utf8');
const builtins = {
  type: x => x == null ? 'null' : Array.isArray(x) ? 'array' : Number.isInteger(x) ? 'int' : typeof x === 'number' ? 'double' : typeof x === 'boolean' ? 'bool' : typeof x,
  length: x => typeof x === 'string' ? Buffer.byteLength(x) : x.length,
  index: (a, x) => a.indexOf(x), match: (x, re) => x.match(re), push: (a, x) => a.push(x),
  slice: (a, start, end) => a.slice(start, end), filter: (a, f) => a.filter(f),
  map: (a, f) => a.map(f),
  split: (x, separator) => x.split(separator), trim: x => x.trim(),
  int: Math.trunc, min: Math.min, max: Math.max,
  sprintf: (_f, x) => JSON.stringify(x), json: JSON.parse,
  die: x => { throw Error(x); }
};
const adapt = x => x.replace(/^import .*;\n/gm, '').replace(/^export /gm, '');
const model = new Function(...Object.keys(builtins), `${adapt(modelSource)};return {max_bytes,budget,empty,normalize,merge,bounded,page};`)(...Object.values(builtins));
const boot = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', now = 2000000000000;
const snapshot = n => ({ schema: 1, collectedAtUnixMs: now + n, memAvailableKiB: 65536,
  package: { available: true, events: [{ event: 'tunnel_exited', time: `Nov ${n}`, engine: 'core', exitStatus: 137 }] },
  kernel: { available: true, events: [] } });

function fixture() {
  const files = new Map(); let free = 20 * 1024**2, captures = 0, writes = 0;
  const metadata = value => ({ type: 'file', uid: 0, nlink: 1, mode: 0o600, inode: 1,
    size: Buffer.byteLength(value), mtime: 1, ctime: 1, dev: { major: 1, minor: 2 } });
  const fs = {
    lstat: p => files.has(p) ? metadata(files.get(p)) : ['/','/etc/foxhole'].includes(p)
      ? { type: 'directory', uid: 0, mode: 0o700, inode: 2, dev: { major: 1, minor: 2 } } : null,
    readfile: p => p === '/proc/sys/kernel/random/boot_id' ? boot : files.get(p) ?? null,
    open(p) {
      if (!files.has(p)) files.set(p, '');
      return { lock: () => true, write: value => { writes++; files.set(p, value); return Buffer.byteLength(value); },
        flush: () => true, close() {} };
    },
    rename: (a, b) => { files.set(b, files.get(a)); files.delete(a); return true; },
    unlink: p => files.delete(p)
  };
  const store = { target() {}, read: p => files.get(p) ?? null,
    file_metadata: s => s?.type === 'file' && s.uid === 0 && s.nlink === 1 && !(s.mode & 0o077) };
  const registry = { capture: argv => { captures++; assert.deepEqual(argv, ['/bin/df','-Pk','/']);
    return `Filesystem 1024-blocks Used Available Capacity Mounted on\noverlay 32768 1 ${free / 1024} 1% /\n`; } };
  const digest = { sha256: x => createHash('sha256').update(x).digest('hex') };
  const service = new Function(...Object.keys(builtins), 'fs','store','registry','model','digest',
    `${adapt(serviceSource)};return {status};`)(...Object.values(builtins), fs,store,registry,model,digest);
  return { service,files,free: x => { free = x; },get captures() { return captures; },get writes() { return writes; } };
}

test('RAM journal does not inspect or create journal files or run disk collectors', () => {
  const f = fixture(), result = f.service.status(snapshot(1), 'RAM', 0);
  assert.equal(result.reason, 'RAM_DISABLED');
  assert.equal(f.files.size, 0); assert.equal(f.captures, 0); assert.equal(f.writes, 0);
});

test('FLASH journal persists sanitized observations and rotates oldest data into a smaller budget', () => {
  const f = fixture();
  for (let n = 0; n < 500; n++) assert.equal(f.service.status(snapshot(n), 'FLASH', 0).available, true);
  f.free(4 * 1024**2);
  const result = f.service.status(snapshot(501), 'FLASH', 0);
  assert.equal(result.available, true); assert.ok(result.droppedRecords > 0);
  assert.equal(result.entries[0].event.time, 'Nov 501');
  const raw = f.files.get('/etc/foxhole/log-journal-v1.json');
  assert.ok(Buffer.byteLength(raw) <= result.limitBytes);
  assert.ok(!f.files.has('/etc/foxhole/log-journal-v1.next'));
});

test('journal data with an unknown role is never overwritten', () => {
  const f = fixture(), path = '/etc/foxhole/log-journal-v1.json', raw = '{"schema":99,"kind":"private-user-file"}';
  f.files.set(path, raw);
  assert.throws(() => f.service.status(snapshot(1), 'FLASH', 0));
  assert.equal(f.files.get(path), raw); assert.equal(f.writes, 0);
});
