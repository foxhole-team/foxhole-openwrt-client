import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const tools = path.resolve(here, '../tools');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'foxhole-transport-fixtures-'));
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const fixture = path.join(temp, 'producer');
execFileSync('python3', [path.join(here, 'fixtures.py'), fixture], { maxBuffer: 4096, timeout: 30000 });
const transport = path.join(fixture, 'transport');
const descriptor = JSON.parse(fs.readFileSync(path.join(transport, 'bundle-transport.json'), 'utf8'));
const archive = fs.readFileSync(path.join(transport, 'native-install.tar'));
const originalSums = fs.readFileSync(path.join(transport, 'SHA256SUMS'), 'utf8');
const adapt = source => source.replace(/^'use strict';\n/m, '').replace(/^import .*;\n/gm, '')
  .replace(/export function /g, 'function ').replace(/for \(let (\w+) in /g, 'for (let $1 of ')
  .replace(/(?<![A-Za-z0-9_'\"])0([0-7]{3,})\b/g, '0o$1');
const builtins = {
  json: JSON.parse,
  type: value => value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value === 'number' ? (Number.isInteger(value) ? 'int' : 'double') : typeof value,
  length: value => value.length, keys: Object.keys, index: (a, b) => a.indexOf(b), lc: value => value.toLowerCase(),
  match: (s, re) => s.match(re), split: (s, d) => s.split(d), join: (s, a) => a.join(s), push: (a, b) => a.push(b),
  sort: value => value.sort(), int: value => Math.trunc(Number(value)), substr: (s, a, b) => b === undefined ? s.slice(a) : s.slice(a, a + b),
  ord: (s, i = 0) => s.charCodeAt(i), chr: String.fromCharCode, min: Math.min,
  sprintf: (format, value) => Number(value).toString(8).padStart(Number(format.match(/%0(\d+)o/)[1]), '0'),
  die: message => { throw new Error(message); },
};
const context = vm.createContext({ ...builtins });
vm.runInContext(adapt(fs.readFileSync(path.join(tools, 'bundle-transport-model.uc'), 'utf8')) +
  '\nglobalThis.api={manifest,descriptor,canonical_descriptor,zeros,header,selection,logical_name};', context);
const model = context.api;
const parsed = model.descriptor(descriptor, model.manifest(originalSums), name => sha(name));
assert.equal(model.canonical_descriptor(descriptor), fs.readFileSync(path.join(transport, 'bundle-transport.json'), 'utf8'));
const selectedName = Object.keys(descriptor.entries)[0];
const select = row => `asset ${selectedName} ${row.sha256} ${row.bytes}\n`;
const plan = select(descriptor.entries[selectedName]);
let cases = 0;

function io() {
  return {
    lstat: filename => {
      try { const s = fs.lstatSync(filename); return { type: s.isDirectory() ? 'directory' : s.isSymbolicLink() ? 'link' : 'file', uid: 0, gid: 0,
        mode: s.mode, nlink: s.nlink, size: s.size, inode: s.ino, dev: s.dev, mtime: s.mtimeMs, ctime: s.ctimeMs }; } catch { return null; }
    },
    readfile: (filename, limit) => { const body = fs.readFileSync(filename); return body.subarray(0, limit).toString('latin1'); },
    unlink: filename => { fs.unlinkSync(filename); return true; },
    open: (filename, mode, acl) => {
      const fd = fs.openSync(filename, mode === 're' ? 'r' : 'wx', acl); let position = 0;
      return {
        read: length => { const body = Buffer.alloc(length); const n = fs.readSync(fd, body, 0, length, position); position += n; return body.subarray(0, n).toString('latin1'); },
        write: value => { const n = fs.writeSync(fd, Buffer.from(value, 'latin1')); return n; },
        seek: (offset, origin) => { assert.equal(origin, 0); position = offset; return true; },
        flush: () => true, close: () => { fs.closeSync(fd); return true; },
      };
    },
    popen: (command, mode) => {
      if (mode === 'r') {
        const name = command.match(/^printf %s ([A-Za-z0-9][A-Za-z0-9_.-]{0,159}) \| sha256sum$/)?.[1];
        assert.ok(name); return { read: () => sha(name) + '  -\n', close: () => 0 };
      }
      const destination = command.match(/^umask 077; sha256sum > (\/tmp\/foxhole-core-install\.[A-Za-z0-9]{6}\/\.bundle-hash)$/)?.[1];
      assert.ok(destination); const digest = crypto.createHash('sha256');
      return { write: value => { digest.update(Buffer.from(value, 'latin1')); return value.length; },
        close: () => { fs.writeFileSync(destination, digest.digest('hex') + '  -\n', { flag: 'wx', mode: 0o600 }); return 0; } };
    },
  };
}

function canonical(value) {
  const sorted = x => x && typeof x === 'object' ? Object.fromEntries(Object.keys(x).sort().map(k => [k, sorted(x[k])])) : x;
  return JSON.stringify(sorted(value)) + '\n';
}

function run(label, edit, shouldFail = true) {
  const stage = fs.mkdtempSync('/tmp/foxhole-core-install.');
  fs.chmodSync(stage, 0o700);
  const state = { archive: Buffer.from(archive), descriptor: structuredClone(descriptor), plan, rawDescriptor: null };
  edit?.(state);
  state.descriptor.archive.bytes = state.archive.length;
  state.descriptor.archive.sha256 = sha(state.archive);
  const text = state.rawDescriptor ?? canonical(state.descriptor);
  const sums = originalSums.replace(/^[a-f0-9]{64}  native-install\.tar$/m, sha(state.archive) + '  native-install.tar')
    .replace(/^[a-f0-9]{64}  bundle-transport\.json$/m, sha(text) + '  bundle-transport.json');
  fs.writeFileSync(path.join(stage, 'native-install.tar'), state.archive, { mode: 0o600 });
  fs.writeFileSync(path.join(stage, 'bundle-transport.json'), text, { mode: 0o600 });
  fs.writeFileSync(path.join(stage, 'SHA256SUMS'), sums, { mode: 0o600 });
  fs.writeFileSync(path.join(stage, 'plan.list'), state.plan, { mode: 0o600 });
  const ctx = vm.createContext({ ...builtins, fs: io(), model, ARGV: ['extract', stage], printf: () => assert.fail('unexpected output') });
  const call = () => vm.runInContext(adapt(fs.readFileSync(path.join(tools, 'bundle-transport.uc'), 'utf8')), ctx, { timeout: 5000 });
  try {
    if (shouldFail) assert.throws(call, /Invalid|Error/, label);
    else {
      call(); assert.ok(fs.existsSync(path.join(stage, selectedName)));
      const other = Object.keys(descriptor.entries).find(x => x !== selectedName);
      assert.ok(!fs.existsSync(path.join(stage, other)));
      assert.equal(sha(fs.readFileSync(path.join(stage, selectedName))), descriptor.entries[selectedName].sha256);
    }
    cases++;
  } finally { fs.rmSync(stage, { recursive: true, force: true }); }
}

function checksum(body, offset = 0) {
  body.fill(32, offset + 148, offset + 156);
  const sum = body.subarray(offset, offset + 512).reduce((a, b) => a + b, 0);
  body.write(sum.toString(8).padStart(6, '0') + '\0 ', offset + 148, 'latin1');
}

try {
  run('actual producer header parity and selected-only extraction', null, false);
  run('unsigned unselected content mismatch', x => { x.archive[512 + 1] ^= 1; });
  run('signed outer but content padding nonzero', x => { x.archive[512 + descriptor.entries[Object.keys(descriptor.entries).sort()[0]].bytes] = 1; });
  run('link type even with valid checksum', x => { x.archive[156] = 50; checksum(x.archive); });
  run('PAX type rejected', x => { x.archive[156] = 120; checksum(x.archive); });
  run('nonzero canonical root uid', x => { x.archive[114] = 49; checksum(x.archive); });
  run('unknown member derived-name mismatch', x => { x.archive[2] = x.archive[2] === 97 ? 98 : 97; checksum(x.archive); });
  run('duplicate member', x => { x.archive.copy(x.archive, 1024, 0, 512); });
  run('missing member', x => { x.archive.fill(0, 1024); });
  run('nonzero trailing bytes', x => { x.archive[x.archive.length - 1] = 1; });
  run('concatenated TAR', x => { x.archive = Buffer.concat([x.archive, archive]); });
  run('wrong selected exact bytes', x => { x.plan = plan.replace(/ \d+\n$/, ' 1\n'); });
  run('duplicate JSON schema key', x => { const base = canonical(x.descriptor); x.rawDescriptor = base.replace('"schema":1}', '"schema":1,"schema":1}'); });
  assert.throws(() => model.manifest(originalSums + '0'.repeat(64) + '  ' + selectedName.toUpperCase() + '\n'));
  cases++;
  const bad = structuredClone(descriptor); bad.archive.bytes = 536870912 + 512;
  assert.throws(() => model.descriptor(bad, { ...model.manifest(originalSums), 'native-install.tar': bad.archive.sha256 }, name => sha(name)));
  cases++;
  const shell = fs.readFileSync(path.join(tools, 'install-compact.sh'), 'utf8');
  assert.ok(shell.indexOf('transport_ram=$((ram * 1024 - transport_budget))') < shell.indexOf('fetch_flat native-install.tar'));
  assert.ok(shell.indexOf('> "$stage/compact-budget.json"') < shell.indexOf('fetch_flat native-install.tar'));
  assert.ok(shell.includes('apk --keys-dir "$directory/keys" verify "$stage/$file"'));
  assert.ok(shell.includes("Existing FoxHole state requires paired management"));
  cases++;
  console.log(JSON.stringify({ cases, producerHeaderParity: true, nativeUcodeStockProcessAPI: 'UNRUN', actualAPKOrRouterAcceptance: null }));
} finally { fs.rmSync(temp, { recursive: true, force: true }); }
