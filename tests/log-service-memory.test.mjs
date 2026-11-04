import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = '../package/foxhole-openwrt-client/root/usr/share/foxhole/';
const serviceSource = readFileSync(new URL(root + 'log-service.uc', import.meta.url), 'utf8');
const modelSource = readFileSync(new URL(root + 'log-model.uc', import.meta.url), 'utf8');
const bindings = {
  type: value => value == null ? 'null' : Array.isArray(value) ? 'array' :
    Number.isInteger(value) ? 'int' : typeof value === 'boolean' ? 'bool' : typeof value,
  length: value => typeof value === 'string' ? Buffer.byteLength(value) : value.length,
  split: (value, separator) => value.split(separator), match: (value, pattern) => value.match(pattern),
  index: (value, item) => value.indexOf(item), push: (values, item) => values.push(item),
  shift: values => values.shift(), substr: (value, start, count) => value.substr(start, count),
  int: value => Math.trunc(Number(value)), min: Math.min, max: Math.max,
  die: () => { throw Error('invalid_log_data'); },
};
const model = new Function(...Object.keys(bindings), modelSource.replace(/^export /gm, '')
  .replace(/for \(let (\w+) in /g, 'for (let $1 of ') +
  ';return {package_events,kernel_events,core_status,runtime_status};')(...Object.values(bindings));

function fixture(initialMemory) {
  let memory = initialMemory;
  let now = 100;
  let phase = 'connected';
  const captures = [];
  const bodies = () => ({
    '/tmp/foxhole/runtime.json': JSON.stringify({ phase, connected: phase === 'connected', enforced: true }),
    '/tmp/foxhole/core-state.json': JSON.stringify({ schema_version: 1, phase: 'running', protocol: 'hysteria2' }),
  });
  const fs = {
    lstat(path) {
      if (path === '/tmp/foxhole') return { type: 'directory', uid: 0, mode: 0o700 };
      const raw = bodies()[path];
      return raw == null ? null : { type: 'file', uid: 0, mode: 0o600, nlink: 1,
        size: Buffer.byteLength(raw), inode: 1, mtime: 1, ctime: 1 };
    },
    readfile(path) {
      if (path === '/proc/meminfo') return memory == null ? '' : `MemAvailable: ${memory} kB\n`;
      if (path === '/proc/uptime') return `${now}.50 0.00\n`;
      return bodies()[path] ?? null;
    },
  };
  const registry = { capture(argv) { captures.push([...argv]); return ''; } };
  const code = serviceSource.replace(/^import .*;\n/gm, '').replace(/^export /gm, '');
  const service = new Function(...Object.keys(bindings), 'fs', 'registry', 'model', 'time', 'filter', 'json',
    code + ';return {status};')(...Object.values(bindings), fs, registry, model, () => now,
    (values, predicate) => values.filter(predicate), JSON.parse);
  return { status: service.status, captures, memory: value => { memory = value; },
    time: value => { now = value; }, phase: value => { phase = value; } };
}

for (const memory of [null, 0, 32767]) {
  test(`no child collector is started with unavailable or insufficient RAM (${memory})`, () => {
    const value = fixture(memory);
    const result = value.status();
    assert.equal(value.captures.length, 0);
    assert.deepEqual(result.package, { available: false, events: [] });
    assert.deepEqual(result.kernel, { available: false, events: [] });
    assert.equal(result.core.eventsAvailable, false);
    assert.equal(result.runtime.phase, 'connected');
    assert.equal(result.core.phase, 'running');
    assert.equal(result.memAvailableKiB, memory);
  });
}

test('admitted collectors keep the existing two commands and three-second cache', () => {
  const value = fixture(32768);
  const first = value.status();
  assert.deepEqual(value.captures, [['/sbin/logread', '-l', '128', '-e', 'foxhole'], ['/bin/dmesg']]);
  assert.equal(first.package.available, true);
  assert.equal(first.kernel.available, true);
  value.time(102);
  assert.equal(value.status(), first);
  assert.equal(value.captures.length, 2);
  value.time(103);
  assert.notEqual(value.status(), first);
  assert.equal(value.captures.length, 4);
});

test('low RAM cannot reuse a cached success and still returns fresh typed state', () => {
  const value = fixture(40000);
  value.status();
  value.time(101); value.memory(6000); value.phase('error');
  const result = value.status();
  assert.equal(value.captures.length, 2);
  assert.equal(result.runtime.phase, 'error');
  assert.equal(result.memAvailableKiB, 6000);
  assert.equal(result.collectedAtUnixMs, 101000);
  assert.deepEqual(result.package, { available: false, events: [] });
  assert.deepEqual(result.kernel, { available: false, events: [] });
  value.time(102); value.memory(40000);
  assert.equal(value.status().package.available, true);
  assert.equal(value.captures.length, 4);
});
