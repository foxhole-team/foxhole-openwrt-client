import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/journal-model.uc', import.meta.url), 'utf8');
const bindings = {
  type: x => x == null ? 'null' : Array.isArray(x) ? 'array' : Number.isInteger(x) ? 'int' : typeof x === 'number' ? 'double' : typeof x === 'boolean' ? 'bool' : typeof x,
  length: x => typeof x === 'string' ? Buffer.byteLength(x) : x.length,
  index: (a, x) => a.indexOf(x), match: (x, re) => x.match(re),
  push: (a, x) => a.push(x), slice: (a, start, end) => a.slice(start, end),
  int: Math.trunc, min: Math.min, max: Math.max,
  sprintf: (_f, x) => JSON.stringify(x), filter: (a, f) => a.filter(f),
  die: x => { throw Error(x); }
};
const model = new Function(...Object.keys(bindings), source.replace(/^export /gm, '') +
  ';return {budget,empty,normalize,merge,bounded,page};')(...Object.values(bindings));
const hash = x => createHash('sha256').update(x).digest('hex');
const boot = 'a'.repeat(8) + '-aaaa-aaaa-aaaa-' + 'a'.repeat(12);
const now = 2000000000000;
const event = n => ({ event: 'tunnel_exited', time: `Nov ${n}`, engine: 'core', exitStatus: 137 });
const snapshot = events => ({ package: { available: true, events }, kernel: { available: true, events: [] } });

test('journal quota is a bounded percentage while preserving system space', () => {
  const value = model.budget(64 * 1024**2, 20 * 1024**2, 0);
  assert.equal(value.limitBytes, Math.floor(20 * 1024**2 * .02));
  assert.ok(value.reserveBytes >= 64 * 1024**2 * .10 - 1);
  assert.ok(model.budget(100 * 1024**3, 50 * 1024**3, 0).limitBytes <= 1024**2);
  assert.throws(() => model.budget(100, -1, 0));
});

test('repeated observations are deduplicated without resetting their retention date', () => {
  const first = model.merge(null, snapshot([event(1)]), now, boot, hash);
  const again = model.merge(first, snapshot([event(1)]), now + 1000, boot, hash);
  assert.equal(again.records.length, 1);
  assert.equal(again.records[0].observedAtUnixMs, now);
});

test('full quota overwrites the oldest entries while preserving the new record', () => {
  let value = null;
  for (let n = 0; n < 40; n++) value = model.merge(value, snapshot([event(n)]), now + n, boot, hash);
  const limited = model.bounded(value, 4096);
  assert.ok(JSON.stringify(limited).length <= 4096);
  assert.ok(limited.records.length > 0 && limited.records.length < 40);
  assert.equal(limited.records.at(-1).event.time, 'Nov 39');
  assert.ok(limited.droppedRecords > 0);
});

test('expired observations disappear and do not reappear from an unchanged source', () => {
  const first = model.merge(null, snapshot([event(1)]), now, boot, hash);
  const later = model.merge(first, snapshot([event(1)]), now + 31 * 86400000, boot, hash);
  assert.equal(later.records.length, 0);
  assert.equal(model.merge(later, snapshot([event(1)]), now + 32 * 86400000, boot, hash).records.length, 0);
});

test('paging has a stable sequence cursor and stored data never exposes unknown payload fields', () => {
  let value = null;
  for (let n = 0; n < 10; n++) value = model.merge(value, snapshot([{ ...event(n), password: 'not-retained' }]), now + n, boot, hash);
  assert.ok(!JSON.stringify(value).includes('not-retained'));
  const first = model.page(value, 0, 4), second = model.page(value, first.beforeSequence, 4);
  assert.equal(first.entries.length, 4);
  assert.equal(second.entries.length, 4);
  assert.ok(Math.max(...second.entries.map(x => x.sequence)) < Math.min(...first.entries.map(x => x.sequence)));
  assert.throws(() => model.normalize({ schema: 99, kind: 'not-a-journal' }));
});
