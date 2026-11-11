import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { read, packageRoot, plain } from './helpers.mjs';

const source = await read(`${packageRoot}/root/usr/share/foxhole/core-update-model.uc`);
const H = 'a'.repeat(64), J = 'b'.repeat(64), C = 'c'.repeat(40);
const now = 1_793_000_000_000;
function fixture() {
 return { schema: 1, feedAbi: 1, channel: 'stable', sequence: 5,
  coreVersion: '1.0.4', releaseTag: 'v1.0.4', publishedAtUnixMs: now - 1000,
  expiresAtUnixMs: now + 86_400_000,
  compatibility: { stateAbi: 1, transactionAbi: 1, routerContractVersion: 1,
   osRelease: '25.12.5', targets: ['x86/64', 'mediatek/filogic'], minimumBaseVersion: '1.0.6-r1' },
  source: { producerCommit: C, publisherCommit: 'd'.repeat(40), publisherTree: 'e'.repeat(40),
   sourceContentSha256: H, sourceManifestSha256: H, signatureReceiptSha256: H, contentJoinReceiptSha256: H },
  catalog: { schema: 1, entries: [{ id: 'vless', storage: 'FLASH', architecture: 'x86_64',
   version: '1.0.4', sourceCommit: C }] } };
}
const context = { nowUnixMs: now, osRelease: '25.12.5', target: 'x86/64',
 architecture: 'x86_64', baseComparison: '=', coreComparison: '<' };
function model() {
 const scope = vm.createContext({
  type: value => value === null ? 'null' : Array.isArray(value) ? 'array' :
   typeof value === 'number' && Number.isInteger(value) ? 'int' : typeof value,
  length: value => typeof value === 'string' || Array.isArray(value) ? value.length : Object.keys(value).length,
  keys: Object.keys, index: (values, value) => values.indexOf(value), match: (text, expression) => text.match(expression),
  substr: (value, start, count) => count == null ? value.slice(start) : value.slice(start, start + count),
  sprintf: (_format, value) => JSON.stringify(value), json: JSON.parse,
  die: message => { throw new Error(message); }
 });
 vm.runInContext(source.replaceAll('export function ', 'function ').replaceAll('export const ', 'const '), scope);
 return scope;
}
function rejected(value, ctx = context, previous = { sequence: 4, sha256: J }, digest = H) {
 assert.throws(() => model().feed(value, ctx, previous, digest), /update_/);
}

test('stable feed retains its exact producer and compatibility identity', () => {
 assert.deepEqual(plain(model().feed(fixture(), context, { sequence: 4, sha256: J }, H)), fixture());
});
test('signed feed ABI must match the compiled consumer ABI', () => {
 for (const feedAbi of [null, 2, '1']) rejected({ ...fixture(), feedAbi });
});
test('channel changes and caller-selected origin or key fields are refused', () => {
 for (const patch of [{ channel: 'dev' }, { origin: 'https://foreign.invalid/' }, { key: 'replacement' }])
  rejected({ ...fixture(), ...patch });
});
test('missing or incompatible consumer ABI and BASE admission are refused', () => {
 for (const patch of [{ stateAbi: 2 }, { transactionAbi: 2 }, { routerContractVersion: 2 },
  { stateAbi: '1' }, { transactionAbi: '1' }, { routerContractVersion: '1' },
  { osRelease: '25.12.6' }, { minimumBaseVersion: '../version' }]) {
  const value = fixture(); Object.assign(value.compatibility, patch); rejected(value);
 }
 rejected(fixture(), { ...context, baseComparison: '<' });
});
test('unknown target and architecture do not inherit another platform proof', () => {
 rejected(fixture(), { ...context, target: 'other/board' });
 rejected(fixture(), { ...context, architecture: 'armv7' });
 rejected(fixture(), { ...context, target: 'mediatek/filogic', architecture: 'x86_64' });
});
test('source receipt digests and commits are mandatory and closed', () => {
 for (const patch of [{ producerCommit: 'missing' }, { signatureReceiptSha256: '' },
  { contentJoinReceiptSha256: 'unknown' }, { verified: true }]) {
  const value = fixture(); Object.assign(value.source, patch); rejected(value);
 }
});
test('feed replay, same-sequence changed bytes and native Core downgrade are refused', () => {
 rejected(fixture(), context, { sequence: 6, sha256: H });
 rejected(fixture(), context, { sequence: 5, sha256: J });
 rejected(fixture(), { ...context, coreComparison: '>' });
 assert.equal(model().feed(fixture(), context, { sequence: 5, sha256: H }, H).sequence, 5);
});
test('expired, future-issued and untrusted-clock metadata stay unavailable', () => {
 rejected({ ...fixture(), expiresAtUnixMs: now - 1 });
 rejected({ ...fixture(), publishedAtUnixMs: now + 300_001 });
 rejected(fixture(), { ...context, nowUnixMs: 0 });
});
test('catalog producer version and source must match the signed feed', () => {
 for (const patch of [{ version: '1.0.3' }, { sourceCommit: 'f'.repeat(40) }]) {
  const value = fixture(); Object.assign(value.catalog.entries[0], patch); rejected(value);
 }
 rejected({ ...fixture(), releaseTag: 'v1.0.5' });
 rejected({ ...fixture(), catalog: { schema: 1, entries: [] } });
});

test('an already signed and selected package remains usable after discovery expiry', () => {
 const value = fixture();
 const installed = { schema: 1, sequence: value.sequence, coreVersion: value.coreVersion,
  packageVersion: '1.0.4-r1', bodySha256: H, bodyBytes: 1024,
  archiveSha256: H, archiveBytes: 2048, indexSha256: J, indexBytes: 512 };
 const later = { ...context, nowUnixMs: now + 2 * 86_400_000 };
 rejected(value, later, { sequence: 5, sha256: H });
 assert.equal(model().cached_feed(value, later, installed).sequence, 5);
 assert.throws(() => model().cached_feed(value, later, { ...installed, sequence: 6 }), /identity_conflict/);
});
