import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { read, packageRoot, plain } from './helpers.mjs';
const source = await read(`${packageRoot}/root/usr/share/foxhole/core-update-model.uc`);
const H = 'a'.repeat(64), J = 'b'.repeat(64);
const old = { id: 'vless', storage: 'RAM', architecture: 'x86_64', version: '1.0.2',
 packageVersion: '1.0.2-r2', manifestSha256: H, binarySha256: H };
const next = { ...old, version: '1.0.4', packageVersion: '1.0.4-r1', manifestSha256: J, binarySha256: J };
function model() {
 const scope = vm.createContext({
  type: value => value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value,
  length: value => value.length, keys: Object.keys, index: (values, value) => values.indexOf(value),
  push: (values, value) => values.push(value), json: JSON.parse, sprintf: (_format, value) => JSON.stringify(value),
  die: reason => { throw new Error(reason); }
 });
 vm.runInContext(source.replaceAll('export function ', 'function ').replaceAll('export const ', 'const '), scope); return scope;
}
function changes(before = [old], entries = [next], comparisons = { vless: { core: '<', package: '<' } }) {
 return plain(model().module_changes(before, { schema: 1, entries }, 'x86_64', comparisons));
}
test('Core-only updates retain installed IDs and storage without adding catalog protocols', () => {
 const result = changes([old], [next, { ...next, id: 'wireguard' }]);
 assert.deepEqual(result.artifacts, [next]);
 assert.deepEqual(result.changes, [{ id: 'vless', storage: 'RAM', fromVersion: '1.0.2-r2', toVersion: '1.0.4-r1' }]);
 assert.equal(old.version, '1.0.2');
});
test('missing exact storage or target does not silently select another artifact', () => {
 for (const patch of [{ storage: 'FLASH' }, { architecture: 'aarch64_cortex-a53' }])
  assert.throws(() => changes([old], [{ ...next, ...patch }]), /unsupported_target/);
});
test('Core and package downgrades are both refused', () => {
 for (const comparison of [{ core: '>', package: '<' }, { core: '<', package: '>' }])
  assert.throws(() => changes([old], [next], { vless: comparison }), /downgrade_rejected/);
});
test('same package version with another body remains an identity conflict', () => {
 assert.throws(() => changes([old], [next], { vless: { core: '<', package: '=' } }), /version_identity_conflict/);
});
test('a newer wrapper package can retain the exact native Core producer', () => {
 const wrapper = { ...old, packageVersion: '1.0.2-r3', manifestSha256: J };
 assert.deepEqual(changes([old], [wrapper], { vless: { core: '=', package: '<' } }).artifacts, [wrapper]);
 assert.throws(() => changes([old], [{ ...wrapper, binarySha256: J }],
  { vless: { core: '=', package: '<' } }), /version_identity_conflict/);
});
test('exact installed package remains unchanged and duplicate IDs are refused', () => {
 assert.deepEqual(changes([old], [old], { vless: { core: '=', package: '=' } }), { artifacts: [], changes: [] });
 assert.throws(() => changes([old, old]), /package_verification_failed/);
});
