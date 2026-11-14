import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { read, packageRoot, functionBody, plain } from './helpers.mjs';

const source = await read(`${packageRoot}/root/usr/share/foxhole/update-service.uc`);
function fixture({ ramSelected = false, failure = false } = {}) {
  let reads = 0;
  const scope = vm.createContext({
    ram_selected: () => ramSelected,
    ram: { deployment: () => ({ storage: 'RAM', version: '1.0.8-r2', generation: 'retained' }) },
    current_version: () => { reads++; if (failure) throw Error('invalid installed identity'); return '1.0.8-r2'; }
  });
  vm.runInContext(`function deployment() ${functionBody(source, 'deployment')}`, scope);
  return { read: () => plain(scope.deployment()), reads: () => reads };
}
test('FLASH status reports the verified installed package version', () => {
  const value = fixture();
  assert.deepEqual(value.read(), { storage: 'FLASH', version: '1.0.8-r2' });
  assert.equal(value.reads(), 1);
});
test('FLASH status keeps an unavailable version honest without breaking discovery', () => {
  const value = fixture({ failure: true });
  assert.deepEqual(value.read(), { storage: 'FLASH', version: null });
  assert.equal(value.reads(), 1);
});
test('RAM status retains its own generation and never reads a FLASH identity', () => {
  const value = fixture({ ramSelected: true });
  assert.deepEqual(value.read(), { storage: 'RAM', version: '1.0.8-r2', generation: 'retained' });
  assert.equal(value.reads(), 0);
});
