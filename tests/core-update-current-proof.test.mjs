import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { read, functionBody, packageRoot } from './helpers.mjs';
const source = await read(`${packageRoot}/root/usr/share/foxhole/core-update-service.uc`);
function proof() {
 const clock = { now: 1793000000000 }, current = { selected: { revision: 1 }, managed: { version: '1.0.6-r1' }, binding: { stopIntent: 0 }, highest: { sequence: 1 } };
 const candidate = { component: 'CORE', changes: [], checkedAtUnixMs: clock.now,
  selected: structuredClone(current.selected), managed: structuredClone(current.managed), binding: structuredClone(current.binding),
  reference: structuredClone(current.highest) };
 const scope = vm.createContext({ time: () => clock.now / 1000,
  type: value => Array.isArray(value) ? 'array' : typeof value, length: value => value.length,
  same: (a, b) => JSON.stringify(a) === JSON.stringify(b), current_binding: () => current.binding,
  registry: { read: () => current.selected }, transaction: { context: () => current.managed }, catalog: { highest: () => current.highest } });
 for (const name of ['valid', 'recent_current', 'current_identity'])
  vm.runInContext(`function ${name}(${name === 'valid' ? 'candidate' : 'value'}) ${functionBody(source, name)}`, scope);
 return { clock, current, candidate, read: () => scope.recent_current({ coreCheckedCandidate: candidate }),
  identity: () => scope.current_identity({ coreCheckedCandidate: candidate }) };
}
test('only a fresh zero-change Core proof can advance a later BASE check', () => {
 const h = proof(); assert.equal(h.read(), h.candidate);
 h.candidate.changes.push({ id: 'vless' }); assert.equal(h.read(), null);
});
test('a higher seen cohort also invalidates a previously current public identity', () => {
 const h = proof(); assert.equal(h.identity(), true); h.current.highest.sequence++;
 assert.equal(h.identity(), false); assert.equal(h.read(), null);
});
test('expired clock Stop selected modules and managed generation invalidate cached Core proof', () => {
 for (const mutate of [h => { h.clock.now += 300001; }, h => { h.clock.now--; },
  h => { h.current.binding.stopIntent++; }, h => { h.current.selected.revision++; },
  h => { h.current.managed.version = '1.0.7-r1'; }, h => { h.current.highest.sequence++; }]) {
  const h = proof(); mutate(h); assert.equal(h.read(), null);
 }
});

test('empty managed registry on a RAM-only BASE does not require a host FLASH identity',()=>{
 const selected={selected:[]}, legacy=[];
 const scope=vm.createContext({registry:{read:()=>selected,legacy_protocols:()=>legacy},
  native:{selected_modules:r=>r.selected,target:()=>{if(selected.unknownTarget)throw Error('UNSUPPORTED_TARGET')}},length:r=>r.length,transaction:{context:()=>{throw Error('unsupported-host-base')}},
  guard:{fail:reason=>{throw Error(reason)}}});
 vm.runInContext(`function check(directory) ${functionBody(source,'check')}`,scope);
 assert.equal(scope.check('/fixture'),null);
 selected.unknownTarget=true;assert.throws(()=>scope.check('/fixture'),/UNSUPPORTED_TARGET/);selected.unknownTarget=false;
 legacy.push('vless');assert.throws(()=>scope.check('/fixture'),/UNSUPPORTED_TARGET/);
 legacy.length=0;selected.selected.push({id:'vless'});assert.throws(()=>scope.check('/fixture'),/unsupported-host-base/);
});
