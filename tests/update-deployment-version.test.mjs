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

test('FLASH ahead of a verified public package reports current without obtaining an unpublished rollback',()=>{
 function run(failure=null){
  const state={revision:3,availability:'NOT_CHECKED'}, stages=[],files=[];
  const fail=error=>{throw Error(error)};
  const context=vm.createContext({
   require_authorized(){},clear_previous_staging(){},store:{directory(){}},progress:(_,stage)=>stages.push(stage),
   current_version:()=>{if(failure==='target')fail('UNSUPPORTED_TARGET');return '1.0.9-r1';},
   native:{prepare_keys:()=>({}),target:()=>({}),policy:()=>({releaseTag:'v1.0.9'}),
    latest:()=>{if(failure==='network')fail('RELEASE_UNAVAILABLE');return 'v1.0.8';},
    base:(tag)=>{files.push(tag);if(failure==='signature')fail('PACKAGE_VERIFICATION_FAILED');assert.equal(tag,'v1.0.8');return {version:'1.0.8-r2'};},
    compare:()=> '>'},
   core_updates:{recent_current:()=>null,check:()=>{if(failure==='legacy')fail('UNSUPPORTED_TARGET');return null;}},
   reason:e=>e.message,model:{fail},registry:{read:()=>[]},current_state:()=>state,context:()=>({}),
   resources(){},transaction:fn=>fn(),index:(a,v)=>a.indexOf(v),length:a=>a.length,authorized:()=>true,
   same:()=>true,binding:x=>x,write(){},STATE:'state',wall:()=>123,
  });
  vm.runInContext(`function perform_check(job) ${functionBody(source,'perform_check')}`,context);
  return {state,files,stages,check:()=>context.perform_check({jobId:'fixture',automatic:false})};
 }
 const ok=run();ok.check();assert.deepEqual(ok.files,['v1.0.8']);
 assert.equal(ok.state.availability,'CURRENT');assert.equal(ok.state.availableVersion,'1.0.9-r1');
 assert.equal(ok.state.candidate,null);assert.equal(ok.stages.at(-1),'SUCCEEDED');
 for(const [failure,cause] of [['target','UNSUPPORTED_TARGET'],['signature','PACKAGE_VERIFICATION_FAILED'],['network','RELEASE_UNAVAILABLE'],['legacy','UNSUPPORTED_TARGET']]){
  const f=run(failure);assert.throws(f.check,new RegExp(cause));assert.notEqual(f.state.availability,'CURRENT');
 }
});
