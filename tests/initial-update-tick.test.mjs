import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { functionBody, packageRoot, read } from './helpers.mjs';

const path = packageRoot + '/root/usr/share/foxhole/';
const source = await read(path + 'update-model.uc');
const types = v => v == null ? 'null' : typeof v === 'boolean' ? 'bool' : Number.isInteger(v) ? 'int' : typeof v;
const shared = vm.createContext({ type: types, lc: s => s.toLowerCase(), die: s => { throw Error(s); } });
function define(program, context, name, args) {
 vm.runInContext(`function ${name}(${args}) ${functionBody(program, name)}`, context);
}
for (const [name, args] of Object.entries({ fail:'reason', safe_int:'value', initial_owner_policy:'auth',
 policy:'value,auth', due:'value,now,busy', auto_authorized:'job,value' })) define(source, shared, name, args);

function controller(program, role, owner, saved) {
 const files = new Map([['/etc/foxhole/auth.json', owner], ['policy', saved]]);
 const launches = [];
 let record = { revision: 0, availability: 'NOT_CHECKED' };
 const principal = { id: 'synthetic-review-owner' };
 const read = key => structuredClone(files.get(key) ?? null);
 const write = (key, value) => files.set(key, structuredClone(value));
 const authorize = who => { if (who !== principal) throw Error('unauthorized'); return who.id; };
 const c = vm.createContext({
  JOB:'job', POLICY:'policy', type:types, model:{policy:shared.policy,due:shared.due,auto_authorized:shared.auto_authorized,
    integer:Number.isInteger,fail:shared.fail}, updates:shared,
  read, write, state:() => ({ ...record }), save_state:value => { record = { ...value, revision:value.revision+1 }; },
  current_state:() => ({ ...record }), current_version:() => '1.0.8-r2', current:() => ({version:'1.0.7-r2'}),
  engine:{update_locked:fn=>fn(),update_principal_current:who=>who===principal},
  transaction:fn=>fn(), backup_service:{guard(){}}, core_upload:{busy:()=>false},
  engine_busy:()=>false, ram_selected:()=>false, reconcile(){}, blocked:()=>false, expire_upload:()=>null,
  require_idle(){}, cleanup_pending_assets(){}, principal_current:authorize, fail:shared.fail,
  check_revision:(wanted, state)=>assert.equal(wanted,state.revision), stop_intent:()=>0,
  new_job:(operation, who, automatic, plan)=>({operation,automatic,principal:who,plan,policyRevision:c.policy().revision,
   stopIntent:0, jobId:'fixture-job',state:'QUEUED'}),
  make_plan:(owner, automatic)=>({owner,automatic}), save_job:job=>write('job',job),
  launch:job=>{ launches.push(job); return job; }, time:()=>1700000000, wall:()=>1700000000000
 });
 for (const [name,args] of [['policy',''], ['tick',''], ['check','request,principal'],
  [role==='FLASH'?'auto_conversion_allowed':'automatic_apply','job']]) define(program,c,name,args);
 return { c, launches, files, read, write, principal, available() {record.availability='AVAILABLE';} };
}

for (const [role, name] of [['FLASH','update-service.uc'], ['RAM','ram-update-service.uc']]) {
 const program = await read(path + name);
 test(`${role} scheduler uses the enrolled choice, respects a saved off, and manual check stays available`, () => {
  for (const [owner,saved,enabled] of [
   [null,null,false], [{changed:false,initialPackageAutoUpdate:true},null,false],
   [{changed:true},null,false], [{changed:true,initialPackageAutoUpdate:false},null,false],
   [{changed:true,initialPackageAutoUpdate:true},null,true],
   [{changed:true,initialPackageAutoUpdate:true},{schema:1,revision:5,enabled:false,lastAttemptAtUnixMs:null},false],
   [{changed:true,initialPackageAutoUpdate:false},{schema:1,revision:5,enabled:true,lastAttemptAtUnixMs:null},true]
  ]) {
   const f=controller(program,role,owner,saved);
   f.c.tick();
   assert.equal(f.launches.length, enabled ? 1 : 0);
   if (enabled) {
    const job=f.read('job');
    assert.equal(job.automatic,true); assert.equal(job.operation,'CHECK');
    const policy=f.read('policy');
    assert.equal(policy.lastAttemptAtUnixMs,1700000000000); assert.equal(policy.revision,saved?.revision??0);
    f.c.tick(); assert.equal(f.launches.length,1);
    f.available(); job.state='SUCCEEDED'; f.write('job',job);
    if (role==='FLASH') assert.equal(f.c.auto_conversion_allowed(job),true);
    else assert.equal(f.c.automatic_apply(job).operation,'APPLY');
    f.write('policy',{...policy,enabled:false,revision:policy.revision+1});
    f.write('job',job);
    if (role==='FLASH') assert.equal(f.c.auto_conversion_allowed(job),false);
    else assert.equal(f.c.automatic_apply(job),null);
   } else {
    assert.deepEqual(f.read('policy'),saved);
    assert.throws(()=>f.c.check({expectedRevision:0},{}));
    const job=f.c.check({expectedRevision:0},f.principal);
    assert.equal(job.operation,'CHECK'); assert.equal(job.automatic,false); assert.equal(f.launches.length,1);
    assert.deepEqual(f.read('policy'),saved);
   }
  }
 });
}
