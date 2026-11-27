import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { functionBody, read, packageRoot } from './helpers.mjs';

const source=await read(`${packageRoot}/root/usr/share/foxhole/engine-service.uc`);
const plain=v=>JSON.parse(JSON.stringify(v));

function fixture() {
 const old={schema:1,revision:5,slots:[{id:'vless'}],selected:[{id:'vless',slotId:'owned'}]};
 const ctx={activeEngineId:'wireguard',bootId:'a'},session={verifier:'owner'};
 const job={owner:'bound',principal:session,previousRegistry:old,bootId:'a',planId:'repair',plan:{operation:'REINSTALL',planId:'repair',planSha256:'planhash',owner:'bound',
   binding:ctx,artifacts:[{id:'vless',version:'1.0.4'}]},worldBefore:['base']};
 const data={reg:plain(old),identity:'before',world:['base'],damaged:true,nativeRuns:0,diagnostics:0,worldChecks:0,repairs:0,events:[],spoofSim:false,invalidOutput:false,corruptAfter:false};
 const fail=reason=>{throw Error(reason)};
 const scope=vm.createContext({fs:{lstat:()=>null},state:()=>({}),principal_current:()=>true,owner:()=> 'bound',
  registry:{snapshot_context:()=>ctx,read:()=>data.reg,write:r=>{data.reg=plain(r)},verify_slot:()=>'/safe/cli',capture:()=>({platform:'linux',router_contract_version:1,core_version:'1.0.4',protocols:['vless']})},
  engines:{reinstall_bound:()=>true,world_pins:(a,b)=>{data.worldChecks++;return JSON.stringify(a)===JSON.stringify(b)},reinstall_only:raw=>raw==='EXACT',
   admit_apply:()=>true},packages:{world:()=>data.world,repair_diagnosis:()=>{data.diagnostics++;return [{damagedPackageFiles:data.damaged?1:0,ramBinaryVerified:true}]},
   apk:args=>{if(args.includes('--simulate')){data.events.push('simulate');return data.spoofSim?'EXTRA':'EXACT'}assert.ok(job.mutationStarted);
    assert.ok(job.reinstallDiagnosis);data.nativeRuns++;data.events.push('fix');data.damaged=data.corruptAfter;return data.invalidOutput?'EXTRA':'EXACT'},
   repair_ram:()=>{data.repairs++},decode:v=>v},reinstall_identity:()=>data.identity,length:v=>v.length,filter:(v,f)=>v.filter(f),
  sprintf:(_,v)=>JSON.stringify(v),fail,nonce:()=> 'a'.repeat(64),now:()=>1000,write:()=>{},JOB:'job',
  progress:(j,s,step,p)=>Object.assign(j,{state:s,step,progressPercent:p})});
 for(const [name,args] of [['repair_state','job,old'],['reinstall','job,old,batch,directory,recovery']])
  vm.runInContext(`function ${name}(${args}) ${functionBody(source,name).replace(/for\(let (\w+) in /g,'for(let $1 of ')}`,scope);
 return {old,job,data,run:(recovery=false)=>scope.reinstall(job,old,{items:[{value:{id:'vless',version:'1.0.4'}}],roots:['owned-name'],common:[]},'/scratch',recovery)};
}
test('normal reinstall diagnoses first, fixes once and preserves registry selections',()=>{
 const f=fixture();f.run();
 assert.deepEqual(f.data.events,['simulate','fix']);assert.equal(f.data.nativeRuns,1);assert.equal(f.data.repairs,1);assert.equal(f.data.diagnostics,2);
 assert.equal(f.job.state,'SUCCEEDED');assert.equal(f.data.reg.revision,6);assert.deepEqual(f.old.selected,f.data.reg.selected);
});
test('unexpected simulated changes are refused before mutation and corrupt post-state cannot commit',()=>{
 const f=fixture();f.data.spoofSim=true;assert.throws(()=>f.run(),/PACKAGE_VERIFICATION_FAILED/);assert.equal(f.data.nativeRuns,0);assert.equal(f.job.mutationStarted,undefined);
 const g=fixture();g.data.corruptAfter=true;assert.throws(()=>g.run(),/PACKAGE_VERIFICATION_FAILED/);assert.equal(g.data.reg.revision,5);assert.equal(g.job.mutationStarted,true);
 g.data.world=['other'];assert.throws(()=>g.run(true),/PACKAGE_VERIFICATION_FAILED/);assert.equal(g.data.nativeRuns,1);
});
test('recovery retries the exact interrupted action once; cannot adopt native drift or unrelated revisions',()=>{
 const f=fixture();f.job.mutationStarted=true;f.job.reinstallInstalledSha256='before';f.job.reinstallDiagnosis=[{id:'vless',damagedPackageFiles:1,ramBinaryVerified:true}];f.run(true);
 assert.equal(f.data.nativeRuns,1);assert.equal(f.job.reinstallRecoveryAttempted,true);assert.equal(f.job.state,'SUCCEEDED');
 const g=fixture();g.job.mutationStarted=true;g.job.reinstallInstalledSha256='before';g.data.identity='changed';
 assert.throws(()=>g.run(true),/RECOVERY_REQUIRED/);assert.equal(g.data.nativeRuns,0);
 const h=fixture();h.data.reg.revision=6;assert.throws(()=>h.run(true),/STALE_PLAN/);
});
test('recovery verifies a completed native fix; an unconfirmed repair cannot be labelled successful',()=>{
 const f=fixture();f.job.reinstallInstalledSha256='before';f.job.reinstallNativeDone=true;f.data.damaged=false;f.run(true);
 assert.equal(f.data.nativeRuns,0);assert.equal(f.job.state,'SUCCEEDED');
 const g=fixture();g.job.reinstallInstalledSha256='before';g.job.reinstallRecoveryAttempted=true;g.data.damaged=false;g.run(true);
 assert.equal(g.data.nativeRuns,0);assert.equal(g.job.state,'FAILED');assert.equal(g.job.failureReason,'ROUTER_UNAVAILABLE');
});
