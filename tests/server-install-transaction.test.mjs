import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const source=readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/server-install-service.uc',import.meta.url),'utf8');
const adapted=source.replace(/^import .*;\n/gm,'').replace(/^export /gm,'').replace(/for \(let (\w+) in /g,'for (let $1 of ');
const sha=s=>createHash('sha256').update(s).digest('hex'), clone=x=>JSON.parse(JSON.stringify(x));
const statePath='/etc/foxhole/state.json',jobPath='/etc/foxhole/vpn-server-job.json';
function fixture(){
 const original={schema:1,revision:7,settings:{vpnServerEnabled:false,killSwitch:true},clients:[{id:'keep',secret:'keep-secret'}],devices:[{id:'paired',address:'192.168.8.2'}]};
 const files=new Map([[statePath,JSON.stringify(original)]]),events=[],principal={kind:'admin',user:'root',verifier:'owner'};
 const descriptor={server:{runtimeMemoryBytes:1},ramReserveBytes:16777216,flashReserveBytes:16777216};
 const binding={stateRevision:7,owner:sha(JSON.stringify(principal)),nativeDbSha256:'a'.repeat(64),worldSha256:'b'.repeat(64),flashAvailableBytes:1e9,ramAvailableBytes:1e9};
 const plan={schema:1,planSha256:'c'.repeat(64),revision:7,descriptor,binding,assets:[],downloadBytes:0};
 const env={pointer:null,authorized:true,fail:null,dbChanged:false,started:1000,instances:{},alive:false,openPorts:false};
 const staged={schema:1,planSha256:plan.planSha256,directory:'owned-generation',descriptor};
 const builtin={
  ubus:{connect:()=>({call:()=>({'foxhole-inbound-services':{instances:env.instances}}),disconnect(){}})},
  registry:{capture:()=>JSON.stringify({nftables:[{set:{family:'inet',table:'fw4',name:'foxhole_inbound_ports',elem:env.openPorts?[14443]:[]}}]})},
  sleep:ms=>{events.push(['sleep',ms]);return true;},push:(a,x)=>a.push(x),
  fs:{lstat:path=>path.endsWith('state.lock')?{type:'file',uid:0,mode:0o600,nlink:1,inode:1}:files.has(path)?{type:'file',uid:0,mode:0o600,nlink:1,inode:1}:null,unlink:path=>files.delete(path),open:()=>({lock:()=>true,close(){}}),readfile:()=> 'random-sixteen!!'},
  digest:{sha256:sha},type:x=>x==null?'null':Array.isArray(x)?'array':Number.isInteger(x)?'int':typeof x==='boolean'?'bool':typeof x,
  sprintf:(_f,x)=>JSON.stringify(x),json:JSON.parse,keys:Object.keys,index:(a,x)=>a.indexOf(x),length:x=>x?.length??0,filter:(a,f)=>a.filter(f),
  match:(s,re)=>s.match(re),hexenc:()=> '1'.repeat(32),die:x=>{throw Error(x);},
  store:{read:path=>files.get(path)??null,target(){},file_metadata:()=>true,write:(path,raw)=>{if(env.fail==='state-write'&&path===statePath){env.fail=null;throw Error('storage_error');}files.set(path,raw);}},
  state_model:{validate_state:clone,defaults:()=>clone(original)},control:{enabled:s=>s.settings.vpnServerEnabled,plan:()=>({available:!!env.pointer,downloadBytes:env.pointer?0:null,planSha256:plan.planSha256})},
  facts:{server:()=>null},backup:{guard(){}},
  engine:{update_locked:f=>f(),guard_mutation(){},update_principal_current:()=>env.authorized,update_now:()=>env.started,update_boot:()=> 'boot',update_self_worker:()=>({pid:12,start:'birth'}),update_process_snapshot:pid=>pid===42&&env.alive?({pid:42,start:'birth42',root:true,zombie:false}):null},
  model:{admit:(value,args,current)=>{if(args.confirmed!==true||args.planSha256!==value.planSha256||current.stateRevision!==7)throw Error('stale_plan');return value;},make_plan:()=>clone(plan)},
  native:{active:()=>clone(env.pointer),remove_owned:expected=>{if(JSON.stringify(expected)!==JSON.stringify(env.pointer)||env.fail==='remove-component')throw Error('vpn_server_verification_failed');events.push(['remove-owned-component']);env.pointer=null;},previous:()=>clone(env.pointer),catalog:()=>({value:{entries:[]}}),installed:()=>env.pointer?{verified:true}:null,
   context:()=>({binding:{...binding,nativeDbSha256:env.dbChanged?'changed':binding.nativeDbSha256},installed:{},state:JSON.parse(files.get(statePath))}),
   cached:()=>({}),stage:(_plan,_snapshot,progress,id)=>{events.push(['stage',id]);progress('DOWNLOADING',30);if(env.fail==='stage')throw Error('verification_failed');if(env.fail==='db-changed')env.dbChanged=true;return clone(staged);},
   publish:value=>{events.push(['publish']);env.pointer=clone(value);},restore:value=>{events.push(['restore']);env.pointer=clone(value);}},
  system:args=>{events.push(args);if(args[0]==='/usr/libexec/foxhole-inbound'&&args[1]==='force'){if(env.fail==='disable-firewall')return 1;env.openPorts=false;}if(args[0]==='/etc/init.d/foxhole-inbound'&&args[1]==='stop'){env.instances={};if(env.fail!=='pid-stuck')env.alive=false;}if((env.fail==='start'&&args[1]==='start')||(env.fail==='rollback'&&args[1]==='stop')){if(env.fail==='start')env.fail=null;return 1;}return 0;}
 };
 const api=new Function(...Object.keys(builtin),`${adapted};return {run,apply,job,ensure,plan,disable};`)(...Object.values(builtin));
 function queue(){files.set(jobPath,JSON.stringify({schema:1,jobId:'vpn-server-job-'+'1'.repeat(32),state:'QUEUED',step:'QUEUED',progressPercent:0,principal,owner:sha(JSON.stringify(principal)),plan:clone(plan),created:1000,bootId:'boot',previous:null,previousEnabled:false,activated:false}));}
 return {api,env,events,files,original,plan,principal,queue,state:()=>JSON.parse(files.get(statePath)),job:()=>JSON.parse(files.get(jobPath))};
}
test('no catalog or installed component means no download, state mutation, job or native install',()=>{
 const f=fixture();const before=[...f.files];assert.equal(f.api.plan(f.principal).available,false);assert.deepEqual([...f.files],before);assert.deepEqual(f.events,[]);
});
test('native staging and activation preserve profiles, pairing data and unrelated routing policy',()=>{
 const f=fixture();f.queue();const result=f.api.run(f.job().jobId);assert.equal(result.state,'SUCCEEDED',JSON.stringify(f.job()));
 assert.equal(f.state().settings.vpnServerEnabled,true);assert.deepEqual(f.state().clients,f.original.clients);assert.deepEqual(f.state().devices,f.original.devices);assert.equal(f.state().settings.killSwitch,true);
 assert.ok(f.events.some(x=>x[0]==='stage'));assert.ok(f.events.some(x=>x[0]==='publish'));assert.ok(!JSON.stringify(result).includes('keep-secret'));
});
for(const failure of ['stage','db-changed','state-write','start'])test(`failure at ${failure} restores pointer/flag and preserves owner data`,()=>{
 const f=fixture();f.queue();f.env.fail=failure;const result=f.api.run(f.job().jobId);assert.equal(result.state,'FAILED',JSON.stringify(f.job()));assert.equal(f.env.pointer,null);assert.equal(f.state().settings.vpnServerEnabled,false);assert.deepEqual(f.state().clients,f.original.clients);assert.deepEqual(f.state().devices,f.original.devices);assert.equal(f.state().settings.killSwitch,true);
});
test('a failed rollback remains RECOVERY_REQUIRED and is never reported as healthy',()=>{
 const f=fixture();f.queue();f.env.fail='rollback';const result=f.api.run(f.job().jobId);assert.equal(result.state,'RECOVERY_REQUIRED');assert.equal(f.job().state,'RECOVERY_REQUIRED');
});
test('revoked authorization cannot download or activate and ends with a failure record',()=>{
 const f=fixture();f.queue();f.env.authorized=false;const result=f.api.run(f.job().jobId);assert.equal(result.state,'FAILED',JSON.stringify(f.job()));assert.ok(!f.events.some(x=>x[0]==='stage'||x[0]==='publish'));assert.deepEqual(f.state(),f.original);
});
test('job status is scoped to original principal and carries no client secrets',()=>{
 const f=fixture();f.queue();const result=f.api.job(f.job().jobId,f.principal);assert.deepEqual(Object.keys(result).sort(),['schema','jobId','state','step','progressPercent','failureReason'].sort());
 assert.throws(()=>f.api.job(f.job().jobId,{kind:'admin',user:'other'}),/not_found/);
});

function incoming(f){const state=f.state();state.settings.vpnServerEnabled=true;f.files.set(statePath,JSON.stringify(state));f.env.instances={shared:{running:true,pid:42,command:['/usr/libexec/foxhole-server-run','server','-c','/tmp/foxhole/inbound/shared.json','--disable-update-check']}};f.env.alive=true;f.env.openPorts=true;}
test('remote OFF returns only queued status before changing VPN path; success waits for process/firewall proof',()=>{const f=fixture();incoming(f);const queued=f.api.disable({revision:7},f.principal);assert.equal(queued.state,'QUEUED');assert.equal(f.state().settings.vpnServerEnabled,true);assert.equal(f.env.alive,true);assert.ok(!f.events.some(x=>x[0]==='/etc/init.d/foxhole-inbound'));const result=f.api.run(queued.jobId);assert.equal(result.state,'SUCCEEDED');assert.equal(f.state().settings.vpnServerEnabled,false);assert.equal(f.env.alive,false);assert.equal(f.env.openPorts,false);assert.deepEqual(f.state().clients,f.original.clients);const wait=f.events.findIndex(x=>x[0]==='sleep'&&x[1]===1000),stop=f.events.findIndex(x=>x[0]==='/etc/init.d/foxhole-inbound'&&x[1]==='stop');assert.ok(wait>=0&&stop>wait);});
for(const failure of ['disable-firewall','pid-stuck'])test(`partial OFF ${failure} never returns green success or re-enables server`,()=>{const f=fixture();incoming(f);f.env.fail=failure;const queued=f.api.disable({revision:7},f.principal);const result=f.api.run(queued.jobId);assert.equal(result.state,'RECOVERY_REQUIRED');assert.equal(f.state().settings.vpnServerEnabled,false);assert.deepEqual(f.state().clients,f.original.clients);});
test('unknown non-owned service command refuses OFF before changing state or killing anything',()=>{const f=fixture();incoming(f);f.env.instances.shared.command[0]='/unrelated/tool';const queued=f.api.disable({revision:7},f.principal);const result=f.api.run(queued.jobId);assert.equal(result.state,'FAILED');assert.equal(f.state().settings.vpnServerEnabled,true);assert.equal(f.env.alive,true);});

// Explicitly isolated in-memory transaction fixtures; no real
// credentials or router I/O.
function ownedComponent(f){f.env.pointer={schema:1,directory:'owned-generation',descriptor:clone(f.plan.descriptor)};}
test('OFF keeps the installed owned component by default',()=>{
 const f=fixture();incoming(f);ownedComponent(f);const before=clone(f.env.pointer);
 const queued=f.api.disable({revision:7},f.principal);assert.deepEqual(f.env.pointer,before);
 assert.equal(f.api.run(queued.jobId).state,'SUCCEEDED');assert.deepEqual(f.env.pointer,before);
});
test('explicit component removal happens only after server and firewall stop, keeping profiles and pairing',()=>{
 const f=fixture();incoming(f);ownedComponent(f);
 const queued=f.api.disable({revision:7,removeComponent:true,confirmed:true,planSha256:f.plan.planSha256},f.principal);
 assert.ok(f.env.pointer);assert.equal(f.env.alive,true);
 const result=f.api.run(queued.jobId);assert.equal(result.state,'SUCCEEDED');assert.equal(f.env.pointer,null);
 assert.deepEqual(f.state().clients,f.original.clients);assert.deepEqual(f.state().devices,f.original.devices);
 const stop=f.events.findIndex(x=>x[0]==='/etc/init.d/foxhole-inbound'&&x[1]==='stop');
 assert.ok(f.events.findIndex(x=>x[0]==='remove-owned-component')>stop);
});
test('component deletion requires explicit confirmation, a current plan and a separately owned generation',()=>{
 for(const request of [{removeComponent:true},{removeComponent:true,confirmed:true,planSha256:'wrong'},{removeComponent:'true'}]){
  const f=fixture();incoming(f);ownedComponent(f);const before=clone(f.state());
  assert.throws(()=>f.api.disable({revision:7,...request},f.principal));assert.deepEqual(f.state(),before);
 }
 const shared=fixture();incoming(shared);
 assert.throws(()=>shared.api.disable({revision:7,removeComponent:true,confirmed:true,planSha256:shared.plan.planSha256},shared.principal));
});
test('component cleanup failure keeps OFF and reports recovery without deleting another generation',()=>{
 const f=fixture();incoming(f);ownedComponent(f);
 const queued=f.api.disable({revision:7,removeComponent:true,confirmed:true,planSha256:f.plan.planSha256},f.principal);
 f.env.pointer.directory='another-generation';const before=clone(f.env.pointer);
 assert.equal(f.api.run(queued.jobId).state,'RECOVERY_REQUIRED');assert.equal(f.state().settings.vpnServerEnabled,false);
 assert.deepEqual(f.env.pointer,before);assert.deepEqual(f.state().clients,f.original.clients);
});
