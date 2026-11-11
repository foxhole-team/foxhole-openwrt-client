'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as model from './core-update-model.uc';
import * as engines from './engine-model.uc';
import * as engine from './engine-service.uc';
import * as registry from './engine-registry.uc';
import * as packages from './package-operations.uc';
import * as native from './update-native.uc';
import * as catalog from './core-update-native.uc';
import * as adapter from './core-adapter.uc';
import * as store from './private-store.uc';
import * as ram from './ram-switch-service.uc';
import * as guard from './update-model.uc';

function same(a,b) {return sprintf('%J',a)==sprintf('%J',b);};
function fail(reason) {guard.fail(reason);};
export function context() {
 let identities=native.installed_identities();
 let base=identities['foxhole-openwrt-client'];
 if(!base || base.arch!='noarch')fail('UNSUPPORTED_TARGET');
 let active=fs.lstat('/tmp/foxhole-ram-active.json')?ram.core_context():
  {storage:'FLASH',version:base.version,baseIdentity:base};
 native.policy('/usr/share/foxhole/update-policy.json',active.version);
 native.target();
 return {...active,hostBaseIdentity:base};
};
function require_context(expected) {
 if(!same(context(),expected))fail('STALE_PLAN');
};
function budget(value) {
 let current=registry.snapshot_context(engine.update_state());
 if(current.flashAvailableBytes<value.flashRequiredBytes ||
  current.ramAvailableBytes<value.ramRequiredBytes)fail('NO_SPACE');
};
function identical(before,after,additions,removed) {
 let names=keys(before);
 for(let i=0;i<length(names);i++)
  if(!same(before[names[i]],after[names[i]]))fail('PACKAGE_VERIFICATION_FAILED');
 for(let name in keys(after))if(before[name]==null) {
  let allowed=filter(additions,row=>row.name==name);
  if(removed || length(allowed)!=1 ||
   after[name].version!=allowed[0].version ||
   after[name].arch!=allowed[0].arch || after[name].cas!=allowed[0].cas)
   fail('PACKAGE_VERIFICATION_FAILED');
 }
 if(removed)for(let row in additions)
  if(after[row.name]!=null)fail('PACKAGE_VERIFICATION_FAILED');
};
function selection_restore(previous) {
 let current=registry.read();
 let restored={...previous,revision:max(previous.revision,current.revision)+1};
 registry.write(restored);
 if(!same(registry.read(),restored))fail('RECOVERY_REQUIRED');
};
function current_restart_allowed(job) {
 return engines.restart_allowed(job.plan.binding,
  registry.snapshot_context(engine.update_state()));
};
function plan_current(job) {
 let current=registry.snapshot_context(engine.update_state());
 let fields=['routerId','bootId','worldSha256','catalogSha256',
  'activeGeneration','activeConfigSha256','activeProfileId',
  'activeEngineId','stopIntent'];
 for(let i=0;i<length(fields);i++)
  if(current[fields[i]]!=job.plan.binding[fields[i]])return false;
 return true;
};
function verify_world(previous, additions, removals) {
 if(!engines.world_pins(previous,packages.world(),additions,removals))
  fail('PACKAGE_VERIFICATION_FAILED');
};
function verify_candidates(job,directory) {
 for(let value in job.plan.candidate.artifacts) {
  let path=registry.verify_slot(value);
  let caps=packages.decode(registry.capture([path,'capabilities'],131072,130000));
  if(type(caps.schema_version)!='int' || caps.schema_version!=1 ||
   type(caps.router_contract_version)!='int' || caps.router_contract_version!=1 || caps.platform!='linux' ||
   caps.core_version!=value.version || !same(caps.protocols,[value.id]))
   fail('PACKAGE_VERIFICATION_FAILED');
  if(value.id==job.plan.binding.activeEngineId) {
   let profile=filter(engine.update_state().servers,
    row=>row.id==job.plan.binding.activeProfileId)[0];
   if(!profile || digest.sha256(profile.config)!=
    job.plan.binding.activeConfigSha256)fail('STALE_PLAN');
   store.write(directory+'/check-config',profile.config);
   try {
    registry.capture([path,'check','--config',directory+'/check-config'],
     65536,130000);
   }catch(error) {
    if(!fs.unlink(directory+'/check-config'))fail('PACKAGE_VERIFICATION_FAILED');
    die(error);
   }
   if(!fs.unlink(directory+'/check-config'))fail('PACKAGE_VERIFICATION_FAILED');
  }
 }
};
function recover_impl(job, callbacks) {
 let tx=job.coreTransaction;
 callbacks.journal(job);
 if(!tx || !job.mutationStarted || job.coreRecoveryAttempted)
  fail('RECOVERY_REQUIRED');
 if(tx.schema!=1 || !same(tx.registry,job.plan.candidate.selected) ||
  !same(tx.context,job.plan.candidate.managed) ||
  !same(tx.catalog,job.plan.candidate.previousReference) ||
  type(tx.worldRaw)!='string' ||
  digest.sha256(tx.worldRaw)!=job.plan.binding.worldSha256 ||
  type(tx.additions)!='array' || length(tx.additions)>3)
  fail('RECOVERY_REQUIRED');
 for(let added in tx.additions) {
  let matches=filter(job.plan.candidate.artifacts,
   row=>row.packageName==added.name && row.packageVersion==added.version &&
    row.architecture==added.arch);
  if(tx.identities[added.name]!=null || length(matches)!=1 ||
   !match(added.cas||'',/^sha256-160:[a-f0-9]{40}$/))
   fail('RECOVERY_REQUIRED');
 }
 job.coreRecoveryAttempted=true;callbacks.save(job);
 require_context(tx.context);
 if(!current_restart_allowed(job) &&
  engine.update_state().activeServerId!=null)fail('RECOVERY_REQUIRED');
 let current=native.installed_identities();
 identical(tx.identities,current,tx.additions,false);
 job.atomicPackagePhase=true;callbacks.save(job);
 if(job.coreRuntimeStopRequested &&
  system(['/etc/init.d/foxhole-runtime','stop'],15000)!=0)
  fail('RECOVERY_REQUIRED');
 selection_restore(tx.registry);
 catalog.restore(tx.catalog);registry.catalog();
 let remove=filter(tx.additions,row=>current[row.name]!=null);
 let names=map(remove,row=>row.name);
 if(length(names)) {
  let simulated=packages.apk(['--no-network','--repositories-file',
   '/dev/null','del','--simulate',...names]);
  if(!engines.purge_only(simulated,names,packages.installed()))
   fail('RECOVERY_REQUIRED');
  packages.apk(['--no-network','--repositories-file','/dev/null',
   'del',...names],120000);
 }
 identical(tx.identities,native.installed_identities(),tx.additions,true);
 verify_world(tx.world,[],[]);require_context(tx.context);
 for(let previous in tx.registry.slots)registry.verify_slot(previous);
 callbacks.preserved(job.protectedBefore,job);
 callbacks.endAtomic(job);
 job.previousConnectionRestored=false;
 if(job.coreRuntimeStopRequested &&
  job.plan.binding.activeProfileId!=null && current_restart_allowed(job) &&
  callbacks.authorized(job)) {
  let generation=adapter.generation(adapter.receipt('owner'));
  let started=engine.update_now();
  let restarted=callbacks.restart(job);
  let proved=restarted && engine.update_wait_reconnect(job,
   engines.selected(tx.registry,job.plan.binding.activeEngineId),
   started,generation);
  if(!proved && current_restart_allowed(job))fail('RECOVERY_REQUIRED');
  job.previousConnectionRestored=proved;
 }
 job.coreRecoverySucceeded=true;callbacks.save(job);
};
export function recover(job, callbacks) {
 return engine.update_locked(()=>recover_impl(job,callbacks));
};
export function apply(job, callbacks) {
 return engine.update_locked(()=>{
  callbacks.admit(job);
  let value=job.plan.candidate,expected=value.managed;
  if(value.component!='CORE' || !callbacks.authorized(job) ||
   !same(value.selected,registry.read()) ||
   !same(value.previousReference,catalog.current()) ||
   !plan_current(job) || engine.update_now()>job.plan.expiresAtUptimeMs)
   fail('STALE_PLAN');
  require_context(expected);budget(job.plan.budget);
  let directory='/tmp/foxhole/'+job.jobId;store.directory(directory);
  let keys=native.prepare_keys(directory),before=native.installed_identities();
  let prepared=[],indices=[],additions=[],roots=[];
  for(let artifact in value.artifacts) {
   if(!callbacks.authorized(job))fail('AUTHENTICATION_FAILED');
   callbacks.progress(job,'DOWNLOADING','DOWNLOADING_PACKAGE',15);
   let candidate=packages.candidate(artifact,directory,keys);
   native.stage_ram(artifact);
   if(before[artifact.packageName]!=null) {
    if(before[artifact.packageName].version!=artifact.packageVersion ||
     before[artifact.packageName].arch!=artifact.architecture ||
     before[artifact.packageName].cas!=native.native_cas(candidate.nativeId))
     fail('VERSION_IDENTITY_CONFLICT');
    registry.verify_slot(artifact);continue;
   }
   let index=directory+'/index-'+artifact.indexSha256+'.adb';
   if(!fs.lstat(index) &&
    system(['/bin/cp',candidate.index,index],5000)!=0)
    fail('PACKAGE_VERIFICATION_FAILED');
   push(prepared,candidate);push(indices,index);push(roots,artifact.packageName);
   push(additions,{name:artifact.packageName,version:artifact.packageVersion,
    arch:artifact.architecture,cas:native.native_cas(candidate.nativeId)});
  }
  for(let old in value.selected.slots)registry.verify_slot(old);
  for(let choice in value.selected.selected)
   native.stage_ram(engines.selected(value.selected,choice.id));
  store.write(directory+'/repositories',join('\n',indices)+'\n');
  let common=['--no-network','--no-cache','--repositories-file',
   directory+'/repositories','--keys-dir',keys];
  let world=packages.world(),world_raw=native.world_state().raw;
  if(digest.sha256(world_raw)!=job.plan.binding.worldSha256)
   fail('STALE_PLAN');
  if(length(roots)) {
   let solved=packages.decode(packages.apk([...common,'query','--format',
    'json','--world','--recursive',...roots]));
   if(type(solved)!='array' || length(solved)>4096)
    fail('PACKAGE_VERIFICATION_FAILED');
   let delta=[];
   for(let row in solved) {
    if(before[row.name]!=null) {
     if(before[row.name].version!=row.version ||
      before[row.name].arch!=row.arch)fail('PACKAGE_VERIFICATION_FAILED');
    }else push(delta,{name:row.name,action:'install'});
   }
   if(!engines.add_only_delta(delta,map(prepared,row=>row.value)))
    fail('PACKAGE_VERIFICATION_FAILED');
   packages.apk([...common,'add','--simulate',...roots]);
  }
  require_context(expected);
  if(!callbacks.authorized(job) || engine.update_now()>job.plan.expiresAtUptimeMs ||
   !same(value.selected,registry.read()) ||
   !plan_current(job))fail('STALE_PLAN');
  identical(before,native.installed_identities(),[],true);
  verify_world(world,[],[]);
  job.coreTransaction={schema:1,context:expected,identities:before,
   registry:value.selected,catalog:value.previousReference,
   world,worldRaw:world_raw,additions};
  job.protectedBefore=callbacks.protect(job);
  callbacks.beginAtomic(job);
  try {
   if(system(['/bin/sync'],30000)!=0)fail('ROUTER_UNAVAILABLE');
   if(length(roots))packages.apk([...common,'add',...roots],120000);
   identical(before,native.installed_identities(),additions,false);
   verify_world(world,roots,[]);require_context(expected);
   catalog.publish(value.reference);registry.catalog();
   callbacks.progress(job,'CHECKING','CHECKING_PACKAGE',65);
   verify_candidates(job,directory);
   if(!callbacks.authorized(job))fail('AUTHENTICATION_FAILED');
   if(job.plan.impact=='RECONNECT_REQUIRED') {
    job.previousGeneration=adapter.generation(adapter.receipt('owner'));
    job.restartStarted=engine.update_now();
    job.coreRuntimeStopRequested=true;callbacks.save(job);
    if(system(['/etc/init.d/foxhole-runtime','stop'],15000)!=0)
     fail('ROUTER_UNAVAILABLE');
   }
   let next=engines.commit(value.selected,value.artifacts,[],value.selected.revision);
   registry.write(next);
   callbacks.preserved(job.protectedBefore,job);
   callbacks.endAtomic(job);
   job.previousConnectionRestored=false;
   if(job.plan.impact=='RECONNECT_REQUIRED' &&
    job.plan.binding.activeProfileId!=null && current_restart_allowed(job) &&
    callbacks.authorized(job)) {
    callbacks.progress(job,'RECONNECTING','RECONNECTING_VPN',85);
    let restarted=callbacks.restart(job);
    let proved=restarted && engine.update_wait_reconnect(job,
     engines.selected(next,job.plan.binding.activeEngineId),
     job.restartStarted,job.previousGeneration);
    if(!proved && current_restart_allowed(job))fail('ROUTER_UNAVAILABLE');
    job.previousConnectionRestored=proved;
   }
   require_context(expected);callbacks.save(job);return true;
  }catch(error) {
   try {recover_impl(job,callbacks);}
   catch(_) {job.failureReason='RECOVERY_REQUIRED';callbacks.save(job);}
   die(error);
  }
 });
};
