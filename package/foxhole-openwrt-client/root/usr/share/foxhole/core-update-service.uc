'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as native from './update-native.uc';
import * as model from './core-update-model.uc';
import * as catalog from './core-update-native.uc';
import * as transaction from './core-update-transaction.uc';
import * as engines from './engine-model.uc';
import * as engine from './engine-service.uc';
import * as registry from './engine-registry.uc';
import * as store from './private-store.uc';
import * as guard from './update-model.uc';
import * as backup_model from './backup-model.uc';

function same(a,b) {return sprintf('%J',a)==sprintf('%J',b);};
function binding(context) {
 let state=engine.update_state();
 return {routerId:context.routerId,bootId:context.bootId,
  worldSha256:context.worldSha256,catalogSha256:context.catalogSha256,
  activeGeneration:context.activeGeneration,
  activeConfigSha256:context.activeConfigSha256,
  activeProfileId:context.activeProfileId,
  activeEngineId:context.activeEngineId,stopIntent:context.stopIntent,
  stateRevision:state.revision,stateWithoutStop:backup_model.without_stop(state)};
};
export function current_binding() {
 return binding(registry.snapshot_context(engine.update_state()));
};
export function modules(selected) {
 let rows=[];
 for(let choice in selected.selected) {
  let value=engines.selected(selected,choice.id);
  if(!value)guard.fail('PACKAGE_VERIFICATION_FAILED');
  push(rows,{id:value.id,storage:value.storage,version:value.packageVersion});
 }
 return rows;
};
export function cleanup_staging(id) {
 if(!match(id||'',/^update-job-[a-f0-9]{32}$/))
  guard.fail('INVALID_REQUEST');
 let folders=fs.glob('/tmp/foxhole/update-job-*')||[];
 if(length(folders)>64)guard.fail('NO_SPACE');
 for(let path in folders) {
  if(path=='/tmp/foxhole/'+id)continue;
  if(!match(path,/^\/tmp\/foxhole\/update-job-[a-f0-9]{32}$/) ||
   !store.directory_metadata(fs.lstat(path)))
   guard.fail('PACKAGE_VERIFICATION_FAILED');
  if(system(['/bin/rm','-rf','--',path],10000)!=0 || fs.lstat(path))
   guard.fail('NO_SPACE');
 }
};
export function from_verified(verified, expected) {
 let managed=transaction.context(),selected=registry.read();
 let before=registry.snapshot_context(engine.update_state()),bound=binding(before);
 let previous_reference=catalog.current();
 if(expected && (!same(expected.managed,managed)||!same(expected.selected,selected)||
  !same(expected.bound,bound)||!same(expected.previous_reference,previous_reference)))
  guard.fail('STALE_PLAN');
 let old=native.selected_modules(selected);
 let changed=native.module_changes(old,verified.feed.catalog,before.architecture);
 catalog.remember(verified.reference);
 if(!same(selected,registry.read()) ||
  !same(bound,binding(registry.snapshot_context(engine.update_state()))) ||
  !same(previous_reference,catalog.current()) ||
  !same(managed,transaction.context()))guard.fail('STALE_PLAN');
 return {component:'CORE',managed,reference:verified.reference,
  previousReference:previous_reference,
  catalog:verified.feed.catalog,selected,artifacts:changed.artifacts,
  changes:changed.changes,binding:bound,
  checkedAtUnixMs:time()*1000};

};
export function check(directory) {
 let selected=registry.read(),old=native.selected_modules(selected);
 if(!length(old)) {
  native.target();
  if(length(registry.legacy_protocols()))guard.fail('UNSUPPORTED_TARGET');
  return null;
 }
 // Pure RAM installations can have no host BASE APK. Only a managed Core cohort needs its transaction context.
 let managed=transaction.context(),before=registry.snapshot_context(engine.update_state());
 let bound=binding(before),previous_reference=catalog.current();
 if(before.activeProfileId!=null && before.activeEngineId==null)
  guard.fail('LEGACY_CONNECTION_ACTIVE');
 store.directory(directory);
 let keys=native.prepare_keys(directory),tag=catalog.latest(directory);
 let verified=catalog.verify_catalog(tag,directory+'/catalog',keys,
  managed.version,catalog.highest());
 return from_verified(verified,{managed,selected,bound,previous_reference});
};
function random() {
 let raw=fs.readfile('/dev/urandom',32);
 if(length(raw||'')!=32)guard.fail('ROUTER_UNAVAILABLE');
 return hexenc(raw);
};
function missing_ram(value) {
 if(value.storage!='RAM')return 0;
 let path='/tmp/foxhole/engine-binaries/'+value.id+'/'+value.binarySha256+'/foxcore-cli';
 let info=fs.lstat(path);
 if(info==null)return value.binaryBytes;
 if(!store.file_metadata(info) || (info.mode&0o7777)!=0o700 ||
  info.size!=value.binaryBytes || registry.hash_file(path)!=value.binarySha256)
  guard.fail('RAM_STAGE_UNAVAILABLE');
 return 0;
};
export function plan_digest(plan) {
 let value={...plan};delete value.planSha256;
 return digest.sha256(sprintf('%J',value));
};
export function plan(candidate, principal_owner, revision) {
 let context=registry.snapshot_context(engine.update_state());
 if(candidate?.component!='CORE' || !length(candidate.changes||[]) ||
  !same(candidate.reference,catalog.highest()) ||
  !same(candidate.managed,transaction.context()) ||
  !same(candidate.selected,registry.read()) ||
  !same(candidate.binding,binding(context)) ||
  time()*1000<candidate.checkedAtUnixMs ||
  time()*1000-candidate.checkedAtUnixMs>300000)guard.fail('STALE_PLAN');
 let wanted=map(candidate.artifacts,row=>row.id);
 let request={operation:'UPDATE',engineIds:wanted,storage:'AUTO',
  expectedRevision:candidate.selected.revision,catalogSha256:context.catalogSha256};
 let engine_plan=engines.plan(request,candidate.catalog,candidate.selected,
  context,principal_owner||digest.sha256('foxhole-core-automatic-v1'),
  random(),engine.update_now());
 let budget={...engine_plan.budget};
 let metadata=candidate.reference.archiveBytes+candidate.reference.indexBytes+
  candidate.reference.bodyBytes;
 budget.downloadBytes+=metadata;
 budget.stagingBytes+=metadata;
 budget.flashRequiredBytes+=3*metadata;
 budget.ramRequiredBytes+=4*metadata;
 for(let choice in candidate.selected.selected)
  budget.ramRequiredBytes+=missing_ram(engines.selected(candidate.selected,choice.id));
 if(context.flashAvailableBytes<budget.flashRequiredBytes ||
  context.ramAvailableBytes<budget.ramRequiredBytes)guard.fail('NO_SPACE');
 let plan={schema:1,routerId:context.routerId,revision,
  planId:'update-plan-'+substr(random(),0,32),
  fromVersion:candidate.managed.version,toVersion:candidate.managed.version,
  engineIds:sort(map(candidate.selected.selected,row=>row.id)),
  changes:candidate.changes,impact:engine_plan.impact,
  confirmationRequired:true,expiresAtUptimeMs:engine.update_now()+300000,
  bootId:context.bootId,budget,owner:principal_owner,binding:binding(context),
  candidate,createdAtUptimeMs:engine.update_now()};
 plan.planSha256=plan_digest(plan);return plan;
};
export function valid(candidate) {
 try {
  return candidate?.component=='CORE' &&
   same(candidate.reference,catalog.highest()) &&
   time()*1000>=candidate.checkedAtUnixMs &&
   time()*1000-candidate.checkedAtUnixMs<=300000 &&
   same(candidate.managed,transaction.context()) &&
   same(candidate.selected,registry.read()) &&
   same(candidate.binding,current_binding());
 }catch(_) {return false;}
};
export function recent_current(value) {
 let candidate=value?.coreCheckedCandidate;
 return type(candidate?.changes)=='array' && !length(candidate.changes) &&
  valid(candidate)?candidate:null;
};
export function current_identity(value) {
 try {
  return value?.coreCheckedCandidate?.reference!=null &&
   same(value.coreCheckedCandidate.reference,catalog.highest());
 }catch(_) {return false;}
};
export function admit(plan, request, principal_owner, revision) {
 if(request.confirmed!=true || type(request.confirmed)!='bool' ||
  plan?.candidate?.component!='CORE' || plan.owner!=principal_owner)
  guard.fail('AUTHENTICATION_FAILED');
 if(plan.planId!=request.planId || plan.planSha256!=request.planSha256 ||
  plan_digest(plan)!=plan.planSha256 || revision!=request.expectedRevision ||
  plan.revision!=revision || engine.update_now()<plan.createdAtUptimeMs ||
  engine.update_now()>plan.expiresAtUptimeMs ||
  !same(plan.binding,binding(registry.snapshot_context(engine.update_state()))) ||
  !same(plan.candidate.selected,registry.read()) ||
  !same(plan.candidate.reference,catalog.highest()) ||
  !same(plan.candidate.managed,transaction.context()))guard.fail('STALE_PLAN');
 return true;
};

