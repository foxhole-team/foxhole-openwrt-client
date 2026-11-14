'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as model from './core-update-model.uc';
import * as uploads from './ram-update-model.uc';
import * as core from './core-update-service.uc';
import * as catalog from './core-update-native.uc';
import * as transaction from './core-update-transaction.uc';
import * as engine from './engine-service.uc';
import * as engines from './engine-model.uc';
import * as registry from './engine-registry.uc';
import * as native from './update-native.uc';
import * as packages from './package-operations.uc';
import * as store from './private-store.uc';
import * as backup from './backup-service.uc';
import * as guard from './update-model.uc';
import * as mounts from './ram-switch-model.uc';

const ROOT='/tmp/foxhole/core-uploads';
const RECORD=ROOT+'/current.json';
const STATE='/etc/foxhole/update-state.json';
const JOB='/etc/foxhole/update-job.json';
const LIVE=['RECEIVING','VERIFYING','WAITING'];
function fail(reason) {guard.fail(reason);};
function same(a,b) {return sprintf('%J',a)==sprintf('%J',b);};
function read(path,maximum) {
 let raw=store.read(path,maximum||524288);return raw?native.decode(raw):null;
};
function write(path,value) {
 let raw=sprintf('%J',value);if(length(raw)>524288)fail('NO_SPACE');
 store.write(path,raw);
};
function profile_locked(fn) {
 let path='/etc/foxhole/state.lock';store.target(path);
 let handle=fs.open(path,'a+',0o600);
 if(!handle||!handle.lock('xn')||!store.file_metadata(fs.lstat(path))) {
  if(handle)handle.close();fail('BUSY');
 }
 try{let value=fn();handle.lock('u');handle.close();return value;}
 catch(error){try{handle.lock('u');handle.close();}catch(_){}die(error);}
};
function owner(principal) {
 if(!engine.update_principal_current(principal))fail('AUTHENTICATION_FAILED');
 return digest.sha256(sprintf('%J',principal));
};
function active(value) {
 return value!=null && index(['SUCCEEDED','FAILED','RECOVERY_REQUIRED'],value.state)<0;
};
function idle() {
 backup.guard();
 for(let value in [read(JOB),read('/etc/foxhole/engine-job.json'),read('/etc/foxhole/vpn-server-job.json',2097152)])
  if(active(value)||value?.state=='RECOVERY_REQUIRED')fail('BUSY');
};
function descriptor(value,id) {
 let rows=filter(value.assets,item=>item.id==id);
 if(length(rows)!=1)fail('INVALID_REQUEST');return rows[0];
};
function asset_path(value,id) {
 if(!uploads.upload_id(value.id) || !model.cohort_asset_id(id))
  fail('PACKAGE_VERIFICATION_FAILED');
 return ROOT+'/'+value.id+'/assets/'+id;
};
function valid_record(value) {
 if(value==null)return null;
 if(value.schema!=1 || !uploads.upload_id(value.id) ||
  type(value.owner)!='string' || !match(value.owner,/^[a-f0-9]{64}$/) ||
  !uploads.integer(value.createdAtUptimeMs) ||
  !uploads.integer(value.expiresAtUptimeMs) ||
  value.expiresAtUptimeMs!=value.createdAtUptimeMs+600000 ||
  type(value.requestId)!='string' || !match(value.requestId,/^[a-f0-9]{32}$/) ||
  type(value.assets)!='array' || length(value.assets)>16 ||
  index([...LIVE,'STAGED','FAILED','EXPIRED'],value.phase)<0)
  fail('PACKAGE_VERIFICATION_FAILED');
 if(type(value.version)!='string' ||
  !match(value.version,/^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$/) ||
  value.releaseTag!='v'+value.version ||
  type(value.principal)!='object' ||
  digest.sha256(sprintf('%J',value.principal))!=value.owner)
  fail('PACKAGE_VERIFICATION_FAILED');
 let seen={};
 for(let item in value.assets) {
  if(!model.cohort_asset_id(item.id) || seen[item.id] ||
   !uploads.integer(item.bytes) || item.bytes<1 ||
   item.bytes>(item.id=='catalog-index'||item.id=='catalog-apk'?1048576:134217728) ||
   type(item.complete)!='bool' ||
   (item.sha256==null?item.id!='catalog-apk':!uploads.sha(item.sha256)) ||
   item.id!='catalog-index'&&item.id!='catalog-apk'&&item.id!='asset-'+item.sha256 ||
   type(item.url)!='string'||length(item.url)>1024 ||
   !match(item.url,/^https:\/\/github\.com\/foxhole-team\/(foxhole-core|foxhole-openwrt-client)\/releases\/download\/v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}\/[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/) ||
   index(['CATALOG_INDEX','CATALOG_APK','INDEX','PACKAGE','BINARY'],item.kind)<0)
   fail('PACKAGE_VERIFICATION_FAILED');
  seen[item.id]=true;
 }
 if(value.current!=null) {
  let current=value.current,item=descriptor(value,current.id);
  if(item.complete || !uploads.sha(current.sha256) ||
   current.sha256!=item.sha256 || current.bytes!=item.bytes ||
   !uploads.integer(current.nextOffset) || current.nextOffset>current.bytes)
   fail('PACKAGE_VERIFICATION_FAILED');
  for(let key in ['pending','last'])if(current[key]!=null) {
   let part=current[key];
   if(!uploads.integer(part.offset)||!uploads.integer(part.bytes)||part.bytes<1||
    part.bytes>65536||!uploads.sha(part.sha256)||part.offset+part.bytes>current.bytes ||
    key=='pending'&&part.offset!=current.nextOffset ||
    key=='last'&&part.offset+part.bytes!=current.nextOffset)
    fail('PACKAGE_VERIFICATION_FAILED');
  }
 }
 return value;
};
function record() {return valid_record(read(RECORD));};
export function busy() {
 let value=record();
 return value!=null && value.bootId==engine.update_boot() &&
  engine.update_now()>=value.createdAtUptimeMs &&
  engine.update_now()<=value.expiresAtUptimeMs && index(LIVE,value.phase)>=0 &&
  engine.update_principal_current(value.principal);
};
function require_upload(id,principal) {
 let identity=owner(principal),value=record();
 if(value?.id!=id || value.owner!=identity)fail('AUTHENTICATION_FAILED');
 if(value.bootId!=engine.update_boot() ||
  engine.update_now()<value.createdAtUptimeMs ||
  engine.update_now()>value.expiresAtUptimeMs)fail('STALE_PLAN');
 if(value.phase=='FAILED'||value.phase=='EXPIRED')fail('STALE_PLAN');
 if(!same(value.binding,core.current_binding()) ||
  !same(value.managed,transaction.context()))fail('STALE_PLAN');
 return value;
};
function public_assets(value) {
 return map(filter(value.assets,item=>item.complete!=true),item=>({
  id:item.id,sha256:item.sha256,bytes:item.bytes,url:item.url,kind:item.kind}));
};
function reply(value) {
 return {schema:1,cohortKind:'CORE',uploadId:value.id,
  assetId:value.current?.id||null,nextOffset:value.current?.nextOffset||0,
  maxChunkBytes:65536,phase:value.phase,requiredAssets:public_assets(value),
  cohortSha256:value.candidate?.reference?.bodySha256||null};
};
function verified_asset_path(value,item) {
 let path=asset_path(value,item.id),info=fs.lstat(path);
 // A crash after rename leaves VERIFYING at the old path.
 if(info==null && value.phase=='VERIFYING' && index(item.id,'asset-')==0) {
  path='/tmp/foxhole/engine-assets/'+item.sha256;info=fs.lstat(path);
 }
 if(!store.file_metadata(info)||(info.mode&0o7777)!=0o600 ||
  info.size!=item.bytes || registry.hash_file(path)!=item.sha256)
  fail('PACKAGE_VERIFICATION_FAILED');
 return path;
};
function reconcile(value) {
 let current=value.current;if(current==null)return value;
 let path=asset_path(value,current.id),info=fs.lstat(path);
 if(info==null && value.phase=='VERIFYING' && current.pending==null &&
  current.nextOffset==current.bytes && index(current.id,'asset-')==0) {
  verified_asset_path(value,descriptor(value,current.id));return value;
 }
 if(!store.file_metadata(info)||(info.mode&0o7777)!=0o600 ||
  info.size>current.bytes)fail('PACKAGE_VERIFICATION_FAILED');
 if(current.pending) {
  let pending=current.pending;
  if(info.size==pending.offset)return value;
  if(info.size!=pending.offset+pending.bytes)fail('PACKAGE_VERIFICATION_FAILED');
  let file=fs.open(path,'re');
  if(!file||file.seek(pending.offset,0)!=true)fail('PACKAGE_VERIFICATION_FAILED');
  let bytes=file.read(pending.bytes);file.close();
  if(bytes==null||length(bytes)!=pending.bytes||digest.sha256(bytes)!=pending.sha256)
   fail('PACKAGE_VERIFICATION_FAILED');
  current.last=pending;current.pending=null;current.nextOffset=info.size;
  write(RECORD,value);
 }else if(info.size!=current.nextOffset)fail('PACKAGE_VERIFICATION_FAILED');
 return value;
};
function capacity(bytes) {
 let context=registry.snapshot_context(engine.update_state());
 if(context.ramAvailableBytes<bytes+16777216)fail('NO_SPACE');
};
function cleanup_previous(value) {
 if(value==null)return;
 let directory=ROOT+'/'+value.id,info=fs.lstat(directory);
 if(info==null)return;
 if(!uploads.upload_id(value.id)||!store.directory_metadata(info))
  fail('PACKAGE_VERIFICATION_FAILED');
 let rows=mounts.mounts(fs.readfile('/proc/self/mountinfo',1048577));
 for(let row in rows)
  if(row.target==directory||index(row.target,directory+'/')==0)fail('BUSY');
 if(system(['/bin/rm','-rf','--',directory],10000)!=0||fs.lstat(directory))
  fail('NO_SPACE');
};
function append_asset(value,item) {
 let existing=filter(value.assets,row=>row.id==item.id);
 if(length(existing)) {
  if(existing[0].sha256!=item.sha256 || existing[0].bytes!=item.bytes ||
   existing[0].url!=item.url)fail('PACKAGE_VERIFICATION_FAILED');
  return;
 }
 if(length(value.assets)>=16)fail('NO_SPACE');push(value.assets,item);
};
function raw_asset(value,item) {
 let base=substr(item.indexUrl,0,length(item.indexUrl)-length('engines.adb'));
 append_asset(value,{id:'asset-'+item.binarySha256,sha256:item.binarySha256,
  bytes:item.binaryBytes,url:base+'engine-'+item.id+'-'+item.architecture+'-'+
   item.binarySha256+'.bin',kind:'BINARY',complete:false});
};
function required_assets(value,candidate) {
 for(let item in candidate.artifacts) {
  append_asset(value,{id:'asset-'+item.indexSha256,sha256:item.indexSha256,
   bytes:item.indexBytes,url:item.indexUrl,kind:'INDEX',complete:false});
  append_asset(value,{id:'asset-'+item.packageSha256,sha256:item.packageSha256,
   bytes:item.archiveBytes,url:item.packageUrl,kind:'PACKAGE',complete:false});
  if(item.storage=='RAM')raw_asset(value,item);
 }
 for(let selected in candidate.selected.selected) {
  let item=engines.selected(candidate.selected,selected.id);
  if(item.storage!='RAM')continue;
  let path='/tmp/foxhole/engine-binaries/'+item.id+'/'+item.binarySha256+'/foxcore-cli';
  let info=fs.lstat(path);
  if(info==null)raw_asset(value,item);
  else if(!store.file_metadata(info)||(info.mode&0o7777)!=0o700 ||
   info.size!=item.binaryBytes||registry.hash_file(path)!=item.binarySha256)
   fail('RAM_STAGE_UNAVAILABLE');
 }
};
function cache_asset(value,item) {
 let path=verified_asset_path(value,item);
 store.directory('/tmp/foxhole/engine-assets');
 let target='/tmp/foxhole/engine-assets/'+item.sha256,info=fs.lstat(target);
 if(info==null) {
  if(!fs.rename(path,target))fail('NO_SPACE');
 }else if(!store.file_metadata(info)||info.size!=item.bytes ||
  registry.hash_file(target)!=item.sha256)fail('PACKAGE_VERIFICATION_FAILED');
};
export function begin(request,principal) {
 model.cohort_begin(request);
 return engine.update_locked(()=>{
  idle();let identity=owner(principal),value=record();
  if(request.uploadId=='') {
   if(request.assetId!='catalog-index')fail('INVALID_REQUEST');
   if(busy()) {
    if(value.owner!=identity || value.requestId!=request.requestId ||
     value.version!=request.version)fail('BUSY');
    let item=descriptor(value,'catalog-index');
    if(item.sha256!=request.fileSha256||item.bytes!=request.fileBytes)
     fail('STALE_PLAN');
    return reply(reconcile(require_upload(value.id,principal)));
   }
   let state=read(STATE),proof=state?.relayEvidence;
   if(!state || request.expectedRevision!=state.revision ||
    !state.deviceDownloadRequired || proof?.owner!=identity ||
    proof.cohortKind!='CORE' || proof.bootId!=engine.update_boot() ||
    proof.observedAtUptimeMs>engine.update_now() ||
    engine.update_now()-proof.observedAtUptimeMs>600000 ||
    !catalog.network_unreachable())fail('STALE_PLAN');
   cleanup_previous(value);
   let random=fs.readfile('/dev/urandom',16);
   if(length(random||'')!=16)fail('ROUTER_UNAVAILABLE');
   let id='update-upload-'+hexenc(random);
   capacity(request.fileBytes);
   if(fs.lstat(ROOT+'/'+id))fail('ROUTER_UNAVAILABLE');
   store.directory(ROOT);store.directory(ROOT+'/'+id);
   store.directory(ROOT+'/'+id+'/assets');
   let created=engine.update_now();
   value={schema:1,id,owner:identity,principal,requestId:request.requestId,
    version:request.version,releaseTag:request.releaseTag,
    binding:core.current_binding(),managed:transaction.context(),assets:[],
    current:null,phase:'WAITING',bootId:engine.update_boot(),
    createdAtUptimeMs:created,expiresAtUptimeMs:created+600000};
   append_asset(value,{id:'catalog-index',sha256:request.fileSha256,
    bytes:request.fileBytes,url:'https://github.com/foxhole-team/foxhole-core/releases/download/'+
     request.releaseTag+'/core-catalog.adb',kind:'CATALOG_INDEX',complete:false});
  }else value=require_upload(request.uploadId,principal);
  if(value.requestId!=request.requestId || value.version!=request.version ||
   value.releaseTag!=request.releaseTag)fail('STALE_PLAN');
  let item=descriptor(value,request.assetId);
  if(item.complete)return reply(value);
  if(item.bytes!=request.fileBytes || item.sha256!=null && item.sha256!=request.fileSha256)
   fail('PACKAGE_VERIFICATION_FAILED');
  if(value.current!=null) {
   if(value.current.id!=item.id)fail('BUSY');
   if(value.current.sha256!=request.fileSha256)fail('STALE_PLAN');
   return reply(reconcile(value));
  }
  capacity(request.fileBytes);
  item.sha256=request.fileSha256;
  store.write(asset_path(value,item.id),'');
  value.current={id:item.id,bytes:item.bytes,sha256:item.sha256,
   nextOffset:0,pending:null,last:null};value.phase='RECEIVING';
  write(RECORD,value);return reply(value);
 });
};
export function chunk(request,principal) {
 model.cohort_action(request,true);
 let bytes=uploads.chunk_request({uploadId:request.uploadId,offset:request.offset,
  dataBase64:request.dataBase64,chunkSha256:request.chunkSha256});
 return engine.update_locked(()=>{
  idle();let value=reconcile(require_upload(request.uploadId,principal));
  let current=value.current;
  if(value.phase!='RECEIVING'||current?.id!=request.assetId)fail('STALE_PLAN');
  if(current.last?.offset==request.offset && current.last.bytes==length(bytes) &&
   current.last.sha256==request.chunkSha256)return reply(value);
  if(request.offset!=current.nextOffset || request.offset+length(bytes)>current.bytes)
   fail('STALE_PLAN');
  capacity(length(bytes)+65536);
  current.pending={offset:request.offset,bytes:length(bytes),sha256:request.chunkSha256};
  write(RECORD,value);
  let file=fs.open(asset_path(value,current.id),'a');
  if(!file||file.write(bytes)!=length(bytes)||!file.flush())fail('NO_SPACE');
  file.close();return reply(reconcile(value));
 });
};
export function status(request,principal) {
 model.cohort_action(request,false);
 return engine.update_locked(()=>{
  let value=reconcile(require_upload(request.uploadId,principal));
  descriptor(value,request.assetId);return reply(value);
 });
};
export function finish(request,principal) {
 model.cohort_action(request,false);
 return engine.update_locked(()=>{
  idle();let value=reconcile(require_upload(request.uploadId,principal));
  let item=descriptor(value,request.assetId);
  if(item.complete)return reply(value);
  if(value.current?.id!=item.id || value.current.nextOffset!=item.bytes)
   fail('STALE_PLAN');
  let path=verified_asset_path(value,item);
  value.phase='VERIFYING';write(RECORD,value);
  try {
   if(item.id=='catalog-index') {
    let keys=native.prepare_keys(ROOT+'/'+value.id+'/catalog-input');
    packages.apk(['--keys-dir',keys,'verify',path]);
    let rows=native.decode(packages.apk(['adbdump','--format','json',path])).packages;
    if(type(rows)!='array'||length(rows)!=1)fail('PACKAGE_VERIFICATION_FAILED');
    let row=rows[0];
    if(row.name!='foxcore-update-catalog'||row.arch!='noarch' ||
     type(row.version)!='string' ||
     !match(row.version,/^[0-9]+\.[0-9]+\.[0-9]+-r[1-9][0-9]{0,5}$/) ||
     substr(row.version,0,length(value.version)+2)!=value.version+'-r' ||
     type(row['file-size'])!='int'||row['file-size']<1||row['file-size']>1048576 ||
     !uploads.sha(row.hashes))
     fail('PACKAGE_VERIFICATION_FAILED');
    append_asset(value,{id:'catalog-apk',sha256:null,bytes:row['file-size'],
     url:'https://github.com/foxhole-team/foxhole-core/releases/download/'+value.releaseTag+
      '/foxcore-update-catalog-'+row.version+'.apk',kind:'CATALOG_APK',complete:false});
   }else if(item.id=='catalog-apk') {
    let directory=ROOT+'/'+value.id+'/catalog-input';
    let keys=native.prepare_keys(directory);
    let verified=catalog.verify_catalog(value.releaseTag,directory+'/verified',keys,
     value.managed.version,catalog.highest(),{
      index:asset_path(value,'catalog-index'),archive:path});
    value.candidate=core.from_verified(verified,null);
    if(value.candidate==null)fail('UNSUPPORTED_TARGET');
    if(length(value.candidate.changes)) {
     core.plan(value.candidate,value.owner,read(STATE).revision);
     required_assets(value,value.candidate);
    }
   }else cache_asset(value,item);
   item.complete=true;value.current=null;value.phase='WAITING';
   if(value.candidate && !length(public_assets(value))) {
    if(!same(value.binding,core.current_binding()) ||
     !same(value.managed,transaction.context()))fail('STALE_PLAN');
    let directory=ROOT+'/'+value.id+'/catalog-input';
    let verified=catalog.verify_catalog(value.releaseTag,directory+'/final-'+request.assetId,
     native.prepare_keys(directory),value.managed.version,catalog.highest(),{
      index:asset_path(value,'catalog-index'),archive:asset_path(value,'catalog-apk')});
    let candidate=core.from_verified(verified,null);
    if(!candidate)fail('UNSUPPORTED_TARGET');
    profile_locked(()=>{
     require_upload(value.id,principal);idle();let state=read(STATE);
     if(state?.coreStagedUploadId!=value.id ||
      state.coreCohortSha256!=candidate.reference.bodySha256) {
      if(!uploads.integer(state?.revision)||state.revision>=0x7ffffffe)
       fail('RECOVERY_REQUIRED');
      state.revision++;state.lastCheckedAtUnixMs=time()*1000;
      state.failureReason=null;state.deviceDownloadRequired=false;state.relayEvidence=null;
      state.coreAvailability=length(candidate.changes)?'AVAILABLE':'CURRENT';
      state.coreCohortSha256=candidate.reference.bodySha256;
      state.coreStagedUploadId=value.id;
      state.candidate=length(candidate.changes)?candidate:null;
      state.coreCheckedCandidate=length(candidate.changes)?null:candidate;
      state.availability=length(candidate.changes)?'AVAILABLE':'NOT_CHECKED';
      state.availableVersion=length(candidate.changes)?value.managed.version:null;
      write(STATE,state);
     }
     value.phase='STAGED';value.candidate=candidate;
    });
   }
   write(RECORD,value);return reply(value);
  }catch(error){value.phase='FAILED';write(RECORD,value);die(error);}
 });
};
