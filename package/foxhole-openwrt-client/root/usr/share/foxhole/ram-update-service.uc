'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as model from './ram-update-model.uc';
import * as updates from './update-model.uc';
import * as native from './update-native.uc';
import * as engine from './engine-service.uc';
import * as registry from './engine-registry.uc';
import * as engines from './engine-model.uc';
import * as state_model from './model.uc';
import * as backup_model from './backup-model.uc';
import * as backup from './backup-service.uc';
import * as store from './private-store.uc';
import * as bootstrap from './ram-bootstrap-link.uc';

const ROOT='/tmp/foxhole/ram-updates';
const STATE='/etc/foxhole/update-state.json';
const JOB='/etc/foxhole/update-job.json';
const POLICY='/etc/foxhole/update-policy.json';
const UPLOAD=ROOT+'/upload.json';
const KEY='/usr/share/foxhole/foxhole-openwrt-apk.pem';
const TERMINAL=['SUCCEEDED','FAILED','RECOVERY_REQUIRED'];
let current_cache=null;
let command_generation=null;

function fail(reason) { model.fail(reason); };
function same(a,b) { return sprintf('%J',a)==sprintf('%J',b); };
function random() {let raw=fs.readfile('/dev/urandom',16);if(length(raw||'')!=16)fail('ROUTER_UNAVAILABLE');return hexenc(raw);};
function now() {
 let found=match(fs.readfile('/proc/uptime',256)||'',/^([0-9]+\.[0-9]+) /);
 if(!found)fail('ROUTER_UNAVAILABLE');return int(+found[1]*1000);
};
function boot() {
 let value=trim(fs.readfile('/proc/sys/kernel/random/boot_id',128)||'');
 if(!match(value,/^[a-f0-9-]{36}$/))fail('ROUTER_UNAVAILABLE');return value;
};
function memory() {
 let found=match(fs.readfile('/proc/meminfo',65537)||'',/\n?MemAvailable:[ \t]+([0-9]+) kB/);
 if(!found)fail('NO_SPACE');return +found[1]*1024;
};
function admit(bytes) {if(!model.integer(bytes)||memory()<bytes+model.reserve_bytes)fail('NO_SPACE');};
function parents(path) {
 for(let part=path;;part=fs.dirname(part)) {
  let info=fs.lstat(part);
  if(info?.type!='directory'||info.uid!=0||(info.mode&0o022)&&!(part=='/tmp'&&(info.mode&0o7777)==0o1777))fail('PACKAGE_VERIFICATION_FAILED');
  if(part=='/')break;
 }
};
function facts(info) {return sprintf('%J',[info?.type,info?.uid,info?.gid,info?.mode,info?.dev,info?.inode,info?.nlink,info?.size,info?.mtime,info?.ctime]);};
function raw(path,maximum,empty) {
 parents(fs.dirname(path));let before=fs.lstat(path);
 if(before?.type!='file'||before.uid!=0||before.nlink!=1||(before.mode&0o022)||before.size<(empty?0:1)||before.size>maximum)
  fail('PACKAGE_VERIFICATION_FAILED');
 admit(2*before.size);let value=fs.readfile(path,maximum+1);
 if(value==null||length(value)!=before.size||facts(before)!=facts(fs.lstat(path)))fail('PACKAGE_VERIFICATION_FAILED');return value;
};
function decode(path,maximum) {try{return json(raw(path,maximum,false));}catch(_){fail('PACKAGE_VERIFICATION_FAILED');}};
function read(path,maximum) {let value=store.read(path,maximum||524288);return value==null?null:json(value);};
function write(path,value) {
 let text=sprintf('%J',value);if(length(text)>524288)fail('PACKAGE_VERIFICATION_FAILED');store.write(path,text);
};
function transaction(fn) {
 store.target('/etc/foxhole/ram-update.lock');let handle=fs.open('/etc/foxhole/ram-update.lock','a+',0o600);
 if(!handle||!handle.lock('xn')||!store.file_metadata(fs.lstat('/etc/foxhole/ram-update.lock'))) {
  if(handle)handle.close();fail('BUSY');
 }
 try{let value=fn();handle.lock('u');handle.close();return value;}
 catch(error){try{handle.lock('u');handle.close();}catch(_){}die(error);}
};
function profile_locked(fn) {
 store.target('/etc/foxhole/state.lock');let handle=fs.open('/etc/foxhole/state.lock','a+',0o600);
 if(!handle||!handle.lock('xn')||!store.file_metadata(fs.lstat('/etc/foxhole/state.lock'))) {
  if(handle)handle.close();fail('BUSY');
 }
 try{let value=fn();handle.lock('u');handle.close();return value;}
 catch(error){try{handle.lock('u');handle.close();}catch(_){}die(error);}
};
function policy() {return updates.policy(read(POLICY,8192));};
function state() {
 let value=read(STATE);
 if(value!=null&&(value.schema!=1||!model.integer(value.revision)||value.revision>=0x7ffffffe))fail('RECOVERY_REQUIRED');
 if(value?.deployment=='RAM_BASE')return value;
 return {schema:1,deployment:'RAM_BASE',revision:value?.revision||0,availability:'NOT_CHECKED',availableVersion:null,
  lastCheckedAtUnixMs:null,failureReason:null,candidate:null,deviceDownloadRequired:false,relayEvidence:null};
};
function save_state(value) {value.revision++;write(STATE,value);return value;};
function job_record() {return read(JOB);};
function active(value) {return value!=null&&index(TERMINAL,value.state)<0;};
function require_idle() {
 backup.guard();let job=job_record(),module_job=read('/etc/foxhole/engine-job.json');
 if(active(job)||job?.state=='RECOVERY_REQUIRED'||active(module_job)||module_job?.state=='RECOVERY_REQUIRED')fail('BUSY');
};
function principal_current(principal) {
 if(type(principal)!='object'||!model.sha(principal.verifier)||!engine.update_principal_current(principal))fail('AUTHENTICATION_FAILED');
 return model.owner(principal);
};
function data_state() {
 let value=read('/etc/foxhole/state.json',262144);if(value==null)fail('PACKAGE_VERIFICATION_FAILED');return state_model.validate_state(value);
};
function stop_intent() {
 let value=read('/etc/foxhole/engine-intent.json',4096)||{schema:1,revision:0};
 if(value.schema!=1||!model.integer(value.revision)||value.revision>=0x7fffffff)fail('PACKAGE_VERIFICATION_FAILED');return value.revision;
};
function capture(operation,args,maximum,milliseconds) {
 admit(2*maximum);store.directory(ROOT);let nonce=random(),output=ROOT+'/io-'+nonce;
 model.capture_arguments(output,operation,args);
 let directory='/tmp/foxhole/engine-command-'+nonce+'.io';store.directory(directory);
 if(command_generation==null)command_generation={helper:raw('/usr/libexec/foxhole-ram-update-command',32768,false),
  utility:raw('/usr/share/foxhole/engine-capture.uc',32768,false)};
 store.write(directory+'/helper',command_generation.helper);
 store.write(directory+'/utility.uc',command_generation.utility);
 let code=system(['/bin/sh',directory+'/helper',output,''+maximum,''+milliseconds,operation,...args],milliseconds+5000);
 let clean=!fs.lstat(directory+'/owner.json')&&!fs.lstat(directory+'/stdout')&&!fs.lstat(directory+'/stderr');
 let stdout=null,stderr=null;
 if(fs.lstat(output)&&fs.lstat(output+'.err')) {
  stdout=raw(output,maximum,true);stderr=raw(output+'.err',operation=='probe'?16384:1048576,true);
 }
 if(clean) {
  for(let path in [directory+'/helper',directory+'/utility.uc'])if(!fs.unlink(path))clean=false;
  if(!fs.rmdir(directory))clean=false;
 }
 for(let path in [output,output+'.err'])if(fs.lstat(path)&&!fs.unlink(path))clean=false;
 if(!clean||stdout==null||stderr==null)fail('PACKAGE_VERIFICATION_FAILED');return {code,stdout,stderr};
};
function native_command(operation,args,maximum) {
 let result=capture(operation,args,maximum||8388608,130000);
 if(result.code!=0)fail('PACKAGE_VERIFICATION_FAILED');return result.stdout;
};
function current() {
 let marker=decode('/tmp/foxhole-ram-active.json',4096);
 if(marker.schema!=1||marker.storage!='RAM'||marker.phase!='active'||!model.stage(marker.stage)||!model.sha(marker.baseSha256)||
  type(marker.version)!='string')fail('UNSUPPORTED_TARGET');
 let database=marker.stage+'/root/lib/apk/db/installed';parents(fs.dirname(database));let info=fs.lstat(database);
 if(info?.type!='file'||info.uid!=0||info.nlink!=1||(info.mode&0o022)||info.size<1||info.size>4194304)fail('UNSUPPORTED_TARGET');
 let cache_key=sprintf('%J',[marker,facts(info)]);
 if(current_cache?.key==cache_key)return current_cache.value;
 if(marker.stageDbSha256!=null&&(!model.sha(marker.stageDbSha256)||
  digest.sha256(raw(database,4194304,false))!=marker.stageDbSha256))fail('VERSION_IDENTITY_CONFLICT');
 let target=native.target(),rows=json(native_command('current',[marker.stage+'/root',target.architecture],32768));
 if(type(rows)!='array'||length(rows)!=1||rows[0].name!='foxhole-openwrt-client'||rows[0].arch!='noarch'||
  !model.version(rows[0].version)||!same(rows[0].status,['installed'])||
  model.release_for(rows[0].version)!='v'+split(marker.version,'-r')[0])fail('UNSUPPORTED_TARGET');
 if(model.version(marker.version)&&marker.version!=rows[0].version)fail('VERSION_IDENTITY_CONFLICT');
 let value={marker,version:rows[0].version,target,root:marker.stage+'/root'};
 current_cache={key:cache_key,value};return value;
};
function context() {
 let profile=data_state(),value=registry.snapshot_context(profile),installed=registry.read(),modules=[];
 for(let selected in installed.selected) {
  let slot=engines.selected(installed,selected.id);if(!slot)fail('PACKAGE_VERIFICATION_FAILED');
  push(modules,{id:slot.id,storage:slot.storage,version:slot.version});
 }
 return {...value,stateRevision:profile.revision,stateWithoutStop:backup_model.without_stop(profile),
  modules,registrySha256:digest.sha256(sprintf('%J',installed))};
};
function binding(value) {
 return {routerId:value.routerId,bootId:value.bootId,worldSha256:value.worldSha256,registrySha256:value.registrySha256,
  activeProfileId:value.activeProfileId,activeConfigSha256:value.activeConfigSha256,stateRevision:value.stateRevision,
  stateWithoutStop:value.stateWithoutStop,stopIntent:value.stopIntent};
};
function authorized(job) {
 if(job.automatic) {
  let flag=policy();return job.mutationStarted==true||flag.enabled&&flag.revision==job.policyRevision;
 }
 return engine.update_principal_current(job.principal);
};
function require_job(job) {
 if(!authorized(job))fail(job.automatic?'STALE_PLAN':'AUTHENTICATION_FAILED');
 if(job.bootId!=boot())fail('STALE_PLAN');
 if(!job.mutationStarted&&job.stopIntent!=stop_intent())fail('STALE_PLAN');
};
function public_job(job) {
 return {schema:1,routerId:job.routerId,jobId:job.jobId,planId:job.planId||null,operation:job.operation,
  automatic:job.automatic==true,state:job.state,step:job.step,progressPercent:job.progressPercent,
  revision:job.revision,failureReason:job.failureReason||null,previousConnectionRestored:job.previousConnectionRestored??null,
  cancelledByStop:job.cancelledByStop==true};
};
function save_job(job) {job.revision++;write(JOB,job);};
function progress(job,phase,step,percent) {
 transaction(()=>{let live=job_record();if(live?.jobId!=job.jobId)fail('STALE_PLAN');
  job.state=phase;job.step=step;job.progressPercent=percent;save_job(job);});
};
function new_job(operation,principal,automatic,plan) {
 let flag=policy(),ctx=context();
 return {schema:1,deployment:'RAM_BASE',routerId:ctx.routerId,jobId:'update-job-'+random(),planId:plan?.planId||null,
  operation,principal,owner:automatic?null:model.owner(principal),automatic,policyRevision:flag.revision,
  state:'QUEUED',step:'PREPARING',progressPercent:0,revision:0,failureReason:null,
  previousConnectionRestored:null,mutationStarted:false,atomicPackagePhase:false,
  bootId:boot(),stopIntent:stop_intent(),plan,createdAtUptimeMs:now(),worker:null};
};
function launch(job) {
 if(system(['/bin/sh','-c','umask 077; /usr/libexec/foxhole-ram-update-job "$1" >/dev/null 2>&1 &','foxhole-ram-update',job.jobId],1000)!=0)
  fail('ROUTER_UNAVAILABLE');
 return public_job(job);
};
function candidate_directory(id) {if(!model.candidate_id(id))fail('PACKAGE_VERIFICATION_FAILED');return ROOT+'/candidates/'+id;};
function verify_payload(directory,document) {
 for(let folder in document.paths) {
  let path=directory+'/root'+(length(folder.name)?'/'+folder.name:'');
  parents(path);let parent=fs.lstat(path);
  if(parent?.type!='directory'||parent.uid!=0||(parent.mode&0o7777)!=folder.acl.mode)fail('PACKAGE_VERIFICATION_FAILED');
  for(let file in folder.files||[]) {
   let target=path+'/'+file.name,info=fs.lstat(target);
   if(info?.type!='file'||info.uid!=0||info.nlink!=1||(info.mode&0o7777)!=file.acl.mode||info.size!=file.size||
    digest.sha256(raw(target,8388608,file.size==0))!=file.hash)fail('PACKAGE_VERIFICATION_FAILED');
  }
 }
};
function verify_dependencies(document) {
 let dependencies=document.info?.depends;
 if(type(dependencies)!='array'||!length(dependencies)||length(dependencies)>64)fail('UNSUPPORTED_TARGET');
 let installed=current(),result=capture('dependencies',[installed.root,installed.target.architecture,...dependencies],262144,30000);
 if(result.code!=0)fail('UNSUPPORTED_TARGET');let rows=json(result.stdout);
 if(type(rows)!='array'||!length(rows)||length(rows)>512)fail('UNSUPPORTED_TARGET');
 for(let row in rows)if(!same(row.status,['installed']))fail('UNSUPPORTED_TARGET');
};
function stage_candidate(archive,manifest,id) {
 let directory=candidate_directory(id);store.directory(directory);store.directory(directory+'/keys');
 let key=raw(KEY,16384,false);if(digest.sha256(key)!=model.signer_sha256)fail('PACKAGE_VERIFICATION_FAILED');
 store.write(directory+'/keys/foxhole.pem',key);
 let bytes=raw(archive,model.maximum_apk_bytes,false);
 if(length(bytes)!=manifest.bytes||digest.sha256(bytes)!=manifest.sha256)fail('PACKAGE_VERIFICATION_FAILED');bytes=null;
 native_command('verify',[directory+'/keys',archive],4096);
 let maximum=min(8388608,int((memory()-model.reserve_bytes)/4));if(maximum<262144)fail('NO_SPACE');
 let text=native_command('dump',[archive],maximum);admit(4*length(text));let document=json(text);text=null;
 model.metadata(document,manifest.version);
 verify_dependencies(document);
 admit(document.info['installed-size']+2*manifest.bytes+4194304);
 if(fs.lstat(directory+'/root'))fail('PACKAGE_VERIFICATION_FAILED');store.directory(directory+'/root');
 // Native extract preserves the existing destination root ACL.
 let signed_root=filter(document.paths,row=>row.name=='');
 if(length(signed_root)!=1||!fs.chmod(directory+'/root',signed_root[0].acl.mode))fail('PACKAGE_VERIFICATION_FAILED');
 native_command('extract',[directory+'/keys',archive,directory+'/root'],4096);
 verify_payload(directory,document);
 let policy=model.policy(decode(directory+'/root/usr/share/foxhole/update-policy.json',8192),manifest.version,manifest.releaseTag);
 if(digest.sha256(raw(directory+'/root'+KEY,16384,false))!=model.signer_sha256)fail('PACKAGE_VERIFICATION_FAILED');
 let recovery=bootstrap.prove(manifest,digest.sha256(sprintf('%J',document)));
 if(digest.sha256(raw(archive,model.maximum_apk_bytes,false))!=manifest.sha256)fail('PACKAGE_VERIFICATION_FAILED');
 native_command('verify',[directory+'/keys',archive],4096);
 if(!same(json(native_command('dump',[archive],maximum)),document))fail('PACKAGE_VERIFICATION_FAILED');
 let receipt={schema:1,id,version:manifest.version,releaseTag:manifest.releaseTag,sha256:manifest.sha256,bytes:manifest.bytes,
  installedBytes:document.info['installed-size'],root:directory+'/root',archive:directory+'/base.apk',policy,payload:document,recovery};
 write(directory+'/receipt.json',receipt);
 return {id,version:receipt.version,releaseTag:receipt.releaseTag,sha256:receipt.sha256,bytes:receipt.bytes,
  installedBytes:receipt.installedBytes,root:receipt.root,archive:receipt.archive,
  receiptSha256:digest.sha256(raw(directory+'/receipt.json',524288,false))};
};
function verified_candidate(value) {
 let directory=candidate_directory(value.id),receipt=decode(directory+'/receipt.json',524288);
 if(digest.sha256(raw(directory+'/receipt.json',524288,false))!=value.receiptSha256||receipt.id!=value.id||
  receipt.sha256!=value.sha256||receipt.version!=value.version||receipt.archive!=directory+'/base.apk'||receipt.root!=directory+'/root')fail('PACKAGE_VERIFICATION_FAILED');
 if(digest.sha256(raw(receipt.archive,model.maximum_apk_bytes,false))!=receipt.sha256)fail('PACKAGE_VERIFICATION_FAILED');
 native_command('verify',[directory+'/keys',receipt.archive],4096);verify_payload(directory,receipt.payload);
 bootstrap.recheck(receipt.recovery,receipt,digest.sha256(sprintf('%J',receipt.payload)));return receipt;
};
function download(url,path,maximum) {
 let result=capture('fetch',[url],maximum,65000);
 if(result.code!=0)return {network:model.network_unreachable(result.code,result.stderr),code:result.code};
 if(length(result.stdout)<1||length(result.stdout)>maximum)fail('DOWNLOAD_FAILED');store.write(path,result.stdout);return {network:false,code:0};
};
function publish_candidate(candidate,guard) {
 return transaction(()=>profile_locked(()=>{if(type(guard)!='function')fail('INVALID_REQUEST');guard();backup.guard();
  if(model.compare(candidate.version,current().version)<=0)fail('DOWNGRADE_REJECTED');
  let value=state(),ctx=context();value.candidate={...candidate,binding:binding(ctx),checkedAtUptimeMs:now()};
  value.availability='AVAILABLE';value.availableVersion=candidate.version;value.lastCheckedAtUnixMs=time()*1000;
  value.failureReason=null;value.deviceDownloadRequired=false;value.relayEvidence=null;return save_state(value);}));
};
function record_check_failure(job,error,network) {
 transaction(()=>{let value=state();value.availability='CHECK_FAILED';value.availableVersion=null;value.candidate=null;
  value.lastCheckedAtUnixMs=time()*1000;value.failureReason=error;value.deviceDownloadRequired=network==true;
  value.relayEvidence=network?{owner:job.owner,jobId:job.jobId,bootId:boot(),observedAtUptimeMs:now()}:null;save_state(value);});
};
function upload_record() {
 let value=read(UPLOAD,16384);if(value==null)return null;
 if(value.schema!=1||!model.upload_id(value.id)||!model.sha(value.owner)||type(value.principal)!='object'||
  model.owner(value.principal)!=value.owner||
  !model.integer(value.nextOffset)||!model.integer(value.stopIntent)||!model.integer(value.expiresAtUptimeMs)||
  index(['RECEIVING','VERIFYING','FINISHED','FAILED','EXPIRED'],value.phase)<0)fail('PACKAGE_VERIFICATION_FAILED');
 try {model.begin_request({...value.manifest,expectedRevision:0});}catch(_){fail('PACKAGE_VERIFICATION_FAILED');}
 if(value.nextOffset>value.manifest.fileBytes)fail('PACKAGE_VERIFICATION_FAILED');
 for(let key in ['pending','last'])if(value[key]!=null) {
  let chunk=value[key];
  if(!model.integer(chunk.offset)||!model.integer(chunk.bytes)||chunk.bytes<1||chunk.bytes>model.maximum_chunk_bytes||
   !model.sha(chunk.sha256)||chunk.offset+chunk.bytes>value.manifest.fileBytes||
   key=='pending'&&chunk.offset!=value.nextOffset||key=='last'&&chunk.offset+chunk.bytes!=value.nextOffset)fail('PACKAGE_VERIFICATION_FAILED');
 }
 if(value.verifiedCandidate!=null&&(!model.candidate_id(value.verifiedCandidate.id)||
  !model.sha(value.verifiedCandidate.receiptSha256)||value.verifiedCandidate.version!=value.manifest.version||
  value.verifiedCandidate.sha256!=value.manifest.fileSha256||value.verifiedCandidate.bytes!=value.manifest.fileBytes))fail('PACKAGE_VERIFICATION_FAILED');
 return value;
};
function upload_path(value) {if(!model.upload_id(value.id))fail('PACKAGE_VERIFICATION_FAILED');return ROOT+'/uploads/'+value.id+'/payload';};
function expire_upload() {
 let value=upload_record();if(value==null)return null;
 if(!model.upload_id(value.id)||!model.integer(value.expiresAtUptimeMs)||value.schema!=1)fail('PACKAGE_VERIFICATION_FAILED');
 if(value.phase!='FINISHED'&&value.phase!='EXPIRED'&&value.stopIntent!=stop_intent()) {
  value.phase='FAILED';value.failureReason='STALE_PLAN';write(UPLOAD,value);return value;
 }
 if(index(['RECEIVING','VERIFYING'],value.phase)>=0&&!engine.update_principal_current(value.principal)) {
  value.phase='FAILED';value.failureReason='AUTHENTICATION_FAILED';write(UPLOAD,value);return value;
 }
 if(value.bootId==boot()&&now()<=value.expiresAtUptimeMs&&index(['EXPIRED','FAILED','FINISHED'],value.phase)<0)return value;
 if(value.bootId==boot()&&now()<=value.expiresAtUptimeMs&&index(['FINISHED','FAILED'],value.phase)>=0)return value;
 let path=upload_path(value),info=fs.lstat(path);
 if(info) {
  parents(fs.dirname(path));
  if(info.type!='file'||info.uid!=0||info.nlink!=1||(info.mode&0o7777)!=0o600||info.size>model.maximum_apk_bytes||
   !fs.unlink(path))fail('PACKAGE_VERIFICATION_FAILED');
 }
 value.phase='EXPIRED';write(UPLOAD,value);return value;
};
function require_upload(id,principal) {
 let owner=principal_current(principal),value=expire_upload();
 if(value?.id!=id||value.owner!=owner)fail('AUTHENTICATION_FAILED');
 if(value.phase=='EXPIRED')fail('STALE_PLAN');
 if(value.phase=='FAILED')fail(index(updates.reasons,value.failureReason)>=0?value.failureReason:'PACKAGE_VERIFICATION_FAILED');
 if(value.stopIntent!=stop_intent()||value.bootId!=boot())fail('STALE_PLAN');return value;
};
function reconcile_chunk(value) {
 let path=upload_path(value),info=fs.lstat(path);
 if(value.phase=='FINISHED')return value;
 if(info?.type!='file'||info.uid!=0||info.nlink!=1||(info.mode&0o7777)!=0o600||info.size>value.manifest.fileBytes)fail('PACKAGE_VERIFICATION_FAILED');
 if(value.pending) {
  if(info.size==value.pending.offset)return value;
  if(info.size!=value.pending.offset+value.pending.bytes)fail('PACKAGE_VERIFICATION_FAILED');
  let file=fs.open(path,'re');if(!file||file.seek(value.pending.offset,0)!=true)fail('PACKAGE_VERIFICATION_FAILED');
  let bytes=file.read(value.pending.bytes);file.close();
  if(bytes==null||length(bytes)!=value.pending.bytes||digest.sha256(bytes)!=value.pending.sha256)fail('PACKAGE_VERIFICATION_FAILED');
  value.last=value.pending;value.nextOffset=info.size;value.pending=null;write(UPLOAD,value);
 } else if(info.size!=value.nextOffset)fail('PACKAGE_VERIFICATION_FAILED');
 return value;
};
function discard_upload(value) {
 if(value==null||index(['FAILED','EXPIRED'],value.phase)<0)return;
 let path=upload_path(value),info=fs.lstat(path);if(info==null)return;
 parents(fs.dirname(path));
 if(info.type!='file'||info.uid!=0||info.nlink!=1||(info.mode&0o7777)!=0o600||info.size>model.maximum_apk_bytes||
  !fs.unlink(path))fail('PACKAGE_VERIFICATION_FAILED');
};
function remove_owned_tree(path,counter) {
 let info=fs.lstat(path);if(info==null)return;
 if(++counter.files>2048||info.uid!=0||(info.mode&0o022))fail('PACKAGE_VERIFICATION_FAILED');
 if(info.type=='directory') {
  for(let child in [...(fs.glob(path+'/*')||[]),...(fs.glob(path+'/.*')||[])]) {
   if(match(child,/\/\.\.?$/))continue;remove_owned_tree(child,counter);
  }
  if(!fs.rmdir(path))fail('PACKAGE_VERIFICATION_FAILED');
 } else {
  counter.bytes+=info.size;
  if(info.type!='file'||info.nlink!=1||counter.bytes>67108864||!fs.unlink(path))fail('PACKAGE_VERIFICATION_FAILED');
 }
};
function clean_candidate(id) {
 if(!model.candidate_id(id))return;let directory=candidate_directory(id);
 if(current().marker.stage==directory)return;
 let mounts=fs.readfile('/proc/self/mountinfo',524289);if(mounts==null||length(mounts)>524288)fail('PACKAGE_VERIFICATION_FAILED');
 for(let line in split(mounts,'\n')) {
  let path=split(line,' ')[4];if(path==directory||index(path||'',directory+'/')==0)fail('BUSY');
 }
 remove_owned_tree(directory,{files:0,bytes:0});
};
function cleanup_pending_assets() {
 let value=state(),previous=job_record(),upload=expire_upload(),ids={};
 if(value.candidate?.id)ids[value.candidate.id]=true;
 if(previous?.operation=='CHECK'&&previous.deployment=='RAM_BASE'&&previous.candidateId)ids[previous.candidateId]=true;
 if(upload?.phase=='FAILED'&&upload.candidateId)ids[upload.candidateId]=true;
 for(let id in keys(ids))clean_candidate(id);
 discard_upload(upload);
};
function budget(candidate,ctx) {
 return {downloadBytes:candidate.bytes,stagingBytes:candidate.installedBytes+2*candidate.bytes+4194304,
  runtimeMemoryBytes:0,flashRequiredBytes:bootstrap.flash_required_bytes,ramRequiredBytes:candidate.installedBytes+4*candidate.bytes+4194304+model.reserve_bytes,
  flashAvailableBytes:ctx.flashAvailableBytes,ramAvailableBytes:ctx.ramAvailableBytes};
};
function switch_available() {
 let path='/usr/libexec/foxhole-ram-switch';parents(fs.dirname(path));let info=fs.lstat(path);
 return info?.type=='file'&&info.uid==0&&info.nlink==1&&(info.mode&0o022)==0&&(info.mode&0o111)!=0&&info.size>0&&info.size<=1048576;
};
function make_plan(principal,automatic) {
 let value=state(),candidate=value.candidate,ctx=context(),installed=current();
 if(value.availability!='AVAILABLE'||candidate==null)fail('NOT_CHECKED');
 if(candidate.checkedAtUptimeMs>now()||now()-candidate.checkedAtUptimeMs>300000||!same(candidate.binding,binding(ctx)))fail('STALE_PLAN');
 if(model.compare(candidate.version,installed.version)<=0)fail('DOWNGRADE_REJECTED');
 verified_candidate(candidate);
 if(!switch_available())fail('RAM_STAGE_UNAVAILABLE');
 let required=budget(candidate,ctx);if(ctx.ramAvailableBytes<required.ramRequiredBytes||ctx.flashAvailableBytes<required.flashRequiredBytes)fail('NO_SPACE');
 let plan={schema:1,routerId:ctx.routerId,revision:value.revision,planId:'update-plan-'+random(),
  fromVersion:installed.version,toVersion:candidate.version,engineIds:sort(map(ctx.modules,item=>item.id)),
  fromBaseSha256:installed.marker.baseSha256,fromStage:installed.marker.stage,
  changes:[{id:'foxhole',fromVersion:installed.version,toVersion:candidate.version,storage:null}],impact:'RECONNECT_REQUIRED',
  confirmationRequired:true,expiresAtUptimeMs:now()+300000,bootId:boot(),budget:required,
  owner:automatic?null:model.owner(principal),binding:binding(ctx),candidate};
 plan.planSha256=digest.sha256(sprintf('%J',plan));return plan;
};
function public_plan(value) {
 let result={...value};for(let field in ['owner','binding','candidate','fromBaseSha256','fromStage'])delete result[field];return result;
};
function plan_digest(value) {let result={...value};delete result.planSha256;return digest.sha256(sprintf('%J',result));};
function failure_reason(error) {
 let code=type(error)=='string'?error:error?.message;
 let reason=index(['update_','engine_'],substr(code||'',0,7))>=0?uc(substr(code,7)):'PACKAGE_VERIFICATION_FAILED';
 return index(updates.reasons,reason)>=0?reason:'PACKAGE_VERIFICATION_FAILED';
};
function failed(job,error) {
 let reason=failure_reason(error);
 let stop_changed=job.stopIntent!=stop_intent();if(stop_changed&&!job.mutationStarted)reason='STALE_PLAN';
 if(job.operation=='CHECK') {
  let value=state(),relay=value.relayEvidence?.jobId==job.jobId&&value.deviceDownloadRequired==true&&
   !stop_changed&&authorized(job);
  record_check_failure(job,reason,relay);
 }
 transaction(()=>profile_locked(()=>{
  let live=job_record();if(live?.jobId!=job.jobId)fail('RECOVERY_REQUIRED');
  job.cancelledByStop=job.stopIntent!=stop_intent();if(job.cancelledByStop&&!job.mutationStarted)reason='STALE_PLAN';
  job.failureReason=job.mutationStarted?'RECOVERY_REQUIRED':reason;job.atomicPackagePhase=false;
  job.state=job.mutationStarted?'RECOVERY_REQUIRED':'FAILED';job.step=job.state;save_job(job);
 }));
 if(job.mutationStarted&&job.cancelledByStop&&data_state().activeServerId==null)
  system(['/etc/init.d/foxhole-runtime','restart'],30000);
};
function require_candidate_manifest(receipt) {
 if(receipt.schema!=1||!model.candidate_id(receipt.id)||!model.version(receipt.version)||!model.sha(receipt.sha256)||
  receipt.root!=candidate_directory(receipt.id)+'/root'||receipt.archive!=candidate_directory(receipt.id)+'/base.apk')fail('PACKAGE_VERIFICATION_FAILED');
};
function protected_snapshot() {
 let result={},pending=['/etc/foxhole'],paths=['/etc/config/foxhole','/etc/config/network','/etc/config/dhcp',
  '/etc/config/firewall','/etc/config/uhttpd','/etc/apk/world','/lib/apk/db/installed'];
 while(length(pending)) {
  let directory=shift(pending);parents(directory);
  if(length(split(directory,'/'))>10)fail('PACKAGE_VERIFICATION_FAILED');
  for(let path in fs.glob(directory+'/*')||[]) {
   if(index([STATE,JOB,POLICY,'/etc/foxhole/update-cache','/etc/foxhole/ram-update'],path)>=0||
    match(path,/^\/etc\/foxhole\/update-last-[a-f0-9]{64}\.json$/))continue;
   let info=fs.lstat(path);
   if(info?.type=='directory')push(pending,path);else push(paths,path);
   if(length(pending)+length(paths)>1024)fail('PACKAGE_VERIFICATION_FAILED');
  }
 }
 let total=0;
 for(let path in paths) {
  let info=fs.lstat(path);
  if(path=='/etc/foxhole/history.json.gz'||path=='/etc/foxhole/history.json.gz.new') {
   if(info?.type!='file'||info.uid!=0||info.nlink!=1||(info.mode&0o022)||info.size>6291456)fail('PACKAGE_VERIFICATION_FAILED');
   result[path]={role:'mutable-history'};continue;
  }
  if(info?.type=='file'&&info.uid==0&&info.nlink==1&&(info.mode&0o7777)==0o600&&info.size==0&&match(path,/\.lock$/)) {
   result[path]={role:'private-lock'};continue;
  }
  let maximum=path=='/lib/apk/db/installed'?4194304:1048576,alias=index(['/etc/foxhole/mobile.crt','/etc/foxhole/mobile-identity/cert.pem'],path)>=0;
  if(info?.type!='file'||info.uid!=0||(info.mode&0o022)||info.size<1||info.size>maximum||
   info.nlink!=1&&!(alias&&info.nlink==2))fail('PACKAGE_VERIFICATION_FAILED');
  admit(2*info.size);let text=fs.readfile(path,maximum+1);total+=length(text||'');
  if(text==null||length(text)!=info.size||total>16777216||facts(info)!=facts(fs.lstat(path)))fail('PACKAGE_VERIFICATION_FAILED');
  if(path=='/etc/config/dhcp')text=join('\n',filter(split(text,'\n'),line=>
   !match(line,/^[ \t]*list[ \t]+addnmount[ \t]+'\/var\/run\/foxhole\.dnsmasq'[ \t]*$/)));
  result[path]={sha256:digest.sha256(text),mode:info.mode,uid:info.uid,gid:info.gid,nlink:info.nlink};
 }
 return result;
};
function protected_unchanged(before,job) {
 let after=protected_snapshot();before={...before};after={...after};
 for(let path in ['/etc/foxhole/history.json.gz','/etc/foxhole/history.json.gz.new']){delete before[path];delete after[path];}
 if(stop_intent()>job.stopIntent) {
  let profile=data_state(),expected=job.plan.binding;
  if(profile.activeServerId!=null||backup_model.without_stop(profile)!=expected.stateWithoutStop||
   profile.revision!=expected.stateRevision+(expected.activeProfileId==null?0:1))fail('RECOVERY_REQUIRED');
  for(let path in ['/etc/foxhole/state.json','/etc/foxhole/engine-intent.json']){delete before[path];delete after[path];}
 }
 if(!same(before,after))fail('RECOVERY_REQUIRED');
};
function automatic_apply(job) {
 if(!job.automatic||state().availability!='AVAILABLE')return null;
 return engine.update_locked(()=>transaction(()=>{
  require_idle();let flag=policy();
  if(!flag.enabled||flag.revision!=job.policyRevision||job.stopIntent!=stop_intent())return null;
  let plan=make_plan(null,true),value=new_job('APPLY',null,true,plan);write(JOB,value);return value;
 }));
};
function runtime_namespace() {
 let directory='/etc/foxhole/ram-update',marker=directory+'/owner.json';
 store.directory(directory);let value=read(marker,4096);
 if(value==null) {
  if(length(fs.glob(directory+'/*')||[])||length(fs.glob(directory+'/.[!.]*')||[]))fail('PACKAGE_VERIFICATION_FAILED');
  write(marker,{schema:1,abi:1,kind:'foxhole-ram-update-runtime-v1'});
 } else if(value.schema!=1||value.abi!=1||value.kind!='foxhole-ram-update-runtime-v1'||length(keys(value))!=3)
  fail('PACKAGE_VERIFICATION_FAILED');
};
function worker_live(job) {
 return job.worker!=null&&engines.worker_current(job.worker,engine.update_process_snapshot(job.worker.pid),boot());
};
function reconcile_job(job) {
 if(job?.deployment!='RAM_BASE'||!active(job)||worker_live(job))return job;
 if(job.state=='QUEUED'&&job.bootId==boot()&&job.createdAtUptimeMs<=now()&&now()-job.createdAtUptimeMs<=10000)return job;
 return transaction(()=>{
  let value=job_record();if(value?.jobId!=job.jobId||!active(value)||worker_live(value))return value;
  value.state=value.mutationStarted?'RECOVERY_REQUIRED':'FAILED';value.step=value.state;
  value.failureReason=value.mutationStarted?'RECOVERY_REQUIRED':'ROUTER_UNAVAILABLE';value.atomicPackagePhase=false;save_job(value);
  if(value.operation=='CHECK') {
   let current_state=state();current_state.availability='CHECK_FAILED';current_state.failureReason=value.failureReason;
   current_state.candidate=null;current_state.availableVersion=null;current_state.deviceDownloadRequired=false;current_state.relayEvidence=null;save_state(current_state);
  }
  return value;
 });
};
function finish_atomic(job) {
 let stopped=transaction(()=>profile_locked(()=>{
  let live=job_record();if(live?.jobId!=job.jobId)fail('RECOVERY_REQUIRED');
  let changed=stop_intent()>job.stopIntent;
  if(changed&&data_state().activeServerId!=null)fail('RECOVERY_REQUIRED');
  job.atomicPackagePhase=false;job.previousConnectionRestored=changed?false:null;save_job(job);return changed;
 }));
 // Stop may have been deferred after the selector had already reconnected.
 // Once the atomic phase ends, apply the current stopped/kill-switch policy.
 if(stopped&&system(['/etc/init.d/foxhole-runtime','restart'],30000)!=0)fail('RECOVERY_REQUIRED');
};

export function status(principal) {
 let owner=principal_current(principal),installed=current(),ctx=context(),flag=policy(),job=reconcile_job(job_record()),value=state();
 let relay=value.deviceDownloadRequired==true&&value.relayEvidence?.owner==owner&&value.relayEvidence.bootId==boot()&&
  value.relayEvidence.observedAtUptimeMs<=now()&&now()-value.relayEvidence.observedAtUptimeMs<=model.upload_lifetime_ms;
 let own=job?.deployment=='RAM_BASE'&&!job.automatic&&job.owner==owner?public_job(job):null;
 if(value.availability=='CURRENT'&&value.availableVersion!=installed.version) {
  value.availability='NOT_CHECKED';value.availableVersion=null;value.failureReason='NOT_CHECKED';
 }
 if(value.availability=='AVAILABLE'&&(value.candidate==null||!fs.lstat(candidate_directory(value.candidate.id)+'/receipt.json')||
  value.candidate.checkedAtUptimeMs>now()||now()-value.candidate.checkedAtUptimeMs>300000||
  !same(value.candidate.binding,binding(ctx)))) {
  value.availability='CHECK_FAILED';value.availableVersion=null;value.failureReason='STALE_PLAN';
 }
 return {schema:1,supported:true,routerId:ctx.routerId,revision:value.revision,currentVersion:installed.version,
  availableVersion:value.availableVersion,availability:value.availability,lastCheckedAtUnixMs:value.lastCheckedAtUnixMs,
  failureReason:value.failureReason,busy:active(job)||job?.state=='RECOVERY_REQUIRED',deviceDownloadRequired:relay,
  autoUpdate:{enabled:flag.enabled,intervalSeconds:86400,lastAttemptAtUnixMs:flag.lastAttemptAtUnixMs,
   nextCheckAtUnixMs:flag.enabled?(flag.lastAttemptAtUnixMs==null?time()*1000:flag.lastAttemptAtUnixMs+86400000):null,
   suspendedReason:job?.state=='RECOVERY_REQUIRED'?'RECOVERY_REQUIRED':null},installedModules:ctx.modules,
  activeOwnJob:own&&active(job)?own:null,lastOwnJob:own,activeAutomaticJob:job?.automatic&&active(job)?{
   operation:job.operation,automatic:true,state:job.state,step:job.step,progressPercent:job.progressPercent,failureReason:job.failureReason}:null};
};
export function deployment() {
 let installed=current();return {storage:'RAM',version:installed.version};
};
export function settings(request,principal) {
 principal_current(principal);backup.guard();current();
 transaction(()=>{let value=state();if(!model.integer(request.expectedRevision)||request.expectedRevision!=value.revision||type(request.autoUpdateEnabled)!='bool')fail('STALE_SESSION');
  let flag=policy();if(flag.revision>=0x7ffffffe)fail('STALE_SESSION');flag.enabled=request.autoUpdateEnabled;flag.revision++;write(POLICY,flag);save_state(value);});return status(principal);
};
export function check(request,principal) {
 principal_current(principal);current();
 let job=engine.update_locked(()=>transaction(()=>{require_idle();let upload=expire_upload();
  if(upload!=null&&index(['EXPIRED','FAILED','FINISHED'],upload.phase)<0)fail('BUSY');
  let value=state();if(!model.integer(request.expectedRevision)||request.expectedRevision!=value.revision)fail('STALE_SESSION');
  cleanup_pending_assets();
  value.deviceDownloadRequired=false;value.relayEvidence=null;value.availability='NOT_CHECKED';value.failureReason='NOT_CHECKED';
  value.candidate=null;value.availableVersion=null;save_state(value);
  let job=new_job('CHECK',principal,false,null);write(JOB,job);return job;}));return launch(job);
};
export function plan(request,principal) {
 principal_current(principal);current();
 return engine.update_locked(()=>transaction(()=>{require_idle();if(!model.integer(request.expectedRevision)||request.expectedRevision!=state().revision)fail('STALE_SESSION');
  let value=make_plan(principal,false);write(ROOT+'/plan-'+model.owner(principal),value);return public_plan(value);}));
};
export function apply(request,principal) {
 let owner=principal_current(principal);current();
 let job=engine.update_locked(()=>transaction(()=>{require_idle();let plan=read(ROOT+'/plan-'+owner,16384);
  if(request.confirmed!=true||type(request.confirmed)!='bool'||!model.integer(request.expectedRevision)||plan==null||plan.owner!=owner||plan.revision!=request.expectedRevision||
   plan.revision!=state().revision||plan.planId!=request.planId||plan.planSha256!=request.planSha256||plan_digest(plan)!=plan.planSha256||
   now()>plan.expiresAtUptimeMs||plan.bootId!=boot()||!same(plan.binding,binding(context())))fail('STALE_PLAN');
  let value=new_job('APPLY',principal,false,plan);write(JOB,value);return value;}));return launch(job);
};
export function job(id,principal) {
 let owner=principal_current(principal),value=reconcile_job(job_record());
 if(!model.job_id(id)||value?.jobId!=id||value.owner!=owner)fail('AUTHENTICATION_FAILED');return public_job(value);
};
export function device_begin(request,principal) {
 let owner=principal_current(principal),manifest=model.begin_request(request),installed=current();
 return engine.update_locked(()=>transaction(()=>{require_idle();let old=expire_upload();
  if(old?.manifest?.requestId==manifest.requestId&&old.owner==owner) {
   if(index(['FAILED','EXPIRED'],old.phase)>=0||!same(old.manifest,manifest))fail('STALE_PLAN');
   return {schema:1,uploadId:old.id,nextOffset:old.nextOffset,maxChunkBytes:model.maximum_chunk_bytes};
  }
  if(old!=null&&index(['EXPIRED','FAILED','FINISHED'],old.phase)<0)fail('BUSY');
  let value=state(),proof=value.relayEvidence;
  if(value.revision!=request.expectedRevision||!value.deviceDownloadRequired||proof?.owner!=owner||proof.bootId!=boot()||
   proof.observedAtUptimeMs>now()||now()-proof.observedAtUptimeMs>model.upload_lifetime_ms)fail('STALE_PLAN');
  if(model.compare(manifest.version,installed.version)<=0)fail('DOWNGRADE_REJECTED');
  discard_upload(old);if(old?.phase=='FAILED')clean_candidate(old.candidateId);admit(2*manifest.fileBytes);
  let id='update-upload-'+random();store.directory(ROOT+'/uploads');store.directory(ROOT+'/uploads/'+id);
  store.write(ROOT+'/uploads/'+id+'/payload','');
  let upload={schema:1,id,owner,principal,manifest,nextOffset:0,last:null,pending:null,phase:'RECEIVING',
   createdAtUptimeMs:now(),expiresAtUptimeMs:now()+model.upload_lifetime_ms,bootId:boot(),stopIntent:stop_intent()};
  write(UPLOAD,upload);save_state(value);return {schema:1,uploadId:id,nextOffset:0,maxChunkBytes:model.maximum_chunk_bytes};}));
};
export function device_chunk(request,principal) {
 let bytes=model.chunk_request(request);current();
 return transaction(()=>{backup.guard();let value=reconcile_chunk(require_upload(request.uploadId,principal));
  if(value.phase!='RECEIVING')fail('STALE_PLAN');
  if(value.last?.offset==request.offset&&value.last.bytes==length(bytes)&&value.last.sha256==request.chunkSha256)
   return {schema:1,nextOffset:value.nextOffset};
  if(request.offset!=value.nextOffset||request.offset+length(bytes)>value.manifest.fileBytes)fail('STALE_PLAN');
  admit(length(bytes)+65536);
  value.pending={offset:request.offset,bytes:length(bytes),sha256:request.chunkSha256};write(UPLOAD,value);
  let file=fs.open(upload_path(value),'a');if(!file||file.write(bytes)!=length(bytes)||!file.flush())fail('NO_SPACE');file.close();
  admit(0);
  value=reconcile_chunk(value);return {schema:1,nextOffset:value.nextOffset};});
};
export function device_status(request,principal) {
 let id=model.upload_request(request);current();
 return transaction(()=>{let value=require_upload(id,principal);
  if(value.phase!='FINISHED'&&!(value.phase=='VERIFYING'&&value.verifiedCandidate!=null))value=reconcile_chunk(value);
  return {schema:1,nextOffset:value.nextOffset,complete:value.nextOffset==value.manifest.fileBytes};});
};
export function device_finish(request,principal) {
 let id=model.upload_request(request);current();
 return engine.update_locked(()=>{
 let value=transaction(()=>{backup.guard();let value=require_upload(id,principal);
  if(value.phase=='FINISHED'||value.phase=='VERIFYING'&&value.verifiedCandidate!=null)return value;
  value=reconcile_chunk(value);
  if(value.phase!='RECEIVING'||value.nextOffset!=value.manifest.fileBytes)fail('STALE_PLAN');
  value.phase='VERIFYING';value.candidateId='candidate-'+random();write(UPLOAD,value);return value;});
 let installed=current();
 if(value.phase=='FINISHED'&&model.compare(installed.version,value.manifest.version)>=0)return status(principal);
 try {
  let directory=candidate_directory(value.candidateId);store.directory(ROOT+'/candidates');store.directory(directory);
  let manifest={version:value.manifest.version,releaseTag:value.manifest.releaseTag,sha256:value.manifest.fileSha256,bytes:value.manifest.fileBytes};
  let candidate=value.verifiedCandidate;
  if(candidate==null) {
   candidate=stage_candidate(upload_path(value),manifest,value.candidateId);
   transaction(()=>{principal_current(principal);if(value.stopIntent!=stop_intent())fail('STALE_PLAN');
    value.verifiedCandidate=candidate;write(UPLOAD,value);});
  }
  transaction(()=>{principal_current(principal);if(value.stopIntent!=stop_intent())fail('STALE_PLAN');
   let source=fs.lstat(upload_path(value)),destination=fs.lstat(candidate.archive);
   if(source&&destination||!source&&!destination)fail('PACKAGE_VERIFICATION_FAILED');
   if(source&&(digest.sha256(raw(upload_path(value),model.maximum_apk_bytes,false))!=manifest.sha256||
    !fs.rename(upload_path(value),candidate.archive)))fail('PACKAGE_VERIFICATION_FAILED');});
  verified_candidate(candidate);principal_current(principal);
  if(value.stopIntent!=stop_intent())fail('STALE_PLAN');
  if(model.compare(candidate.version,current().version)<=0)fail('DOWNGRADE_REJECTED');
  publish_candidate(candidate,()=>{principal_current(principal);if(value.stopIntent!=stop_intent())fail('STALE_PLAN');});
  transaction(()=>{value.phase='FINISHED';value.candidate=candidate;write(UPLOAD,value);});return status(principal);
 }catch(error){transaction(()=>{value.phase='FAILED';value.failureReason=failure_reason(error);write(UPLOAD,value);let status=state();status.availability='CHECK_FAILED';
  status.candidate=null;status.availableVersion=null;status.deviceDownloadRequired=false;status.relayEvidence=null;
  status.failureReason=value.failureReason;save_state(status);});die(error);}
 });
};

// Worker execution is below the shared validation/upload path. It never
// executes downloaded package scripts and never writes the host APK database.
export function run(id) {
 if(!model.job_id(id))fail('INVALID_REQUEST');current();
 let job=transaction(()=>{let value=job_record();if(value?.deployment!='RAM_BASE'||value.jobId!=id||value.state!='QUEUED')fail('STALE_PLAN');
  value.worker=engine.update_self_worker();value.state='VERIFYING';value.step='PREPARING';save_job(value);return value;});
 try {
  require_job(job);backup.guard();
  if(job.operation=='CHECK') {
   let probe=capture('probe',[model.release_api],32,6000);require_job(job);
   if(probe.code!=0){record_check_failure(job,'DOWNLOAD_FAILED',model.network_unreachable(probe.code,probe.stderr));fail('DOWNLOAD_FAILED');}
   let id='candidate-'+random(),directory=candidate_directory(id);store.directory(ROOT+'/candidates');store.directory(directory);
   transaction(()=>{job.candidateId=id;save_job(job);});
   let maximum=min(8388608,int((memory()-model.reserve_bytes)/4));if(maximum<65536)fail('NO_SPACE');
   progress(job,'DOWNLOADING','CHECKING_RELEASE',5);
   let fetched=download(model.release_api,directory+'/releases.json',maximum);require_job(job);
   if(fetched.code!=0){record_check_failure(job,'DOWNLOAD_FAILED',fetched.network);fail('DOWNLOAD_FAILED');}
   let releases_raw=raw(directory+'/releases.json',maximum,false);admit(4*length(releases_raw));
   let selected=model.select_release(json(releases_raw),current().version);releases_raw=null;
   if(selected==null){transaction(()=>{let value=state();value.availability='CURRENT';value.availableVersion=current().version;
    value.lastCheckedAtUnixMs=time()*1000;value.failureReason=null;value.candidate=null;value.deviceDownloadRequired=false;value.relayEvidence=null;save_state(value);});}
   else {
    progress(job,'DOWNLOADING','DOWNLOADING_INDEX',10);
    fetched=download(model.origin+selected.releaseTag+'/SHA256SUMS',directory+'/SHA256SUMS',1048576);require_job(job);
    if(fetched.code!=0){record_check_failure(job,'DOWNLOAD_FAILED',fetched.network);fail('DOWNLOAD_FAILED');}
    selected.sha256=model.checksum(raw(directory+'/SHA256SUMS',1048576,false),selected.file);
    progress(job,'DOWNLOADING','DOWNLOADING_PACKAGE',20);
    fetched=download(model.origin+selected.releaseTag+'/'+selected.file,directory+'/base.apk',selected.bytes);require_job(job);
    if(fetched.code!=0){record_check_failure(job,'DOWNLOAD_FAILED',fetched.network);fail('DOWNLOAD_FAILED');}
    progress(job,'VERIFYING','VERIFYING_PACKAGE',30);
    let candidate=stage_candidate(directory+'/base.apk',selected,id);require_job(job);publish_candidate(candidate,()=>require_job(job));
   }
   progress(job,'SUCCEEDED','COMPLETED',100);
   let automatic=automatic_apply(job);if(automatic)launch(automatic);
  } else if(job.operation=='APPLY') {
   engine.update_locked(()=>{
    backup.guard();require_job(job);let plan=job.plan;
    if(plan==null||plan_digest(plan)!=plan.planSha256||!same(plan.binding,binding(context()))||now()>plan.expiresAtUptimeMs)fail('STALE_PLAN');
    if(current().version!=plan.fromVersion||current().marker.baseSha256!=plan.fromBaseSha256||current().marker.stage!=plan.fromStage||
     model.compare(plan.candidate.version,current().version)<=0)fail('STALE_PLAN');
    let candidate=verified_candidate(plan.candidate);require_candidate_manifest(candidate);require_job(job);
    if(!switch_available())fail('RAM_STAGE_UNAVAILABLE');admit(plan.budget.ramRequiredBytes-model.reserve_bytes);
    runtime_namespace();
    let previous=current();job.candidate=plan.candidate;
    job.previous={stage:previous.marker.stage,root:previous.root,version:previous.version,sha256:previous.marker.baseSha256,
     markerSha256:digest.sha256(raw('/tmp/foxhole-ram-active.json',4096,false)),
     stageDbSha256:digest.sha256(raw(previous.root+'/lib/apk/db/installed',4194304,false))};
    job.protectedBefore=profile_locked(()=>protected_snapshot());job.policyBefore=policy();job.binding=plan.binding;
    transaction(()=>profile_locked(()=>{require_job(job);backup.guard();if(!same(plan.binding,binding(context()))||
     current().version!=plan.fromVersion||current().marker.baseSha256!=plan.fromBaseSha256||current().marker.stage!=plan.fromStage)fail('STALE_PLAN');
     job.mutationStarted=true;job.atomicPackagePhase=true;job.state='INSTALLING';job.step='INSTALLING_PACKAGE';job.progressPercent=40;save_job(job);}));
    let switched=capture('switch',[job.jobId],4096,125000);
    if(switched.code!=0)fail('RECOVERY_REQUIRED');
    let installed=current();if(installed.version!=candidate.version||installed.marker.baseSha256!=candidate.sha256)fail('RECOVERY_REQUIRED');
    verify_payload(candidate_directory(candidate.id),candidate.payload);
    profile_locked(()=>protected_unchanged(job.protectedBefore,job));
    let current_policy=policy();
    if(current_policy.revision<job.policyBefore.revision||current_policy.revision==job.policyBefore.revision&&
     !same(current_policy,job.policyBefore))fail('RECOVERY_REQUIRED');
    finish_atomic(job);
    transaction(()=>{let value=state();value.availability='CURRENT';value.availableVersion=installed.version;
     value.candidate=null;value.failureReason=null;value.deviceDownloadRequired=false;value.relayEvidence=null;save_state(value);});
    progress(job,'SUCCEEDED','COMPLETED',100);
   });
  } else fail('INVALID_REQUEST');
 }catch(error){failed(job,error);}
 return public_job(job_record());
};
export function tick() {
 current();let queued=null;
 engine.update_locked(()=>transaction(()=>{require_idle();let upload=expire_upload();
  if(upload!=null&&index(['EXPIRED','FAILED','FINISHED'],upload.phase)<0)return;
  let flag=policy(),wall=time()*1000;
  if(!flag.enabled||wall<1577836800000||flag.lastAttemptAtUnixMs!=null&&wall<flag.lastAttemptAtUnixMs+86400000)return;
  cleanup_pending_assets();let value=state();value.availability='NOT_CHECKED';value.candidate=null;value.availableVersion=null;
  value.failureReason='NOT_CHECKED';value.deviceDownloadRequired=false;value.relayEvidence=null;save_state(value);
  flag.lastAttemptAtUnixMs=wall;write(POLICY,flag);queued=new_job('CHECK',null,true,null);write(JOB,queued);
 }));if(queued)return launch(queued);return null;
};
