'use strict';
import * as fs from 'fs';
import * as digest from 'digest';
import * as store from './private-store.uc';
import * as model from './ram-update-model.uc';
const BOOT='/etc/foxhole/ram-update/boot.json';
const TRUST='/etc/foxhole/ram-update/bootstrap';
const BANK='/tmp/foxhole-ram-stage-boot-v1/bank.apk';
const ROOT='/tmp/foxhole/ram-updates';
export const maximum_descriptor=8192;
export const flash_required_bytes=524288+65536+3*8192;
let generation=null;
function fail(reason) {model.fail(reason||'PACKAGE_VERIFICATION_FAILED');};
function same(a,b) {
 if(a==null||b==null)return a==b;
 if(type(a)!=type(b))return false;
 if(type(a)=='array') {if(length(a)!=length(b))return false;for(let i=0;i<length(a);i++)if(!same(a[i],b[i]))return false;return true;}
 if(type(a)=='object') {let left=keys(a),right=keys(b);if(length(left)!=length(right))return false;
  for(let key in left)if(index(right,key)<0||!same(a[key],b[key]))return false;return true;}
 return a==b;
};
function exact(value,names) {
 if(type(value)!='object'||length(keys(value))!=length(names))fail();
 for(let name in keys(value))if(index(names,name)<0)fail();
};
function identity(info) {return sprintf('%J',[info?.type,info?.uid,info?.gid,info?.dev,info?.inode,info?.nlink,info?.mode,info?.size,info?.mtime,info?.ctime]);};
function parents(path) {
 for(let p=path;;p=fs.dirname(p)) {
  let info=fs.lstat(p);
  if(info?.type!='directory'||info.uid!=0||(info.mode&0o022)&&!(p=='/tmp'&&(info.mode&0o7777)==0o1777))fail();
  if(p=='/')break;
 }
};
function raw(path,maximum,empty) {
 parents(fs.dirname(path));let before=fs.lstat(path);
 if(before?.type!='file'||before.uid!=0||before.nlink!=1||(before.mode&0o022)||before.size<(empty?0:1)||before.size>maximum)fail();
 let text=fs.readfile(path,maximum+1);
 if(text==null||length(text)!=before.size||identity(before)!=identity(fs.lstat(path)))fail();return text;
};
function url(value,prefix) {
 if(type(value)!='string'||length(value)>1024||match(value,/[[:cntrl:]]/))return false;
 let found=match(value,/^https:\/\/([A-Za-z0-9][A-Za-z0-9.-]*)(:([1-9][0-9]{0,4}))?(\/[A-Za-z0-9._~%+\/-]*)$/);
 return found!=null&&(!found[3]||+found[3]<=65535)&&!match(found[4],/\/(\.|\.\.)(\/|$)/)&&
  !match(found[4],/%(00|0[aAdD]|2[eEfF]|3[fF]|23|40|5[cC])/)&&(!prefix||substr(value,-1)=='/');
};
export function recovery_overlay(value,version,sha,bytes) {
 if(!model.version(version)||!model.sha(sha)||!model.integer(bytes)||bytes<1||bytes>8388608||
  model.compare(version,value.baseVersion)<=0)fail();
 let address=value.recoveryOrigin+'foxhole-openwrt-client-'+version+'.apk';if(!url(address,false))fail();
 return {baseVersion:version,baseSha256:sha,artifact:{url:address,bytes,sha256:sha}};
};
export function descriptor(value) {
 let names=['schema','kind','artifact','version','baseVersion','arch','target','osRelease','baseSha256','signerPemSha256','caFileSha256','recoveryOrigin'];
 if(type(value)!='object')fail();if(index(keys(value),'overlay')>=0)push(names,'overlay');exact(value,names);exact(value.artifact,['url','bytes','sha256']);
 if(value.schema!=1||value.kind!='foxhole-ram-bootstrap-v1'||!model.version(value.version)||!model.version(value.baseVersion)||
  !model.sha(value.baseSha256)||value.signerPemSha256!=model.signer_sha256||value.caFileSha256!=null&&!model.sha(value.caFileSha256)||
  !url(value.artifact.url,false)||!model.integer(value.artifact.bytes)||value.artifact.bytes<1||value.artifact.bytes>33554432||
  !model.sha(value.artifact.sha256)||!url(value.recoveryOrigin,true)||value.osRelease!='25.12.5'||
  !(value.arch=='aarch64_cortex-a53'&&value.target=='mediatek/filogic'||value.arch=='x86_64'&&value.target=='x86/64'))fail();
 if(value.overlay!=null) {
  exact(value.overlay,['baseVersion','baseSha256','artifact']);exact(value.overlay.artifact,['url','bytes','sha256']);
  if(!same(value.overlay,recovery_overlay(value,value.overlay.baseVersion,value.overlay.baseSha256,value.overlay.artifact.bytes)))fail();
 }
 return value;
};
function random() {let value=fs.readfile('/dev/urandom',16);if(length(value||'')!=16)fail();return hexenc(value);};
function memory(bytes) {
 let found=match(fs.readfile('/proc/meminfo',65537)||'',/\n?MemAvailable:[ \t]+([0-9]+) kB/);
 if(!found||+found[1]*1024<bytes+model.reserve_bytes)fail('NO_SPACE');
};
function directory_identity(info) {return sprintf('%J',[info?.type,info?.uid,info?.gid,info?.dev,info?.inode,info?.mode]);};
function capture(operation,args,maximum,timeout,descriptor_raw) {
 memory(2*maximum);store.directory(ROOT);let nonce=random(),io='/tmp/foxhole/engine-command-'+nonce+'.io',output=ROOT+'/recovery-io-'+nonce;
 store.directory(io);
 if(generation==null)generation={helper:raw('/usr/libexec/foxhole-ram-recovery-command',32768,false),utility:raw('/usr/share/foxhole/engine-capture.uc',32768,false)};
 store.write(io+'/helper',generation.helper);store.write(io+'/utility.uc',generation.utility);store.write(io+'/descriptor.json',descriptor_raw);
 let code=system(['/bin/sh',io+'/helper',output,''+maximum,''+timeout,operation,...args],timeout+5000);
 let clean=!fs.lstat(io+'/owner.json')&&!fs.lstat(io+'/stdout')&&!fs.lstat(io+'/stderr');
 let stdout=null,stderr=null,outputs=[];
 // Unknown ownership and refused/missing logs stay untouched and are never retried.
 if(clean&&fs.lstat(output)&&fs.lstat(output+'.err')) {
  for(let path in [output,output+'.err']) {
   let before=fs.lstat(path),text=raw(path,path==output?maximum:operation=='fetch'?16384:1048576,true);
   if(identity(before)!=identity(fs.lstat(path)))fail();
   push(outputs,{path,identity:identity(before)});if(path==output)stdout=text;else stderr=text;
  }
 }
 if(clean) {
  for(let path in [io+'/helper',io+'/utility.uc',io+'/descriptor.json'])if(!fs.unlink(path))clean=false;
  if(!fs.rmdir(io))clean=false;
 }
 return {code,stdout,stderr,clean,outputs,parentIdentity:directory_identity(fs.lstat(ROOT))};
};
function discard(result) {
 if(!result.clean||result.code!=0||type(result.outputs)!='array'||length(result.outputs)!=2)fail();
 let first=result.outputs[0].path;
 if(!match(first,/^\/tmp\/foxhole\/ram-updates\/recovery-io-[a-f0-9]{32}$/)||result.outputs[1].path!=first+'.err')fail();
 function checked(row) {
  parents(fs.dirname(row.path));
  if(!store.directory_metadata(fs.lstat(ROOT))||directory_identity(fs.lstat(ROOT))!=result.parentIdentity||
   !store.file_metadata(fs.lstat(row.path))||identity(fs.lstat(row.path))!=row.identity)fail();
 }
 // Validate both identities before deleting either accepted raw.
 for(let row in result.outputs)checked(row);
 for(let row in result.outputs) {checked(row);if(!fs.unlink(row.path))fail();}
};
function snapshot() {
 let text=store.read(BOOT,maximum_descriptor);if(text==null)fail('RAM_STAGE_UNAVAILABLE');
 let value;try{value=descriptor(json(text));}catch(_){fail('RAM_STAGE_UNAVAILABLE');}
 for(let path in [TRUST,TRUST+'/keys'])if(!store.directory_metadata(fs.lstat(path)))fail();
 if(!store.file_metadata(fs.lstat(BOOT))||!store.file_metadata(fs.lstat(TRUST+'/keys/signer.pem'))||
  digest.sha256(raw(TRUST+'/keys/signer.pem',16384,false))!=value.signerPemSha256)fail();
 if(value.caFileSha256!=null&&(!store.file_metadata(fs.lstat(TRUST+'/ca.pem'))||digest.sha256(raw(TRUST+'/ca.pem',262144,false))!=value.caFileSha256))fail();
 parents(fs.dirname(BANK));let bank=fs.lstat(BANK);
 if(bank?.type!='file'||bank.uid!=0||bank.nlink!=1||(bank.mode&0o022)||bank.size!=value.artifact.bytes)fail('RAM_STAGE_UNAVAILABLE');
 let hashed=capture('bank',[],128,10000,text);
 if(!hashed.clean||hashed.code!=0||hashed.stdout==null||hashed.stderr==null)fail();
 let match_hash=match(hashed.stdout,/^([a-f0-9]{64})  \/tmp\/foxhole-ram-stage-boot-v1\/bank\.apk\n$/);
 if(!match_hash||match_hash[1]!=value.artifact.sha256||identity(bank)!=identity(fs.lstat(BANK)))fail();
 discard(hashed);
 return {raw:text,sha256:digest.sha256(text),value,bankIdentity:identity(bank)};
};
function current_matches(context) {
 let marker=json(raw('/tmp/foxhole-ram-active.json',4096,false)),effective=context.value.overlay||context.value;
 if(marker.schema!=1||marker.phase!='active'||marker.storage!='RAM'||marker.version!=effective.baseVersion||marker.baseSha256!=effective.baseSha256||
  marker.bankVersion!=null&&marker.bankVersion!=context.value.version||marker.bankBaseVersion!=null&&marker.bankBaseVersion!=context.value.baseVersion||
  marker.bankBaseSha256!=null&&marker.bankBaseSha256!=context.value.baseSha256)fail('STALE_PLAN');
};
export function prove(candidate,payload_sha) {
 let context=snapshot();current_matches(context);
 if(!model.sha(payload_sha)||model.compare(candidate.version,(context.value.overlay||context.value).baseVersion)<=0)fail('DOWNGRADE_REJECTED');
 let overlay=recovery_overlay(context.value,candidate.version,candidate.sha256,candidate.bytes);
 let fetched=capture('fetch',[overlay.artifact.url,context.value.caFileSha256==null?'system':'pinned',candidate.version],candidate.bytes,65000,context.raw);
 // The pinned fetch helper rejects non-HTTPS hops before connection.
 if(!fetched.clean||fetched.code!=0||fetched.stdout==null||fetched.stderr==null||match(fetched.stderr,/[Rr][Ee][Dd][Ii][Rr][Ee][Cc][Tt]|[Cc]ertificate|SSL error|[Tt][Ll][Ss] error/)||
  length(fetched.stdout)!=candidate.bytes||digest.sha256(fetched.stdout)!=candidate.sha256)fail('DOWNLOAD_FAILED');
 if(store.read(BOOT,maximum_descriptor)!=context.raw||identity(fs.lstat(BANK))!=context.bankIdentity)fail('STALE_PLAN');
 discard(fetched);
 return {schema:1,kind:'foxhole-ram-bootstrap-recovery-proof-v1',descriptorSha256:context.sha256,bankSha256:context.value.artifact.sha256,
  bankIdentity:context.bankIdentity,baselineBaseVersion:context.value.baseVersion,baselineBaseSha256:context.value.baseSha256,
  candidatePayloadSha256:payload_sha,overlay};
};
function proof_matches(proof,candidate,payload_sha,context) {
 exact(proof,['schema','kind','descriptorSha256','bankSha256','bankIdentity','baselineBaseVersion','baselineBaseSha256','candidatePayloadSha256','overlay']);
 if(proof.schema!=1||proof.kind!='foxhole-ram-bootstrap-recovery-proof-v1'||proof.descriptorSha256!=context.sha256||
  proof.bankSha256!=context.value.artifact.sha256||proof.bankIdentity!=context.bankIdentity||
  proof.baselineBaseVersion!=context.value.baseVersion||proof.baselineBaseSha256!=context.value.baseSha256||proof.candidatePayloadSha256!=payload_sha||
  !same(proof.overlay,recovery_overlay(context.value,candidate.version,candidate.sha256,candidate.bytes)))fail('STALE_PLAN');
};
export function recheck(proof,candidate,payload_sha) {
 let context=snapshot();current_matches(context);proof_matches(proof,candidate,payload_sha,context);return true;
};
export function journal(proof,candidate,payload_sha) {
 let context=snapshot();current_matches(context);proof_matches(proof,candidate,payload_sha,context);
 let next={...context.value,overlay:proof.overlay},text=sprintf('%J',descriptor(next));if(length(text)>maximum_descriptor)fail();
 return {schema:1,kind:'foxhole-ram-bootstrap-overlay-journal-v1',oldRaw:context.raw,oldSha256:context.sha256,newRaw:text,
  newSha256:digest.sha256(text),bankIdentity:context.bankIdentity};
};
function journal_valid(value) {
 exact(value,['schema','kind','oldRaw','oldSha256','newRaw','newSha256','bankIdentity']);
 if(value.schema!=1||value.kind!='foxhole-ram-bootstrap-overlay-journal-v1'||type(value.oldRaw)!='string'||type(value.newRaw)!='string'||
  length(value.oldRaw)>maximum_descriptor||length(value.newRaw)>maximum_descriptor||digest.sha256(value.oldRaw)!=value.oldSha256||digest.sha256(value.newRaw)!=value.newSha256)fail();
 let old=descriptor(json(value.oldRaw)),next=descriptor(json(value.newRaw)),baseline={...next};
 if(index(keys(old),'overlay')>=0)baseline.overlay=old.overlay;else delete baseline.overlay;
 if(!same(old,baseline)||next.overlay==null||model.compare(next.overlay.baseVersion,(old.overlay||old).baseVersion)<=0)fail();
};
export function before_quiesce(value) {
 journal_valid(value);
 if(store.read(BOOT,maximum_descriptor)!=value.oldRaw||identity(fs.lstat(BANK))!=value.bankIdentity)fail('STALE_PLAN');
};
export function commit(value) {
 journal_valid(value);let current=store.read(BOOT,maximum_descriptor);
 if(current!=value.oldRaw&&current!=value.newRaw||identity(fs.lstat(BANK))!=value.bankIdentity)fail('STALE_PLAN');
 if(current!=value.newRaw)store.write(BOOT,value.newRaw);
 if(store.read(BOOT,maximum_descriptor)!=value.newRaw)fail();
};
export function restore(value) {
 journal_valid(value);let current=store.read(BOOT,maximum_descriptor);
 if(current!=value.oldRaw&&current!=value.newRaw)fail('RECOVERY_REQUIRED');
 if(current!=value.oldRaw)store.write(BOOT,value.oldRaw);
 if(store.read(BOOT,maximum_descriptor)!=value.oldRaw)fail('RECOVERY_REQUIRED');
};
