'use strict';

import * as digest from 'digest';
import * as updates from './update-model.uc';

export const maximum_apk_bytes=8388608;
export const maximum_chunk_bytes=65536;
export const upload_lifetime_ms=600000;
export const reserve_bytes=16777216;
export const signer_sha256='fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1';
export const origin='https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/';
export const release_api='https://api.github.com/repos/foxhole-team/foxhole-openwrt-client/releases?per_page=10';
export const core_release_api='https://api.github.com/repos/foxhole-team/foxhole-core/releases/latest';

export function fail(reason) { updates.fail(reason); };
export function integer(value) { return type(value)=='int'&&value>=0&&value<=9007199254740991; };
export function sha(value) { return type(value)=='string'&&match(value,/^[a-f0-9]{64}$/)!=null; };
export function version(value) {
 return type(value)=='string'&&match(value,/^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}-r[1-9][0-9]{0,5}$/)!=null;
};
export function tag(value) {
 return type(value)=='string'&&match(value,/^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$/)!=null;
};
export function release_for(value) {
 if(!version(value))fail('INVALID_REQUEST');return 'v'+split(value,'-r')[0];
};
export function compare(a,b) {
 if(!version(a)||!version(b))fail('PACKAGE_VERIFICATION_FAILED');
 let x=split(replace(a,'-r','.'),'.'),y=split(replace(b,'-r','.'),'.');
 for(let i=0;i<4;i++){if(+x[i]>+y[i])return 1;if(+x[i]<+y[i])return -1;}return 0;
};
export function owner(principal) { return digest.sha256(sprintf('%J',principal)); };
export function candidate_id(value) { return type(value)=='string'&&match(value,/^candidate-[a-f0-9]{32}$/)!=null; };
export function upload_id(value) { return type(value)=='string'&&match(value,/^update-upload-[a-f0-9]{32}$/)!=null; };
export function job_id(value) { return type(value)=='string'&&match(value,/^update-job-[a-f0-9]{32}$/)!=null; };
export function stage(value) {
 return type(value)=='string'&&(
  match(value,/^\/tmp\/foxhole-ram-stage-[A-Za-z0-9_.-]{6,64}$/)!=null||
  match(value,/^\/tmp\/foxhole\/ram-updates\/candidates\/candidate-[a-f0-9]{32}$/)!=null);
};
function fields(value,names) {
 if(type(value)!='object')fail('INVALID_REQUEST');
 for(let key in keys(value))if(key!='token'&&index(names,key)<0)fail('INVALID_REQUEST');
 for(let key in names)if(value[key]==null)fail('INVALID_REQUEST');
};
export function begin_request(value) {
 fields(value,['expectedRevision','requestId','releaseTag','version','fileSha256','fileBytes']);
 if(!integer(value.expectedRevision)||type(value.requestId)!='string'||!match(value.requestId,/^[a-f0-9]{32}$/)||
  !tag(value.releaseTag)||!version(value.version)||release_for(value.version)!=value.releaseTag||!sha(value.fileSha256)||
  !integer(value.fileBytes)||value.fileBytes<1||value.fileBytes>maximum_apk_bytes)fail('INVALID_REQUEST');
 return {requestId:value.requestId,releaseTag:value.releaseTag,version:value.version,
  fileSha256:value.fileSha256,fileBytes:value.fileBytes};
};
export function chunk_request(value) {
 fields(value,['uploadId','offset','dataBase64','chunkSha256']);
 if(!upload_id(value.uploadId)||!integer(value.offset)||type(value.dataBase64)!='string'||
  length(value.dataBase64)<4||length(value.dataBase64)>87384||length(value.dataBase64)%4||
  !match(value.dataBase64,/^[A-Za-z0-9+\/]+={0,2}$/)||!sha(value.chunkSha256))fail('INVALID_REQUEST');
 let raw=b64dec(value.dataBase64);
 if(raw==null||length(raw)<1||length(raw)>maximum_chunk_bytes||b64enc(raw)!=value.dataBase64||
  digest.sha256(raw)!=value.chunkSha256)fail('PACKAGE_VERIFICATION_FAILED');
 return raw;
};
export function upload_request(value) {
 fields(value,['uploadId']);if(!upload_id(value.uploadId))fail('INVALID_REQUEST');return value.uploadId;
};
export function network_unreachable(code,stderr) {
 if(type(stderr)!='string'||length(stderr)>1048576)return false;
 // TLS, HTTP and verification errors never enable the device
 // relay.
 if(match(stderr,/(SSL|TLS|certificat|HTTP error|signature|verification)/i))return false;
 if(code!=4)return false;
 return match(stderr,/Connection error: Connection (failed|timed out)/)!=null;
};
export function official_base_release(release) {
 const api='https://api.github.com/repos/foxhole-team/foxhole-openwrt-client/releases/';
 const web='https://github.com/foxhole-team/foxhole-openwrt-client/releases/tag/';
 if(!integer(release?.id)||release.id<1||!tag(release.tag_name)||release.url!=api+release.id||
    release.html_url!=web+release.tag_name||type(release.assets)!='array'||length(release.assets)>1024)fail('RELEASE_UNAVAILABLE');
 for(let asset in release.assets) {
  if(asset?.name=='SHA256SUMS'||match(asset?.name||'',/^foxhole-openwrt-client-.*\.apk$/)) {
   if(asset.browser_download_url!=origin+release.tag_name+'/'+asset.name)fail('RELEASE_UNAVAILABLE');
  }
 }
};
export function select_release(value,current) {
 if(type(value)!='array'||length(value)>10||!version(current))fail('RELEASE_UNAVAILABLE');
 let chosen=null,eligible=0;
 for(let release in value) {
  if(release?.draft!=false||type(release.prerelease)!='bool'||!tag(release.tag_name))continue;
  official_base_release(release);
  let sums=false,base=null,seen={};
  for(let asset in release.assets) {
   if(type(asset.name)!='string'||length(asset.name)>255||seen[asset.name])fail('RELEASE_UNAVAILABLE');seen[asset.name]=true;
   if(asset.name=='SHA256SUMS'&&integer(asset.size)&&asset.size>0&&asset.size<=1048576)sums=true;
   let found=match(asset.name,/^foxhole-openwrt-client-([0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}-r[1-9][0-9]{0,5})\.apk$/);
   if(!found||release_for(found[1])!=release.tag_name)continue;
   if(!integer(asset.size)||asset.size<1||asset.size>maximum_apk_bytes)fail('PACKAGE_VERIFICATION_FAILED');
   if(base==null||compare(found[1],base.version)>0)base={version:found[1],file:asset.name,bytes:asset.size,releaseTag:release.tag_name};
  }
  if(!sums||base==null) {
   // An incomplete current or newer release leaves status unknown.
   if(release.tag_name==release_for(current)||compare(substr(release.tag_name,1)+'-r1',current)>0)fail('RELEASE_UNAVAILABLE');
   continue;
  }
  eligible++;
  if(compare(base.version,current)<=0)continue;
  if(chosen==null||compare(base.version,chosen.version)>0)chosen=base;
 }
 if(!eligible)fail('RELEASE_UNAVAILABLE');return chosen;
};
export function checksum(raw,file) {
 if(type(raw)!='string'||length(raw)<1||length(raw)>1048576)fail('PACKAGE_VERIFICATION_FAILED');
 let wanted=null,count=0;
 for(let line in split(raw,'\n')) {
  if(!length(line))continue;if(++count>1024)fail('PACKAGE_VERIFICATION_FAILED');
  let found=match(line,/^([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9_.+-]{0,254})$/);
  if(!found)fail('PACKAGE_VERIFICATION_FAILED');
  if(found[2]==file){if(wanted!=null)fail('PACKAGE_VERIFICATION_FAILED');wanted=found[1];}
 }
 if(!sha(wanted))fail('PACKAGE_VERIFICATION_FAILED');return wanted;
};
export function supports_firmware(value,observed) {
 if(index(['25.12.5','25.12.6'],observed)<0)fail('UNSUPPORTED_TARGET');
 let releases=value.schema==1?[value.osRelease]:value.supportedOpenWrt;
 if(index(releases,observed)<0)fail('UNSUPPORTED_TARGET');return true;
};
export function policy(value,wanted,release,observed) {
 let legacy=value?.schema==1,fields=['schema','transactionAbi','stateAbi',legacy?'osRelease':'supportedOpenWrt','packageVersion','releaseTag','targets'];
 if(type(value)!='object'||length(keys(value))!=7)fail('PACKAGE_VERIFICATION_FAILED');
 for(let key in keys(value))if(index(fields,key)<0)fail('PACKAGE_VERIFICATION_FAILED');
 if(type(value.schema)!='int'||index([1,2],value.schema)<0||type(value.transactionAbi)!='int'||value.transactionAbi!=1||
  type(value.stateAbi)!='int'||value.stateAbi!=1||value.packageVersion!=wanted||value.releaseTag!=release||
  !version(wanted)||release_for(wanted)!=release||type(value.targets)!='array'||length(value.targets)!=2||
  value.targets[0]!='x86/64'||value.targets[1]!='mediatek/filogic')fail('PACKAGE_VERIFICATION_FAILED');
 if(legacy?value.osRelease!='25.12.5':type(value.supportedOpenWrt)!='array'||length(value.supportedOpenWrt)!=2||
  value.supportedOpenWrt[0]!='25.12.5'||value.supportedOpenWrt[1]!='25.12.6')fail('PACKAGE_VERIFICATION_FAILED');
 if(observed!=null)supports_firmware(value,observed);
 return value;
};
export function policy_records(legacy,modern,wanted,release,observed) {
 if(modern==null)return policy(legacy,wanted,release,observed);
 let prior=policy(legacy,wanted,release,null),current=policy(modern,wanted,release,null);
 if(prior.schema!=1 || current.schema!=2 || index(current.supportedOpenWrt,prior.osRelease)<0)
  fail('PACKAGE_VERIFICATION_FAILED');
 if(observed!=null)supports_firmware(current,observed);
 return current;
};
export function metadata(value,wanted) { return updates.base_layout(value,wanted); };
export function capture_arguments(output,operation,args) {
 if(type(output)!='string'||!match(output,/^\/tmp\/foxhole\/ram-updates\/io-[a-f0-9]{32}$/)||type(args)!='array')fail('INVALID_REQUEST');
 let archive=/^\/tmp\/foxhole\/ram-updates\/(candidates\/candidate-[a-f0-9]{32}\/base\.apk|uploads\/update-upload-[a-f0-9]{32}\/payload)$/;
 let keys=/^\/tmp\/foxhole\/ram-updates\/candidates\/candidate-[a-f0-9]{32}\/keys$/;
 if(operation=='verify') {
  if(length(args)!=2||!match(args[0],keys)||!match(args[1],archive))fail('INVALID_REQUEST');
 } else if(operation=='dump') {
  if(length(args)!=1||!match(args[0],archive))fail('INVALID_REQUEST');
 } else if(operation=='extract') {
  if(length(args)!=3||!match(args[0],keys)||!match(args[1],archive)||
   !match(args[2],/^\/tmp\/foxhole\/ram-updates\/candidates\/candidate-[a-f0-9]{32}\/root$/))fail('INVALID_REQUEST');
 } else if(operation=='current'||operation=='dependencies') {
  if(operation=='current'&&length(args)!=2||operation=='dependencies'&&(length(args)<3||length(args)>66)||
   !match(args[0],/\/root$/)||!stage(substr(args[0],0,length(args[0])-5))||
   index(['x86_64','aarch64_cortex-a53'],args[1])<0)fail('INVALID_REQUEST');
  if(operation=='dependencies')for(let constraint in slice(args,2))
   if(type(constraint)!='string'||length(constraint)>255||!match(constraint,/^[A-Za-z0-9][A-Za-z0-9_.+:/~<>=-]*$/))fail('INVALID_REQUEST');
 } else if(operation=='fetch'||operation=='probe') {
  if(operation=='probe'&&length(args)==1&&args[0]==core_release_api)return true;
  if(length(args)!=1||args[0]!=release_api&&
   !match(args[0],/^https:\/\/github\.com\/foxhole-team\/foxhole-openwrt-client\/releases\/download\/v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}\/(SHA256SUMS|foxhole-openwrt-client-[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}-r[1-9][0-9]{0,5}\.apk)$/))fail('INVALID_REQUEST');
 } else if(operation=='switch') {
  if(length(args)!=1||!job_id(args[0]))fail('INVALID_REQUEST');
 } else fail('INVALID_REQUEST');
 return true;
};
