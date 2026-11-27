'use strict';

import * as fs from 'fs';
import * as digest from 'digest';

function reject() { die('Fresh FLASH accounting validation failed\n'); };
function exact(value, expected) {
 if (type(value) != 'object' || join(',', sort(keys(value))) != join(',', sort(expected))) reject();
};
function hash(value) { return type(value) == 'string' && match(value, /^[a-f0-9]{64}$/); };
function number(value) { return type(value) == 'int' && value >= 0 && value <= 9007199254740991; };
function name(value) { return type(value) == 'string' && match(value, /^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$/); };
function same(a,b) {
 return a && b && a.dev.major == b.dev.major && a.dev.minor == b.dev.minor && a.inode == b.inode &&
  a.uid == b.uid && a.mode == b.mode && a.nlink == b.nlink && a.size == b.size;
};
export function protected_bytes(path, maximum) {
 let before=fs.lstat(path), parent=fs.lstat(replace(path, /\/[^/]+$/, ''));
 if (parent?.type != 'directory' || parent.uid != 0 || (parent.mode & 0o022) ||
     before?.type != 'file' || before.uid != 0 || before.nlink != 1 || (before.mode & 0o022) ||
     before.size < 1 || before.size > maximum) reject();
 let handle=fs.open(path,'r'), held=handle ? fs.stat('/proc/self/fd/'+handle.fileno()) : null, raw=handle?.read(before.size+1);
 if (!same(before,held) || !same(held,fs.lstat(path)) || length(raw) != before.size) reject();
 handle.close(); return raw;
};
export function snapshot(raw) {
 if (type(raw) != 'string' || length(raw) < 1 || length(raw) > 1048576 ||
     index(raw, '\x00') >= 0 || index(raw, '\r') >= 0 || substr(raw,-2) != '\n\n') reject();
 let records=split(substr(raw,0,length(raw)-2),'\n\n'), result={}, cids={};
 if (!length(records) || length(records)>4096) reject();
 for (let record in records) {
  if (!length(record)) reject();
  let fields={};
  for (let line in split(record,'\n')) {
   if (length(line)<2 || length(line)>65536 || substr(line,1,1)!=':' || index('CPVASTULomtcDprqsfgFMRaZikI',substr(line,0,1))<0) reject();
   let field=substr(line,0,1);
   if (index('PVACf',field)>=0) {
    if (index(keys(fields),field)>=0) reject();
    fields[field]=substr(line,2);
   }
  }
  if (type(fields.P)!='string' || !match(fields.P,/^[A-Za-z0-9.][A-Za-z0-9_.+-]{0,127}$/) ||
      type(fields.V)!='string' || !match(fields.V,/^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,159}$/) ||
      type(fields.A)!='string' || !match(fields.A,/^[a-z0-9][a-z0-9_-]{0,63}$/) ||
      type(fields.C)!='string' || !match(fields.C,/^Q1[A-Za-z0-9+\/]{27}=$/)) reject();
  let flags=fields.f || '', seen={};
  for (let i=0;i<length(flags);i++) { let f=substr(flags,i,1); if(index('Sfsx',f)<0 || seen[f]) reject(); seen[f]=true; }
  let binary=b64dec(substr(fields.C,2));
  if (length(binary)!=20 || b64enc(binary)!=substr(fields.C,2)) reject();
  let cid=hexenc(binary);
  if (result[fields.P] || cids[cid]) reject();
  cids[cid]=true; result[fields.P]={name:fields.P,version:fields.V,architecture:fields.A,nativeCid160:cid,flags};
 }
 return { sha256:digest.sha256(raw),bytes:length(raw),packages:result };
};
export function profile(value) {
 exact(value,['schema','kind','requiredMode','databaseFormat','nativeApkVersion','nativeApkPath','nativeApkSha256',
  'guardStagingBytes','configs','hookDirectories']);
 if (value.schema!=1 || type(value.schema)!='int' || value.kind!='fresh-flash-installed-delta-v1' || value.requiredMode!='flash' ||
     value.databaseFormat!='apk-v3-q1-sha256-160' || value.nativeApkVersion!='3.0.5' ||
     index(['/bin/apk','/sbin/apk','/usr/bin/apk','/usr/sbin/apk'],value.nativeApkPath)<0 || !hash(value.nativeApkSha256) ||
     !number(value.guardStagingBytes) || value.guardStagingBytes<6291456 || value.guardStagingBytes>16777216 ||
     type(value.configs)!='array' || length(value.configs)!=2 || type(value.hookDirectories)!='array' || length(value.hookDirectories)!=2) reject();
 let configs={};
 for (let item in value.configs) {
  exact(item,['path','sha256']);
  if (index(['/etc/apk/config','/lib/apk/config'],item.path)<0 || configs[item.path] || (item.sha256!=null && !hash(item.sha256))) reject();
  configs[item.path]=true;
 }
 let directories={}, names={};
 for (let directory in value.hookDirectories) {
  exact(directory,['path','present','files']);
  if (index(['/etc/apk/commit_hooks.d','/lib/apk/commit_hooks.d'],directory.path)<0 || directories[directory.path] ||
      type(directory.present)!='bool' || type(directory.files)!='array' || length(directory.files)>32 ||
      (!directory.present && length(directory.files))) reject();
  directories[directory.path]=true;
  for (let item in directory.files) {
   exact(item,['name','sha256','mode']);
   if (!name(item.name) || item.name>='zzzz-foxhole-' || names[item.name] || !hash(item.sha256) ||
       type(item.mode)!='int' || index([0o700,0o755],item.mode)<0) reject();
   names[item.name]=true;
  }
 }
 return value;
};
export function accounting(state, packages, authentications, mode, asset, guard_staging) {
 if (mode!='flash' || type(packages)!='array' || !length(packages) || length(packages)>512 ||
     type(authentications)!='array' || length(authentications)!=length(packages) || !number(guard_staging)) reject();
 let full=0, retained_bytes=0, retained=[], names={}, cids={};
 for (let item in packages) {
  if (!name(item.name) || names[item.name] || !number(item.installedBytes) || item.installedBytes>2147483648) reject();
  names[item.name]=true;
  let matching=filter(authentications,row=>row.file==item.file);
  if (length(matching)!=1) reject();
  let auth=matching[0];
  if (auth.name!=item.name || auth.version!=item.version || auth.architecture!=item.arch || !hash(auth.packageIdentity)) reject();
  let cid=substr(auth.packageIdentity,0,40), current=state.packages[item.name];
  if (cids[cid]) reject();
  for (let name in state.packages) if (state.packages[name].nativeCid160==cid && name!=item.name) reject();
  cids[cid]=true; full+=item.installedBytes;
  if (!current) continue;
  if (current.flags!='S') reject();
  if (current.version==item.version && current.architecture==item.arch && current.nativeCid160==cid) {
   retained_bytes+=item.installedBytes;
   push(retained,{name:item.name,version:item.version,architecture:item.arch,nativeCid160:cid,
    packageIdentity:auth.packageIdentity,installedBytes:item.installedBytes});
  }
 }
 if (!number(full) || !number(retained_bytes) || retained_bytes>full) reject();
 sort(retained,(a,b)=>a.name<b.name ? -1 : a.name>b.name ? 1 : 0);
 return {schema:1,kind:'fresh-flash-installed-delta-v1',requiredMode:'flash',profile:asset,
  installedDb:{sha256:state.sha256,bytes:state.bytes,format:'apk-v3-q1-sha256-160'},fullInstalledBytes:full,
  retainedInstalledBytes:retained_bytes,additionalInstalledBytes:full-retained_bytes,
  guardStagingBytes:guard_staging,retainedPackages:retained};
};
export function validate_budget(value) {
 let a=value.installAccounting;
 exact(a,['schema','kind','requiredMode','profile','installedDb','fullInstalledBytes','retainedInstalledBytes',
  'additionalInstalledBytes','guardStagingBytes','retainedPackages']);
 exact(a.profile,['file','sha256']); exact(a.installedDb,['sha256','bytes','format']);
 if (value.schema!=3 || type(value.schema)!='int' || value.kind!='compact-selected-budget-v2' || value.mode!='flash' ||
     a.schema!=1 || type(a.schema)!='int' || a.kind!='fresh-flash-installed-delta-v1' || a.requiredMode!='flash' ||
     !hash(a.profile.sha256) || !match(a.profile.file||'',/^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$/) ||
     !hash(a.installedDb.sha256) || !number(a.installedDb.bytes) || a.installedDb.bytes<1 || a.installedDb.bytes>1048576 ||
     a.installedDb.format!='apk-v3-q1-sha256-160' || !number(a.guardStagingBytes) || a.guardStagingBytes<6291456 || a.guardStagingBytes>16777216 ||
     type(a.retainedPackages)!='array' || length(a.retainedPackages)>length(value.packages||[])) reject();
 let full=0, retained=0, names={}, ids={}, prior='';
 for (let p in value.packages) { if (!number(p.installedBytes)) reject(); full+=p.installedBytes; }
 for (let p in a.retainedPackages) {
  exact(p,['name','version','architecture','nativeCid160','packageIdentity','installedBytes']);
  let candidates=filter(value.packages,row=>row.name==p.name), auth=filter(value.packageAuthentications,row=>row.name==p.name);
  if (length(candidates)!=1 || length(auth)!=1 || names[p.name] || p.name<=prior ||
      p.version!=candidates[0].version || p.architecture!=candidates[0].arch || p.installedBytes!=candidates[0].installedBytes ||
      p.packageIdentity!=auth[0].packageIdentity || !hash(p.packageIdentity) ||
      p.nativeCid160!=substr(p.packageIdentity,0,40) || ids[p.nativeCid160]) reject();
  names[p.name]=true;ids[p.nativeCid160]=true;prior=p.name;retained+=p.installedBytes;
 }
 if (!number(full) || !number(retained) || full!=value.installedFlashBytes || a.fullInstalledBytes!=full ||
     a.retainedInstalledBytes!=retained || a.additionalInstalledBytes!=full-retained || !number(a.additionalInstalledBytes) ||
     value.requiredFlashBytes!=a.additionalInstalledBytes+value.flashReserveBytes ||
     value.stagingBytes!=2*value.compressedBytes+a.additionalInstalledBytes+value.installedRamBytes+
      2*value.repositoryIndexBytes+value.trustKeyBytes+a.guardStagingBytes ||
     value.requiredRamBytes!=value.stagingBytes+value.runtimeMemoryBytes+value.ramReserveBytes) reject();
 return value;
};
export function apply(value,state,asset,profile_value) {
 let p=profile(profile_value), a=accounting(state,value.packages,value.packageAuthentications,value.mode,asset,p.guardStagingBytes);
 value.schema=3;value.kind='compact-selected-budget-v2';value.installAccounting=a;
 value.stagingBytes=2*value.compressedBytes+a.additionalInstalledBytes+value.installedRamBytes+
  2*value.repositoryIndexBytes+value.trustKeyBytes+a.guardStagingBytes;
 value.requiredFlashBytes=a.additionalInstalledBytes+value.flashReserveBytes;
 value.requiredRamBytes=value.stagingBytes+value.runtimeMemoryBytes+value.ramReserveBytes;
 return validate_budget(value);
};
