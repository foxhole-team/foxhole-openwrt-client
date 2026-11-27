'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as fresh from './fresh-install-accounting.uc';

function reject() { die('Fresh FLASH transaction guard refused; inspect the private installation state\n'); };
function require_same(a,b,directory) {
 if (!a || !b || a.type!=b.type || a.dev.major!=b.dev.major || a.dev.minor!=b.dev.minor ||
     a.inode!=b.inode || a.uid!=b.uid || a.mode!=b.mode || a.nlink!=b.nlink || (!directory && a.size!=b.size)) reject();
};
function pid(value) { if (!match(value||'',/^[1-9][0-9]{0,9}$/)) reject(); return int(value); };
function process(value) {
 let id=pid(''+value), text=fs.readfile('/proc/'+id+'/stat',4097);
 if (type(text)!='string' || length(text)>4096) reject();
 let parts=match(text,/^([1-9][0-9]*) \(.*\) (.*)\n$/);
 if (!parts || int(parts[1])!=id) reject();
 let fields=split(parts[2],' ');
 if (length(fields)<20 || !match(fields[19],/^[0-9]+$/) || !match(fields[1],/^[0-9]+$/)) reject();
 return {pid:id,start:fields[19],parent:int(fields[1]),state:fields[0]};
};
function boot() {
 let value=fs.readfile('/proc/sys/kernel/random/boot_id',38);
 if (!match(value||'',/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\n$/)) reject();
 return substr(value,0,36);
};
function immutable(path,value) {
 let raw=type(value)=='string'?value:sprintf('%J\n',value), h=fs.open(path,'wx',0o400);
 if (!h || h.write(raw)!=length(raw) || !h.flush() || !h.close()) reject();
};
function document(path) { return json(fresh.protected_bytes(path,1048576)); };
function qualified_bytes(path,maximum) {
 let before=fs.lstat(path), parent=fs.lstat(fs.dirname(path));
 if (parent?.type!='directory' || parent.uid!=0 || (parent.mode&0o022) || before?.type!='file' ||
     before.uid!=0 || before.nlink!=1 || (before.mode&0o022) || before.size<0 || before.size>maximum) reject();
 let h=fs.open(path,'r'), held=h?fs.stat('/proc/self/fd/'+h.fileno()):null, raw=h?.read(before.size+1);
 require_same(before,held,false);require_same(held,fs.lstat(path),false);
 if (length(raw)!=before.size || !h.close()) reject(); return raw;
};
function native_profile(stage,budget) {
 let asset=budget.installAccounting?.profile;
 if (!asset || !match(asset.file||'',/^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$/)) reject();
 let raw=fresh.protected_bytes(stage+'/'+asset.file,65536);
 if (digest.sha256(raw)!=asset.sha256) reject();
 let p=fresh.profile(json(raw));
 if (p.guardStagingBytes!=budget.installAccounting.guardStagingBytes) reject();
 return p;
};
function factory(p,hook,owned_directory) {
 let executable=qualified_bytes(p.nativeApkPath,16777216);
 if (digest.sha256(executable)!=p.nativeApkSha256) reject();
 for (let item in p.configs) {
  let info=fs.lstat(item.path);
  if (item.sha256==null) { if (info) reject(); continue; }
  let raw=qualified_bytes(item.path,65536);
  if (digest.sha256(raw)!=item.sha256) reject();
  // Profiles cannot disable these prerequisites.
  for (let line in split(raw,'\n')) {
   let clean=trim(split(line,'#')[0]);
   if (match(clean,/^(no-scripts|no-commit-hooks)([ =]|$)/) || match(clean,/^(scripts|commit-hooks)[ =]+(no|false|0)([ ]|$)/)) reject();
  }
 }
 for (let directory in p.hookDirectories) {
  let info=fs.lstat(directory.path), expected={};
  for (let item in directory.files) expected[item.name]=item;
  let own=hook && fs.dirname(hook)==directory.path;
  if (!directory.present && !own && directory.path!=owned_directory) { if(info) reject(); continue; }
  if (info?.type!='directory' || info.uid!=0 || (info.mode&0o022)) reject();
  let names=fs.lsdir(directory.path);
  if (type(names)!='array' || length(names)!=length(directory.files)+(own?1:0)) reject();
  for (let name in names) {
   if (own && name==fs.basename(hook)) continue;
   let item=expected[name], s=fs.lstat(directory.path+'/'+name);
   if (!item || s?.mode!=item.mode || digest.sha256(qualified_bytes(directory.path+'/'+name,65536))!=item.sha256) reject();
  }
 }
};
function uptime() {
 let raw=fs.readfile('/proc/uptime',129), match_value=match(raw||'',/^([0-9]+)(\.[0-9]+)? [0-9]+(\.[0-9]+)?\n$/);
 if (!match_value || length(raw)>128) reject(); return int(match_value[1]);
};
function simulation(raw,budget,phase,temporary) {
 if(type(raw)!='string' || length(raw)>1048576 || index(raw,'\x00')>=0 ||
    type(budget?.packages)!='array' || !length(budget.packages) || length(budget.packages)>512)reject();
 let selected={}, retained={}, virtual_seen=0;
 for(let item in budget.packages)selected[item.name]=item;
 for(let item in budget.installAccounting?.retainedPackages || [])retained[item.name]=true;
 for(let line in split(raw,'\n')) {
  if(!match(line,/^\(/))continue;
  let change=match(line,/^\( {0,2}[1-9][0-9]*\/[1-9][0-9]*\) (Installing|Upgrading|Downgrading|Replacing|Reinstalling|Purging|Updating pinning) ([A-Za-z0-9.][A-Za-z0-9_.+-]*) \(([^\r\n()]+)\)$/);
  if(!change)reject();
  let action=change[1],name=change[2],versions=split(change[3],' -> '),item=selected[name];
  if(phase==1 && temporary && name==temporary) {
   if(action!='Installing' || length(versions)!=1 || !match(versions[0],/^[0-9]{8}\.[0-9]{6}$/) || ++virtual_seen!=1)reject();
   continue;
  }
  if(!item || (action!='Installing' && action!='Updating pinning') || length(versions)!=1 ||
     versions[0]!=item.version || (phase!=1 && action!='Updating pinning') || (retained[name] && action!='Updating pinning'))reject();
 }
 if(phase==1 && temporary && virtual_seen!=1)reject();
};
function held(owner) {
 let current=process(owner.driver.pid);
 if (current.start!=owner.driver.start || boot()!=owner.bootId || uptime()<owner.startedUptime || uptime()>owner.expiresUptime) reject();
 // The live owner establishes these roles and holds both FDs.
 let file=fs.stat('/proc/'+owner.driver.pid+'/fd/8'), directory=fs.stat('/proc/'+owner.driver.pid+'/fd/9');
 require_same(owner.hookIdentity,file,false);require_same(file,fs.lstat(owner.hook),false);
 require_same(owner.directoryIdentity,directory,true);require_same(directory,fs.lstat(fs.dirname(owner.hook)),true);
 if (file.type!='file' || file.uid!=0 || file.mode!=0o700 || file.nlink!=1 ||
     directory.type!='directory' || directory.uid!=0 || (directory.mode&0o022) ||
     digest.sha256(fs.readfile('/proc/'+owner.driver.pid+'/fd/8',65537))!=owner.hookSha256 ||
     digest.sha256(qualified_bytes(owner.hook,65536))!=owner.hookSha256) reject();
};
function owner_state(stage,driver) {
 let owner=document(stage+'/guard-owner.json');
 if (owner.schema!=1 || owner.kind!='fresh-flash-guard-owner-v1' || owner.stage!=stage ||
     owner.driver.pid!=pid(''+driver)) reject();
 held(owner); return owner;
};
function native_call(owner,call) {
 let current=process(call.child.pid);
 if (call.schema!=1 || call.kind!='fresh-flash-native-call-v1' || call.ownerSha256!=digest.sha256(fresh.protected_bytes(owner.stage+'/guard-owner.json',1048576)) ||
     current.start!=call.child.start || current.parent!=owner.driver.pid || boot()!=call.bootId) reject();
 let actual=fs.readfile('/proc/'+current.pid+'/cmdline',65537);
 if (actual!=join('\x00',call.arguments)+'\x00' ||
     digest.sha256(fs.readfile('/proc/'+current.pid+'/exe',16777217))!=owner.profile.nativeApkSha256) reject();
 return current;
};
function identity(a,b) {
 return a && b && a.name==b.name && a.version==b.version && a.architecture==b.architecture &&
  a.nativeCid160==b.nativeCid160 && a.flags==b.flags;
};
function world_snapshot(raw) {
 if(type(raw)!='string' || length(raw)>65536 || index(raw,'\x00')>=0 || index(raw,'\r')>=0)reject();
 let rows=length(trim(raw))?split(trim(raw),'\n'):[],seen={};
 for(let row in rows) {
  let name=match(row,/^([A-Za-z0-9_.+-]+)[^ \t\r\n]*$/);
  if(!name || seen[name[1]])reject();seen[name[1]]=true;
 }
 return {raw,rows,sha256:digest.sha256(raw),bytes:length(raw)};
};
function before_state(call,database,world) {
 if(!match(call.expectedDbSha256||'',/^[a-f0-9]{64}$/) ||
    !match(call.expectedWorldSha256||'',/^[a-f0-9]{64}$/) ||
    database.sha256!=call.expectedDbSha256 || world.sha256!=call.expectedWorldSha256)reject();
 return true;
};
function after_world(owner,call,prior,now) {
 let expected={},temporary=null;
 for(let row in prior.rows) {
  expected[row]=true;
  let parts=split(row,'=');
  if(parts[0]==owner.temporaryConstraint) {
   if(length(parts)!=2 || !match(parts[1],/^[0-9]{8}\.[0-9]{6}$/) || temporary)reject();
   temporary=row;
  }
 }
 if(call.phase==1) {
  if(temporary)reject();
  for(let row in now.rows)if(!expected[row]) {
   let parts=split(row,'=');
   if(temporary || length(parts)!=2 || parts[0]!=owner.temporaryConstraint ||
      !match(parts[1],/^[0-9]{8}\.[0-9]{6}$/))reject();
   temporary=row;expected[row]=true;
  }
  if(!temporary)reject();
 } else if(call.phase==2) {
  if(!temporary || type(owner.budget.rootPackages)!='array' || !length(owner.budget.rootPackages))reject();
  for(let name in owner.budget.rootPackages)expected[name]=true;
 } else if(call.phase==3) {
  if(!temporary)reject();delete expected[temporary];
 } else reject();
 if(length(now.rows)!=length(keys(expected)))reject();
 for(let row in now.rows) {if(!expected[row])reject();delete expected[row];}
 if(length(keys(expected)))reject();
};
function after_database(owner,call,prior,now) {
 let selected={};
 for (let auth in owner.budget.packageAuthentications) selected[auth.name]=auth;
 for (let name in prior.packages) {
  let before=prior.packages[name], after=now.packages[name];
  if (call.phase==3 && name==owner.temporaryConstraint) { if(after) reject(); continue; }
  if (selected[name] && call.phase==1) continue;
  if (!identity(before,after)) reject();
 }
 for (let name in now.packages) {
  let item=now.packages[name], wanted=selected[name];
  if (wanted) {
   if (item.version!=wanted.version || item.architecture!=wanted.architecture || item.flags!='S' ||
       item.nativeCid160!=substr(wanted.packageIdentity,0,40)) reject();
  } else if (name==owner.temporaryConstraint && call.phase==1) {
   if (prior.packages[name] || item.architecture!='noarch' || item.flags!='' || !match(item.version,/^[0-9]{8}\.[0-9]{6}$/)) reject();
  } else if (!prior.packages[name]) reject();
 }
 for (let name in selected) if (!now.packages[name]) reject();
};

let action=ARGV[0];
if (action=='snapshot') { print(fresh.protected_bytes('/lib/apk/db/installed',1048576)); exit(0); }
if (action=='stopped') { let child=process(ARGV[1]); exit(child.state=='T'?0:2); }
let stage=ARGV[1], info=fs.lstat(stage);
if (!match(stage||'',/^\/tmp\/foxhole-core-install\.[A-Za-z0-9]{6}$/) || info?.type!='directory' || info.uid!=0 || info.mode!=0o700) reject();
let budget=document(stage+'/compact-budget.json');
if (action=='preflight') {
 let temporary=ARGV[2];
 if (!match(temporary||'',/^\.foxhole-exact-[a-f0-9]{16}$/)) reject();
 if (budget.installAccounting != null) {
  fresh.validate_budget(budget);
  factory(native_profile(stage,budget),null,null);
 }
 simulation(fresh.protected_bytes(stage+'/exact-simulate.log',1048576),budget,1,temporary);
 exit(0);
}
budget=fresh.validate_budget(budget);
let p=native_profile(stage,budget);
if (action=='create') {
 factory(p,null,null);
 if(length(sprintf('%J',budget))+length(sprintf('%J',p))+65536>1048576)reject();
 let directory='/etc/apk/commit_hooks.d', declared=filter(p.hookDirectories,item=>item.path==directory)[0], created=false;
 if (!declared.present) { if(!fs.mkdir(directory,0o700)) reject(); created=true; }
 let hook=directory+'/zzzz-foxhole-'+fs.basename(stage);
 let raw='#!/bin/sh\nexec /usr/bin/ucode \''+stage+'/fresh-install-guard.uc\' hook \''+stage+'\' "$1" "$PPID"\n';
 let h=fs.open(hook,'wx',0o700);
 if (!h || h.write(raw)!=length(raw) || !h.flush() || !h.close()) reject();
 immutable(stage+'/guard-created.json',{schema:1,hook,createdDirectory:created?directory:null,hookSha256:digest.sha256(raw)});
 print(hook); exit(0);
}
if (action=='seal') {
 let created=document(stage+'/guard-created.json'), driver=process(ARGV[2]);
 if (created.schema!=1 || driver.pid!=pid(ARGV[2])) reject();
 let file=fs.stat('/proc/'+driver.pid+'/fd/8'), directory=fs.stat('/proc/'+driver.pid+'/fd/9');
 require_same(file,fs.lstat(created.hook),false); require_same(directory,fs.lstat(fs.dirname(created.hook)),true);
 let owner={schema:1,kind:'fresh-flash-guard-owner-v1',stage,driver,bootId:boot(),startedUptime:uptime(),expiresUptime:uptime()+1800,hook:created.hook,
  hookIdentity:file,directoryIdentity:directory,hookSha256:created.hookSha256,createdDirectory:created.createdDirectory,
  profile:p,budget,temporaryConstraint:ARGV[3]};
 if (!match(owner.temporaryConstraint||'',/^\.foxhole-exact-[a-f0-9]{16}$/)) reject();
 held(owner);factory(p,owner.hook,owner.createdDirectory);
 let raw=fresh.protected_bytes(stage+'/installed-before.db',1048576), state=fresh.snapshot(raw);
 let initial_world=world_snapshot(qualified_bytes(stage+'/world.before',65536));
 owner.initialWorldSha256=initial_world.sha256;
 if (state.sha256!=budget.installAccounting.installedDb.sha256 || state.bytes!=budget.installAccounting.installedDb.bytes) reject();
 let computed=fresh.accounting(state,budget.packages,budget.packageAuthentications,'flash',budget.installAccounting.profile,p.guardStagingBytes);
 if (length(computed.retainedPackages)!=length(budget.installAccounting.retainedPackages) ||
     computed.fullInstalledBytes!=budget.installAccounting.fullInstalledBytes ||
     computed.retainedInstalledBytes!=budget.installAccounting.retainedInstalledBytes ||
     computed.additionalInstalledBytes!=budget.installAccounting.additionalInstalledBytes) reject();
 for(let i=0;i<length(computed.retainedPackages);i++) {
  let a=computed.retainedPackages[i],b=budget.installAccounting.retainedPackages[i];
  if(a.name!=b.name || a.version!=b.version || a.architecture!=b.architecture || a.nativeCid160!=b.nativeCid160 ||
     a.packageIdentity!=b.packageIdentity || a.installedBytes!=b.installedBytes) reject();
 }
 simulation(fresh.protected_bytes(stage+'/exact-simulate.log',1048576),budget,1,owner.temporaryConstraint);
 immutable(stage+'/guard-owner.json',owner);exit(0);
}
let driver=action=='hook'?null:ARGV[2];
if (action=='hook') {
 let owner=document(stage+'/guard-owner.json'); held(owner);factory(p,owner.hook,owner.createdDirectory);
 let event=ARGV[2], native_pid=pid(ARGV[3]), call=null;
 for(let phase=1;phase<=3;phase++) {
  let path=stage+'/guard-call-'+phase+'.json';
  if(!fs.lstat(path)) continue;
  let candidate=document(path);
  if(candidate.child.pid==native_pid && candidate.child.start==process(native_pid).start) {
   if(call || fs.lstat(stage+'/guard-terminal-'+phase+'.json')) reject(); call=candidate;
  }
 }
 if(!call) reject();native_call(owner,call);
 let raw=fresh.protected_bytes('/lib/apk/db/installed',1048576), state=fresh.snapshot(raw);
 let prior_raw=fresh.protected_bytes(call.priorDatabase,1048576), prior=fresh.snapshot(prior_raw);
 let current_world=world_snapshot(qualified_bytes('/etc/apk/world',65536));
 let prior_world=world_snapshot(qualified_bytes(call.priorWorld,65536));
 if(prior.sha256!=call.expectedDbSha256 || prior_world.sha256!=call.expectedWorldSha256) reject();
 if(event=='pre-commit') {
  before_state(call,state,current_world);
  immutable(stage+'/guard-pre-'+call.phase+'.json',{schema:1,phase:call.phase,child:call.child,
   sha256:state.sha256,worldSha256:current_world.sha256,bootId:owner.bootId});
 } else if(event=='post-commit') {
  let pre=stage+'/guard-pre-'+call.phase+'.json';
  if(!fs.lstat(pre)) reject();
  let observed=document(pre);
  if(observed.phase!=call.phase || observed.child.pid!=call.child.pid || observed.child.start!=call.child.start ||
     observed.bootId!=owner.bootId || observed.sha256!=prior.sha256 || observed.worldSha256!=prior_world.sha256)reject();
  after_database(owner,call,prior,state);
  after_world(owner,call,prior_world,current_world);
  immutable(stage+'/guard-post-'+call.phase+'.db',raw);
  immutable(stage+'/guard-post-'+call.phase+'.world',current_world.raw);
  immutable(stage+'/guard-post-'+call.phase+'.json',{schema:1,phase:call.phase,child:call.child,
   priorSha256:prior.sha256,sha256:state.sha256,bytes:state.bytes,bootId:owner.bootId,
   priorWorldSha256:prior_world.sha256,worldSha256:current_world.sha256,worldBytes:current_world.bytes});
 } else reject();
 exit(0);
}
let owner=owner_state(stage,driver);factory(p,owner.hook,owner.createdDirectory);
if(action=='arm') {
 let phase=int(ARGV[3]), child=process(ARGV[4]), arguments=slice(ARGV,5);
 if(phase<1 || phase>3 || child.parent!=owner.driver.pid || child.state!='T' || arguments[0]!=p.nativeApkPath) reject();
 let previous=phase>1?document(stage+'/guard-terminal-'+(phase-1)+'.json'):null;
 if(previous && previous.exitCode!=0)reject();
 if(phase==2)simulation(fresh.protected_bytes(stage+'/roots-simulate.log',1048576),budget,2);
 let prior=phase==1?stage+'/installed-before.db':stage+'/guard-post-'+(phase-1)+'.db';
 let state=fresh.snapshot(fresh.protected_bytes(prior,1048576));
 let prior_world=phase==1?stage+'/world.before':stage+'/guard-post-'+(phase-1)+'.world';
 let world=world_snapshot(qualified_bytes(prior_world,65536));
 if(phase==1?world.sha256!=owner.initialWorldSha256:previous.sha256!=state.sha256 || previous.worldSha256!=world.sha256)reject();
 let expected=[];
 let common=[p.nativeApkPath,'--no-network','--no-cache','--scripts','--commit-hooks','--keys-dir',stage+'/keys',
  '--repositories-file',stage+'/repositories.list','--cache-dir',stage+'/cache'];
 if(phase==1) {
  expected=['add','--virtual',owner.temporaryConstraint];
  for(let auth in owner.budget.packageAuthentications) push(expected,auth.name+'><X1'+substr(auth.packageIdentity,0,40));
 } else if(phase==2) {expected=['add'];for(let name in owner.budget.rootPackages)push(expected,name);}
 else expected=['del',owner.temporaryConstraint];
 if(length(arguments)!=length(common)+length(expected)) reject();
 for(let i=0;i<length(common);i++)if(arguments[i]!=common[i])reject();
 // Request order may differ; identity and multiplicity may not.
 let tail=slice(arguments,length(common)), mandatory=slice(expected,0,phase==1?3:1);
 for(let i=0;i<length(mandatory);i++)if(tail[i]!=mandatory[i])reject();
 if(join('\x00',sort(slice(tail,length(mandatory))))!=join('\x00',sort(slice(expected,length(mandatory)))))reject();
 immutable(stage+'/guard-call-'+phase+'.json',{schema:1,kind:'fresh-flash-native-call-v1',phase,child,arguments,
  expectedDbSha256:state.sha256,priorDatabase:prior,bootId:owner.bootId,
  expectedWorldSha256:world.sha256,priorWorld:prior_world,
  ownerSha256:digest.sha256(fresh.protected_bytes(stage+'/guard-owner.json',1048576))});exit(0);
}
if(action=='terminal') {
 let phase=int(ARGV[3]), child_pid=pid(ARGV[4]), status=int(ARGV[5]);
 let call=document(stage+'/guard-call-'+phase+'.json');
 if(call.child.pid!=child_pid || fs.lstat('/proc/'+child_pid)) reject();
 // APK ignores POST errors; independently verify its observation.
 if(status!=0) reject();
 let post=document(stage+'/guard-post-'+phase+'.json'), raw=fresh.protected_bytes(stage+'/guard-post-'+phase+'.db',1048576);
 let world=qualified_bytes(stage+'/guard-post-'+phase+'.world',65536);
 if(post.child.start!=call.child.start || post.child.pid!=child_pid || post.priorSha256!=call.expectedDbSha256 ||
    post.bootId!=owner.bootId || post.sha256!=digest.sha256(raw) || post.bytes!=length(raw) ||
    post.priorWorldSha256!=call.expectedWorldSha256 || post.worldSha256!=digest.sha256(world) || post.worldBytes!=length(world)) reject();
 immutable(stage+'/guard-terminal-'+phase+'.json',{schema:1,phase,child:call.child,exitCode:status,
  sha256:post.sha256,worldSha256:post.worldSha256});exit(0);
}
if(action=='cleanup') {
 for(let phase=1;phase<=3;phase++)if(fs.lstat(stage+'/guard-call-'+phase+'.json')) {
  let call=document(stage+'/guard-call-'+phase+'.json');
  if(fs.lstat('/proc/'+call.child.pid))reject();
 }
 held(owner);
 if(!fs.unlink(owner.hook))reject();
 if(owner.createdDirectory && !fs.rmdir(owner.createdDirectory))reject();
 immutable(stage+'/guard-cleanup.json',{schema:1,kind:'fresh-flash-hook-cleaned-v1',bootId:owner.bootId,hookSha256:owner.hookSha256});
 exit(0);
}
reject();
