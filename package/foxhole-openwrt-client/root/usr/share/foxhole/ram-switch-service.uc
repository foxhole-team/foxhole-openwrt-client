'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as model from './ram-switch-model.uc';
import * as update_model from './ram-update-model.uc';
import * as engine from './engine-service.uc';
import * as engines from './engine-model.uc';
import * as registry from './engine-registry.uc';
import * as state_model from './model.uc';
import * as backup_model from './backup-model.uc';
import * as backup from './backup-service.uc';
import * as bootstrap from './ram-bootstrap-link.uc';

const PRIVATE='/etc/foxhole/ram-update';
const MARKER='/tmp/foxhole-ram-active.json';
const JOB='/etc/foxhole/update-job.json';
const RUNTIME='/tmp/foxhole/ram-updates';
const BASE='foxhole-openwrt-client';
const RESERVE=16777216;
let native_generation=null;

function fail() {die('RAM_SWITCH_VALIDATION_FAILED');};
function same(a,b) {return sprintf('%J',a)==sprintf('%J',b);};
function facts(value) {
 return sprintf('%J',[value?.type,value?.dev,value?.inode,value?.uid,value?.gid,value?.nlink,
  value?.mode,value?.size,value?.mtime,value?.ctime]);
};
function parents(path) {
 for(let p=path;;p=fs.dirname(p)) {
  let s=fs.lstat(p);
  if(s?.type!='directory'||s.uid!=0||(s.mode&0o022)&&!(p=='/tmp'&&(s.mode&0o7777)==0o1777))fail();
  if(p=='/')break;
 }
};
function raw(path,maximum,empty) {
 parents(fs.dirname(path));let before=fs.lstat(path);
 if(before?.type!='file'||before.uid!=0||before.nlink!=1||(before.mode&0o022)||
  before.size<(empty?0:1)||before.size>maximum)fail();
 let text=fs.readfile(path,maximum+1);
 if(text==null||length(text)!=before.size||facts(before)!=facts(fs.lstat(path)))fail();return text;
};
function decode(path,maximum) {return json(raw(path,maximum,false));};
function random() {let text=fs.readfile('/dev/urandom',16);if(length(text||'')!=16)fail();return hexenc(text);};
function now() {
 let found=match(fs.readfile('/proc/uptime',256)||'',/^([0-9]+\.[0-9]+) /);if(!found)fail();return int(+found[1]*1000);
};
function boot() {let value=trim(fs.readfile('/proc/sys/kernel/random/boot_id',128)||'');if(!match(value,/^[a-f0-9-]{36}$/))fail();return value;};
function memory(bytes) {
 let found=match(fs.readfile('/proc/meminfo',65537)||'',/\n?MemAvailable:[ \t]+([0-9]+) kB/);
 if(!found||+found[1]*1024<bytes+RESERVE)fail();
};
function mkdir(path,mode) {
 parents(fs.dirname(path));if(fs.lstat(path)||!fs.mkdir(path,mode))fail();parents(path);
};
function private_directory(path) {
 parents(path);let s=fs.lstat(path);if((s.mode&0o7777)!=0o700)fail();
};
function write(path,text,mode) {
 parents(fs.dirname(path));if(type(text)!='string'||fs.lstat(path))fail();let f=fs.open(path,'wxe',mode||0o600);
 if(!f||f.write(text)!=length(text)||f.flush()!=true)fail();f.close();
};
function replace(path,value,limit) {
 let text=sprintf('%J',value);if(length(text)>limit)fail();
 if(fs.lstat(path))raw(path,limit,false);
 let temporary=path+'.new-'+random();write(temporary,text,0o600);if(!fs.rename(temporary,path))fail();
};
function command(argv,milliseconds) {if(system(argv,milliseconds)!=0)fail();};
function mount_rows() {return model.mounts(fs.readfile('/proc/self/mountinfo',1048577));};
function covering(rows,path) {
 let chosen=null;for(let row in rows)
  if((row.target=='/'||path==row.target||index(path,row.target+'/')==0)&&(!chosen||length(row.target)>length(chosen.target)))chosen=row;
 if(!chosen)fail();return chosen;
};
function ram_backing(rows,path,depth) {
 if(depth>4||index(path,'/tmp/')!=0)fail();let row=covering(rows,path);
 if(row.filesystem=='tmpfs')return;
 if(row.filesystem!='overlay')fail();let options={};
 for(let entry in split(row.superOptions,',')) {let p=split(entry,'=');if(length(p)==2)options[p[0]]=p[1];}
 if(!options.lowerdir||!options.upperdir||!options.workdir)fail();
 for(let lower in split(options.lowerdir,':'))ram_backing(rows,lower,depth+1);
 ram_backing(rows,options.upperdir,depth+1);ram_backing(rows,options.workdir,depth+1);
};
function owner_namespace() {
 private_directory(PRIVATE);
 let owner=decode(PRIVATE+'/owner.json',4096);
 if(!same(owner,{schema:1,abi:1,kind:'foxhole-ram-update-runtime-v1'}))fail();
 for(let name in ['generations','switches']) {
  let path=PRIVATE+'/'+name;if(!fs.lstat(path))mkdir(path,0o700);private_directory(path);
 }
};
function native(operation,args,maximum) {
 if(native_generation==null)native_generation={helper:raw('/usr/libexec/foxhole-ram-switch-command',32768,false),
  utility:raw('/usr/share/foxhole/engine-capture.uc',32768,false)};
 memory(2*maximum);let nonce=random(),io='/tmp/foxhole/engine-command-'+nonce+'.io',output=RUNTIME+'/switch-io-'+nonce;
 mkdir(io,0o700);write(io+'/helper',native_generation.helper);write(io+'/utility.uc',native_generation.utility);
 let code=system(['/bin/sh',io+'/helper',output,''+maximum,'10000',operation,...args],13000);
 // Failed captures are left private and bounded for review; never read a refused/missing log through another path.
 if(!fs.lstat(output)||!fs.lstat(output+'.err'))fail();
 let stdout=raw(output,maximum,true);raw(output+'.err',1048576,true);
 if(fs.lstat(io+'/owner.json')||fs.lstat(io+'/stdout')||fs.lstat(io+'/stderr')||code!=0)fail();
 for(let path in [io+'/helper',io+'/utility.uc'])if(!fs.unlink(path))fail();if(!fs.rmdir(io))fail();
 if(!fs.unlink(output)||!fs.unlink(output+'.err'))fail();
 return stdout;
};
function intent() {
 let value=fs.lstat('/etc/foxhole/engine-intent.json')?decode('/etc/foxhole/engine-intent.json',4096):{schema:1,revision:0};
 if(value.schema!=1||type(value.revision)!='int'||value.revision<0||value.revision>=0x7fffffff)fail();return value.revision;
};
function profile() {return state_model.validate_state(decode('/etc/foxhole/state.json',262144));};
function guard(job,allow_stop) {
 backup.guard();let live=decode(JOB,524288),state=profile(),stop=intent();
 if(live.jobId!=job.jobId||live.revision!=job.revision||live.state!='INSTALLING'||!live.atomicPackagePhase||
  !live.mutationStarted||!same(live.worker,job.worker)||live.bootId!=boot()||job.bootId!=boot()||
  !engines.worker_current(job.worker,engine.update_process_snapshot(job.worker?.pid),boot()))fail();
 if(!job.automatic&&(!engine.update_principal_current(job.principal)||
  digest.sha256(sprintf('%J',job.principal))!=job.owner))fail();
 let bound=job.plan.binding;
 if(job.routerId!=job.plan.routerId||job.routerId!=bound.routerId||job.plan.bootId!=job.bootId||
  !allow_stop&&now()>job.plan.expiresAtUptimeMs)fail();
 if(backup_model.without_stop(state)!=bound.stateWithoutStop||
  digest.sha256(sprintf('%J',registry.read()))!=bound.registrySha256||
  digest.sha256(raw('/etc/apk/world',65536,true))!=bound.worldSha256)fail();
 if(stop==job.stopIntent) {
  if(state.revision!=bound.stateRevision||state.activeServerId!=bound.activeProfileId)fail();
 }else if(!allow_stop||stop<job.stopIntent||state.activeServerId!=null||
  state.revision!=bound.stateRevision+(bound.activeProfileId==null?0:1))fail();
};
function verify_mount(row,readonly) {
 parents(fs.dirname(row.target));parents(fs.dirname(row.source));
 let source=fs.lstat(row.source),target=fs.lstat(row.target),mounted=model.one_mount(mount_rows(),row.target);
 if(source?.type!=row.type||target?.type!=row.type||source.uid!=0||target.uid!=0||
  !same(source.dev,row.dev)||source.inode!=row.inode||!same(source.dev,target.dev)||source.inode!=target.inode||
  (source.mode&0o022)||(readonly&&index(split(mounted.options,','),'ro')<0))fail();
 if(row.type=='file'&&(source.nlink!=1||digest.sha256(raw(row.source,8388608,true))!=row.sha256))fail();
};
function verify_payload(root,document) {
 for(let folder in document.paths) {
  let path=root+(length(folder.name)?'/'+folder.name:'');parents(path);let s=fs.lstat(path);
  if((s.mode&0o7777)!=folder.acl.mode)fail();
  for(let file in folder.files||[]) {
   let target=path+'/'+file.name,info=fs.lstat(target);
   if(info?.type!='file'||info.uid!=0||info.nlink!=1||(info.mode&0o7777)!=file.acl.mode||info.size!=file.size||
    digest.sha256(raw(target,8388608,file.size==0))!=file.hash)fail();
  }
 }
};
function payload_files(document) {
 let result={};for(let folder in document.paths)for(let file in folder.files||[])
  result['/'+folder.name+'/'+file.name]=file;return result;
};
function public_targets(document) {
 let targets={},files=payload_files(document),directories=['/usr/share/foxhole','/usr/share/licenses/foxhole-openwrt-client',
  '/www/luci-static/resources/foxhole','/www/luci-static/resources/view/foxhole','/www/foxhole-mobile'];
 for(let path in keys(files)) {
  let directory=null;for(let prefix in directories)if(index(path,prefix+'/')==0)directory=prefix;
  if(directory)targets[directory]=true;else if(model.public_path(path))targets[path]=true;
 }
 if(!targets['/usr/share/foxhole']||!targets['/etc/init.d/foxhole-runtime']||!targets['/etc/init.d/foxhole-mobile'])fail();
 return sort(keys(targets));
};
function copy_database(previous,upper) {
 let paths=[];for(let path in fs.glob(previous+'/lib/apk/db/*')||[])push(paths,path);
 if(length(paths)>16||!length(paths))fail();let total=0;
 for(let path in paths) {let info=fs.lstat(path);if(info?.type!='file'||info.uid!=0||info.nlink!=1||(info.mode&0o022)||info.size>4194304)fail();total+=info.size;}
 if(total>8388608)fail();memory(2*total);
 for(let part in ['/lib','/lib/apk','/lib/apk/db','/etc','/etc/apk'])mkdir(upper+part,0o755);
 for(let path in paths) {let info=fs.lstat(path);write(upper+'/lib/apk/db/'+fs.basename(path),raw(path,4194304,true),info.mode&0o777);}
 let world=raw(previous+'/etc/apk/world',65536,false);write(upper+'/etc/apk/world',world,0o644);return total;
};
function clear_native_cache(path,created,archive,input,maximum) {
 let root=fs.lstat(path),source=fs.lstat(archive),items=[],links=0,total=0,seen=0;
 if(root?.type!='directory'||root.uid!=0||root.inode!=created.inode||!same(root.dev,created.dev)||(root.mode&0o022)||
  source?.type!='file'||source.uid!=0||source.inode!=input.inode||!same(source.dev,input.dev)||source.size!=input.size||(source.mode&0o022))fail();
 function collect(at,depth) {
  let info=fs.lstat(at);if(depth>8||++seen>256||info?.uid!=0||(info.mode&0o022))fail();
  if(info.type=='directory') {
   if(!same(info.dev,created.dev))fail();
   for(let child in [...(fs.glob(at+'/*')||[]),...(fs.glob(at+'/.*')||[])]) {
    if(match(child,/\/\.\.?$/))continue;
    if(fs.dirname(child)!=at||length(fs.basename(child))>255)fail();collect(child,depth+1);
   }
  } else if(info.type=='file') {
   total+=info.size;if(total>maximum)fail();
   let linked=info.inode==input.inode&&same(info.dev,input.dev);
   if(linked)links++;else if(info.nlink!=1||!same(info.dev,created.dev))fail();
  } else fail();
  push(items,{path:at,info});
 }
 collect(path,0);
 if(source.nlink!=links+1)fail();
 // Validate the whole fresh tree before unlinking anything. Failed native captures never enter here.
 for(let row in items) {
  let info=fs.lstat(row.path),linked=info?.inode==input.inode&&same(info?.dev,input.dev);
  if(info?.type!=row.info.type||info.uid!=0||info.inode!=row.info.inode||!same(info.dev,row.info.dev)||(info.mode&0o022))fail();
  if(info.type=='directory') {if(!fs.rmdir(row.path))fail();}
  else {
   if(linked) {if(info.nlink!=links+1||info.size!=input.size)fail();links--;}
   else if(facts(info)!=facts(row.info))fail();
   if(!fs.unlink(row.path))fail();
  }
 }
 if(fs.lstat(path)||fs.lstat(archive)?.nlink!=1)fail();
};
function process_role(command_text,rpc) {
 let args=split(command_text,'\x00');
 if(rpc)return index(args,'/sbin/rpcd')>=0||index(args,'/usr/sbin/rpcd')>=0;
 for(let name in ['/usr/libexec/foxhole-supervisor','/usr/libexec/foxhole-history-loop','/usr/libexec/foxhole-inbound-loop',
  '/tmp/foxhole/hysteria.json','/tmp/foxhole/core.json','/tmp/foxhole/core-state.json','/www/foxhole-mobile'])
  if(index(args,name)>=0)return true;
 return false;
};
function wait_consumers(rpc,milliseconds) {
 let deadline=now()+milliseconds;
 for(;;) {
  let found=false;for(let path in fs.glob('/proc/[0-9]*/cmdline')||[]) {
   let info=fs.stat(fs.dirname(path));if(!info||info.uid!=0)continue;
   let text=fs.readfile(path,8193);if(text!=null&&length(text)>8192)fail();
   if(text!=null&&process_role(text,rpc))found=true;
  }
  if(!found)return;if(now()>=deadline||sleep(100)!=true)fail();
 }
};
function stop_services(journal,path) {
 journal.quiesceStarted=true;replace(path,journal,131072);
 for(let name in ['foxhole-inbound','foxhole-history','foxhole-mobile','foxhole-runtime'])
  command(['/etc/init.d/'+name,'stop'],3000);
 wait_consumers(false,15000);
 journal.rpcStopped=true;replace(path,journal,131072);command(['/etc/init.d/rpcd','stop'],3000);wait_consumers(true,20000);
 journal.phase='QUIESCED';replace(path,journal,131072);
};
function start_services(journal) {
 // Runtime always rereads CURRENT desired state; a later Stop is never reverted.
 if(journal.rpcStopped)command(['/etc/init.d/rpcd','start'],3000);
 if(journal.quiesceStarted)for(let name in ['foxhole-runtime','foxhole-mobile','foxhole-history','foxhole-inbound'])
  command(['/etc/init.d/'+name,'start'],3000);
};
function bind(source,target) {
 command(['/bin/mount','--bind',source,target],2000);
 command(['/bin/mount','-o','remount,bind,ro',target],2000);
};
function absent_target(path,source,created,journal_path,journal) {
 if(fs.lstat(path))return;let missing=[],at=fs.dirname(path);
 while(!fs.lstat(at)) {if(length(missing)>=8)fail();push(missing,at);at=fs.dirname(at);}
 parents(at);
 for(let i=length(missing)-1;i>=0;i--) {mkdir(missing[i],0o755);push(created,{path:missing[i],type:'directory'});replace(journal_path,journal,131072);}
 if(source.type=='directory')mkdir(path,0o755);else write(path,'',0o644);
 push(created,{path,type:source.type});replace(journal_path,journal,131072);
};
function restore_marker(journal) {
 let present=decode(MARKER,4096);
 if(!same(present,journal.previousMarker)&&!same(present,journal.newMarker))fail();
 replace(MARKER,journal.previousMarker,4096);
};
function rollback(journal,path) {
 if(journal.restarted)stop_services(journal,path);
 let actions=model.rollback_actions(journal.unmounted,journal.mounted);
 for(let row in actions.remove) {
  verify_mount(row,false);command(['/bin/umount',row.target],2000);
  journal.mounted=filter(journal.mounted,item=>item.target!=row.target);replace(path,journal,131072);
 }
 for(let row in actions.restore) {
  if(length(filter(mount_rows(),item=>item.target==row.target)))fail();bind(row.source,row.target);verify_mount(row,true);
  journal.unmounted=filter(journal.unmounted,item=>item.target!=row.target);replace(path,journal,131072);
 }
 for(let i=length(journal.created)-1;i>=0;i--) {
  let row=journal.created[i];if(length(filter(mount_rows(),item=>item.target==row.path)))fail();
  if(row.type=='file'?!fs.unlink(row.path):!fs.rmdir(row.path))fail();
 }
 journal.created=[];restore_marker(journal);bootstrap.restore(journal.bootstrap);start_services(journal);
 journal.phase='ROLLED_BACK';replace(path,journal,131072);
};
function preparation(job,journal,path) {
 let selected=job.plan.candidate,directory=RUNTIME+'/candidates/'+selected.id;
 if(!model.candidate(selected.id))fail();private_directory(directory);
 let receipt_raw=raw(directory+'/receipt.json',524288,false),receipt=json(receipt_raw);
 if(digest.sha256(receipt_raw)!=selected.receiptSha256||receipt.schema!=1||receipt.id!=selected.id||
  receipt.root!=directory+'/root'||receipt.archive!=directory+'/base.apk'||receipt.sha256!=selected.sha256||
  receipt.version!=selected.version||receipt.version!=job.plan.toVersion||
  job.previous.version!=job.plan.fromVersion||update_model.compare(receipt.version,job.previous.version)<=0||
  !model.sha(receipt.sha256)||receipt.bytes<1||receipt.bytes>8388608||
  digest.sha256(raw(receipt.archive,8388608,false))!=receipt.sha256||fs.lstat(receipt.archive).size!=receipt.bytes)fail();
 if(digest.sha256(raw(directory+'/keys/foxhole.pem',16384,false))!=update_model.signer_sha256)fail();
 if(length(fs.glob(directory+'/keys/*')||[])!=1)fail();
 native('verify',[directory+'/keys',receipt.archive],4096);
 let document=json(native('dump',[receipt.archive],524288));update_model.metadata(document,receipt.version);
 if(!same(document,receipt.payload))fail();verify_payload(receipt.root,document);
 journal.bootstrap=bootstrap.journal(receipt.recovery,receipt,digest.sha256(sprintf('%J',document)));
 replace(path,journal,131072);
 update_model.policy(decode(receipt.root+'/usr/share/foxhole/update-policy.json',8192),receipt.version,receipt.releaseTag);
 if(digest.sha256(raw(receipt.root+'/usr/share/foxhole/foxhole-openwrt-apk.pem',16384,false))!=update_model.signer_sha256)fail();
 guard(job,false);
 let previous=job.previous,marker=decode(MARKER,4096);
 if(marker.schema!=1||marker.phase!='active'||marker.storage!='RAM'||!model.stage(marker.stage)||
  marker.stage!=previous.stage||previous.root!=marker.stage+'/root'||marker.baseSha256!=previous.sha256||
  digest.sha256(raw(MARKER,4096,false))!=previous.markerSha256||
  digest.sha256(raw(previous.root+'/lib/apk/db/installed',4194304,false))!=previous.stageDbSha256||
  !model.ledger_path(marker.mountLedger))fail();
 let ledger=model.ledger(decode(marker.mountLedger,131072),marker);
 for(let row in ledger.mounts)verify_mount(row,true);
 let rows=mount_rows();ram_backing(rows,previous.root,0);ram_backing(rows,directory,0);
 for(let row in rows)if(index(row.target,previous.root+'/')==0||index(row.target,directory+'/')==0)fail();
 let before=json(native('query',[previous.root,trim(raw('/etc/apk/arch',128,false))],1048576));
 let architecture=trim(raw('/etc/apk/arch',128,false));
 model.retained_packages(before,previous.version);
 let database_bytes=fs.lstat(previous.root+'/lib/apk/db/installed').size;
 memory(receipt.installedBytes+2*receipt.bytes+2*database_bytes+8388608);
 let work=directory+'/switch';mkdir(work,0o700);
 for(let name in ['lower','upper','work'])mkdir(work+'/'+name,0o700);
 let signed_root=filter(document.paths,row=>row.name=='');
 if(length(signed_root)!=1||type(signed_root[0].acl?.mode)!='int'||signed_root[0].acl.mode!=0o755||
  !fs.chmod(work+'/upper',signed_root[0].acl.mode))fail();
 journal.previousMarker=marker;journal.previousLedger=ledger;journal.directory=directory;
 journal.lower=work+'/lower';journal.root=receipt.root;journal.previousDbSha256=previous.stageDbSha256;
 journal.oldWorld=raw(previous.root+'/etc/apk/world',65536,false);journal.phase='PREPARING';replace(path,journal,131072);
 bind(previous.root,journal.lower);journal.lowerMounted=true;replace(path,journal,131072);
 copy_database(previous.root,work+'/upper');
 if(!fs.rename(receipt.root,work+'/verified-base'))fail();mkdir(receipt.root,0o700);
 command(['/bin/mount','-t','overlay','overlay','-o','lowerdir='+journal.lower+',upperdir='+work+'/upper,workdir='+work+'/work',receipt.root],3000);
 journal.overlayMounted=true;replace(path,journal,131072);ram_backing(mount_rows(),receipt.root,0);
 let cache=receipt.root+'/.foxhole-apk-cache',input_archive=fs.lstat(receipt.archive);
 mkdir(cache,0o700);let cache_created=fs.lstat(cache);
 let args=[receipt.root,architecture,directory+'/keys',receipt.archive];
 native('simulate',args,1048576);guard(job,false);native('install',args,1048576);
 clear_native_cache(cache,cache_created,receipt.archive,input_archive,2*receipt.bytes+4194304);
 if(digest.sha256(raw(receipt.archive,8388608,false))!=receipt.sha256)fail();
 let after=json(native('query',[receipt.root,architecture],1048576));
 journal.retainedPackages=model.package_fence(before,after,previous.version,receipt.version);
 model.world_fence(journal.oldWorld,raw(receipt.root+'/etc/apk/world',65536,false));
 verify_payload(receipt.root,document);
 if(digest.sha256(raw(previous.root+'/lib/apk/db/installed',4194304,false))!=previous.stageDbSha256)fail();
 if(raw(previous.root+'/etc/apk/world',65536,false)!=journal.oldWorld)fail();
 let mounts=[];for(let target in public_targets(document)) {
  let source=receipt.root+target,s=fs.lstat(source);
  if(index(['file','directory'],s?.type)<0||s.uid!=0||(s.mode&0o022))fail();
  push(mounts,{target,source,type:s.type,dev:s.dev,inode:s.inode,sha256:s.type=='file'?digest.sha256(raw(source,8388608,true)):null,role:'base'});
 }
 for(let row in ledger.mounts)if(index(['/usr/bin/openssl','/usr/lib/ucode/socket.so'],row.target)>=0)push(mounts,row);
 let new_marker={schema:1,storage:'RAM',phase:'active',deployment:'foxhole-ram-generation-v1',version:receipt.version,
  baseSha256:receipt.sha256,stage:directory,stageDbSha256:digest.sha256(raw(receipt.root+'/lib/apk/db/installed',4194304,false)),
  mountLedger:PRIVATE+'/generations/generation-'+random()+'.json'};
 let boot_descriptor=json(journal.bootstrap.oldRaw);
 new_marker.bankVersion=boot_descriptor.version;new_marker.bankBaseVersion=boot_descriptor.baseVersion;
 new_marker.bankBaseSha256=boot_descriptor.baseSha256;
 let new_ledger={schema:1,abi:1,kind:'foxhole-ram-mount-ledger-v1',stage:directory,baseSha256:receipt.sha256,mounts};
 model.ledger(new_ledger,new_marker);write(new_marker.mountLedger,sprintf('%J',new_ledger));
 journal.newMarker=new_marker;journal.newLedger=new_ledger;journal.phase='PREPARED';replace(path,journal,131072);
 guard(job,false);memory(2097152);return {receipt,document};
};
export function run(id) {
 if(fs.stat('/proc/self')?.uid!=0||!model.job_id(id))fail();owner_namespace();private_directory(RUNTIME);
 let journal_path=PRIVATE+'/switches/'+id+'.json';
 // Never replay a partially applied transaction as a new update.
 if(fs.lstat(journal_path))fail();
 let job=decode(JOB,524288);
 if(job.schema!=1||job.deployment!='RAM_BASE'||job.operation!='APPLY'||job.jobId!=id||
  job.previous==null||job.candidate==null||!same(job.candidate.id,job.plan?.candidate?.id))fail();
 let plan={...job.plan};delete plan.planSha256;
 if(!model.sha(job.plan.planSha256)||digest.sha256(sprintf('%J',plan))!=job.plan.planSha256)fail();
 guard(job,false);
 let journal={schema:1,kind:'foxhole-ram-switch-journal-v1',jobId:id,bootId:boot(),phase:'VALIDATING',
  owner:digest.sha256(sprintf('%J',job.worker)),unmounted:[],mounted:[],created:[],quiesceStarted:false,rpcStopped:false};
 write(journal_path,sprintf('%J',journal));
 try {
  let prepared=preparation(job,journal,journal_path);guard(job,false);
  bootstrap.before_quiesce(journal.bootstrap);
  // This helper runs under the caller's engine lock. It never acquires it or writes the API job.
  stop_services(journal,journal_path);guard(job,false);
  if(!same(decode(MARKER,4096),journal.previousMarker))fail();
  for(let row in journal.previousLedger.mounts)verify_mount(row,true);
  for(let row in journal.previousLedger.mounts) {
   command(['/bin/umount',row.target],2000);push(journal.unmounted,row);replace(journal_path,journal,131072);
  }
  for(let row in journal.newLedger.mounts) {
   if(length(filter(mount_rows(),item=>item.target==row.target)))fail();
   absent_target(row.target,fs.lstat(row.source),journal.created,journal_path,journal);
   // Record immediately after the successful bind, before the remount can fail.
   command(['/bin/mount','--bind',row.source,row.target],2000);push(journal.mounted,row);replace(journal_path,journal,131072);
   command(['/bin/mount','-o','remount,bind,ro',row.target],2000);verify_mount(row,true);
  }
  guard(job,false);verify_payload(journal.root,prepared.document);
  if(digest.sha256(raw(journal.root+'/lib/apk/db/installed',4194304,false))!=journal.newMarker.stageDbSha256)fail();
  replace(MARKER,journal.newMarker,4096);journal.phase='ACTIVE';replace(journal_path,journal,131072);
  bootstrap.commit(journal.bootstrap);
  guard(job,true);journal.restarted=true;replace(journal_path,journal,131072);start_services(journal);guard(job,true);
  print(sprintf('%J',{schema:1,jobId:id,phase:'ACTIVE',version:prepared.receipt.version,hostApkUpdated:false}));return true;
 }catch(_) {
  try {
   if(journal.quiesceStarted)rollback(journal,journal_path);
   else {journal.phase='FAILED_PREPARE';replace(journal_path,journal,131072);}
  }catch(_) {journal.phase='RECOVERY_REQUIRED';try{replace(journal_path,journal,131072);}catch(_) {}}
  die('RAM switch failed; private journal retained\n');
 }
};
