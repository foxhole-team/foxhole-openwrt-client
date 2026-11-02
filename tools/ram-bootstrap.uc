'use strict';
import * as fs from 'fs';
import * as digest from 'digest';
import * as model from './ram-bootstrap-model.uc';

const PRIVATE='/etc/foxhole/ram-update';
const MARKER='/tmp/foxhole-ram-active.json';
const TOOLS=['ram-bootstrap.uc','ram-bootstrap-model.uc','ram-bootstrap-admit.uc','ram-bootstrap-capture.uc','ram-bootstrap-command.sh'];
let generation=null;
function fail() {die('RAM_BOOTSTRAP_VALIDATION_FAILED');};
function same(a,b) {return sprintf('%J',a)==sprintf('%J',b);};
function facts(s) {return sprintf('%J',[s?.type,s?.uid,s?.gid,s?.mode,s?.dev,s?.inode,s?.nlink,s?.size,s?.mtime,s?.ctime]);};
function parents(path) {
 for(let at=path;;at=fs.dirname(at)) {
  let s=fs.lstat(at);if(s?.type!='directory'||s.uid!=0||(s.mode&0o022)&&!(at=='/tmp'&&(s.mode&0o7777)==0o1777))fail();
  if(at=='/')break;
 }
};
function regular(path,maximum,empty) {
 parents(fs.dirname(path));let s=fs.lstat(path);
 if(s?.type!='file'||s.uid!=0||s.nlink!=1||(s.mode&0o022)||s.size<(empty?0:1)||s.size>maximum)fail();return s;
};
function raw(path,maximum,empty) {
 let s=regular(path,maximum,empty),value=fs.readfile(path,maximum+1);
 if(value==null||length(value)!=s.size||facts(s)!=facts(fs.lstat(path)))fail();return value;
};
function decode(path,maximum) {return json(raw(path,maximum,false));};
function private_file(path,maximum) {let s=regular(path,maximum,false);if((s.mode&0o7777)!=0o600)fail();return s;};
function mkdir(path,mode) {parents(fs.dirname(path));if(fs.lstat(path)||!fs.mkdir(path,mode))fail();parents(path);};
function directory(path) {parents(path);if((fs.lstat(path).mode&0o7777)!=0o700)fail();};
function write(path,value,mode) {
 parents(fs.dirname(path));if(fs.lstat(path))fail();let f=fs.open(path,'wxe',mode||0o600);
 if(!f||f.write(value)!=length(value)||f.flush()!=true)fail();f.close();
};
function random() {let data=fs.readfile('/dev/urandom',16);if(length(data||'')!=16)fail();return hexenc(data);};
function replace(path,value,maximum) {
 let text=sprintf('%J',value);if(length(text)>maximum)fail();if(fs.lstat(path))private_file(path,maximum);
 let temporary=path+'.new-'+random();write(temporary,text);if(!fs.rename(temporary,path))fail();
};
function memory(bytes) {
 let found=match(fs.readfile('/proc/meminfo',65537)||'',/\n?MemAvailable:[ \t]+([0-9]+) kB/);
 if(!found||+found[1]*1024<bytes+16777216)fail();
};
function command(args,timeout) {if(system(args,timeout)!=0)fail();};
function boot_id() {let text=trim(fs.readfile('/proc/sys/kernel/random/boot_id',128)||'');if(!match(text,/^[a-f0-9-]{36}$/))fail();return text;};
function now() {let found=match(fs.readfile('/proc/uptime',256)||'',/^([0-9]+\.[0-9]+) /);if(!found)fail();return int(+found[1]*1000);};
function mounted(target) {
 let data=fs.readfile('/proc/self/mountinfo',1048577);if(data==null||length(data)>1048576)fail();let rows=[];
 for(let line in split(data,'\n')) {let pair=split(line,' - '),fields=split(pair[0],' ');if(fields[4]==target)push(rows,{id:fields[0],options:fields[5],type:split(pair[1]||'',' ')[0]});}
 return rows;
};
function actual_platform(value) {
 let release=raw('/etc/openwrt_release',8192,false),arch=trim(raw('/etc/apk/arch',128,false));
 let version=match(release,/(^|\n)DISTRIB_RELEASE='([^']+)'/),target=match(release,/(^|\n)DISTRIB_TARGET='([^']+)'/);
 if(!version||!target||version[2]!=value.osRelease||target[2]!=value.target||arch!=value.arch)fail();
};
function owner_namespace(create) {
 parents('/etc/foxhole');if(!fs.lstat(PRIVATE)&&create)mkdir(PRIVATE,0o700);directory(PRIVATE);
 let path=PRIVATE+'/owner.json';
 if(!fs.lstat(path)&&create) {
  if(length(fs.lsdir(PRIVATE)||[]))fail();write(path,sprintf('%J',{schema:1,abi:1,kind:'foxhole-ram-update-runtime-v1'}));
 }
 private_file(path,4096);let value=decode(path,4096);
 if(!same(value,{schema:1,abi:1,kind:'foxhole-ram-update-runtime-v1'}))fail();
};
function trust_check(expected) {
 directory(model.trust);directory(model.trust+'/keys');private_file(PRIVATE+'/boot.json',8192);
 if(digest.sha256(raw(model.trust+'/keys/signer.pem',32768,false))!=expected.signerPemSha256||
  length(fs.lsdir(model.trust+'/keys')||[])!=1)fail();
 private_file(model.trust+'/keys/signer.pem',32768);
 if(expected.caFileSha256!=null) {
  private_file(model.trust+'/ca.pem',32768);if(digest.sha256(raw(model.trust+'/ca.pem',32768,false))!=expected.caFileSha256)fail();
 }else if(fs.lstat(model.trust+'/ca.pem'))fail();
 let recorded=decode(model.trust+'/tools.json',16384),total=0;
 if(recorded.schema!=1||type(recorded.files)!='array'||length(recorded.files)!=length(TOOLS))fail();
 let seen={};for(let row in recorded.files) {
  if(index(TOOLS,row.name)<0||seen[row.name]||!model.sha(row.sha256))fail();seen[row.name]=true;
  private_file(model.trust+'/'+row.name,65536);let bytes=raw(model.trust+'/'+row.name,65536,false);total+=length(bytes);
  if(digest.sha256(bytes)!=row.sha256)fail();
 }
 total+=fs.lstat(model.trust+'/keys/signer.pem').size+(expected.caFileSha256!=null?fs.lstat(model.trust+'/ca.pem').size:0)+
  fs.lstat(PRIVATE+'/boot.json').size+fs.lstat(model.trust+'/tools.json').size+regular('/etc/init.d/foxhole-ram-bootstrap',8192,false).size+4096;
 if(total>131072)fail();
};
function capture(operation,args,limit,timeout) {
 if(generation==null)generation={helper:raw(model.trust+'/ram-bootstrap-command.sh',32768,false),
  utility:raw(model.trust+'/ram-bootstrap-capture.uc',32768,false),admit:raw(model.trust+'/ram-bootstrap-admit.uc',32768,false),
  model:raw(model.trust+'/ram-bootstrap-model.uc',32768,false)};
 let id=random(),io='/tmp/foxhole/engine-command-'+id+'.io',output=model.stage+'/io-'+id;
 mkdir(io,0o700);write(io+'/helper',generation.helper);write(io+'/utility.uc',generation.utility);
 write(io+'/ram-bootstrap-admit.uc',generation.admit);write(io+'/ram-bootstrap-model.uc',generation.model);
 let code=system(['/bin/sh',io+'/helper',output,''+limit,''+timeout,operation,...args],timeout+5000);
 if(!fs.lstat(output)||!fs.lstat(output+'.err'))fail();
 let out=regular(output,limit,true),stderr=raw(output+'.err',operation=='fetch'?16384:1048576,true);
 if(fs.lstat(io+'/owner.json')||fs.lstat(io+'/stdout')||fs.lstat(io+'/stderr'))fail();
 for(let name in ['helper','utility.uc','ram-bootstrap-admit.uc','ram-bootstrap-model.uc'])if(!fs.unlink(io+'/'+name))fail();
 if(!fs.rmdir(io))fail();return {code,path:output,bytes:out.size,stderr};
};
function native(operation,args,limit,timeout) {
 let result=capture(operation,args,limit,timeout||30000);if(result.code!=0)fail();
 memory(2*result.bytes);let text=raw(result.path,limit,true);
 if(!fs.unlink(result.path)||!fs.unlink(result.path+'.err'))fail();return text;
};
function hash_files(paths) {
 let result={};if(!length(paths))return result;
 for(let at=0;at<length(paths);at+=64) {
  let batch=slice(paths,at,at+64),list=model.stage+'/hash-batch.list',before={};
  for(let path in batch)before[path]=facts(regular(path,33554432,true));
  if(fs.lstat(list)) {private_file(list,32768);if(!fs.unlink(list))fail();}
  write(list,join('\n',batch)+'\n');let text=native('hash',[],65536,30000),seen={};
  for(let line in split(trim(text),'\n')) {
   let found=match(line,/^([a-f0-9]{64})  (\/[A-Za-z0-9_+.,@=:\/-]+)$/);
   if(!found||index(batch,found[2])<0||seen[found[2]])fail();seen[found[2]]=true;result[found[2]]=found[1];
  }
  if(length(keys(seen))!=length(batch))fail();
  for(let path in batch)if(before[path]!=facts(fs.lstat(path)))fail();
 }
 return result;
};
function host_snapshot() {
 let paths=['/lib/apk/db/installed','/etc/apk/world'],hashes=hash_files(paths),result={};
 for(let path in paths)result[path]={sha256:hashes[path],facts:facts(regular(path,4194304,path=='/etc/apk/world'))};return result;
};
function exact_tree(root,inventory) {
 let pending=[''],seen={},hashes=[];
 if(inventory['']!=null) {
  let s=fs.lstat(root);if(s?.type!='directory'||s.uid!=0||s.gid!=0||(s.mode&0o7777)!=inventory[''].mode)fail();seen['']=true;
 }
 while(length(pending)) {
  let parent=shift(pending),names=fs.lsdir(root+(length(parent)?'/'+parent:''));if(type(names)!='array')fail();
  for(let name in names) {
   if(name=='.'||name=='..')continue;let relative=length(parent)?parent+'/'+name:name,expected=inventory[relative];
   if(!expected||seen[relative]||!model.relative(relative))fail();seen[relative]=true;
   let path=root+'/'+relative,s=fs.lstat(path),type_name=expected.type=='symlink'?'link':expected.type;
   if(s?.type!=type_name||s.uid!=0||s.gid!=0||(s.mode&0o7777)!=expected.mode||
    expected.type!='directory'&&s.nlink!=1)fail();
   if(expected.type=='directory') {parents(path);push(pending,relative);}
   else if(s.size!=expected.bytes)fail();
   if(expected.type=='file')push(hashes,path);
   else if(expected.type=='symlink'&&fs.readlink(path)!=expected.linkTarget)fail();
   if(length(keys(seen))>8195||length(split(relative,'/'))>20)fail();
  }
 }
 if(length(keys(seen))!=length(keys(inventory)))fail();let actual=hash_files(hashes);
 for(let path in hashes)if(actual[path]!=inventory[substr(path,length(root)+1)].sha256)fail();
};
function matches_mount(row) {
 let source=fs.lstat(row.source),target=fs.lstat(row.target),mounts=mounted(row.target);
 if(length(mounts)!=1||source?.type!=row.type||target?.type!=row.type||!same(source.dev,row.dev)||source.inode!=row.inode||
  !same(source.dev,target.dev)||source.inode!=target.inode)fail();
};
function absent_target(target,source,journal) {
 if(fs.lstat(target)) {parents(fs.dirname(target));let s=fs.lstat(target);if(s.type!=source.type||s.uid!=0||(s.mode&0o022))fail();return;}
 let missing=[],at=fs.dirname(target);while(!fs.lstat(at)) {push(missing,at);at=fs.dirname(at);if(length(missing)>8)fail();}
 parents(at);for(let i=length(missing)-1;i>=0;i--) {mkdir(missing[i],0o755);let info=fs.lstat(missing[i]);push(journal.created,{path:missing[i],type:'directory',dev:info.dev,inode:info.inode,facts:facts(info)});}
 if(source.type=='directory')mkdir(target,0o755);else write(target,'',0o644);
 let info=fs.lstat(target);push(journal.created,{path:target,type:source.type,dev:info.dev,inode:info.inode,facts:facts(info)});
};
function process_role(text,rpc) {
 let args=split(text,'\x00');if(rpc)return index(args,'/sbin/rpcd')>=0||index(args,'/usr/sbin/rpcd')>=0;
 for(let name in ['/usr/libexec/foxhole-supervisor','/usr/libexec/foxhole-history-loop','/usr/libexec/foxhole-inbound-loop',
  '/tmp/foxhole/hysteria.json','/tmp/foxhole/core.json','/tmp/foxhole/core-state.json','/www/foxhole-mobile'])if(index(args,name)>=0)return true;
 return false;
};
function consumers(rpc) {
 for(let path in fs.glob('/proc/[0-9]*/cmdline')||[]) {
  let info=fs.stat(fs.dirname(path));if(!info||info.uid!=0)continue;let text=fs.readfile(path,8193);
  if(text!=null&&length(text)>8192)fail();if(text!=null&&process_role(text,rpc))return true;
 }
 return false;
};
function wait_exit(rpc,timeout) {let deadline=now()+timeout;while(consumers(rpc))if(now()>=deadline||sleep(100)!=true)fail();};
function rollback(journal) {
 if(journal.starting) {
  for(let unit in ['foxhole-inbound','foxhole-history','foxhole-mobile','foxhole-runtime'])command(['/etc/init.d/'+unit,'stop'],3000);
  wait_exit(false,15000);command(['/etc/init.d/rpcd','stop'],3000);wait_exit(true,20000);
 }
 for(let i=length(journal.mounted)-1;i>=0;i--) {
  let row=journal.mounted[i];matches_mount(row);command(['/bin/umount',row.target],2000);
  pop(journal.mounted);replace(model.stage+'/journal.json',journal,131072);
 }
 if(journal.markerWritten) {
  if(digest.sha256(raw(MARKER,4096,false))!=journal.markerSha256||!fs.unlink(MARKER))fail();journal.markerWritten=false;
 }
 for(let i=length(journal.created)-1;i>=0;i--) {
  let row=journal.created[i];if(length(mounted(row.path)))fail();let info=fs.lstat(row.path);
  if(info?.type!=row.type||info.uid!=0||!same(info.dev,row.dev)||info.inode!=row.inode)fail();
  if(row.type=='file'&&(info.size!=0||facts(info)!=row.facts))fail();
  if(row.type=='directory'?!fs.rmdir(row.path):!fs.unlink(row.path))fail();
 }
 if(journal.starting)command(['/etc/init.d/rpcd','start'],3000);
 journal.phase='ROLLED_BACK';replace(model.stage+'/journal.json',journal,131072);
};
function initialize_destination(path,document) {
 // APK extraction/add does not apply the signed empty-name node to an existing destination.
 parents(path);let before=fs.lstat(path),mode=model.destination_mode(document,before.mode&0o7777);
 if(before.type!='directory'||before.uid!=0||before.gid!=0)fail();
 if((before.mode&0o7777)!=mode&&!fs.chmod(path,mode))fail();
 let after=fs.lstat(path);
 if(after?.type!='directory'||after.uid!=0||after.gid!=0||!same(after.dev,before.dev)||after.inode!=before.inode||(after.mode&0o7777)!=mode)fail();
};
function bank_load(expected,journal) {
 memory(expected.artifact.bytes+8388608);
 let download=capture('fetch',[expected.artifact.url,expected.caFileSha256==null?'system':'pinned'],expected.artifact.bytes,65000);
 if(!model.accepted_download(download.stderr,download.code)||download.bytes!=expected.artifact.bytes)fail();
 if(!fs.rename(download.path,model.stage+'/bank.apk'))fail();
 if(hash_files([model.stage+'/bank.apk'])[model.stage+'/bank.apk']!=expected.artifact.sha256)fail();
 native('verify',[],4096,30000);let document=json(native('dump',[],model.maximum_metadata,30000));
 let signed=model.native_document(document,expected);
 memory(document.info['installed-size']+8388608+2*model.maximum_metadata);
 mkdir(model.stage+'/payload',0o700);initialize_destination(model.stage+'/payload',document);native('extract',[],4096,60000);
 let container=model.stage+'/payload/'+model.prefix;
 let bank=model.descriptor(expected),manifest=decode(container+'/bank.json',1048576);
 let inventory=model.bank(manifest,bank);model.join_inventory(signed,inventory);
 // Check all native payload paths, including ancestors and bank.json, before narrowing the export.
 exact_tree(model.stage+'/payload',signed);
 if(manifest.stageDbSha256!=inventory['root/lib/apk/db/installed'].sha256)fail();
 if(!fs.rename(container+'/root',model.stage+'/root')||!fs.rename(container+'/adapters',model.stage+'/adapters'))fail();
 if(hash_files([model.stage+'/root/lib/apk/db/installed'])[model.stage+'/root/lib/apk/db/installed']!=manifest.stageDbSha256)fail();
 let rows=json(native('query',[expected.arch],1048576,30000));model.installed(rows,expected);
 if(hash_files([model.stage+'/root/lib/apk/db/installed'])[model.stage+'/root/lib/apk/db/installed']!=manifest.stageDbSha256)fail();
 let mounts=[];for(let row in manifest.mounts) {
  let source=model.stage+'/'+row.sourceRelative,s=fs.lstat(source),declared=inventory[row.sourceRelative];
  parents(fs.dirname(source));
  push(mounts,{target:row.target,source,type:s.type,dev:s.dev,inode:s.inode,
   sha256:declared.type=='file'?declared.sha256:null,role:row.role=='base'?'base':'retained-adapter'});
 }
 journal.bankSha256=expected.artifact.sha256;journal.mounts=mounts;journal.stageDbSha256=manifest.stageDbSha256;
 return manifest;
};
function retained_files(bank,document) {
 let hashes=[],directories={};for(let folder in document.paths)directories['root'+(length(folder.name)?'/'+folder.name:'')]=true;
 for(let row in bank.files) {
  if(model.mutable_base_file(row.path)||row.type=='directory'&&(directories[row.path]||model.mutable_base_directory(row.path)))continue;
  let path=model.stage+'/'+row.path,s=fs.lstat(path);
  parents(fs.dirname(path));
  if(s?.type!=(row.type=='symlink'?'link':row.type)||s.uid!=0||s.gid!=0||(s.mode&0o7777)!=row.mode||
   row.type!='directory'&&(s.nlink!=1||s.size!=row.bytes))fail();
  if(row.type=='file')push(hashes,path);
  else if(row.type=='symlink'&&fs.readlink(path)!=row.linkTarget)fail();
 }
 let actual=hash_files(hashes);
 for(let row in bank.files)if(row.type=='file'&&!model.mutable_base_file(row.path)&&actual[model.stage+'/'+row.path]!=row.sha256)fail();
};
function base_payload(document) {
 let hashes=[],expected={};
 for(let folder in document.paths) {
  let directory=model.stage+'/root'+(length(folder.name)?'/'+folder.name:'');parents(directory);
  if((fs.lstat(directory).mode&0o7777)!=folder.acl.mode)fail();
  for(let file in folder.files||[]) {
   let path=directory+'/'+file.name,s=regular(path,8388608,file.size==0);
   if(s.gid!=0||s.size!=file.size||(s.mode&0o7777)!=file.acl.mode)fail();push(hashes,path);expected[path]=file.hash;
  }
 }
 let actual=hash_files(hashes);for(let path in hashes)if(actual[path]!=expected[path])fail();
};
function clean_overlay_cache(created,input) {
 const root=model.stage+'/root/.foxhole-apk-cache',archive=model.stage+'/overlay.apk';
 function identity(now,old) {return now?.type==old.type&&now.uid==0&&now.gid==0&&same(now.dev,old.dev)&&now.inode==old.inode;};
 function original() {
  parents(fs.dirname(archive));let info=fs.lstat(archive);
  if(!identity(info,input)||(info.mode&0o7777)!=(input.mode&0o7777)||info.size!=input.size||info.mtime!=input.mtime)fail();return info;
 };
 parents(fs.dirname(root));let current=fs.lstat(root);
 if(!identity(current,created)||current.type!='directory'||(current.mode&0o7777)!=0o700)fail();
 let pending=[root],directories=[],files=[],total=0,links=0;
 while(length(pending)) {
  let directory=shift(pending),info=fs.lstat(directory);parents(directory);
  if(info?.type!='directory'||info.uid!=0||info.gid!=0||!same(info.dev,created.dev)||(info.mode&0o022))fail();push(directories,{path:directory,info});
  let entries=fs.lsdir(directory);if(type(entries)!='array')fail();
  for(let name in entries) {
   if(name=='.'||name=='..')continue;let path=directory+'/'+name;
   if(!model.relative(substr(path,length(root)+1))||length(split(path,'/'))-length(split(root,'/'))>4)fail();
   let value=fs.lstat(path);
   if(value?.uid!=0||value.gid!=0||!same(value.dev,created.dev)||(value.mode&0o022))fail();
   if(value.type=='directory')push(pending,path);
   else if(value.type=='file') {
    if(value.size<0||value.size>8388608||value.nlink<1)fail();
    let linked=identity(value,input);
    if(value.nlink!=1&&!linked)fail();if(linked)links++;
    if(!linked||links==1)total+=value.size;if(total>input.size+4194304)fail();push(files,{path,info:value,linked});
   }else fail();
   if(length(pending)+length(directories)+length(files)>128)fail();
  }
 }
 // Validate the complete tree before deleting anything. A foreign link is never adopted.
 if(original().nlink!=links+1)fail();
 for(let row in files) {
  let value=fs.lstat(row.path);
  if(!identity(value,row.info)||value.size!=row.info.size||value.mtime!=row.info.mtime||value.mode!=row.info.mode||
   !row.linked&&facts(value)!=facts(row.info)||row.linked&&value.nlink!=links+1)fail();
 }
 for(let row in files) {
  let value=fs.lstat(row.path);
  if(row.linked) {
   if(!identity(value,input)||original().nlink!=links+1||value.nlink!=links+1||value.size!=input.size||value.mtime!=input.mtime)fail();
  }else if(facts(value)!=facts(row.info))fail();
  if(!fs.unlink(row.path))fail();if(row.linked)links--;
 }
 for(let n=length(directories)-1;n>=0;n--) {
  let row=directories[n],value=fs.lstat(row.path);
  if(!identity(value,row.info)||value.mode!=row.info.mode||!fs.rmdir(row.path))fail();
 }
 if(original().nlink!=1||fs.lstat(root))fail();
};
function overlay_load(expected,bank,journal) {
 let effective={baseVersion:expected.baseVersion,baseSha256:expected.baseSha256,stageDbSha256:bank.stageDbSha256};
 if(expected.overlay==null)return effective;
 let overlay=expected.overlay;memory(overlay.artifact.bytes+8388608);
 let download=capture('fetch',[overlay.artifact.url,expected.caFileSha256==null?'system':'pinned'],overlay.artifact.bytes,65000);
 if(!model.accepted_download(download.stderr,download.code)||download.bytes!=overlay.artifact.bytes||
  !fs.rename(download.path,model.stage+'/overlay.apk'))fail();
 if(hash_files([model.stage+'/overlay.apk'])[model.stage+'/overlay.apk']!=overlay.baseSha256)fail();
 native('verify-overlay',[],4096,30000);
 let document=json(native('dump-overlay',[],model.maximum_metadata,30000));model.base_layout(document,overlay.baseVersion);
 initialize_destination(model.stage+'/root',document);
 memory(document.info['installed-size']+2*overlay.artifact.bytes+8388608);
 let before=json(native('query',[expected.arch],1048576,30000)),world=raw(model.stage+'/root/etc/apk/world',65536,false);
 model.installed(before,expected);let cache=model.stage+'/root/.foxhole-apk-cache';
 if(fs.lstat(cache))fail();mkdir(cache,0o700);directory(cache);
 let created_cache=fs.lstat(cache),input=regular(model.stage+'/overlay.apk',8388608,false);
 native('simulate-overlay',[expected.arch],1048576,30000);native('install-overlay',[expected.arch],1048576,60000);
 clean_overlay_cache(created_cache,input);
 if(hash_files([model.stage+'/overlay.apk'])[model.stage+'/overlay.apk']!=overlay.baseSha256)fail();
 let after=json(native('query',[expected.arch],1048576,30000));model.package_fence(before,after,expected);
 model.world_fence(world,raw(model.stage+'/root/etc/apk/world',65536,false));
 base_payload(document);retained_files(bank,document);
 model.base_policy(decode(model.stage+'/root/usr/share/foxhole/update-policy.json',8192),overlay.baseVersion);
 if(digest.sha256(raw(model.stage+'/root/usr/share/foxhole/foxhole-openwrt-apk.pem',32768,false))!=expected.signerPemSha256)fail();
 let mounts=[],hashes=[];for(let target in model.overlay_targets(document)) {
  let source=model.stage+'/root'+target,s=fs.lstat(source);parents(fs.dirname(source));
  if(index(['file','directory'],s?.type)<0||s.uid!=0||(s.mode&0o022))fail();if(s.type=='file')push(hashes,source);
  push(mounts,{target,source,type:s.type,dev:s.dev,inode:s.inode,sha256:null,role:'base'});
 }
 let actual=hash_files(hashes);for(let row in mounts)if(row.type=='file')row.sha256=actual[row.source];
 for(let row in journal.mounts)if(index(['/usr/bin/openssl','/usr/lib/ucode/socket.so'],row.target)>=0)push(mounts,row);
 let db=model.stage+'/root/lib/apk/db/installed';effective={baseVersion:overlay.baseVersion,baseSha256:overlay.baseSha256,stageDbSha256:hash_files([db])[db]};
 journal.mounts=mounts;journal.baselineDbSha256=bank.stageDbSha256;journal.stageDbSha256=effective.stageDbSha256;
 journal.effective=effective;return effective;
};
function start(journal) {
 journal.starting=true;replace(model.stage+'/journal.json',journal,131072);
 command(['/etc/init.d/rpcd','restart'],5000);
 // These units read existing authoritative desired state; bootstrap never sets activeServerId.
 for(let unit in ['foxhole-runtime','foxhole-mobile','foxhole-history','foxhole-inbound'])command(['/etc/init.d/'+unit,'start'],5000);
};
function boot() {
 owner_namespace(false);let descriptor_text=raw(PRIVATE+'/boot.json',8192,false),expected=model.descriptor(json(descriptor_text));trust_check(expected);actual_platform(expected);
 if(fs.lstat(MARKER)||fs.lstat(model.stage)||consumers(false))fail();
 let tmp=mounted('/tmp');if(length(tmp)!=1||tmp[0].type!='tmpfs')fail();
 if(!fs.lstat('/tmp/foxhole'))mkdir('/tmp/foxhole',0o700);directory('/tmp/foxhole');mkdir(model.stage,0o700);
 let journal={schema:1,kind:'foxhole-ram-bootstrap-journal-v1',bootId:boot_id(),phase:'PREPARING',mounted:[],created:[],starting:false,markerWritten:false};
 write(model.stage+'/journal.json',sprintf('%J',journal));
 try {
  let host_before=host_snapshot(),bank=bank_load(expected,journal),effective=overlay_load(expected,bank,journal);
  journal.phase='PREPARED';replace(model.stage+'/journal.json',journal,131072);
  if(fs.lstat(MARKER)||consumers(false)||descriptor_text!=raw(PRIVATE+'/boot.json',8192,false)||!same(host_before,host_snapshot()))fail();memory(4194304);
  for(let row in journal.mounts)if(length(mounted(row.target)))fail();
  for(let row in journal.mounts) {
   absent_target(row.target,fs.lstat(row.source),journal);replace(model.stage+'/journal.json',journal,131072);
   command(['/bin/mount','--bind',row.source,row.target],2000);push(journal.mounted,row);replace(model.stage+'/journal.json',journal,131072);
   command(['/bin/mount','-o','remount,bind,ro',row.target],2000);matches_mount(row);
   if(index(split(mounted(row.target)[0].options,','),'ro')<0)fail();
  }
  let generations=PRIVATE+'/generations';if(!fs.lstat(generations))mkdir(generations,0o700);directory(generations);
  let ledger_path=generations+'/generation-'+random()+'.json';
  write(ledger_path,sprintf('%J',{schema:1,abi:1,kind:'foxhole-ram-mount-ledger-v1',stage:model.stage,baseSha256:effective.baseSha256,mounts:journal.mounts}));
  let marker={schema:1,version:effective.baseVersion,storage:'RAM',deployment:'foxhole-ram-bootstrap-v1',phase:'active',
   stage:model.stage,baseSha256:effective.baseSha256,stageDbSha256:effective.stageDbSha256,mountLedger:ledger_path,
   bankVersion:expected.version,bankBaseVersion:expected.baseVersion,bankBaseSha256:expected.baseSha256};
  let text=sprintf('%J',marker);write(model.stage+'/marker.json',text);
  if(fs.lstat(MARKER)||!fs.rename(model.stage+'/marker.json',MARKER))fail();
  journal.markerWritten=true;journal.markerSha256=digest.sha256(text);
  journal.phase='ACTIVE';replace(model.stage+'/journal.json',journal,131072);
  start(journal);if(!same(host_before,host_snapshot()))fail();
  journal.phase='STARTED';replace(model.stage+'/journal.json',journal,131072);
  replace(PRIVATE+'/boot-last.json',{schema:1,bootId:journal.bootId,phase:'STARTED',baseVersion:effective.baseVersion,baseSha256:effective.baseSha256,
   baselineBaseVersion:expected.baseVersion,bankVersion:expected.version,bankSha256:expected.artifact.sha256,hostApkUpdated:false,rebootQualified:false},4096);
  print('RAM bootstrap started; tunnel state is reported by the runtime\n');
 }catch(_) {
  try {rollback(journal);}catch(_) {journal.phase='RECOVERY_REQUIRED';try {replace(model.stage+'/journal.json',journal,131072);}catch(_) {}}
  try {replace(PRIVATE+'/boot-last.json',{schema:1,bootId:journal.bootId,phase:journal.phase=='ROLLED_BACK'?'FAILED':'RECOVERY_REQUIRED',
   hostApkUpdated:false,rebootQualified:false},4096);}catch(_) {}
  die('RAM bootstrap failed; private stage retained\n');
 }
};
function install(source,descriptor_path,pem_path,ca_path) {
 parents(source);let descriptor_text=raw(descriptor_path,8192,false),expected=model.descriptor(json(descriptor_text));actual_platform(expected);
 let pem=raw(pem_path,32768,false),ca=ca_path!=''?raw(ca_path,32768,false):null;
 if(digest.sha256(pem)!=expected.signerPemSha256||
  (expected.caFileSha256==null?ca!=null:ca==null||digest.sha256(ca)!=expected.caFileSha256))fail();
 let bodies={},manifest={schema:1,files:[]},total=length(descriptor_text)+length(pem)+length(ca||'');
 for(let name in TOOLS) {
  let text=raw(source+'/'+name,65536,false);bodies[name]=text;total+=length(text);push(manifest.files,{name,sha256:digest.sha256(text)});
 }
 let init=raw(source+'/ram-bootstrap.init',8192,false);total+=length(init)+length(sprintf('%J',manifest))+4096;
 if(total>131072)fail();
 let output=fs.popen('/bin/df -Pk /etc/foxhole','r');if(!output)fail();let report=output.read('all'),code=output.close();
 if(code!=0||type(report)!='string'||length(report)>16384)fail();let lines=split(trim(report),'\n'),fields=split(trim(lines[length(lines)-1]),/[ \t]+/);
 if(length(fields)<6||!match(fields[3],/^[0-9]+$/)||+fields[3]*1024<total+524288)fail();
 owner_namespace(true);
 if(fs.lstat(model.trust)||fs.lstat(PRIVATE+'/boot.json')||fs.lstat('/etc/init.d/foxhole-ram-bootstrap')||fs.lstat('/etc/rc.d/S99foxhole-ram-bootstrap'))fail();
 mkdir(model.trust,0o700);mkdir(model.trust+'/keys',0o700);
 for(let name in TOOLS)write(model.trust+'/'+name,bodies[name]);
 write(model.trust+'/keys/signer.pem',pem);if(ca!=null)write(model.trust+'/ca.pem',ca);
 write(model.trust+'/tools.json',sprintf('%J',manifest));write('/etc/init.d/foxhole-ram-bootstrap',init,0o755);
 write(PRIVATE+'/boot.json',descriptor_text);
 if(!fs.symlink('../init.d/foxhole-ram-bootstrap','/etc/rc.d/S99foxhole-ram-bootstrap'))fail();
 trust_check(expected);print('RAM bootstrap installed and enabled; activation was not run\n');
};
if(fs.stat('/proc/self')?.uid!=0)fail();
if(ARGV[0]=='boot'&&length(ARGV)==1)boot();
else if(ARGV[0]=='install'&&length(ARGV)==5)install(ARGV[1],ARGV[2],ARGV[3],ARGV[4]);
else fail();
