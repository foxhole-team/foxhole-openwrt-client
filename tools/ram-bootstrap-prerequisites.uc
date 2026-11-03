'use strict';
import * as fs from 'fs';
import * as digest from 'digest';
import * as paths from './ram-bootstrap-prerequisites-model.uc';
import * as registry from '/usr/share/foxhole/engine-registry.uc';
import * as engines from '/usr/share/foxhole/engine-model.uc';

function fail(reason){die('RAM_RECOVERY_PREREQUISITE: '+reason+'\n');};
if(fs.stat('/proc/self')?.uid!=0)fail('root enrollment required');
function facts(value){return sprintf('%J',[value?.type,value?.uid,value?.gid,value?.mode,value?.dev,value?.inode,value?.nlink,value?.size,value?.mtime,value?.ctime]);};
function protected_directory(path){let value=fs.lstat(path);if(value?.type!='directory'||value.uid!=0||(value.mode&0o022))fail('unprotected '+path);};
function root_chain(path){for(let at=path;;at=fs.dirname(at)){protected_directory(at);if(at=='/')break;}};
let mount_raw=fs.readfile('/proc/self/mountinfo',262145);
if(mount_raw==null||length(mount_raw)>262144)fail('mount evidence unavailable');
let mounts=[];
for(let line in split(trim(mount_raw),'\n')) {
 let fields=split(line,' '),separator=index(fields,'-');
 if(separator<6||!fields[separator+1]||match(fields[4],/\\/))fail('unsupported mount namespace');
 push(mounts,{path:fields[4],type:fields[separator+1],options:split(fields[5],',')});
}
function filesystem(path){let matches=sort(filter(mounts,row=>row.path=='/'||path==row.path||index(path,row.path+'/')==0),(a,b)=>length(b.path)-length(a.path));if(!length(matches))fail('mount backing missing');return matches[0];};
let rom=filesystem('/rom'),overlay=filesystem('/overlay/upper');
if(rom.path!='/rom'||index(['squashfs','erofs'],rom.type)<0||index(rom.options,'ro')<0)fail('supported read-only ROM required');
if(index(['ubifs','jffs2','ext4','f2fs','btrfs','xfs'],overlay.type)<0)fail('persistent overlay filesystem required');
root_chain('/rom');root_chain('/overlay/upper');

function candidate(root,path,temporary) {
 let parts=split(substr(paths.normalize(path),1),'/'),at=root;
 for(let i=0;i<length(parts);i++) {
  at+='/'+parts[i];let value=fs.lstat(at);if(!value)return null;
  let owned_tmp=temporary==true&&root==''&&at=='/tmp'&&(value.mode&0o7777)==0o1777;
  if(value.uid!=0||(value.type!='link'&&(value.mode&0o022)&&!owned_tmp))fail('unprotected backing '+path);
  if(i+1<length(parts)) {if(value.type!='directory')return null;}
  else return {...value,physical:at,backing:root,target:value.type=='link'?fs.readlink(at):null,ownedTemporaryInput:owned_tmp};
 }
 return null;
};
function current(path){return candidate('',path);};
function temporary_current(path){
 let row=candidate('',path,true);if(row&&path=='/tmp')row.ownedTemporaryInput=true;return row;
};
function persistent(path){return candidate('/overlay/upper',path)||candidate('/rom',path);};
function raw(path,maximum){let before=fs.lstat(path);if(before?.type!='file'||before.uid!=0||before.nlink!=1||(before.mode&0o022)||before.size<1||before.size>maximum)fail('invalid '+path);let value=fs.readfile(path,maximum+1);if(value==null||length(value)!=before.size||facts(before)!=facts(fs.lstat(path)))fail('changed '+path);return value;};
function hash(path){
 paths.normalize(path);let before=fs.lstat(path),input=fs.popen('/usr/bin/sha256sum '+path,'r');if(!input)fail('hash unavailable');
 let output=input.read(4097),code=input.close(),found=match(output||'',/^([a-f0-9]{64})  ([A-Za-z0-9_+.,@=:\/-]+)\n$/);
 if(code!=0||length(output||'')>4096||!found||found[2]!=path||facts(before)!=facts(fs.lstat(path)))fail('hash changed '+path);return found[1];
};
let checked={},pending=[],machine=0;
let architecture=trim(raw('/etc/apk/arch',128));
if(architecture=='aarch64_cortex-a53')machine=183;else if(architecture=='x86_64')machine=62;else fail('unsupported architecture');
function is_bound(path){return length(filter(mounts,row=>row.path!='/'&&(row.path==path||index(path,row.path+'/')==0)))>0;};
function backing(path) {
 let live=paths.resolve(path,current),boot=paths.resolve(path,persistent);
 if(boot.row.backing=='/rom'&&(is_bound(path)||is_bound(live.path)||length(filter(live.links,row=>is_bound(row.path)))))fail('RAM-bound dependency '+path);
 let first=hash(live.row.physical),second=hash(boot.row.physical);
 paths.same_file(live,boot,first,second);
 checked[path]={sha256:first,bytes:live.row.size,backing:boot.row.backing};return live;
};
function library(name) {
 if(substr(name,0,1)=='/')return paths.normalize(name);
 for(let root in ['/lib','/usr/local/lib','/usr/lib'])if(fs.stat(root+'/'+name)){paths.resolve(root+'/'+name,current);return root+'/'+name;}
 fail('missing library '+name);
};
function elf(path,persistent_file,required) {
 let live=persistent_file?backing(path):paths.resolve(path,temporary_current),file=fs.open(live.row.physical,'re'),before=facts(fs.lstat(live.row.physical));
 if(!file)fail('ELF open failed');
 function read(offset,bytes){if(offset<0||bytes<0||bytes>262144||offset+bytes>live.row.size||file.seek(offset,0)!=true)fail('ELF read range');let value=file.read(bytes);if(value==null||length(value)!=bytes)fail('short ELF read');return value;};
 let dependencies;
 try{dependencies=paths.elf_dependencies(read,live.row.size,machine);}catch(error){file.close();fail('ELF '+path+' -> '+live.path+': '+(error?.message||error));}
 file.close();if(facts(fs.lstat(live.row.physical))!=before)fail('ELF changed');
 if(required&&dependencies==null)fail('ELF required '+path);
 if(persistent_file)checked[path].isElf=dependencies!=null;
 if(dependencies)for(let name in dependencies)push(pending,library(name));
 return live;
};
function require_file(path,inspect,required){if(checked[path]){if(required&&checked[path].isElf!=true)fail('ELF required '+path);return;}if(inspect)elf(path,true,required);else backing(path);};
// This primitive is hashed directly before it is used to stream larger dependencies.
let sha_live=paths.resolve('/usr/bin/sha256sum',current),sha_boot=paths.resolve('/usr/bin/sha256sum',persistent);
paths.same_file(sha_live,sha_boot,digest.sha256(raw(sha_live.row.physical,2097152)),digest.sha256(raw(sha_boot.row.physical,2097152)));
for(let path in ['/usr/bin/ucode','/usr/lib/ucode/fs.so','/usr/lib/ucode/digest.so','/usr/bin/apk','/usr/bin/sha256sum',
 '/bin/sh','/bin/mount','/bin/umount','/bin/df','/sbin/procd'])require_file(path,true,true);
for(let path in ['/etc/apk/arch','/etc/openwrt_release','/etc/rc.common','/lib/functions.sh','/lib/functions/service.sh','/lib/functions/procd.sh','/usr/share/libubox/jshn.sh'])require_file(path,false);
function require_command(command) {
 let path=null;for(let root in ['/usr/sbin','/usr/bin','/sbin','/bin']){let value=fs.stat(root+'/'+command);if(value?.type=='file'&&(value.mode&0o111)){path=root+'/'+command;break;}}
 if(!path)fail('missing command '+command);require_file(path,true,true);
};
for(let command in ['ubus','jshn','mkfifo','id','flock','awk','mktemp','wc','ln','chmod','rm','mv','mkdir','uname','uclient-fetch'])require_command(command);
let loader_path='/etc/ld-musl-'+(machine==183?'aarch64':'x86_64')+'.path';
if(fs.lstat(loader_path)){require_file(loader_path,false);let content=trim(raw(loader_path,4096));for(let path in split(content,/[:\n]/))if(index(['/lib','/usr/local/lib','/usr/lib'],path)<0)fail('custom dynamic loader path');}
let helper=ARGV[0],wanted=ARGV[1];
if(type(helper)!='string'||!match(wanted||'',/^[a-f0-9]{64}$/)||hash(helper)!=wanted)fail('helper digest differs');
elf(helper,false,true);push(pending,library('libustream-ssl.so'));
let certificates=fs.glob('/etc/ssl/certs/*.crt');if(type(certificates)!='array'||!length(certificates)||length(certificates)>256)fail('stock CA trust missing');
for(let path in certificates)require_file(path,false);
for(let at=0;at<length(pending);at++){if(at>128)fail('ELF closure limit');require_file(pending[at],true,true);}

function runtime(action){let pipe=fs.popen('/usr/libexec/foxhole-runtime '+action,'r');if(!pipe)fail('selected provider unavailable');let value=pipe.read(1025),code=pipe.close();if(code!=0||length(value||'')>1024)fail('selected provider unavailable');return trim(value);};
let provider=runtime('engine');
if(provider=='hysteria') {
 require_file('/usr/bin/hysteria',true);
 if(!paths.legacy_launcher(checked['/usr/bin/hysteria'].sha256))fail('unsupported Go launcher; verify its published package first');
 if(checked['/usr/bin/hysteria'].sha256=='c264e9a3b6f9bbfa5bd842c91101ffefc848da2f3f616d855150d1a379850286')require_command('stat');
}else if(provider=='core') {
 let value=registry.read(),slots=filter(value.slots,row=>length(filter(value.selected,item=>item.slotId==engines.slot_id(row)))==1);
 if(!length(slots))fail('selected Core slot is not verified');
 require_file('/etc/foxhole/engines.json',false);
 for(let slot in slots) {
  let binary=registry.executable(slot);if(registry.verify_slot(slot)!=binary)fail('selected Core slot is not verified');
  let folder=fs.dirname(binary),notices='/usr/share/licenses/'+slot.packageName;
  for(let name in ['slot.json','core-producer.json','capabilities.json'])require_file(folder+'/'+name,false);
  for(let name in ['LEGAL-PROVENANCE.json','LICENSE','THIRD_PARTY_NOTICES.md','DEPENDENCY-LICENSES.txt','RUNTIME-NOTICES.txt'])require_file(notices+'/'+name,false);
  require_file(binary,true);
 }
}else fail('unsupported selected provider');
let release=trim(fs.readfile('/proc/sys/kernel/osrelease',256)||'');
if(!match(release,/^[A-Za-z0-9_.+-]{1,96}$/))fail('kernel identity unavailable');
let module=null,builtin='/lib/modules/'+release+'/modules.builtin';
for(let path in ['/lib/modules/'+release+'/tun.ko','/lib/modules/'+release+'/kernel/drivers/net/tun.ko'])if(fs.lstat(path)){module=path;break;}
if(module) {
 require_file(module,false);let content=raw(module,2097152);
 if(index(content,'vermagic='+release+' ')<0)fail('TUN kernel ABI differs');
}else {
 require_file(builtin,false);if(!match(raw(builtin,1048576),/(^|\n)(kernel\/)?drivers\/net\/tun\.ko(\n|$)/)||fs.stat('/sys/module/tun')?.type!='directory')fail('persistent TUN or builtin proof required');
}
for(let at=0;at<length(pending);at++){if(at>160)fail('ELF closure limit');require_file(pending[at],true,true);}
print(sprintf('%J',{schema:1,persistentPrerequisitesVerified:true,selectedProvider:provider,checkedFiles:length(keys(checked)),
 helperCopiedByAdmission:false,extraSourcePersisted:false,configurationChanged:false,kernelOrLibrariesInstalled:false,rebootPerformed:false}),'\n');
