'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as guard from './update-model.uc';
import * as engines from './engine-model.uc';
import * as engine from './engine-service.uc';
import * as registry from './engine-registry.uc';
import * as store from './private-store.uc';

const ORIGIN = 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/';
const KEY = '/usr/share/foxhole/foxhole-openwrt-apk.pem';
const SIGNER_PUBLIC_PEM_SHA256 = 'fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1';
export function decode(raw) {
	try { return json(raw); } catch (_) { guard.fail('PACKAGE_VERIFICATION_FAILED'); }
};
export function public_raw(path, maximum) {
	let a = fs.lstat(path);
	if (a?.type != 'file' || a.uid != 0 || a.nlink != 1 || (a.mode & 0o022) || a.size < 1 || a.size > maximum)
		guard.fail('PACKAGE_VERIFICATION_FAILED');
	let raw = fs.readfile(path, maximum + 1), b = fs.lstat(path);
	if (raw == null || length(raw) != a.size || sprintf('%J',[a.dev,a.inode,a.size,a.mode,a.mtime,a.ctime]) != sprintf('%J',[b?.dev,b?.inode,b?.size,b?.mode,b?.mtime,b?.ctime])) guard.fail('PACKAGE_VERIFICATION_FAILED');
	return raw;
};
export function policy(path, version) {
	let value = decode(public_raw(path, 8192));
	if (value.schema != 1 || value.transactionAbi != 1 || value.stateAbi != 1 || value.packageVersion != version ||
	    value.osRelease != '25.12.5' || !match(value.releaseTag || '', /^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$/) ||
	    sprintf('%J', value.targets) != sprintf('%J', ['x86/64','mediatek/filogic'])) guard.fail('UNSUPPORTED_TARGET');
	return value;
};
export function target() {
	let raw = public_raw('/etc/openwrt_release', 8192);
	let release = match(raw, /(^|\n)DISTRIB_RELEASE='([^']+)'/), board = match(raw, /(^|\n)DISTRIB_TARGET='([^']+)'/);
	let architecture = registry.architecture();
	if ((release ? release[2] : null) != '25.12.5' || !(((board ? board[2] : null) == 'x86/64' && architecture == 'x86_64') ||
	    ((board ? board[2] : null) == 'mediatek/filogic' && architecture == 'aarch64_cortex-a53'))) guard.fail('UNSUPPORTED_TARGET');
	return { release:release[2], target:board[2], architecture };
};
export function prepare_keys(directory) {
	store.directory(directory); store.directory(directory + '/keys');
	if (registry.hash_file(KEY) != SIGNER_PUBLIC_PEM_SHA256 || system(['/bin/cp', KEY, directory + '/keys/foxhole.pem'],3000) != 0)
		guard.fail('PACKAGE_VERIFICATION_FAILED');
	return directory + '/keys';
};
export function fetch(url, maximum) {
	store.directory('/tmp/foxhole/engine-assets');
	let random = fs.readfile('/dev/urandom',16);
	if (length(random || '') != 16) guard.fail('ROUTER_UNAVAILABLE');
	let path = '/tmp/foxhole/engine-assets/update-' + hexenc(random);
	if (system(['/usr/libexec/foxhole-engine-fetch',url,path,''+maximum],125000) != 0) guard.fail('DOWNLOAD_FAILED');
	public_raw(path,maximum);
	return path;
};
export function latest(directory) {
	let path = directory + '/release-hint.json';
	store.target(path);
	if (fs.lstat(path) || system(['/usr/libexec/foxhole-update-hint',path],25000) != 0) guard.fail('RELEASE_UNAVAILABLE');
	return guard.release_tag(decode(public_raw(path,262144)));
};
export function compare(a,b) {
	return trim(engine.update_apk(['--no-network','--repositories-file','/dev/null','version','-t',a,b]));
};
function staging_memory(required) {
	let raw=fs.readfile('/proc/meminfo',65536),found=match(raw||'',/\n?MemAvailable:[ \t]+([0-9]+) kB/);
	if(!found||+found[1]*1024<required)guard.fail('NO_SPACE');
};
export function base(tag,directory,keys_dir) {
	if (!match(tag || '',/^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$/)) guard.fail('RELEASE_UNAVAILABLE');
	store.directory(directory);staging_memory(33554432);
	let index = fetch(ORIGIN + tag + '/base.adb',1048576);
	engine.update_apk(['--keys-dir',keys_dir,'verify',index]);
	let document = decode(engine.update_apk(['adbdump','--format','json',index])), rows = document.packages;
	if (type(rows) != 'array' || length(rows) != 1) guard.fail('PACKAGE_VERIFICATION_FAILED');
	let row = rows[0];
	if (row.name != 'foxhole-openwrt-client' || row.arch != 'noarch' ||
	    !match(row.version || '',/^[0-9]+\.[0-9]+\.[0-9]+-r[1-9][0-9]{0,5}$/) ||
	    type(row['file-size']) != 'int' || row['file-size'] < 1 || row['file-size'] > 8388608 ||
	    type(row['installed-size'])!='int'||row['installed-size']<1||row['installed-size']>33554432 ||
	    !match(row.hashes || '', /^[a-f0-9]{64}$/)) guard.fail('PACKAGE_VERIFICATION_FAILED');
	staging_memory(4*row['file-size']+row['installed-size']+36700160);
	let filename = row.name + '-' + row.version + '.apk';
	let archive = fetch(ORIGIN + tag + '/' + filename,row['file-size']);
	if (fs.lstat(archive).size != row['file-size']) guard.fail('PACKAGE_VERIFICATION_FAILED');
	engine.update_apk(['--keys-dir',keys_dir,'verify',archive]);
	let payload = decode(engine.update_apk(['adbdump','--format','json',archive]));
	let paths = guard.base_layout(payload,row.version);
	// A native fetch from the authenticated index binds its package
	// digest to these exact bytes.
	store.directory(directory + '/root'); store.directory(directory + '/fetched');
	if (system(['/bin/cp',index,directory + '/packages.adb'],3000) != 0 ||
	    system(['/bin/cp',archive,directory + '/' + filename],5000) != 0) guard.fail('PACKAGE_VERIFICATION_FAILED');
	store.write(directory + '/repositories',directory + '/packages.adb\n');
	let common = ['--root',directory + '/root','--arch',registry.architecture(),'--no-network','--no-cache',
		'--repositories-file',directory + '/repositories','--keys-dir',keys_dir];
	engine.update_apk([...common,'add','--initdb']);
	engine.update_apk([...common,'fetch','--output',directory + '/fetched',row.name]);
	if (registry.hash_file(directory + '/fetched/' + filename) != registry.hash_file(archive)) guard.fail('PACKAGE_VERIFICATION_FAILED');
	store.directory(directory + '/extracted');
	engine.update_apk(['--keys-dir',keys_dir,'extract','--no-chown','--destination',directory + '/extracted',archive]);
	let embedded = policy(directory + '/extracted/usr/share/foxhole/update-policy.json',row.version);
	if (embedded.releaseTag != tag || registry.hash_file(directory + '/extracted' + KEY) != SIGNER_PUBLIC_PEM_SHA256) guard.fail('PACKAGE_VERIFICATION_FAILED');
	let catalog_raw = public_raw(directory + '/extracted/usr/share/foxhole/engine-catalog.json',262144);
	let catalog = engines.catalog(decode(catalog_raw));
	return { archive, index, filename, version:row.version, nativeId:row.hashes, sha256:registry.hash_file(archive),
		archiveBytes:row['file-size'],installedBytes:payload.info['installed-size'],
		indexSha256:registry.hash_file(index),catalog,catalogSha256:digest.sha256(catalog_raw),
		tag,policy:embedded,paths,payload,directory };
};
export function installed_base(value) {
	let current = engine.update_installed()['foxhole-openwrt-client'];
	if (!current || current.arch != 'noarch' || current.version != value.version) guard.fail('ROLLBACK_UNAVAILABLE');
	// Configuration is mutable by design; every immutable installed
	// BASE payload must match.
	for (let folder in value.payload.paths) for (let file in folder.files || []) {
		let path = folder.name + '/' + file.name;
		if (path == 'etc/config/foxhole' || path == 'lib/apk/packages/foxhole-openwrt-client.list') continue;
		// Native postinst consumes this one setup script.
		if (path == 'etc/uci-defaults/99-foxhole-openwrt-client' && !fs.lstat('/' + path)) continue;
		if (registry.hash_file('/' + path) != file.hash) guard.fail('VERSION_IDENTITY_CONFLICT');
	}
	return true;
};
export function selected_modules(current) {
	let result = [];
	for (let choice in current.selected) {
		let value = engines.selected(current,choice.id);
		if (!value || index(['vless','hysteria2','wireguard'],value.id) < 0) guard.fail('UNSUPPORTED_TARGET');
		registry.verify_slot(value);
		push(result,value);
	}
	if (length(result) > 3) guard.fail('UNSUPPORTED_TARGET');
	return result;
};
export function module_changes(old,catalog,architecture) {
	let artifacts = [], changes = [];
	for (let previous in old) {
		let matches = filter(catalog.entries,item => item.id == previous.id && item.storage == previous.storage && item.architecture == architecture);
		if (length(matches) != 1) guard.fail('UNSUPPORTED_TARGET');
		let next = matches[0];
		let changed = guard.version_admit(compare(previous.version,next.version),previous.manifestSha256,next.manifestSha256);
		if (!changed) continue;
		push(artifacts,next);
		push(changes,{id:next.id,fromVersion:previous.version,toVersion:next.version,storage:previous.storage});
	}
	return { artifacts,changes };
};
export function stage_ram(value) {
	if (value.storage != 'RAM') return;
	let directory = '/tmp/foxhole/engine-binaries/' + value.id + '/' + value.binarySha256;
	store.directory(directory);
	let path = directory + '/foxcore-cli', info = fs.lstat(path);
	if (!info) {
		let url = ORIGIN + 'v' + value.version + '/engine-' + value.id + '-' + value.architecture + '-' + value.binarySha256 + '.bin';
		let raw = engine.update_asset(url,value.binarySha256,value.binaryBytes);
		if (fs.lstat(raw).size != value.binaryBytes || system(['/bin/cp',raw,path],10000) != 0 || !fs.chmod(path,0o700))
			guard.fail('RAM_STAGE_UNAVAILABLE');
		info = fs.lstat(path);
	}
	if (!store.file_metadata(info) || (info.mode & 0o7777) != 0o700 || info.size != value.binaryBytes ||
	    registry.hash_file(path) != value.binarySha256) guard.fail('RAM_STAGE_UNAVAILABLE');
};

const TOOL_SOURCE = 'e47373813001b0f5a36470b34b4f0390324182636233736b514e4c7e85fd4557';
const CACHE = '/etc/foxhole/update-cache';
function exact(value, fields) {
 if(type(value)!='object'||length(keys(value))!=length(fields))guard.fail('PACKAGE_VERIFICATION_FAILED');
 for(let key in keys(value))if(index(fields,key)<0)guard.fail('PACKAGE_VERIFICATION_FAILED');
};
function sha(value){return type(value)=='string'&&match(value,/^[a-f0-9]{64}$/)!=null;};
function facts(info){return sprintf('%J',[info?.type,info?.uid,info?.gid,info?.mode,info?.dev,info?.inode,info?.nlink,info?.size,info?.mtime,info?.ctime]);};
function chain(path){
 for(let directory=fs.dirname(path);;directory=fs.dirname(directory)){
  let s=fs.lstat(directory);
  if(s?.type!='directory'||s.uid!=0||(s.mode&0o022)&&(directory!='/tmp'||(s.mode&0o7777)!=0o1777))guard.fail('PACKAGE_VERIFICATION_FAILED');
  if(directory=='/')break;
 }
};
function regular(path,maximum,size,private) {
 chain(path);let info=fs.lstat(path);
 if(info?.type!='file'||info.uid!=0||info.nlink!=1||(info.mode&0o022)||
    private&&(info.mode&0o7777)!=0o600||info.size<1||info.size>maximum||size!=null&&info.size!=size)guard.fail('PACKAGE_VERIFICATION_FAILED');
 return info;
};
function raw_role(path,maximum,size,private) {
 let before=regular(path,maximum,size,private),parent=fs.lstat(fs.dirname(path)),raw=fs.readfile(path,maximum+1);
 if(raw==null||length(raw)!=before.size||facts(regular(path,maximum,size,private))!=facts(before)||facts(fs.lstat(fs.dirname(path)))!=facts(parent))guard.fail('PACKAGE_VERIFICATION_FAILED');
 return raw;
};
export function installed_identities() {
 let raw=raw_role('/lib/apk/db/installed',4194304,null,false),result={},count=0;
 for(let block in split(raw,'\n\n')){
  if(!length(trim(block)))continue;
  let fields={};
  for(let line in split(block,'\n'))if(index(['P','V','A','C','f'],substr(line,0,1))>=0&&substr(line,1,1)==':'){
   let key=substr(line,0,1);if(fields[key]!=null)guard.fail('PACKAGE_VERIFICATION_FAILED');fields[key]=substr(line,2);
  }
  if(!match(fields.P||'',/^[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,255}$/)||result[fields.P]||!length(fields.V||'')||!length(fields.A||'')||++count>4096)guard.fail('PACKAGE_VERIFICATION_FAILED');
  if(!match(fields.C||'',/^Q1[A-Za-z0-9+/]{27}=$/))guard.fail('PACKAGE_VERIFICATION_FAILED');
  let bytes=b64dec(substr(fields.C,2));if(length(bytes||'')!=20)guard.fail('PACKAGE_VERIFICATION_FAILED');
  result[fields.P]={name:fields.P,version:fields.V,arch:fields.A,
   cas:(index(fields.f||'','S')>=0?'sha256-160:':'sha1:')+hexenc(bytes),flags:fields.f||''};
 }
 return result;
};
export function native_cas(identity) {
 if(!sha(identity))guard.fail('PACKAGE_VERIFICATION_FAILED');
 return 'sha256-160:'+substr(identity,0,40);
};
export function world_plan(raw, additions) {
 if(type(raw)!='string'||length(raw)<1||length(raw)>65536||substr(raw,length(raw)-1)!='\n'||type(additions)!='array'||length(additions)>3)guard.fail('PACKAGE_VERIFICATION_FAILED');
 let rows=split(raw,'\n');pop(rows);let names={},base=0;
 for(let row in rows){
  let parsed=match(row,/^!?([A-Za-z0-9][A-Za-z0-9+_.-]*)(@[A-Za-z0-9][A-Za-z0-9+_.-]*)?((<=|>=|=|<|>|~)[A-Za-z0-9][A-Za-z0-9+_.~:-]*)?$/);
  if(!parsed||length(row)>512||names[parsed[1]])guard.fail('PACKAGE_VERIFICATION_FAILED');names[parsed[1]]=true;
  if(parsed[1]=='foxhole-openwrt-client'){if(row!='foxhole-openwrt-client')guard.fail('UNSUPPORTED_TARGET');base++;}
 }
 if(base!=1)guard.fail('PACKAGE_VERIFICATION_FAILED');
 for(let name in additions){
  if(!match(name||'',/^foxcore-engine-(vless|hysteria2|wireguard)-(flash|ram)-[a-f0-9]{64}$/)||names[name])guard.fail('PACKAGE_VERIFICATION_FAILED');
  names[name]=true;push(rows,name);
 }
 let after=join('\n',rows)+'\n';if(length(after)>65536)guard.fail('PACKAGE_VERIFICATION_FAILED');
 return {beforeRaw:raw,beforeSha256:digest.sha256(raw),afterRaw:after,afterSha256:digest.sha256(after)};
};
export function world_state() {let raw=raw_role('/etc/apk/world',65536,null,false),info=fs.lstat('/etc/apk/world');return {raw,sha256:digest.sha256(raw),metadata:{uid:info.uid,gid:info.gid,mode:info.mode,nlink:info.nlink}};};
export function cache_asset(path,wanted,size) {
 if(!sha(wanted)||type(size)!='int'||size<1||size>134217728)guard.fail('PACKAGE_VERIFICATION_FAILED');
 regular(path,134217728,size,false);if(registry.hash_file(path)!=wanted)guard.fail('PACKAGE_VERIFICATION_FAILED');
 store.directory(CACHE);let destination=CACHE+'/'+wanted;
 if(!fs.lstat(destination)&&system(['/bin/sh','-c','set -eu; umask 077; set -C; exec /bin/cat "$1" > "$2"','foxhole-cache',path,destination],15000)!=0)guard.fail('ROLLBACK_UNAVAILABLE');
 regular(destination,134217728,size,true);if(registry.hash_file(destination)!=wanted)guard.fail('ROLLBACK_UNAVAILABLE');return destination;
};
function cached_raw(row,maximum) {
 exact(row,['sha256','bytes']);if(!sha(row.sha256)||type(row.bytes)!='int'||row.bytes<1||row.bytes>maximum)guard.fail('PACKAGE_VERIFICATION_FAILED');
 let raw=raw_role(CACHE+'/'+row.sha256,maximum,row.bytes,true);if(digest.sha256(raw)!=row.sha256)guard.fail('PACKAGE_VERIFICATION_FAILED');return raw;
};
function tool_record(value) {
 exact(value,['schema','abi','sourceArchiveSha256','architecture','manifestSha256','elfSha256','elfBytes','gzipSha256','gzipBytes','helpers']);
 if(value.schema!=1||value.abi!=1||value.sourceArchiveSha256!=TOOL_SOURCE||value.architecture!=registry.architecture()||
    index(['x86_64','aarch64_cortex-a53'],value.architecture)<0||!sha(value.manifestSha256)||!sha(value.elfSha256)||!sha(value.gzipSha256)||
    type(value.elfBytes)!='int'||value.elfBytes<64||value.elfBytes>16777216||type(value.gzipBytes)!='int'||value.gzipBytes<1||value.gzipBytes>8388608)guard.fail('PACKAGE_VERIFICATION_FAILED');
 exact(value.helpers,['command','utility','stager']);for(let key in keys(value.helpers))cached_raw(value.helpers[key],32768);
 regular(CACHE+'/'+value.gzipSha256,8388608,value.gzipBytes,true);
 if(registry.hash_file(CACHE+'/'+value.gzipSha256)!=value.gzipSha256)guard.fail('PACKAGE_VERIFICATION_FAILED');return value;
};
function load_tool_manifest() {
 let raw=raw_role('/usr/share/foxhole/transaction-tool.json',16384,null,false),value=decode(raw);
 exact(value,['schema','abi','sourceArchiveSha256','targets']);exact(value.targets,['x86_64','aarch64_cortex-a53']);
 if(value.schema!=1||value.abi!=1||value.sourceArchiveSha256!=TOOL_SOURCE)guard.fail('UNSUPPORTED_TARGET');
 for(let architecture in keys(value.targets)){
  let row=value.targets[architecture];exact(row,['elfSha256','elfBytes','gzipSha256','gzipBytes']);
  if(!sha(row.elfSha256)||!sha(row.gzipSha256)||type(row.elfBytes)!='int'||row.elfBytes<64||row.elfBytes>16777216||type(row.gzipBytes)!='int'||row.gzipBytes<1||row.gzipBytes>8388608)guard.fail('PACKAGE_VERIFICATION_FAILED');
 }
 let architecture=registry.architecture(),row=value.targets[architecture];if(!row)guard.fail('UNSUPPORTED_TARGET');
 return {raw,value,architecture,row};
};
export function tool_budget() {
 let value=load_tool_manifest(),row=value.row;
 return {flashBytes:row.gzipBytes+98304,ramBytes:row.elfBytes+row.gzipBytes+16777216};
};
function stage_tool(raw) {
 let value=tool_record(raw);store.directory('/tmp/foxhole/transaction-tools');let folder='/tmp/foxhole/transaction-tools/'+value.elfSha256;store.directory(folder);
 let executable=folder+'/transaction',info=fs.lstat(executable);
 if(!info){
  let stager=cached_raw(value.helpers.stager,32768);
  let script=folder+'/stage';if(fs.lstat(script)){if(raw_role(script,32768,value.helpers.stager.bytes,true)!=stager)guard.fail('RAM_STAGE_UNAVAILABLE');}
  else store.write(script,stager);
  if(system(['/bin/sh',script,CACHE+'/'+value.gzipSha256,executable],25000)!=0)guard.fail('RAM_STAGE_UNAVAILABLE');
 }
 info=regular(executable,16777216,value.elfBytes,false);
 if((info.mode&0o7777)!=0o700||registry.hash_file(executable)!=value.elfSha256)guard.fail('RAM_STAGE_UNAVAILABLE');
 let file=fs.open(executable,'re'),header=file?file.read(20):null;if(file)file.close();
 let machine=value.architecture=='x86_64'?62:183;
 if(length(header||'')!=20||substr(header,0,4)!='\x7fELF'||ord(substr(header,4,1))!=2||ord(substr(header,5,1))!=1||ord(substr(header,18,1))+256*ord(substr(header,19,1))!=machine)guard.fail('RAM_STAGE_UNAVAILABLE');
 return executable;
};
export function prepare_tool() {
 let source=load_tool_manifest(),raw=source.raw,architecture=source.architecture,row=source.row;
 cache_asset('/usr/share/foxhole/transaction-'+architecture+'.gz',row.gzipSha256,row.gzipBytes);
 let helpers={},paths={command:'/usr/libexec/foxhole-transaction-command-v1',utility:'/usr/share/foxhole/engine-capture.uc',stager:'/usr/libexec/foxhole-transaction-stage-v1'};
 for(let key in keys(paths)){let data=raw_role(paths[key],32768,null,false),pin=digest.sha256(data);cache_asset(paths[key],pin,length(data));helpers[key]={sha256:pin,bytes:length(data)};}
 let result={schema:1,abi:1,sourceArchiveSha256:TOOL_SOURCE,architecture,manifestSha256:digest.sha256(raw),...row,helpers};
 stage_tool(result);return result;
};
export function transaction_capture(tool,argv) {
 let executable=stage_tool(tool),random=fs.readfile('/dev/urandom',12);if(length(random||'')!=12)guard.fail('ROUTER_UNAVAILABLE');
 let path='/tmp/foxhole/engine-command-'+hexenc(random),stage=path+'.io';if(fs.lstat(stage))guard.fail('PACKAGE_VERIFICATION_FAILED');store.directory(stage);
 store.write(stage+'/helper',cached_raw(tool.helpers.command,32768));store.write(stage+'/utility.uc',cached_raw(tool.helpers.utility,32768));
 let code=system(['/bin/sh',stage+'/helper',path,'8388608','120000',executable,...argv],125000);
 let cleaned=!fs.lstat(stage+'/owner.json')&&!fs.lstat(stage+'/stdout')&&!fs.lstat(stage+'/stderr');
 if(cleaned){for(let name in ['helper','utility.uc'])if(!fs.unlink(stage+'/'+name))cleaned=false;if(!fs.rmdir(stage))cleaned=false;}
 let stdout=null,stderr=null;try{stdout=store.read(path,8388608);stderr=store.read(path+'.err',8388608);}catch(_){}
 for(let output in [path,path+'.err'])try{fs.unlink(output);}catch(_){}
 if(code!=0||!cleaned||stdout==null||match(stdout,/(^|\n)ERROR:/)||match(stderr||'',/(^|\n)ERROR:/))guard.fail('RECOVERY_REQUIRED');
};
export function owned_payload_files(payload) {
 let paths=[];for(let folder in payload.paths||[])for(let file in folder.files||[]){
  let path='/'+(length(folder.name)?folder.name+'/':'')+file.name;
  if(!match(path,/^\/(usr|lib)\/[A-Za-z0-9_+./-]+$/)||match(path,/\/(\.|\.\.)(\/|$)/)||index(paths,path)>=0||length(paths)>=2048)guard.fail('PACKAGE_VERIFICATION_FAILED');push(paths,path);
 }
 return paths;
};
export function native_args(tx,recovery,current) {
 if(tx.schema!=1||tx.abi!=1||!sha(tx.beforeSha256)||!sha(tx.afterSha256)||type(tx.modules)!='array'||length(tx.modules)>3||
    !sha(tx.oldBase.nativeId)||!sha(tx.newBase.nativeId)||tx.oldCas!=native_cas(tx.oldBase.nativeId)||tx.newCas!=native_cas(tx.newBase.nativeId))guard.fail('RECOVERY_REQUIRED');
 if(recovery&&current!=tx.beforeSha256&&current!=tx.afterSha256||!recovery&&current!=tx.beforeSha256)guard.fail('RECOVERY_REQUIRED');
 let argv=['--root','/','--no-network','--no-cache','--keys-dir',tx.keys,'--repositories-file',tx.repositories];
 if(recovery)push(argv,'foxhole-recover','foxhole-openwrt-client='+tx.oldBase.version,'foxhole-openwrt-client='+tx.newBase.version,
  current,tx.beforeSha256,tx.oldCas,tx.newCas,tx.oldBase.nativeId,tx.oldBase.archive,tx.newBase.nativeId,tx.newBase.archive);
 else push(argv,'foxhole-apply','foxhole-openwrt-client='+tx.newBase.version,tx.oldBase.version,current,tx.oldCas,tx.newBase.nativeId,tx.newBase.archive);
 let seen={};for(let item in tx.modules){
  if(!match(item.name||'',/^foxcore-engine-(vless|hysteria2|wireguard)-(flash|ram)-[a-f0-9]{64}$/)||seen[item.name]||!sha(item.nativeId)||!match(item.version||'',/^[a-zA-Z0-9][a-zA-Z0-9_.~+-]{0,159}$/))guard.fail('RECOVERY_REQUIRED');seen[item.name]=true;
  push(argv,item.name+'='+item.version,item.nativeId,item.archive);
 }
 return argv;
};
function repository_asset(directory,name,cache,wanted,size) {
 if(length(name||'')>384||!match(name||'',/^[A-Za-z0-9][A-Za-z0-9_.+-]*$/)||!sha(wanted)||cache!=CACHE+'/'+wanted)guard.fail('RECOVERY_REQUIRED');
 regular(cache,8388608,size,true);if(registry.hash_file(cache)!=wanted)guard.fail('RECOVERY_REQUIRED');
 let path=directory+'/'+name;
 if(!fs.lstat(path)&&system(['/bin/sh','-c','set -eu; umask 077; set -C; exec /bin/cat "$1" > "$2"','foxhole-repository',cache,path],15000)!=0)guard.fail('ROLLBACK_UNAVAILABLE');
 regular(path,8388608,size,true);if(registry.hash_file(path)!=wanted)guard.fail('RECOVERY_REQUIRED');return path;
};
export function verify_transaction(id,tx) {
 if(!match(id||'',/^update-job-[a-f0-9]{32}$/)||tx.schema!=1||tx.abi!=1||tx.keys!=CACHE+'/job-'+id+'/keys'||tx.repositories!=CACHE+'/job-'+id+'/repositories'||!sha(tx.repositoriesSha256))guard.fail('RECOVERY_REQUIRED');
 if(!sha(tx.beforeSha256)||!sha(tx.afterSha256)||digest.sha256(tx.beforeRaw||'')!=tx.beforeSha256||digest.sha256(tx.afterRaw||'')!=tx.afterSha256)guard.fail('RECOVERY_REQUIRED');
 let recomputed=world_plan(tx.beforeRaw,map(tx.modules,item=>item.name));if(recomputed.afterRaw!=tx.afterRaw)guard.fail('RECOVERY_REQUIRED');
 regular(tx.keys+'/foxhole.pem',16384,null,true);
 if(registry.hash_file(tx.keys+'/foxhole.pem')!=SIGNER_PUBLIC_PEM_SHA256||digest.sha256(raw_role(tx.repositories,8192,null,true))!=tx.repositoriesSha256)guard.fail('RECOVERY_REQUIRED');
 let indices=[];
 for(let item in [tx.oldBase,tx.newBase]){
  if(!sha(item.sha256)||!sha(item.indexSha256)||!sha(item.nativeId)||item.archive!=CACHE+'/job-'+id+'/assets/'+item.filename||item.index!=CACHE+'/job-'+id+'/assets/index-'+item.indexSha256+'.adb'||
     !match(item.version||'',/^[0-9]+\.[0-9]+\.[0-9]+-r[1-9][0-9]{0,5}$/)||item.filename!='foxhole-openwrt-client-'+item.version+'.apk')guard.fail('RECOVERY_REQUIRED');
  store.directory(CACHE+'/job-'+id+'/assets');
  repository_asset(CACHE+'/job-'+id+'/assets',item.filename,CACHE+'/'+item.sha256,item.sha256,item.archiveBytes);
  repository_asset(CACHE+'/job-'+id+'/assets','index-'+item.indexSha256+'.adb',CACHE+'/'+item.indexSha256,item.indexSha256,fs.lstat(CACHE+'/'+item.indexSha256)?.size);
  regular(item.archive,8388608,item.archiveBytes,true);regular(item.index,1048576,null,true);
  if(registry.hash_file(item.archive)!=item.sha256||registry.hash_file(item.index)!=item.indexSha256)guard.fail('RECOVERY_REQUIRED');
  engine.update_apk(['--keys-dir',tx.keys,'verify',item.archive,item.index],130000);
  let rows=decode(engine.update_apk(['adbdump','--format','json',item.index])).packages;
  if(type(rows)!='array'||length(rows)!=1||rows[0].name!='foxhole-openwrt-client'||rows[0].version!=item.version||rows[0].hashes!=item.nativeId||rows[0].arch!='noarch')guard.fail('RECOVERY_REQUIRED');push(indices,item.index);
 }
 for(let item in tx.modules){
  if(!sha(item.archiveSha256)||!sha(item.indexSha256)||!sha(item.nativeId)||item.archive!=CACHE+'/job-'+id+'/assets/'+item.name+'-'+item.version+'.apk'||item.index!=CACHE+'/job-'+id+'/assets/index-'+item.indexSha256+'.adb'||type(item.payloadFiles)!='array')guard.fail('RECOVERY_REQUIRED');
  repository_asset(CACHE+'/job-'+id+'/assets',item.name+'-'+item.version+'.apk',CACHE+'/'+item.archiveSha256,item.archiveSha256,item.archiveBytes);
  repository_asset(CACHE+'/job-'+id+'/assets','index-'+item.indexSha256+'.adb',CACHE+'/'+item.indexSha256,item.indexSha256,item.indexBytes);
  regular(item.archive,8388608,item.archiveBytes,true);regular(item.index,8388608,item.indexBytes,true);
  if(registry.hash_file(item.archive)!=item.archiveSha256||registry.hash_file(item.index)!=item.indexSha256)guard.fail('RECOVERY_REQUIRED');
  engine.update_apk(['--keys-dir',tx.keys,'verify',item.archive,item.index],130000);
  let rows=decode(engine.update_apk(['adbdump','--format','json',item.index])).packages;
  let found=type(rows)=='array'?filter(rows,row=>row.name==item.name):[];
  if(length(found)!=1||found[0].version!=item.version||found[0].arch!=item.arch||found[0].hashes!=item.nativeId)guard.fail('RECOVERY_REQUIRED');
  let payload=decode(engine.update_apk(['adbdump','--format','json',item.archive]));
  if(sprintf('%J',owned_payload_files(payload))!=sprintf('%J',item.payloadFiles))guard.fail('RECOVERY_REQUIRED');push(indices,item.index);
 }
 let unique=[];for(let path in indices)if(index(unique,path)<0)push(unique,path);
 if(raw_role(tx.repositories,8192,null,true)!=join('\n',unique)+'\n')guard.fail('RECOVERY_REQUIRED');
 native_args(tx,false,tx.beforeSha256);stage_tool(tx.tool);
};
export function prepare_transaction(id,value,prepared,world,tool) {
 if(!match(id||'',/^update-job-[a-f0-9]{32}$/))guard.fail('PACKAGE_VERIFICATION_FAILED');
 let directory=CACHE+'/job-'+id;store.directory(directory);store.directory(directory+'/keys');store.directory(directory+'/assets');let assets=directory+'/assets';
 let key=cache_asset(KEY,SIGNER_PUBLIC_PEM_SHA256,fs.lstat(KEY).size),key_path=directory+'/keys/foxhole.pem';
 if(!fs.lstat(key_path)&&system(['/bin/sh','-c','set -eu; umask 077; set -C; exec /bin/cat "$1" > "$2"','foxhole-key-cache',key,key_path],3000)!=0)guard.fail('ROLLBACK_UNAVAILABLE');
 regular(key_path,16384,fs.lstat(key).size,true);if(registry.hash_file(key_path)!=SIGNER_PUBLIC_PEM_SHA256)guard.fail('ROLLBACK_UNAVAILABLE');
 let bases=[];for(let item in [value.rollback,value.base]){
  if(!sha(item.nativeId))guard.fail('PACKAGE_VERIFICATION_FAILED');
  let archive=cache_asset(item.archive,item.sha256,item.archiveBytes),idx=cache_asset(item.index,item.indexSha256,fs.lstat(item.index).size);
  push(bases,{...item,archive:repository_asset(assets,item.filename,archive,item.sha256,item.archiveBytes),index:repository_asset(assets,'index-'+item.indexSha256+'.adb',idx,item.indexSha256,fs.lstat(idx).size)});
 }
 let modules=[],indices=[bases[0].index,bases[1].index];
 for(let item in prepared){
  let artifact=item.value;if(!sha(item.nativeId)||artifact.archiveBytes>8388608)guard.fail('UNSUPPORTED_TARGET');
  let archive_cache=cache_asset(item.package,artifact.packageSha256,artifact.archiveBytes),index_cache=cache_asset(item.index,artifact.indexSha256,artifact.indexBytes);
  let archive=repository_asset(assets,artifact.packageName+'-'+artifact.packageVersion+'.apk',archive_cache,artifact.packageSha256,artifact.archiveBytes),index_path=repository_asset(assets,'index-'+artifact.indexSha256+'.adb',index_cache,artifact.indexSha256,artifact.indexBytes);
  push(indices,index_path);push(modules,{name:artifact.packageName,version:artifact.packageVersion,arch:artifact.architecture,
   nativeId:item.nativeId,archive,archiveSha256:artifact.packageSha256,archiveBytes:artifact.archiveBytes,
   index:index_path,indexSha256:artifact.indexSha256,indexBytes:artifact.indexBytes,payloadFiles:owned_payload_files(item.payload)});
 }
 let unique=[];for(let path in indices)if(index(unique,path)<0)push(unique,path);
 let repositories=directory+'/repositories',raw=join('\n',unique)+'\n';
 if(fs.lstat(repositories)){if(store.read(repositories,8192)!=raw)guard.fail('ROLLBACK_UNAVAILABLE');}else store.write(repositories,raw);
 let result={schema:1,abi:1,oldBase:bases[0],newBase:bases[1],oldCas:native_cas(bases[0].nativeId),newCas:native_cas(bases[1].nativeId),
  beforeSha256:world.beforeSha256,afterSha256:world.afterSha256,beforeRaw:world.beforeRaw,afterRaw:world.afterRaw,
  modules,tool,keys:directory+'/keys',repositories,repositoriesSha256:digest.sha256(raw)};
 verify_transaction(id,result);return result;
};
export function assert_identities(before,after,tx,recovered) {
 let base='foxhole-openwrt-client',wanted=recovered?tx.oldBase:tx.newBase,cas=recovered?tx.oldCas:tx.newCas;
 if(after[base]?.version!=wanted.version||after[base]?.arch!='noarch'||after[base]?.cas!=cas)guard.fail('RECOVERY_REQUIRED');
 let additions={};for(let item in tx.modules)additions[item.name]=item;
 for(let name in keys(before))if(name!=base&&sprintf('%J',after[name])!=sprintf('%J',before[name]))guard.fail('RECOVERY_REQUIRED');
 for(let name in keys(after))if(!before[name]){
  let item=additions[name];if(recovered||!item||after[name].version!=item.version||after[name].arch!=item.arch||after[name].cas!=native_cas(item.nativeId))guard.fail('RECOVERY_REQUIRED');
 }
 for(let item in tx.modules){
  if(recovered){if(after[item.name])guard.fail('RECOVERY_REQUIRED');for(let path in item.payloadFiles)if(fs.lstat(path))guard.fail('RECOVERY_REQUIRED');}
  else if(after[item.name]?.version!=item.version||after[item.name]?.arch!=item.arch||after[item.name]?.cas!=native_cas(item.nativeId))guard.fail('RECOVERY_REQUIRED');
 }
};
