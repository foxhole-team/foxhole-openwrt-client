#!/bin/sh
# Prepare an isolated RAM BASE root. This never activates the prepared files.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset LD_PRELOAD LD_LIBRARY_PATH APK_CONFIG

bundle='' manifest_hash='' keys='' base='' stage=''
universe=universe-filogic.json architecture='' release=25.12.5
usage() {
 echo 'Usage: install-ram-stage.sh --bundle DIR --manifest-sha256 HASH --keys-dir DIR --base APK --stage /tmp/foxhole-ram.NAME [--universe FILE] [--architecture ARCH] [--release RELEASE]'
 echo 'Prepare only: signed local repositories, empty isolated APK database, no service or mount changes.'
}
while [ "$#" -gt 0 ]; do
 case "$1" in
  --bundle) bundle=${2:?}; shift 2 ;;
  --manifest-sha256) manifest_hash=${2:?}; shift 2 ;;
  --keys-dir) keys=${2:?}; shift 2 ;;
  --base) base=${2:?}; shift 2 ;;
  --stage) stage=${2:?}; shift 2 ;;
  --universe) universe=${2:?}; shift 2 ;;
  --architecture) architecture=${2:?}; shift 2 ;;
  --release) release=${2:?}; shift 2 ;;
  --help|-h) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
 esac
done
[ "$(id -u)" = 0 ] || { echo 'Root is required' >&2; exit 1; }
[ -n "$bundle" ] && [ -n "$keys" ] && [ -n "$base" ] && [ -n "$stage" ] || { usage >&2; exit 2; }
case "$manifest_hash" in ''|*[!a-f0-9]*) exit 2 ;; esac
[ "${#manifest_hash}" = 64 ] || exit 2
for tool in apk ucode env df flock mkfifo; do command -v "$tool" >/dev/null; done
source_directory=${0%/*}
case "$source_directory" in /*) ;; *) echo 'Use an absolute installer path' >&2; exit 2 ;; esac
native_command=$source_directory/ram-native-command.sh
[ -f "$native_command" ] && [ -f "$source_directory/ram-native-command.uc" ] || exit 1
/bin/sh -n "$native_command"
ucode -c -o /dev/null "$source_directory/ram-native-command.uc"

# Only the new, direct child of the actual RAM filesystem may be created.
ucode -e '
 import * as fs from "fs";
 function fail(){die("Unsafe RAM staging input\n");}
 function chain(path){
  if(!match(path||"",/^\/[A-Za-z0-9_.\/-]+$/)||match(path,/\/(\.|\.\.)(\/|$)/)||path!="/"&&substr(path,length(path)-1)=="/")fail();
  for(let current=path;;current=fs.dirname(current)){
   let s=fs.lstat(current);
   if(s?.type!="directory"||s.uid!=0||((s.mode&0o022)!=0&&!(current=="/tmp"&&(s.mode&0o7777)==0o1777)))fail();
   if(current=="/")break;
  }
 }
 chain(ARGV[0]);chain(ARGV[1]);chain("/tmp");
 if(!match(ARGV[2]||"",/^\/tmp\/foxhole-ram[.-][A-Za-z0-9_.-]{6,80}$/)||fs.lstat(ARGV[2]))fail();
 let mounts=fs.readfile("/proc/mounts",131073),ram=false;
 if(mounts==null||length(mounts)>131072)fail();
 for(let line in split(mounts,"\n")){let fields=split(line," ");if(fields[1]=="/tmp"&&fields[2]=="tmpfs")ram=true;}
 if(!ram||!fs.mkdir(ARGV[2],0o700))fail();
' -- "$bundle" "$keys" "$stage"

finish() {
 code=$?
 trap - EXIT INT TERM HUP
 if [ "$code" -ne 0 ]; then
  printf '{"schema":1,"state":"failed","active":false,"hostApkUpdated":false,"exitCode":%s}\n' "$code" > "$stage/failure.json"
  echo 'RAM preparation failed; retained stage is inactive' >&2
 fi
 exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

cat > "$stage/validate.uc" <<'UCODE'
'use strict';
import * as fs from 'fs';
import * as digest from 'digest';

const RESERVE=16777216, NATIVE_OVERHEAD=8388608, METADATA=4194304;
function fail(){die('RAM preparation validation failed\n');}
function integer(v){return type(v)=='int'&&v>=0&&v<=9007199254740991;}
function hash(v){return type(v)=='string'&&match(v,/^[a-f0-9]{64}$/)!=null;}
function filename(v){return type(v)=='string'&&match(v,/^[A-Za-z0-9][A-Za-z0-9_.+-]{0,254}$/)!=null;}
function package_name(v){return type(v)=='string'&&match(v,/^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$/)!=null;}
function version(v){return type(v)=='string'&&match(v,/^[A-Za-z0-9][A-Za-z0-9_.~+:-]{0,159}$/)!=null;}
function facts(s){return sprintf('%J',[s?.type,s?.uid,s?.gid,s?.mode,s?.dev,s?.inode,s?.nlink,s?.size,s?.mtime,s?.ctime]);}
function parents(path){
 for(let p=path;;p=fs.dirname(p)){
  let s=fs.lstat(p);
  if(s?.type!='directory'||s.uid!=0||((s.mode&0o022)!=0&&!(p=='/tmp'&&(s.mode&0o7777)==0o1777)))fail();
  if(p=='/')break;
 }
}
function memory(){
 let raw=fs.readfile('/proc/meminfo',65537),m=match(raw||'',/\n?MemAvailable:[ \t]+([0-9]+) kB/);
 if(raw==null||length(raw)>65536||!m)fail();return +m[1]*1024;
}
function admit(required){if(!integer(required)||memory()<required)die('Insufficient available RAM for preparation and reserve\n');}
function raw(path,maximum,allow_empty){
 parents(fs.dirname(path));let a=fs.lstat(path);
 if(a?.type!='file'||a.uid!=0||a.nlink!=1||(a.mode&0o022)||a.size<(allow_empty?0:1)||a.size>maximum)fail();
 admit(RESERVE+2*a.size);
 let value=fs.readfile(path,maximum+1),b=fs.lstat(path);
 if(value==null||length(value)!=a.size||facts(a)!=facts(b))fail();return value;
}
function decode(path,maximum){try{return json(raw(path,maximum,false));}catch(_){fail();}}
function write(path,value){
 parents(fs.dirname(path));if(fs.lstat(path))fail();
 let f=fs.open(path,'wxe',0o600);if(!f)fail();
 if(f.write(value)!=length(value)||!f.flush())fail();f.close();
}
function directory(path){parents(fs.dirname(path));if(fs.lstat(path)||!fs.mkdir(path,0o700))fail();}
function snapshot(){
 let result={};
 for(let item in [
  ['/etc/apk/world',65536],['/etc/apk/arch',128],['/lib/apk/db/installed',4194304],
  ['/lib/apk/db/triggers',1048576],['/lib/apk/db/scripts.tar',8388608],['/lib/apk/db/scripts.tar.gz',8388608]
 ]){
  let path=item[0],s=fs.lstat(path);
  if(!s){result[path]=null;continue;}
  let value=raw(path,item[1],true);result[path]={facts:facts(s),sha256:digest.sha256(value)};
 }
 if(!result['/etc/apk/world']||!result['/lib/apk/db/installed'])fail();return result;
}
function read_plan(stage){return decode(stage+'/plan.json',524288);}
function copy_verified(source,destination,size,wanted){
 if(!integer(size)||size<1||!hash(wanted))fail();
 let value=raw(source,size,false);
 if(length(value)!=size||digest.sha256(value)!=wanted)fail();write(destination,value);
 if(digest.sha256(raw(destination,size,false))!=wanted)fail();
}
function bounded_logs(stage,prefix){
 for(let ending in ['.stdout','.stderr']){
  let maximum=prefix=='index-dump'&&ending=='.stdout'?16777216:1048576;
  let value=raw(stage+'/'+prefix+ending,maximum,true);
  if(match(value,/(^|\n)ERROR:/))fail();
 }
}
let action=ARGV[0],stage=ARGV[1];
parents(stage);
if(!match(stage||'',/^\/tmp\/foxhole-ram[.-][A-Za-z0-9_.-]{6,80}$/)||(fs.lstat(stage).mode&0o7777)!=0o700)fail();
if(action=='plan'){
 let bundle=ARGV[2],keys_path=ARGV[3],wanted_manifest=ARGV[4],universe_file=ARGV[5],base_file=ARGV[6],arch=ARGV[7],release=ARGV[8];
 parents(bundle);parents(keys_path);
 if(!hash(wanted_manifest)||!filename(universe_file)||!filename(base_file))fail();
 let sums_raw=raw(bundle+'/SHA256SUMS',1048576,false),sums={};
 if(digest.sha256(sums_raw)!=wanted_manifest)fail();
 for(let line in split(sums_raw,'\n')){
  if(line=='')continue;
  let m=match(line,/^([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9_.+-]{0,254})$/);
  if(!m||sums[m[2]]||length(keys(sums))>=1024)fail();sums[m[2]]=m[1];
 }
 let universe_raw=raw(bundle+'/'+universe_file,2097152,false);
 if(!sums[universe_file]||digest.sha256(universe_raw)!=sums[universe_file])fail();
 let u=json(universe_raw);arch=arch||u.architecture;
 if(u.schema!=2||u.kind!='compact-package-universe-v1'||index(['aarch64_cortex-a53','x86_64'],arch)<0||u.architecture!=arch||
  release!='25.12.5'||index(u.supportedOpenWrt||[],release)<0||u.verification?.signatures!=true||
  u.verification?.signatureModel!='canonical-apk-and-upstream-index-v1'||type(u.packages)!='array'||length(u.packages)>512||
  type(u.requires)!='object'||type(u.packageAuthentications)!='array'||type(u.repositoryIndexes)!='array'||type(u.trustKeys)!='array')fail();
 let by_name={},bindings={},indexes={},trust={};
 for(let row in u.packages){if(!package_name(row.name)||by_name[row.name])fail();by_name[row.name]=row;}
 for(let row in u.packageAuthentications){if(!package_name(row.name)||bindings[row.name])fail();bindings[row.name]=row;}
 for(let row in u.repositoryIndexes){if(!filename(row.file)||indexes[row.file])fail();indexes[row.file]=row;}
 for(let row in u.trustKeys){if(!filename(row.file)||trust[row.file])fail();trust[row.file]=row;}
 let pending=['foxhole-openwrt-client'],seen={},packages=[],used_indexes={},used_keys={};
 let archive_bytes=0,installed_bytes=0,largest=0;
 for(let at=0;at<length(pending);at++){
  if(at>=128)fail();let name=pending[at];if(seen[name])continue;seen[name]=true;
  if(name!='foxhole-openwrt-client'&&(match(name,/^foxcore-/)||match(name,/^hysteria($|-)/)))fail();
  let row=by_name[name],binding=bindings[name];
  if(!row||!binding||!filename(row.file)||!match(row.file,/\.apk$/)||!version(row.version)||
   index(['noarch',arch],row.arch)<0||!hash(row.sha256)||sums[row.file]!=row.sha256||u.filesSha256?.[row.file]!=row.sha256||
   !integer(row.archiveBytes)||row.archiveBytes<1||row.archiveBytes>8388608||
   !integer(row.installedBytes)||row.installedBytes>33554432||binding.file!=row.file||binding.version!=row.version||
   binding.architecture!=row.arch||!hash(binding.packageIdentity)||!indexes[binding.indexFile])fail();
  if(name=='foxhole-openwrt-client'&&(row.file!=base_file||row.arch!='noarch'||!match(row.version,/^[0-9]+\.[0-9]+\.[0-9]+-r[1-9][0-9]{0,5}$/)))fail();
  let destination=name+'-'+row.version+'.apk';
  if(length(destination)>255||match(destination,/[^A-Za-z0-9_.~+:-]/))fail();
  push(packages,{...row,indexFile:binding.indexFile,packageIdentity:binding.packageIdentity,destination});used_indexes[binding.indexFile]=true;
  archive_bytes+=row.archiveBytes;installed_bytes+=row.installedBytes;largest=max(largest,row.archiveBytes);
  let dependencies=u.requires[name];if(type(dependencies)!='array'||length(dependencies)>128)fail();
  let unique={};for(let dep in dependencies){
   if(!package_name(dep)||unique[dep]||!by_name[dep])fail();unique[dep]=true;
   if(index(pending,dep)<0)push(pending,dep);
  }
 }
 let selected_indexes=[],selected_keys=[],index_bytes=0,key_bytes=0;
 for(let file in sort(keys(used_indexes))){
  let row=indexes[file];
  if(!hash(row.sha256)||sums[file]!=row.sha256||!integer(row.bytes)||row.bytes<1||row.bytes>2097152||
   index(['foxhole','upstream'],row.role)<0||type(row.trustKeyFiles)!='array'||!length(row.trustKeyFiles)||length(row.trustKeyFiles)>8)fail();
  for(let key in row.trustKeyFiles){if(!trust[key])fail();used_keys[key]=true;}
  push(selected_indexes,row);index_bytes+=row.bytes;
 }
 for(let file in sort(keys(used_keys))){
  let row=trust[file];
  if(!hash(row.sha256)||sums[file]!=row.sha256||!integer(row.bytes)||row.bytes<1||row.bytes>16384)fail();
  push(selected_keys,row);key_bytes+=row.bytes;
 }
 if(length(selected_keys)>8||archive_bytes>67108864||installed_bytes>134217728||index_bytes>8388608||key_bytes>131072)fail();
 let required=archive_bytes+index_bytes+key_bytes+installed_bytes+2*largest+NATIVE_OVERHEAD+METADATA+RESERVE;
 let available=memory();admit(required);
 let plan={schema:1,kind:'ram-base-preparation-plan-v1',architecture:arch,release,
  manifestSha256:wanted_manifest,universeFile:universe_file,universeSha256:sums[universe_file],
  baseConstraint:'foxhole-openwrt-client='+by_name['foxhole-openwrt-client'].version,
  packages,repositoryIndexes:selected_indexes,trustKeys:selected_keys,
  archiveBytes:archive_bytes,indexBytes:index_bytes,trustKeyBytes:key_bytes,installedBytes:installed_bytes,
  largestArchiveBytes:largest,nativeOverheadBytes:NATIVE_OVERHEAD,metadataAllowanceBytes:METADATA,
  reserveBytes:RESERVE,requiredAvailableBytes:required,availableBeforeBytes:available,
  memoryEvidence:'Conservative preparation bound; not runtime or activation qualification'};
 write(stage+'/host-before.json',sprintf('%J',snapshot()));
 write(stage+'/plan.json',sprintf('%J',plan));
 write(stage+'/SHA256SUMS',sums_raw);write(stage+'/'+universe_file,universe_raw);
 directory(stage+'/root');directory(stage+'/keys');directory(stage+'/repositories');
 for(let row in selected_keys){
  copy_verified(keys_path+'/'+row.file,stage+'/keys/'+row.file,row.bytes,row.sha256);
  let pem=raw(stage+'/keys/'+row.file,16384,false);
  if(match(pem,/PRIVATE KEY/)||!match(pem,/-----BEGIN (RSA )?PUBLIC KEY-----/))fail();
 }
 let repositories='';
 for(let row in selected_indexes){
  let directory_path=stage+'/repositories/'+row.file;directory(directory_path);directory(directory_path+'/keys');
  copy_verified(bundle+'/'+row.file,directory_path+'/packages.adb',row.bytes,row.sha256);
  for(let name in row.trustKeyFiles){let key=trust[name];copy_verified(keys_path+'/'+name,directory_path+'/keys/'+name,key.bytes,key.sha256);}
  repositories+=directory_path+'/packages.adb\n';
 }
 for(let row in packages)copy_verified(bundle+'/'+row.file,stage+'/repositories/'+row.indexFile+'/'+row.destination,row.archiveBytes,row.sha256);
 write(stage+'/repositories.list',repositories);
 let constraints=plan.baseConstraint+'\n';
 for(let row in packages)constraints+=row.name+'><X1'+substr(row.packageIdentity,0,40)+'\n';
 write(stage+'/constraints.list',constraints);
}else if(action=='list'){
 let p=read_plan(stage);
 if(ARGV[2]=='architecture')print(p.architecture);
 else if(ARGV[2]=='signatures'){
  for(let row in p.repositoryIndexes)printf('%s %s\n',stage+'/repositories/'+row.file+'/keys',stage+'/repositories/'+row.file+'/packages.adb');
  for(let row in p.packages)for(let index in p.repositoryIndexes)if(index.file==row.indexFile&&index.role=='foxhole')
   printf('%s %s\n',stage+'/repositories/'+row.indexFile+'/keys',stage+'/repositories/'+row.indexFile+'/'+row.destination);
 }else if(ARGV[2]=='indexes'){
  for(let row in p.repositoryIndexes)printf('%s %s\n',row.file,stage+'/repositories/'+row.file+'/packages.adb');
 }else fail();
}else if(action=='logs')bounded_logs(stage,ARGV[2]);
else if(action=='index'){
 let p=read_plan(stage),file=ARGV[2],info=fs.lstat(stage+'/index-dump.stdout');
 if(info?.type!='file'||info.size<1||info.size>16777216)fail();admit(RESERVE+4*info.size);
 let dump=decode(stage+'/index-dump.stdout',16777216),found=false;
 for(let row in p.repositoryIndexes)if(row.file==file)found=true;
 if(!found||type(dump.packages)!='array'||!length(dump.packages)||length(dump.packages)>50000||
  dump['pkgname-spec']!=null&&dump['pkgname-spec']!='${name}-${version}.apk')fail();
 for(let expected in p.packages){
  if(expected.indexFile!=file)continue;let selected=null;
  for(let row in dump.packages)if(row.name==expected.name&&row.version==expected.version&&row.arch==expected.arch){
   if(selected)fail();selected=row;
  }
  if(!selected||selected.hashes!=expected.packageIdentity||selected['file-size']!=expected.archiveBytes||selected['installed-size']!=expected.installedBytes)fail();
 }
}
else if(action=='capacity'){
 let p=read_plan(stage),required=p.installedBytes+NATIVE_OVERHEAD+METADATA+RESERVE;admit(required);
 let text=raw(stage+'/capacity.stdout',65536,false),lines=split(trim(text),'\n'),fields=split(trim(lines[length(lines)-1]),/[ \t]+/);
 if(length(fields)<6||!match(fields[3],/^[0-9]+$/)||+fields[3]*1024<p.installedBytes+METADATA+RESERVE)fail();
}else if(action=='selected'||action=='installed'){
 let p=read_plan(stage),rows=decode(stage+'/'+ARGV[2],1048576),seen={};
 if(type(rows)!='array'||length(rows)!=length(p.packages))fail();
 let wanted={};for(let row in p.packages)wanted[row.name]=row;
 for(let row in rows){let expected=wanted[row.name];
  if(!expected||seen[row.name]||row.version!=expected.version||row.arch!=expected.arch||
   row['installed-size']!=expected.installedBytes||action=='installed'&&sprintf('%J',row.status)!=sprintf('%J',['installed']))fail();seen[row.name]=true;
 }
}else if(action=='finish'){
 let p=read_plan(stage),before=decode(stage+'/host-before.json',65536),after=snapshot();
 if(sprintf('%J',before)!=sprintf('%J',after))die('Host APK state changed during preparation\n');
 admit(RESERVE);write(stage+'/host-after.json',sprintf('%J',after));
 let receipt={schema:1,kind:'foxhole-ram-base-stage-v1',state:'prepared',active:false,storage:'RAM',
  hostApkUpdated:false,hostConfigurationChanged:false,servicesChanged:false,mountsChanged:false,
  architecture:p.architecture,release:p.release,baseConstraint:p.baseConstraint,
  manifestSha256:p.manifestSha256,universeSha256:p.universeSha256,planSha256:digest.sha256(raw(stage+'/plan.json',524288,false)),
  packageCount:length(p.packages),archiveBytes:p.archiveBytes,installedBytes:p.installedBytes,
  availableBeforeBytes:p.availableBeforeBytes,availableAfterBytes:memory(),reserveBytes:RESERVE,
  simulationPassed:true,isolatedInstallationPassed:true,activationQualified:false,runtimeQualified:false,
  isolatedRootHasOnlyStagedDependencies:true,hostDependenciesReplaced:false,
  limitation:'Prepared files and an isolated APK database only; no mounts, boot setup, credentials or active/global version claim'};
 write(stage+'/receipt.json',sprintf('%J',receipt));
}else fail();
UCODE

ucode -c -o /dev/null "$stage/validate.uc"
ucode "$stage/validate.uc" plan "$stage" "$bundle" "$keys" "$manifest_hash" "$universe" "$base" "$architecture" "$release"
architecture=$(ucode "$stage/validate.uc" list "$stage" architecture)

# Logs have fixed roles and are checked after each bounded native command.
# No file-size ulimit is inherited by native APK extraction.
run_apk() {
 log=$1; shift
 result=0
 env -i PATH="$PATH" LC_ALL=C /bin/sh "$native_command" "$stage" "$log" 180000 /usr/bin/apk "$@" || result=$?
 if [ ! -e "$stage/$log.stdout" ] || [ ! -e "$stage/$log.stderr" ]; then
  echo 'Native helper did not produce both capture logs; retained failure requires review' >&2
  [ "$result" -ne 0 ] || result=1
  return "$result"
 fi
 ucode "$stage/validate.uc" logs "$stage" "$log"
 [ "$result" -eq 0 ] || { echo 'Native APK operation failed; no activation performed' >&2; return "$result"; }
}
ucode "$stage/validate.uc" list "$stage" signatures > "$stage/signatures.list"
while read -r key_directory file; do
 run_apk signature --no-network --no-cache --keys-dir "$key_directory" verify "$file"
done < "$stage/signatures.list"
ucode "$stage/validate.uc" list "$stage" indexes > "$stage/indexes.list"
while read -r index_name index_path; do
 run_apk index-dump --no-network --no-cache adbdump --format json "$index_path"
 ucode "$stage/validate.uc" index "$stage" "$index_name"
 rm "$stage/index-dump.stdout" "$stage/index-dump.stderr"
done < "$stage/indexes.list"

# The database is new and empty; host metadata is never copied or mounted.
offline() {
 log=$1; shift
 case "${1-}" in
  add) scripts_flags='yes' ;;
  query) scripts_flags='' ;;
  *) return 1 ;;
 esac
 if [ "$scripts_flags" = yes ]; then
  run_apk "$log" --root "$stage/root" --arch "$architecture" --no-network --no-cache \
   --scripts=no --commit-hooks=no --logfile=no --keys-dir "$stage/keys" \
   --repositories-file "$stage/repositories.list" "$@"
  return
 fi
 run_apk "$log" --root "$stage/root" --arch "$architecture" --no-network --no-cache \
  --logfile=no --keys-dir "$stage/keys" \
  --repositories-file "$stage/repositories.list" "$@"
}
offline init add --initdb
set --
while IFS= read -r constraint; do
 [ -n "$constraint" ] || exit 1
 set -- "$@" "$constraint"
done < "$stage/constraints.list"
[ "$#" -gt 1 ] || exit 1
offline selected query --from repositories --recursive --fields name,version,arch,installed-size --format json "$@"
ucode "$stage/validate.uc" selected "$stage" selected.stdout
offline simulate add --simulate "$@"
df -Pk "$stage" > "$stage/capacity.stdout"
ucode "$stage/validate.uc" capacity "$stage"
offline apply add "$@"
offline installed query --from installed --installed --all-matches --fields name,version,arch,installed-size,status --format json '*'
ucode "$stage/validate.uc" installed "$stage" installed.stdout
ucode "$stage/validate.uc" finish "$stage"
echo 'RAM BASE stage prepared; inactive, host APK database unchanged'
