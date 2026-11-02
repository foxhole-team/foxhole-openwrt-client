'use strict';

function fail() { die('RAM_SWITCH_VALIDATION_FAILED'); };
function exact(value, fields) {
 if(type(value)!='object'||length(keys(value))!=length(fields))fail();
 for(let key in keys(value))if(index(fields,key)<0)fail();
};
export function sha(value) {return type(value)=='string'&&match(value,/^[a-f0-9]{64}$/)!=null;};
export function job_id(value) {return type(value)=='string'&&match(value,/^update-job-[a-f0-9]{32}$/)!=null;};
export function candidate(value) {return type(value)=='string'&&match(value,/^candidate-[a-f0-9]{32}$/)!=null;};
export function stage(value) {
 return type(value)=='string'&&(match(value,/^\/tmp\/foxhole-ram-stage-[A-Za-z0-9_.-]{6,64}$/)!=null||
  match(value,/^\/tmp\/foxhole\/ram-updates\/candidates\/candidate-[a-f0-9]{32}$/)!=null);
};
export function ledger_path(value) {
 return type(value)=='string'&&match(value,/^\/etc\/foxhole\/ram-update\/generations\/generation-[a-f0-9]{32}\.json$/)!=null;
};
export function public_path(path) {
 if(type(path)!='string')return false;
 if(index(['/usr/share/foxhole','/usr/share/licenses/foxhole-openwrt-client','/www/luci-static/resources/foxhole',
  '/www/luci-static/resources/view/foxhole','/www/foxhole-mobile','/usr/share/rpcd/ucode/foxhole.uc',
  '/usr/share/rpcd/acl.d/luci-app-foxhole.json','/usr/share/luci/menu.d/luci-app-foxhole.json',
  '/www/cgi-bin/foxhole','/www/foxhole.html','/lib/upgrade/keep.d/foxhole-openwrt-client'],path)>=0)return true;
 return match(path,/^\/(usr\/libexec|etc\/init.d)\/foxhole-[A-Za-z0-9_.-]+$/)!=null||
  match(path,/^\/usr\/share\/nftables.d\/chain-pre\/(input|forward)\/3[01]-foxhole(-mobile|-inbound)?\.nft$/)!=null;
};
export function retained_target(path) {
 return index(['/usr/bin/openssl','/usr/lib/ucode/socket.so','/etc/init.d/foxhole-mobile',
  '/lib/upgrade/keep.d/foxhole-openwrt-client'],path)>=0;
};
export function ledger(value, marker) {
 exact(value,['schema','abi','kind','stage','baseSha256','mounts']);
 if(value.schema!=1||value.abi!=1||value.kind!='foxhole-ram-mount-ledger-v1'||!stage(value.stage)||
  value.stage!=marker.stage||!sha(value.baseSha256)||value.baseSha256!=marker.baseSha256||
  type(value.mounts)!='array'||length(value.mounts)<1||length(value.mounts)>96)fail();
 let seen={};
 for(let row in value.mounts) {
  exact(row,['target','source','type','dev','inode','sha256','role']);
  if(seen[row.target]||index(['file','directory'],row.type)<0||type(row.dev?.major)!='int'||row.dev.major<0||
   type(row.dev?.minor)!='int'||row.dev.minor<0||length(keys(row.dev))!=2||
   type(row.inode)!='int'||row.inode<1||type(row.source)!='string'||length(row.source)>240||
   !match(row.source,/^\/tmp\/[A-Za-z0-9_./-]+$/)||match(row.source,/\/(\.|\.\.)(\/|$)/))fail();
  if(row.type=='file'?!sha(row.sha256):row.sha256!=null)fail();
  if(row.role=='base') {
   if(!public_path(row.target)||row.source!=value.stage+'/root'+row.target)fail();
  } else if(row.role!='retained-adapter'||!retained_target(row.target)||row.type!='file')fail();
  seen[row.target]=true;
 }
 // Nested public binds would hide a generation or create a mount stack.
 for(let a in value.mounts)for(let b in value.mounts)
  if(a.target!=b.target&&index(b.target,a.target+'/')==0)fail();
 return value;
};
export function mounts(text) {
 if(type(text)!='string'||length(text)>1048576)fail();let rows=[];
 for(let line in split(text,'\n')) {
  if(!length(line))continue;let pair=split(line,' - '),left=split(pair[0],' '),right=split(pair[1]||'',' ');
  if(length(pair)!=2||length(left)<6||length(right)<3||!match(left[0],/^[0-9]+$/)||
   !match(left[1],/^[0-9]+$/)||!match(left[4],/^\/[A-Za-z0-9_./-]*$/))fail();
  push(rows,{id:+left[0],parent:+left[1],device:left[2],root:left[3],target:left[4],options:left[5],
   filesystem:right[0],source:right[1],superOptions:join(' ',slice(right,2))});
  if(length(rows)>2048)fail();
 }
 return rows;
};
export function one_mount(rows,target) {
 let found=filter(rows,row=>row.target==target);if(length(found)!=1)fail();return found[0];
};
export function retained_packages(rows,version) {
 if(type(rows)!='array'||length(rows)<1||length(rows)>256)fail();let result={},base=0;
 for(let row in rows) {
  if(type(row.name)!='string'||!match(row.name,/^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$/)||result[row.name]!=null||
   type(row.version)!='string'||type(row.arch)!='string'||sprintf('%J',row.status)!=sprintf('%J',['installed']))fail();
  if(row.name=='foxhole-openwrt-client') {if(row.version!=version||row.arch!='noarch')fail();base++;}
  result[row.name]=row;
 }
 if(base!=1)fail();delete result['foxhole-openwrt-client'];return result;
};
export function package_fence(before,after,old_version,new_version) {
 let old=retained_packages(before,old_version),fresh=retained_packages(after,new_version);
 if(sprintf('%J',sort(keys(old)))!=sprintf('%J',sort(keys(fresh))))fail();
 for(let name in keys(old))if(sprintf('%J',old[name])!=sprintf('%J',fresh[name]))fail();
 return length(keys(old));
};
export function world_fence(before,after) {
 function retained(text) {
  if(type(text)!='string'||length(text)>65536)fail();let rows=[],base=0;
  for(let row in split(trim(text),'\n')) {
   if(match(row,/^foxhole-openwrt-client([<>=~].*)?$/))base++;
   else if(length(row))push(rows,row);
  }
  if(base!=1)fail();return sort(rows);
 };
 if(sprintf('%J',retained(before))!=sprintf('%J',retained(after)))fail();return true;
};
export function rollback_actions(unmounted,mounted) {
 // Only successful syscalls enter these ledgers; absent targets are never invented.
 let remove=[],restore=[];
 for(let i=length(mounted)-1;i>=0;i--)push(remove,mounted[i]);
 for(let i=length(unmounted)-1;i>=0;i--)push(restore,unmounted[i]);
 return {remove,restore};
};
