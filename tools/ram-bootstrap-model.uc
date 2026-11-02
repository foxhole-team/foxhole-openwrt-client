'use strict';

export const stage='/tmp/foxhole-ram-stage-boot-v1';
export const trust='/etc/foxhole/ram-update/bootstrap';
export const prefix='usr/share/foxhole-ram-bootstrap-bank';
export const maximum_archive=33554432;
export const maximum_metadata=4194304;
function fail() {die('RAM_BOOTSTRAP_VALIDATION_FAILED');};
function exact(value,fields) {
 if(type(value)!='object'||length(keys(value))!=length(fields))fail();
 for(let name in keys(value))if(index(fields,name)<0)fail();
};
export function sha(value) {return type(value)=='string'&&match(value,/^[a-f0-9]{64}$/)!=null;};
export function integer(value) {return type(value)=='int'&&value>=0&&value<=9007199254740991;};
export function version(value) {return type(value)=='string'&&match(value,/^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}-r[1-9][0-9]{0,5}$/)!=null;};
export function compare(a,b) {
 if(!version(a)||!version(b))fail();let left=split(replace(a,'-r','.'),'.'),right=split(replace(b,'-r','.'),'.');
 for(let n=0;n<4;n++) {if(+left[n]>+right[n])return 1;if(+left[n]<+right[n])return -1;}return 0;
};
export function relative(value) {
 return type(value)=='string'&&length(value)>0&&length(value)<=240&&match(value,/^[A-Za-z0-9_+.,@=:\/-]+$/)!=null&&
  substr(value,0,1)!='/'&&substr(value,length(value)-1)!='/'&&!match(value,/(^|\/)\.\.?($|\/)/);
};
export function url(value) {
 if(type(value)!='string'||length(value)>1024||match(value,/[[:cntrl:]]/))return false;
 let found=match(value,/^https:\/\/([A-Za-z0-9][A-Za-z0-9.-]*)(:([1-9][0-9]{0,4}))?(\/[A-Za-z0-9._~%+\/-]+)$/);
 if(!found||found[3]&&+found[3]>65535||match(found[4],/\/(\.|\.\.)(\/|$)/)||match(found[4],/%(00|0[aAdD]|2[eEfF]|3[fF]|23|40|5[cC])/))return false;
 return true;
};
function platform(arch,target,release) {
 if(release!='25.12.5'||!(arch=='aarch64_cortex-a53'&&target=='mediatek/filogic'||arch=='x86_64'&&target=='x86/64'))fail();
};
export function descriptor(value) {
 let fields=['schema','kind','artifact','version','baseVersion','arch','target','osRelease','baseSha256','signerPemSha256','caFileSha256','recoveryOrigin'];
 if(type(value)=='object'&&index(keys(value),'overlay')>=0)push(fields,'overlay');exact(value,fields);
 exact(value.artifact,['url','bytes','sha256']);
 if(value.schema!=1||value.kind!='foxhole-ram-bootstrap-v1'||!version(value.version)||!version(value.baseVersion)||
  !sha(value.baseSha256)||!sha(value.signerPemSha256)||value.caFileSha256!=null&&!sha(value.caFileSha256)||
  !url(value.artifact.url)||!integer(value.artifact.bytes)||value.artifact.bytes<1||value.artifact.bytes>maximum_archive||!sha(value.artifact.sha256))fail();
 if(!url(value.recoveryOrigin)||substr(value.recoveryOrigin,length(value.recoveryOrigin)-1)!='/')fail();
 if(value.overlay!=null) {
  let overlay=value.overlay;exact(overlay,['baseVersion','baseSha256','artifact']);exact(overlay.artifact,['url','bytes','sha256']);
  if(!version(overlay.baseVersion)||compare(overlay.baseVersion,value.baseVersion)<=0||!sha(overlay.baseSha256)||
   overlay.artifact.sha256!=overlay.baseSha256||!integer(overlay.artifact.bytes)||overlay.artifact.bytes<1||overlay.artifact.bytes>8388608||
   !url(overlay.artifact.url)||overlay.artifact.url!=value.recoveryOrigin+'foxhole-openwrt-client-'+overlay.baseVersion+'.apk')fail();
 }
 platform(value.arch,value.target,value.osRelease);return value;
};
export function public_target(path) {
 if(path=='/etc/init.d/foxhole-ram-bootstrap')return false;
 if(index(['/usr/share/foxhole','/usr/share/licenses/foxhole-openwrt-client','/www/luci-static/resources/foxhole',
  '/www/luci-static/resources/view/foxhole','/www/foxhole-mobile','/usr/share/rpcd/ucode/foxhole.uc',
  '/usr/share/rpcd/acl.d/luci-app-foxhole.json','/usr/share/luci/menu.d/luci-app-foxhole.json','/www/cgi-bin/foxhole',
  '/www/foxhole.html','/lib/upgrade/keep.d/foxhole-openwrt-client'],path)>=0)return true;
 return type(path)=='string'&&(match(path,/^\/(usr\/libexec|etc\/init.d)\/foxhole-[A-Za-z0-9_.-]+$/)!=null||
  match(path,/^\/usr\/share\/nftables.d\/chain-pre\/(input|forward)\/3[01]-foxhole(-mobile|-inbound)?\.nft$/)!=null);
};
export function link(path,target) {
 if(type(target)!='string'||!length(target)||length(target)>240||!match(target,/^[A-Za-z0-9_+.,@=:\/-]+$/)||substr(target,0,1)=='/')fail();
 let parts=split(path,'/');pop(parts);
 for(let piece in split(target,'/')) {
  if(piece=='.')continue;
  if(piece=='..') {if(length(parts)<=1)fail();pop(parts);}else if(!length(piece))fail();else push(parts,piece);
 }
 if(parts[0]!=split(path,'/')[0])fail();return join('/',parts);
};
export function files(value) {
 if(type(value)!='array'||length(value)<3||length(value)>8192)fail();let result={},total=0;
 for(let row in value) {
  exact(row,['path','type','mode','bytes','sha256','linkTarget']);
  if(!relative(row.path)||!match(row.path,/^(root|adapters)(\/|$)/)||result[row.path]!=null||
   match(row.path,/^root\/etc\/foxhole(\/|$)/)||match(row.path,/^root\/\.foxhole-apk-cache(\/|$)/)||
   match(row.path,/(^|\/)(\.local-secrets|AGENTS\.md|userdata|id_rsa|id_ed25519|authorized_keys|shadow|ssh_host_[A-Za-z0-9_-]*key)(\/|$)/)||
   type(row.mode)!='int'||row.mode<0||row.mode>0o777||!integer(row.bytes)||row.bytes>33554432)fail();
  if(row.type=='directory') {if((row.mode&0o022)||row.sha256!=null||row.linkTarget!=null||row.bytes!=0)fail();}
  else if(row.type=='file') {if((row.mode&0o022)||!sha(row.sha256)||row.linkTarget!=null)fail();total+=row.bytes;}
  else if(row.type=='symlink') {if(row.mode!=0o777||row.sha256!=null||type(row.linkTarget)!='string'||row.bytes!=length(row.linkTarget))fail();link(row.path,row.linkTarget);}
  else fail();result[row.path]=row;
 }
 if(total>134217728||result.root?.type!='directory'||result.adapters?.type!='directory')fail();
 for(let path in keys(result)) {
  let parent=join('/',slice(split(path,'/'),0,-1));
  if(length(parent)&&result[parent]?.type!='directory')fail();
  if(result[path].type=='symlink'&&!result[link(path,result[path].linkTarget)])fail();
 }
 return result;
};
export function bank(value,expected) {
 exact(value,['schema','kind','osRelease','target','arch','version','baseVersion','baseSha256','stageDbSha256','hostNativePackageCount','mounts','files']);
 if(value.schema!=1||value.kind!='foxhole-ram-bootstrap-bank-v1'||!sha(value.stageDbSha256)||value.hostNativePackageCount!=75)fail();
 for(let key in ['osRelease','target','arch','version','baseVersion','baseSha256'])if(value[key]!=expected[key])fail();
 let inventory=files(value.files),seen={};
 if(type(value.mounts)!='array'||length(value.mounts)<1||length(value.mounts)>96)fail();
 for(let row in value.mounts) {
  exact(row,['target','sourceRelative','role']);let info=inventory[row.sourceRelative];
  if(type(row.target)!='string'||seen[row.target]||!info||index(['file','directory'],info.type)<0)fail();
  if(row.role=='base') {if(!public_target(row.target)||row.sourceRelative!='root'+row.target)fail();}
  else if(row.role=='dependency') {if(row.target!='/usr/lib/ucode/socket.so'||row.sourceRelative!='root'+row.target||info.type!='file')fail();}
  else if(row.role!='adapter'||row.target!='/usr/bin/openssl'||row.sourceRelative!='adapters/openssl'||info.type!='file')fail();
  if(info.type=='directory'?info.mode!=0o755:index([0o644,0o755],info.mode)<0)fail();seen[row.target]=true;
 }
 for(let a in value.mounts)for(let b in value.mounts)
  if(a.target!=b.target&&index(b.target,a.target+'/')==0)fail();
 for(let target in ['/usr/share/foxhole','/usr/share/rpcd/ucode/foxhole.uc','/etc/init.d/foxhole-runtime','/etc/init.d/foxhole-mobile',
  '/usr/bin/openssl','/usr/lib/ucode/socket.so'])
  if(!seen[target])fail();
 if(inventory['root/lib/apk/db/installed']?.type!='file'||inventory['root/etc/apk/world']?.type!='file')fail();
 return inventory;
};
function acl(value) {
 if(type(value?.mode)!='int'||value.mode<0||value.mode>0o777||index(['root','0'],value.user)<0||
  index(['root','0'],value.group)<0||length(value.xattrs||[]))fail();return value.mode;
};
export function native_document(document,expected) {
 if(document?.info?.name!='foxhole-ram-bootstrap-bank'||document.info.arch!=expected.arch||document.info.version!=expected.version||
  !integer(document.info['installed-size'])||document.info['installed-size']<1||document.info['installed-size']>134217728||
  length(document.triggers||[])||length(keys(document.scripts||{}))||type(document.paths)!='array'||length(document.paths)>2048)fail();
 for(let key in ['depends','provides','replaces','install-if','recommends'])if(length(document.info[key]||[]))fail();
 let result={},count=0;
 for(let folder in document.paths) {
  let name=folder.name||'',mode=acl(folder.acl);
  if(mode&0o022)fail();
  if(name!=''&&name!='usr'&&name!='usr/share'&&name!=prefix&&index(name,prefix+'/')!=0)fail();
  if(name&&(!relative(name)||result[name]))fail();
  result[name]={path:name,type:'directory',mode,bytes:0,sha256:null,linkTarget:null};
  for(let file in folder.files||[]) {
   if(!relative(file.name)||index(file.name,'/')>=0)fail();let path=name+'/'+file.name,record;
   if(index(path,prefix+'/')!=0||result[path])fail();let mode=acl(file.acl);
   if(file.target!=null) {
    // APKv3 target is hex: little-endian S_IFLNK followed by target bytes.
    if(type(file.target)!='string'||!match(file.target,/^00[aA]0([a-fA-F0-9]{2})+$/))fail();
    let target=hexdec(substr(file.target,4));
    record={path,type:'symlink',mode,bytes:length(target),sha256:null,linkTarget:target};
   }else {
    if(!integer(file.size)||file.size>33554432||!sha(file.hash))fail();
    record={path,type:'file',mode,bytes:file.size,sha256:file.hash,linkTarget:null};
   }
   result[path]=record;if(++count>8193)fail();
  }
 }
 if(result[prefix+'/bank.json']?.type!='file'||result[prefix+'/bank.json'].bytes>1048576)fail();return result;
};
export function join_inventory(document,manifest) {
 let expected={};for(let path in keys(document)) {
  if(path==prefix+'/root'||path==prefix+'/adapters'||index(path,prefix+'/root/')==0||index(path,prefix+'/adapters/')==0)
   expected[substr(path,length(prefix)+1)]=document[path];
  else if(path!=''&&path!='usr'&&path!='usr/share'&&path!=prefix&&path!=prefix+'/bank.json')fail();
 }
 if(length(keys(expected))!=length(keys(manifest)))fail();
 for(let path in keys(manifest)) {
  let signed=expected[path];if(!signed)fail();signed={...signed,path};
  for(let key in ['path','type','mode','bytes','sha256','linkTarget'])if(signed[key]!=manifest[path][key])fail();
 }
 return true;
};
export function installed(rows,expected) {
 if(type(rows)!='array'||length(rows)!=75)fail();let seen={},found=false;
 for(let row in rows) {
  if(type(row.name)!='string'||!match(row.name,/^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$/)||seen[row.name]||
   type(row.version)!='string'||!length(row.version)||length(row.version)>128||match(row.version,/[[:cntrl:]]/)||
   index(['noarch',expected.arch],row.arch)<0||sprintf('%J',row.status)!=sprintf('%J',['installed']))fail();seen[row.name]=true;
  if(row.name=='foxhole-openwrt-client') {if(row.version!=expected.baseVersion||row.arch!='noarch')fail();found=true;}
 }
 if(!found)fail();return true;
};
export function accepted_download(stderr,code) {
 return code==0&&type(stderr)=='string'&&!match(stderr,/[Rr][Ee][Dd][Ii][Rr][Ee][Cc][Tt]/)&&
  !match(stderr,/[Cc]ertificate|SSL error|[Tt][Ll][Ss] error/);
};

// Keep the established BASE path/layout guard; APK scripts remain disabled.
function same_value(a,b) {return sprintf('%J',a)==sprintf('%J',b);};
export function base_path(path) {
	if (type(path) != 'string' || length(path) > 256 ||
	    !match(path, /^[a-zA-Z0-9_+./-]+$/) || match(path, /(^|\/)\.\.?($|\/)/)) return false;
	if (index(['etc/config/foxhole','etc/uci-defaults/99-foxhole-openwrt-client',
		'etc/nftables.d/31-foxhole-inbound.nft','etc/nftables.d/30-foxhole-mobile.nft',
		'usr/share/nftables.d/chain-pre/input/30-foxhole-mobile.nft','www/foxhole.html',
		'www/cgi-bin/foxhole','www/foxhole-mobile/cgi-bin/foxhole',
		'usr/share/rpcd/ucode/foxhole.uc','usr/share/rpcd/acl.d/luci-app-foxhole.json',
		'usr/share/luci/menu.d/luci-app-foxhole.json','lib/apk/packages/foxhole-openwrt-client.list',
		'lib/apk/packages/foxhole-openwrt-client.conffiles',
		'lib/apk/packages/foxhole-openwrt-client.conffiles_static',
		'lib/upgrade/keep.d/foxhole-openwrt-client',
		'usr/libexec/foxhole-engine-command-v2','usr/libexec/foxhole-transaction-stage-v1',
		'usr/libexec/foxhole-transaction-command-v1','usr/share/foxhole/transaction-x86_64.gz',
		'usr/share/foxhole/transaction-aarch64_cortex-a53.gz'], path) >= 0) return true;
	return match(path, /^etc\/init.d\/foxhole-[a-z-]+$/) != null ||
		match(path, /^usr\/libexec\/foxhole-[a-z-]+$/) != null ||
		match(path, /^usr\/share\/foxhole\/[a-zA-Z0-9_.-]+\.(uc|json|pem)$/) != null ||
		match(path, /^usr\/share\/nftables.d\/chain-pre\/(input|forward)\/3[01]-foxhole(-inbound)?\.nft$/) != null ||
		match(path, /^usr\/share\/licenses\/foxhole-openwrt-client\/[a-zA-Z0-9_.-]+$/) != null ||
		match(path, /^www\/luci-static\/resources\/(foxhole\/[a-zA-Z0-9_+./-]+|view\/foxhole\/[a-z-]+\.js)$/) != null;
};
function base_acl(value, modes) {
	let mode = type(value?.mode) == 'int' ? value.mode : -1;
	return index(modes, mode) >= 0 && index(['root','0'], value.user) >= 0 &&
		index(['root','0'], value.group) >= 0 && !length(value.xattrs || []);
};
export function base_layout(document, version) {
	let info = document?.info;
	if (info?.name != 'foxhole-openwrt-client' || info.version != version || info.arch != 'noarch' ||
	    !integer(info['installed-size']) || info['installed-size'] > 33554432 ||
	    type(document.paths) != 'array' || length(document.paths) > 192 ||
	    length(document.triggers || []) || type(document.scripts || {}) != 'object') fail('PACKAGE_VERIFICATION_FAILED');
	for (let key in keys(document.scripts || {}))
		if (index(['pre-install','post-install','pre-deinstall','post-deinstall','pre-upgrade','post-upgrade'], key) < 0)
			fail('PACKAGE_VERIFICATION_FAILED');
	if (info.provides != null && (type(info.provides) != 'array' ||
	    length(info.provides) && !same_value(info.provides, ['foxhole-openwrt-client-any'])))
		fail('PACKAGE_VERIFICATION_FAILED');
	for (let key in ['replaces','install-if','recommends'])
		if (length(info[key] || [])) fail('PACKAGE_VERIFICATION_FAILED');
	let seen = {}, directories = {}, count = 0, total = 0;
	for (let folder in document.paths) {
		let name = folder.name || '';
		if (directories[name] || !base_acl(folder.acl,[0o755]) || type(folder.files || []) != 'array' ||
		    name && (!match(name,/^[a-zA-Z0-9_+./-]+$/) || match(name,/(^|\/)\.\.?($|\/)/))) fail('PACKAGE_VERIFICATION_FAILED');
		directories[name] = true;
		for (let file in folder.files || []) {
			let path = name + '/' + file.name;
			if (!base_path(path) || seen[path] || file.target != null || !base_acl(file.acl,path=='etc/config/foxhole'?[0o600,0o644,0o755]:[0o644,0o755]) ||
			    !integer(file.size) || file.size > 8388608 || !match(file.hash || '', /^[a-f0-9]{64}$/)) fail('PACKAGE_VERIFICATION_FAILED');
			seen[path] = true; count++; total += file.size;
		}
	}
	if (count < 8 || count > 768 || total > 33554432) fail('PACKAGE_VERIFICATION_FAILED');
	for (let name in keys(directories)) if (name && !length(filter(keys(seen), path => substr(path,0,length(name)+1) == name + '/')))
		fail('PACKAGE_VERIFICATION_FAILED');
	for (let path in ['usr/share/foxhole/update-policy.json','usr/share/foxhole/engine-catalog.json',
		'usr/share/foxhole/update-service.uc','usr/libexec/foxhole-update-job','www/foxhole.html',
		'usr/share/rpcd/ucode/foxhole.uc','etc/config/foxhole','lib/apk/packages/foxhole-openwrt-client.list'])
		if (!seen[path]) fail('PACKAGE_VERIFICATION_FAILED');
	return seen;
};
export function base_policy(value,wanted) {
 exact(value,['schema','transactionAbi','stateAbi','osRelease','packageVersion','releaseTag','targets']);
 if(value.schema!=1||value.transactionAbi!=1||value.stateAbi!=1||value.osRelease!='25.12.5'||value.packageVersion!=wanted||
  value.releaseTag!='v'+split(wanted,'-r')[0]||!same_value(value.targets,['x86/64','mediatek/filogic']))fail();return value;
};
export function package_fence(before,after,expected) {
 installed(before,expected);installed(after,{...expected,baseVersion:expected.overlay.baseVersion});
 let rows={};for(let row in before)if(row.name!='foxhole-openwrt-client')rows[row.name]=row;
 for(let row in after) {
  if(row.name=='foxhole-openwrt-client')continue;let previous=rows[row.name];if(!previous)fail();
  if(!same_value(sort(keys(previous)),sort(keys(row))))fail();
  for(let key in keys(row))if(!same_value(previous[key],row[key]))fail();delete rows[row.name];
 }
 if(length(keys(rows)))fail();return 74;
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
 if(!same_value(retained(before),retained(after)))fail();return true;
};
export function mutable_base_file(path) {
 return index(path,'root/')==0&&(base_path(substr(path,5))||index(path,'root/lib/apk/db/')==0||
  path=='root/etc/apk/world'||index(path,'root/.foxhole-apk-cache/')==0);
};
export function mutable_base_directory(path) {
 for(let root in ['root/usr/share/foxhole','root/usr/share/licenses/foxhole-openwrt-client',
  'root/www/luci-static/resources/foxhole','root/www/luci-static/resources/view/foxhole','root/www/foxhole-mobile'])
  if(path==root||index(path,root+'/')==0)return true;
 return false;
};
export function overlay_targets(document) {
 let targets={},directories=['/usr/share/foxhole','/usr/share/licenses/foxhole-openwrt-client',
  '/www/luci-static/resources/foxhole','/www/luci-static/resources/view/foxhole','/www/foxhole-mobile'];
 for(let folder in document.paths)for(let file in folder.files||[]) {
  let path='/'+folder.name+'/'+file.name,chosen=null;
  for(let directory in directories)if(index(path,directory+'/')==0)chosen=directory;
  if(chosen)targets[chosen]=true;else if(public_target(path))targets[path]=true;
 }
 for(let path in ['/usr/share/foxhole','/usr/share/rpcd/ucode/foxhole.uc','/etc/init.d/foxhole-runtime','/etc/init.d/foxhole-mobile'])
  if(!targets[path])fail();return sort(keys(targets));
};
export function destination_mode(document,fallback) {
 if(type(fallback)!='int'||fallback<0||fallback>0o777||(fallback&0o022))fail();
 let result=fallback,found=false;
 for(let folder in document.paths)if((folder.name||'')=='') {
  if(found)fail();found=true;result=acl(folder.acl);if(result&0o022)fail();
 }
 return result;
};
