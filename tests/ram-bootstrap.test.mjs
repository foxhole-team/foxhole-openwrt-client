// Pure source-adapted checks. No downloads, native APK, mounts or services are run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const root=new URL('../',import.meta.url);
const read=path=>readFileSync(new URL(path,root),'utf8');
const source=read('tools/ram-bootstrap-model.uc'),loader=read('tools/ram-bootstrap.uc'),capture=read('tools/ram-bootstrap-command.sh');
const adapt=text=>text.replace(/^import [^;]+;\s*/gm,'').replace(/^export /gm,'').replace(/\bfor\s*\(\s*let\s+(\w+)\s+in\s+/g,'for(let $1 of ');
const sha=text=>createHash('sha256').update(text).digest('hex');
const functions={die:()=>{throw Error('rejected');},
 type:value=>value==null?'null':Array.isArray(value)?'array':Number.isInteger(value)?'int':typeof value,
 length:value=>typeof value=='string'||Array.isArray(value)?value.length:Object.keys(value).length,
 match:(value,pattern)=>value.match(new RegExp(pattern.source.replaceAll('[[:cntrl:]]','[\\u0000-\\u001f\\u007f]'),pattern.flags)),
 keys:Object.keys,index:(value,item)=>value.indexOf(item),split:(value,pattern)=>value.split(pattern),
 substr:(value,start,count)=>value.substr(start,count),slice:(value,start,end)=>value.slice(start,end),
 join:(separator,value)=>value.join(separator),push:(array,value)=>array.push(value),pop:array=>array.pop(),shift:array=>array.shift(),
 replace:(value,search,replacement)=>value.replace(search,replacement),sort:value=>value.sort(),trim:value=>value.trim(),
 filter:(value,predicate)=>value.filter(predicate),
 hexdec:value=>Buffer.from(value,'hex').toString('utf8'),json:JSON.parse,sprintf:(_format,value)=>JSON.stringify(value)};
const exports=[...source.matchAll(/^export (?:function|const) (\w+)/gm)].map(row=>row[1]);
const model=new Function(...Object.keys(functions),`${adapt(source)}\nreturn {${exports.join(',')}};`)(...Object.values(functions));
const descriptor=()=>({schema:1,kind:'foxhole-ram-bootstrap-v1',artifact:{url:'https://artifacts.example.invalid/bank.apk',bytes:1000,sha256:sha('bank')},
 version:'1.0.2-r2',baseVersion:'1.0.2-r1',arch:'aarch64_cortex-a53',target:'mediatek/filogic',osRelease:'25.12.5',
 baseSha256:sha('base'),signerPemSha256:sha('public signer'),caFileSha256:null,recoveryOrigin:'https://artifacts.example.invalid/base/'});
const overlayFor=expected=>({baseVersion:'1.0.3-r1',baseSha256:sha('new BASE'),artifact:{
 url:expected.recoveryOrigin+'foxhole-openwrt-client-1.0.3-r1.apk',bytes:2000,sha256:sha('new BASE')}});
function bankFixture(){
 const entries=new Map(),add=(path,type='file',mode=0o644,body='public',target=null)=>{
  const parts=path.split('/');for(let n=1;n<parts.length;n++){
   const name=parts.slice(0,n).join('/');if(!entries.has(name))entries.set(name,{path:name,type:'directory',mode:0o755,bytes:0,sha256:null,linkTarget:null});
  }
  entries.set(path,{path,type,mode,bytes:type=='directory'?0:type=='symlink'?target.length:body.length,
   sha256:type=='file'?sha(body):null,linkTarget:target});
 };
 add('root','directory',0o700);add('adapters','directory',0o700);
 add('root/usr/share/foxhole','directory',0o755);add('root/usr/share/foxhole/model.uc');
 add('root/usr/share/rpcd/ucode/foxhole.uc');add('root/etc/init.d/foxhole-runtime','file',0o755);add('root/etc/init.d/foxhole-mobile','file',0o755);
 add('root/lib/apk/db/installed','file',0o600);add('root/etc/apk/world');
 add('adapters/openssl','file',0o755);add('root/usr/lib/ucode/socket.so','file',0o644);
 add('root/lib/libc.so','file',0o755);add('root/lib/ld-musl.so','symlink',0o777,'','libc.so');
 const mounts=[{target:'/usr/share/foxhole',sourceRelative:'root/usr/share/foxhole',role:'base'},
  {target:'/usr/share/rpcd/ucode/foxhole.uc',sourceRelative:'root/usr/share/rpcd/ucode/foxhole.uc',role:'base'},
  ...['foxhole-runtime','foxhole-mobile'].map(name=>({target:`/etc/init.d/${name}`,sourceRelative:`root/etc/init.d/${name}`,role:'base'})),
  {target:'/usr/bin/openssl',sourceRelative:'adapters/openssl',role:'adapter'},
  {target:'/usr/lib/ucode/socket.so',sourceRelative:'root/usr/lib/ucode/socket.so',role:'dependency'}];
 const expected=descriptor(),bank={schema:1,kind:'foxhole-ram-bootstrap-bank-v1',osRelease:expected.osRelease,target:expected.target,arch:expected.arch,
  version:expected.version,baseVersion:expected.baseVersion,baseSha256:expected.baseSha256,stageDbSha256:entries.get('root/lib/apk/db/installed').sha256,
  hostNativePackageCount:75,mounts,files:[...entries.values()]};
 return {expected,bank};
}
function signedFixture(bank,expected){
 const prefix=model.prefix,paths=new Map(),acl=mode=>({mode,user:'root',group:'root'});
 for(const name of ['','usr','usr/share',prefix])paths.set(name,{name,acl:acl(0o755),files:[]});
 for(const row of bank.files)if(row.type=='directory')paths.set(`${prefix}/${row.path}`,{name:`${prefix}/${row.path}`,acl:acl(row.mode),files:[]});
 for(const row of bank.files)if(row.type!='directory'){
  const at=row.path.lastIndexOf('/'),name=row.path.slice(at+1),folder=paths.get(`${prefix}/${row.path.slice(0,at)}`);
  folder.files.push(row.type=='file'?{name,acl:acl(row.mode),size:row.bytes,hash:row.sha256}:
   {name,acl:acl(row.mode),size:row.bytes,target:'00a0'+Buffer.from(row.linkTarget).toString('hex')});
 }
 paths.get(prefix).files.push({name:'bank.json',acl:acl(0o644),size:2,hash:sha('{}')});
 return {info:{name:'foxhole-ram-bootstrap-bank',version:expected.version,arch:expected.arch,'installed-size':10000},paths:[...paths.values()]};
}
function nativeCaFixture(){
 const value=bankFixture(),body='public CA fixture',target='/etc/ssl/certs/ca-certificates.crt';
 for(const path of ['root/etc/ssl','root/etc/ssl/certs'])
  value.bank.files.push({path,type:'directory',mode:0o755,bytes:0,sha256:null,linkTarget:null});
 value.bank.files.push({path:'root/etc/ssl/certs/ca-certificates.crt',type:'file',mode:0o644,
  bytes:body.length,sha256:sha(body),linkTarget:null});
 value.bank.files.push({path:'root/etc/ssl/cert.pem',type:'symlink',mode:0o777,
  bytes:target.length,sha256:null,linkTarget:target});
 return value;
}
test('native CA alias preserves the exact signed native link bytes and regular target',()=>{
 const {bank,expected}=nativeCaFixture(),inventory=model.bank(bank,expected);
 assert.equal(model.link('root/etc/ssl/cert.pem','/etc/ssl/certs/ca-certificates.crt'),
  'root/etc/ssl/certs/ca-certificates.crt');
 assert.equal(inventory['root/etc/ssl/cert.pem'].linkTarget,'/etc/ssl/certs/ca-certificates.crt');
 assert.equal(inventory['root/etc/ssl/certs/ca-certificates.crt'].mode,0o644);
 const document=model.native_document(signedFixture(bank,expected),expected);
 assert.equal(model.join_inventory(document,inventory),true);
 for(const field of ['sha256','mode']){
  const changed=structuredClone(inventory);
  changed['root/etc/ssl/certs/ca-certificates.crt'][field]=field=='sha256'?sha('different CA'):0o600;
  assert.throws(()=>model.join_inventory(document,changed));
 }
});
test('native CA alias requires an exact regular public target and never permits a host CA mount',()=>{
 const {bank,expected}=nativeCaFixture(),target='root/etc/ssl/certs/ca-certificates.crt';
 assert.throws(()=>model.files(bank.files.filter(row=>row.path!=target)));
 for(const patch of [{mode:0o600},{mode:0o755},{mode:0o666},{sha256:null},{bytes:0},
  {type:'directory',mode:0o755,bytes:0,sha256:null},
  {type:'symlink',mode:0o777,bytes:20,sha256:null,linkTarget:'../../../lib/libc.so'}])
  assert.throws(()=>model.files(bank.files.map(row=>row.path==target?{...row,...patch}:row)));
 for(const path of ['/etc/ssl/cert.pem','/etc/ssl/certs','/etc/ssl/certs/ca-certificates.crt'])
  assert.equal(model.public_target(path),false);
 assert.throws(()=>model.bank({...bank,mounts:[...bank.mounts,
  {target:'/etc/ssl/certs',sourceRelative:'root/etc/ssl/certs',role:'base'}]},expected));
});
test('native CA alias exception rejects every different absolute path or traversal spelling',()=>{
 for(const [path,target]of [
  ['root/lib/alias','/etc/ssl/certs/ca-certificates.crt'],
  ['adapters/cert.pem','/etc/ssl/certs/ca-certificates.crt'],
  ['root/etc/ssl/cert.pem','/etc/passwd'],
  ['root/etc/ssl/cert.pem','//etc/ssl/certs/ca-certificates.crt'],
  ['root/etc/ssl/cert.pem','/etc/ssl/certs/../certs/ca-certificates.crt'],
  ['root/etc/ssl/cert.pem','/etc/ssl/certs/ca-certificates.crt/extra'],
  ['root/etc/ssl/cert.pem','../../../adapters/openssl']])
  assert.throws(()=>model.link(path,target),path+' '+target);
});
test('descriptor keeps bank version distinct from native BASE version and rejects future/null trust',()=>{
 assert.equal(model.descriptor(descriptor()).baseVersion,'1.0.2-r1');
 const template=JSON.parse(read('tools/ram-bootstrap-descriptor.template.json'));assert.throws(()=>model.descriptor(template));
 for(const patch of [{baseVersion:null},{signerPemSha256:null},{arch:'x86_64'},{osRelease:'unknown'},{url:'http://invalid'}])
  assert.throws(()=>model.descriptor({...descriptor(),...patch}));
 assert.throws(()=>model.descriptor({...descriptor(),artifact:{...descriptor().artifact,bytes:33554433}}));
});
test('only HTTPS artifact URLs without credentials/query/fragment/control are admitted',()=>{
 for(const value of ['https://example.invalid/bank.apk','https://10.0.0.1:444/bank.apk'])assert.equal(model.url(value),true);
 for(const value of ['http://example.invalid/a','https://user:pass@example.invalid/a','https://example.invalid/a?q=1',
  'https://example.invalid/a#f','https://example.invalid/a\nb','https://example.invalid/a/../b','https://example.invalid/%2e%2e/a'])assert.equal(model.url(value),false,value);
});
test('native ACLs including private directories survive without global chmod',()=>{
 const {expected,bank}=bankFixture(),inventory=model.bank(bank,expected);
 assert.equal(inventory.root.mode,0o700);assert.equal(inventory['root/lib/apk/db/installed'].mode,0o600);
 assert.equal(inventory['root/lib/ld-musl.so'].linkTarget,'libc.so');
 const document=model.native_document(signedFixture(bank,expected),expected);
 assert.equal(model.join_inventory(document,inventory),true);
 const reordered=Object.fromEntries(Object.entries(inventory).map(([path,row])=>[path,Object.fromEntries(Object.entries(row).reverse())]));
 assert.equal(model.join_inventory(document,reordered),true);
});
test('manifest inventory is exact and cannot hide an unsigned extra or omit a signed file',()=>{
 const {expected,bank}=bankFixture(),document=model.native_document(signedFixture(bank,expected),expected),inventory=model.bank(bank,expected);
 const missing={...inventory};delete missing['root/lib/libc.so'];assert.throws(()=>model.join_inventory(document,missing));
 const extra={...inventory,other:inventory.root};assert.throws(()=>model.join_inventory(document,extra));
 const changed={...inventory,'root/lib/libc.so':{...inventory['root/lib/libc.so'],sha256:sha('tampered')}};assert.throws(()=>model.join_inventory(document,changed));
});
test('owner data, special files, escaping links, writable files and symlink parents fail closed',()=>{
 const {bank}=bankFixture();
 for(const row of [
  {path:'root/etc/foxhole/state.json',type:'file',mode:0o600,bytes:0,sha256:sha(''),linkTarget:null},
  {path:'root/fifo',type:'fifo',mode:0o600,bytes:0,sha256:null,linkTarget:null},
  {path:'root/lib/escape',type:'symlink',mode:0o777,bytes:14,sha256:null,linkTarget:'../../etc/pass'},
  {path:'root/lib/writable',type:'file',mode:0o666,bytes:0,sha256:sha(''),linkTarget:null}
 ])assert.throws(()=>model.files([...bank.files,row]));
 assert.throws(()=>model.link('root/lib/example','/etc/passwd'));
 assert.throws(()=>model.link('root/lib/example','../../adapters/openssl'));
 const changed=bank.files.map(row=>row.path=='root/lib'?{...row,type:'symlink',mode:0o777,bytes:3,linkTarget:'usr',sha256:null}:row);
 assert.throws(()=>model.files(changed));
});
test('native bank metadata cannot execute scripts, install dependencies, expose host paths or include device nodes/hardlinks',()=>{
 const {expected,bank}=bankFixture();
 for(const mutate of [value=>value.scripts={'post-install':'x'},value=>value.info.depends=['libc'],value=>value.info.arch='noarch',
  value=>value.paths.push({name:'etc/foxhole',acl:{mode:0o700,user:'root',group:'root'},files:[]}),
  value=>value.paths.find(row=>row.files.length).files[0].target='008078',value=>value.paths[0].acl.mode=0o777]){
  const document=signedFixture(bank,expected);mutate(document);assert.throws(()=>model.native_document(document,expected));
 }
});
test('mounts are fixed public BASE/dependency/adapter roles, without host DB or bootstrap takeover',()=>{
 for(const target of ['/etc/foxhole','/etc/config/foxhole','/lib/apk/db/installed','/etc/apk/world','/etc/init.d/foxhole-ram-bootstrap'])assert.equal(model.public_target(target),false);
 const {expected,bank}=bankFixture();
 for(const mounts of [[...bank.mounts,bank.mounts[0]],bank.mounts.filter(row=>row.target!='/usr/bin/openssl'),
  bank.mounts.map(row=>row.target=='/usr/bin/openssl'?{...row,target:'/usr/bin/curl'}:row),
  bank.mounts.map(row=>row.target=='/etc/init.d/foxhole-mobile'?{...row,sourceRelative:'adapters/openssl'}:row)])
  assert.throws(()=>model.bank({...bank,mounts},expected));
});
test('native query validates 75 BANK packages while checking the distinct BASE version; host count is unconstrained',()=>{
 const expected=descriptor(),rows=Array.from({length:74},(_,n)=>({name:`package-${n}`,version:'1-r1',arch:expected.arch,status:['installed']}));
 rows.push({name:'foxhole-openwrt-client',version:expected.baseVersion,arch:'noarch',status:['installed']});assert.equal(model.installed(rows,expected),true);
 assert.throws(()=>model.installed(rows.slice(1),expected));
 assert.throws(()=>model.installed(rows.map(row=>row.name=='foxhole-openwrt-client'?{...row,version:expected.version}:row),expected));
 assert.throws(()=>model.installed([...rows.slice(1),rows[1]],expected));
});
test('stock uclient path requires direct success, never infers a redirect scheme from path-only logs',()=>{
 assert.equal(model.accepted_download('Downloading HTTPS artifact\nWriting to stdout\n',0),true);
 for(const text of ['Redirected to /bank.apk on example.invalid','Failed to redirect to /bank on example.invalid','SSL error: invalid peer','certificate rejected'])
  assert.equal(model.accepted_download(text,0),false);
 assert.equal(model.accepted_download('',5),false);
 assert.doesNotMatch(capture,/no-check-certificate|allow-untrusted|--insecure|ulimit|force-non-repository|curl/);
});
function actualFunction(name,bindings){
 const found=loader.match(new RegExp(`^function ${name}\\([^]*?^};`,'m'));assert.ok(found,name);
 return new Function(...Object.keys({...functions,...bindings}),`${adapt(found[0])}\nreturn ${name};`)(...Object.values({...functions,...bindings}));
}
test('installer rejects wrong signer/CA before writing any persistent file',()=>{
 const expected=descriptor();
 const make=(pem,ca,policy)=>actualFunction('install',{parents:()=>{},raw:path=>path=='descriptor'?JSON.stringify(policy):path=='pem'?pem:path=='ca'?ca:(()=>{throw Error('trust-admitted');})(),
  model:{descriptor:value=>value,enrollment:()=>{}},fs:{lstat:()=>null},MARKER:'/tmp/foxhole-ram-active.json',
  actual_platform:()=>{},digest:{sha256:sha},TOOLS:[],fail:()=>{throw Error('rejected');}});
 assert.throws(()=>make('wrong',null,expected)('/source','descriptor','pem',''),/rejected/);
 assert.throws(()=>make('public signer','unexpected',expected)('/source','descriptor','pem','ca'),/rejected/);
 const pinned={...expected,caFileSha256:sha('trusted CA')};
 assert.throws(()=>make('public signer',null,pinned)('/source','descriptor','pem',''),/rejected/);
 assert.throws(()=>make('public signer','wrong CA',pinned)('/source','descriptor','pem','ca'),/rejected/);
 assert.throws(()=>make('public signer',null,expected)('/source','descriptor','pem','','fetch',''),/trust-admitted/);
});
test('recovery enrollment pins the actual active or prepared BASE and does not select a new version',()=>{
 const expected=descriptor(),active={schema:1,phase:'active',storage:'RAM',version:expected.baseVersion,baseSha256:expected.baseSha256};
 const prepared={schema:1,kind:'ram-base-preparation-plan-v1',architecture:expected.arch,release:expected.osRelease,
  baseConstraint:'foxhole-openwrt-client='+expected.baseVersion,packages:[{name:'foxhole-openwrt-client',version:expected.baseVersion,sha256:expected.baseSha256}]};
 assert.equal(model.enrollment(expected,active,prepared),true);
 assert.equal(model.enrollment(expected,null,null),true);
 for(const patch of [{version:'1.0.4-r1'},{baseSha256:sha('other')},{storage:'FLASH'},{phase:'prepared'}])
  assert.throws(()=>model.enrollment(expected,{...active,...patch},null));
 for(const patch of [{architecture:'x86_64'},{baseConstraint:'foxhole-openwrt-client=1.0.4-r1'},
  {packages:[{...prepared.packages[0],sha256:sha('other')}]},{packages:[]}])
  assert.throws(()=>model.enrollment(expected,null,{...prepared,...patch}));
 const overlay=overlayFor(expected);
 assert.equal(model.enrollment({...expected,overlay},{...active,version:overlay.baseVersion,baseSha256:overlay.baseSha256},null),true);
});
test('persistent native fetch input requires its selected release digest and actual ELF architecture',()=>{
 const expected=descriptor(),elf=Buffer.alloc(64);elf.write('\x7fELF');elf[4]=2;elf[5]=1;elf[18]=183;
 const bytes=elf.toString('latin1'),digest={sha256:value=>sha(value)};
 const installer=body=>actualFunction('install',{parents:()=>{},raw:path=>path=='descriptor'?JSON.stringify(expected):
  path=='pem'?'public signer':path=='fetch'?body:(()=>{throw Error('native-admitted');})(),
  model,fs:{lstat:()=>null},MARKER:'/tmp/foxhole-ram-active.json',actual_platform:()=>{},digest,TOOLS:['foxhole-ram-fetch'],FETCH:'foxhole-ram-fetch',
  ord:(value,at)=>value.charCodeAt(at),fail:()=>{throw Error('rejected');}});
 assert.throws(()=>installer(bytes)('/source','descriptor','pem','','fetch','',sha('other')),/rejected/);
 const wrongArch=Buffer.from(elf);wrongArch[18]=62;const wrongBytes=wrongArch.toString('latin1');
 assert.throws(()=>installer(wrongBytes)('/source','descriptor','pem','','fetch','',sha(wrongBytes)),/rejected/);
 assert.throws(()=>installer(bytes)('/source','descriptor','pem','','fetch','',sha(bytes)),/native-admitted/);
});
test('boot network recovery retries transient failures within a fixed budget and never retries failed security checks',()=>{
 assert.equal(model.retryable_download('Connection timed out',4,1),true);
 assert.equal(model.retryable_download('Capture deadline elapsed',124,5),true);
 for(const [log,code,attempt] of [['',4,6],['',0,1],['',5,1],['SSL error',4,1],['certificate rejected',4,1],
  ['Redirected to /a on host',4,1],['HTTP error 404',4,1],['RAM fetch refused a redirect before connection',4,1]])
  assert.equal(model.retryable_download(log,code,attempt),false);
 const removed=[],receipts=[],waits=[];let calls=0;
 const fetch=actualFunction('fetch_artifact',{model,memory:()=>{},capture:()=>++calls==1?
  {code:4,path:'/owned/first',bytes:5,stderr:'Connection timed out'}:
  {code:0,path:'/owned/final',bytes:1000,stderr:'FoxHole HTTPS-only fetch v1'},
  replace:(path,value)=>receipts.push(value),fs:{unlink:path=>{removed.push(path);return true;}},
  digest:{sha256:sha},sleep:ms=>{waits.push(ms);return true;},fail:()=>{throw Error('rejected');}});
 assert.equal(fetch(descriptor().artifact,descriptor(),'bank').path,'/owned/final');
 assert.deepEqual(removed,['/owned/first']);assert.deepEqual(waits,[15000]);assert.equal(receipts[0].attempt,1);
 const init=read('tools/ram-bootstrap.init');assert.match(init,/USE_PROCD=1/);assert.doesNotMatch(init,/respawn|umount/);
});
test('rollback removes only actual own binds and restarts no VPN profile snapshot',()=>{
 const events=[],journal={mounted:[{target:'/one'},{target:'/two'}],created:[],starting:false,markerWritten:false};
 const rollback=actualFunction('rollback',{matches_mount:row=>events.push(['verify',row.target]),command:argv=>events.push(argv),
  replace:()=>{},model,fs:{},mounted:()=>[],same:(a,b)=>JSON.stringify(a)==JSON.stringify(b)});
 rollback(journal);assert.deepEqual(events.filter(row=>row[0]=='/bin/umount').map(row=>row[1]),['/two','/one']);assert.equal(journal.phase,'ROLLED_BACK');
 assert.doesNotMatch(loader,/write\('\/etc\/foxhole\/(state|auth|pairing)|activeServerId\s*=|\/etc\/init.d\/uhttpd|firewall.*reload/);
});
test('capture utility is byte-identical to the already qualified owned-PID/drainer utility',()=>{
 assert.equal(read('tools/ram-bootstrap-capture.uc'),read('package/foxhole-openwrt-client/root/usr/share/foxhole/engine-capture.uc'));
 assert.match(capture,/wait_owned/);assert.match(capture,/--no-chown --destination \/tmp\/foxhole-ram-stage-boot-v1\/payload/);
 assert.match(capture,/error_limit=16384/);assert.doesNotMatch(loader,/hostNativePackageCount.*\/lib\/apk\/db/);
});
test('new Ucode grammar is source-adapted only; POSIX bounds stay within 255',()=>{
 for(const path of ['tools/ram-bootstrap-model.uc','tools/ram-bootstrap-admit.uc','tools/ram-bootstrap.uc']){
  const body=read(path);assert.doesNotThrow(()=>new Function(adapt(body)));
  for(const row of body.matchAll(/\{\d+,(\d+)\}/g))assert.ok(+row[1]<=255);
 }
});
test('overlay pins only a strictly newer BASE artifact at the exact immutable recovery origin',()=>{
 const expected=descriptor(),overlay=overlayFor(expected);
 assert.equal(model.descriptor({...expected,overlay}).overlay.baseVersion,'1.0.3-r1');
 assert.equal(model.descriptor({...expected,overlay:null}).baseVersion,expected.baseVersion);
 for(const mutate of [value=>delete value.recoveryOrigin,value=>value.recoveryOrigin+='?q=x',
  value=>value.overlay.artifact.url='https://other.example.invalid/base.apk',
  value=>value.overlay.artifact.sha256=sha('other'),value=>value.overlay.artifact.bytes=8388609,
  value=>value.overlay.baseVersion=value.baseVersion,value=>value.overlay.extra='unsafe']){
  const value={...expected,overlay:structuredClone(overlay)};mutate(value);assert.throws(()=>model.descriptor(value));
 }
});
test('overlay native transaction retains all 74 dependency identities and non-BASE world pins',()=>{
 const expected={...descriptor(),overlay:overlayFor(descriptor())};
 const before=Array.from({length:74},(_,n)=>({name:`package-${n}`,version:'1-r1',arch:expected.arch,'installed-size':100,status:['installed']}));
 before.push({name:'foxhole-openwrt-client',version:expected.baseVersion,arch:'noarch','installed-size':100,status:['installed']});
 const after=before.map(row=>row.name=='foxhole-openwrt-client'?{...row,version:expected.overlay.baseVersion}:row);
 assert.equal(model.package_fence(before,after,expected),74);
 assert.throws(()=>model.package_fence(before,after.map(row=>row.name=='package-1'?{...row,'installed-size':101}:row),expected));
 assert.equal(model.world_fence('libc=1\nfoxhole-openwrt-client=1.0.2-r1\n','foxhole-openwrt-client><X1abc\nlibc=1\n'),true);
 assert.throws(()=>model.world_fence('libc=1\nfoxhole-openwrt-client=1\n','libc=2\nfoxhole-openwrt-client=2\n'));
 for(const path of ['root/usr/lib/libssl.so','adapters/openssl','root/usr/lib/ucode/socket.so'])assert.equal(model.mutable_base_file(path),false);
 for(const path of ['root/lib/apk/db/installed','root/etc/apk/world','root/.foxhole-apk-cache/installed','root/usr/share/foxhole/update-service.uc'])assert.equal(model.mutable_base_file(path),true);
 assert.equal(model.mutable_base_directory('root/www/luci-static/resources/foxhole/removed-old-base-directory'),true);
 assert.equal(model.mutable_base_directory('root/usr/lib'),false);
});
test('overlay preserves established BASE layout/ABI guards and derives new mounts from the new signed document',()=>{
 const files=['usr/share/foxhole/update-policy.json','usr/share/foxhole/engine-catalog.json','usr/share/foxhole/update-service.uc',
  'usr/libexec/foxhole-update-job','www/foxhole.html','usr/share/rpcd/ucode/foxhole.uc','etc/config/foxhole',
  'lib/apk/packages/foxhole-openwrt-client.list','etc/init.d/foxhole-runtime','etc/init.d/foxhole-mobile','usr/libexec/foxhole-new-worker'];
 const folders=new Map();for(const path of files){
  const pieces=path.split('/');for(let n=1;n<pieces.length;n++){
   const name=pieces.slice(0,n).join('/');if(!folders.has(name))folders.set(name,{name,acl:{mode:0o755,user:'root',group:'root'},files:[]});
  }
  folders.get(pieces.slice(0,-1).join('/')).files.push({name:pieces.at(-1),size:4,hash:sha('data'),acl:{mode:path=='etc/config/foxhole'?0o600:0o644,user:'root',group:'root'}});
 }
 const document={info:{name:'foxhole-openwrt-client',version:'1.0.3-r1',arch:'noarch','installed-size':1000},paths:[...folders.values()]};
 assert.equal(Object.keys(model.base_layout(document,'1.0.3-r1')).length,files.length);
 assert.ok(model.overlay_targets(document).includes('/usr/libexec/foxhole-new-worker'));
 assert.equal(model.base_path('usr/bin/openssl'),false);assert.equal(model.base_path('etc/foxhole/state.json'),false);
 const policy={schema:1,transactionAbi:1,stateAbi:1,osRelease:'25.12.5',packageVersion:'1.0.3-r1',releaseTag:'v1.0.3',targets:['x86/64','mediatek/filogic']};
 assert.equal(model.base_policy(policy,'1.0.3-r1'),policy);
 assert.throws(()=>model.base_policy({...policy,stateAbi:2},'1.0.3-r1'));
 assert.match(capture,/--root \/tmp\/foxhole-ram-stage-boot-v1\/root --arch "\$1" --root-tmpfs --no-network --cache-dir \.foxhole-apk-cache --scripts=no --commit-hooks=no/);
 assert.match(loader,/native\('simulate-overlay'/);assert.match(loader,/native\('install-overlay'/);
 assert.match(loader,/base_payload\(document\);retained_files\(bank,document\)/);
});
function cacheFixture(){
 const root=model.stage+'/root/.foxhole-apk-cache',archive=model.stage+'/overlay.apk',dev={major:0,minor:1};
 const record=(type,inode,mode,size=0)=>({type,inode,mode,size,dev,uid:0,gid:0,nlink:1,mtime:10,ctime:10});
 const input=record('file',10,0o600,2000),created=record('directory',20,0o700);
 const entries=new Map([[archive,{...input,nlink:2,ctime:12}],[root,created],
  [root+'/base.apk',{...input,nlink:2,ctime:12}],[root+'/installed',record('file',21,0o644,100)]]),removed=[];
 const fs={dirname:path=>path.slice(0,path.lastIndexOf('/'))||'/',lstat:path=>entries.has(path)?structuredClone(entries.get(path)):null,
  lsdir:path=>[...entries.keys()].filter(name=>name.startsWith(path+'/')&&!name.slice(path.length+1).includes('/')).map(name=>name.slice(path.length+1)),
  unlink:path=>{const value=entries.get(path);if(!value)return false;for(const row of entries.values())if(row.inode==value.inode)row.nlink--;entries.delete(path);removed.push(path);return true;},
  rmdir:path=>{if([...entries.keys()].some(name=>name.startsWith(path+'/')))return false;entries.delete(path);removed.push(path);return true;}};
 const clean=actualFunction('clean_overlay_cache',{model,fs,parents:()=>{},same:(a,b)=>JSON.stringify(a)==JSON.stringify(b),
  facts:JSON.stringify,fail:()=>{throw Error('rejected');}});
 return {root,archive,input:structuredClone(input),created:structuredClone(created),entries,removed,clean,record};
}
test('fresh overlay cache cleanup restores the exact input APK hardlink to nlink1',()=>{
 const value=cacheFixture();value.clean(value.created,value.input);
 assert.equal(value.entries.get(value.archive).nlink,1);assert.equal(value.entries.has(value.root),false);
 assert.deepEqual(value.removed,[value.root+'/base.apk',value.root+'/installed',value.root]);
 assert.match(loader,/native\('install-overlay'[^]*?clean_overlay_cache\(created_cache,input\);[^]*?hash_files\(\[model.stage\+'\/overlay.apk'\]\)/);
});
test('fresh overlay cache validation preserves artifacts on foreign links/symlinks and refuses bank cache exports',()=>{
 for(const foreign of [row=>({...row,inode:99,nlink:2}),row=>({...row,type:'link',inode:99})]){
  const value=cacheFixture();value.entries.set(value.root+'/foreign',foreign(value.record('file',99,0o600,10)));
  assert.throws(()=>value.clean(value.created,value.input));assert.deepEqual(value.removed,[]);
  assert.equal(value.entries.get(value.archive).nlink,2);assert.equal(value.entries.has(value.root+'/base.apk'),true);
 }
 const {bank}=bankFixture();assert.throws(()=>model.files([...bank.files,
  {path:'root/.foxhole-apk-cache',type:'directory',mode:0o700,bytes:0,sha256:null,linkTarget:null}]));
});
test('signed destination root ACL is applied explicitly while private stage and absent-root-node ACL stay unchanged',()=>{
 const path=model.stage+'/payload',dev={major:0,minor:1},entry={type:'directory',uid:0,gid:0,mode:0o700,dev,inode:22},changed=[];
 const fs={lstat:()=>({...entry}),chmod:(target,mode)=>{changed.push(target);entry.mode=mode;return true;}};
 const initialize=actualFunction('initialize_destination',{fs,model,parents:()=>{},same:(a,b)=>JSON.stringify(a)==JSON.stringify(b),fail:()=>{throw Error('rejected');}});
 const root={name:'',acl:{mode:0o755,user:'root',group:'root'}};
 initialize(path,{paths:[root]});assert.equal(entry.mode,0o755);assert.deepEqual(changed,[path]);
 entry.mode=0o700;changed.length=0;initialize(path,{paths:[{name:'usr',acl:root.acl}]});assert.equal(entry.mode,0o700);assert.deepEqual(changed,[]);
 assert.match(loader,/initialize_destination\(model.stage\+'\/payload',document\);native\('extract'/);
 assert.match(loader,/model.base_layout\(document,overlay.baseVersion\);\n initialize_destination\(model.stage\+'\/root',document\)/);
});
