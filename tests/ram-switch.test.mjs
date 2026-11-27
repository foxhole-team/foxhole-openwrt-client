// Pure source-adapted checks. Native APK, OverlayFS and service
// lifecycle need target qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const root=new URL('../package/foxhole-openwrt-client/root/',import.meta.url);
const source=readFileSync(new URL('usr/share/foxhole/ram-switch-model.uc',root),'utf8');
const service=readFileSync(new URL('usr/share/foxhole/ram-switch-service.uc',root),'utf8');
const command=readFileSync(new URL('usr/libexec/foxhole-ram-switch-command',root),'utf8');
const adapt=text=>text.replace(/^import [^;]+;\s*/gm,'').replace(/^export /gm,'').replace(/\bfor\(let (\w+) in /g,'for(let $1 of ');
const sha=text=>createHash('sha256').update(text).digest('hex');
const builtins={die:()=>{throw Error('rejected');},type:value=>value==null?'null':Array.isArray(value)?'array':Number.isInteger(value)?'int':typeof value,
 length:value=>typeof value=='string'||Array.isArray(value)?value.length:Object.keys(value).length,
 match:(value,pattern)=>value.match(pattern),keys:Object.keys,index:(value,item)=>value.indexOf(item),
 split:(value,pattern)=>value.split(pattern),join:(separator,value)=>value.join(separator),slice:(value,start,end)=>value.slice(start,end),
 sort:value=>value.sort(),filter:(value,predicate)=>value.filter(predicate),push:(value,item)=>value.push(item),trim:value=>value.trim(),
 sprintf:(_format,value)=>JSON.stringify(value),substr:(value,start,count)=>value.substr(start,count)};
const names=[...source.matchAll(/^export function (\w+)/gm)].map(row=>row[1]);
const model=new Function(...Object.keys(builtins),`${adapt(source)}\nreturn {${names.join(',')}};`)(...Object.values(builtins));
const stage='/tmp/foxhole-ram-stage-qualification';
const marker={stage,baseSha256:'a'.repeat(64)};
const mount=(target='/usr/share/foxhole',role='base')=>({target,source:stage+'/root'+target,type:'directory',
 dev:{major:0,minor:42},inode:123,sha256:null,role});
const ledger=()=>({schema:1,abi:1,kind:'foxhole-ram-mount-ledger-v1',...marker,mounts:[mount()]});
const packageRow=(name,version)=>({name,version,arch:name=='foxhole-openwrt-client'?'noarch':'aarch64_cortex-a53','installed-size':100,status:['installed']});

test('ledger is explicit, bounded, tied to exact previous generation and native device identity',()=>{
 assert.equal(model.ledger(ledger(),marker).mounts.length,1);
 for(const mutate of [value=>delete value.kind,value=>value.stage=stage+'other',value=>value.baseSha256='b'.repeat(64),
  value=>value.mounts[0].dev=42,value=>value.mounts[0].source='/tmp/foreign/root/usr/share/foxhole',
  value=>value.mounts[0].target='/etc/foxhole',value=>value.mounts[0].inode=0]){
  const value=ledger();mutate(value);assert.throws(()=>model.ledger(value,marker));
 }
});
test('only fixed dependency adapters may retain an external source and require a content hash',()=>{
 const row={target:'/usr/bin/openssl',source:'/tmp/foxhole-owned/adapters/openssl',type:'file',
  dev:{major:0,minor:42},inode:124,sha256:'b'.repeat(64),role:'retained-adapter'};
 assert.equal(model.ledger({...ledger(),mounts:[mount(),row]},marker).mounts.length,2);
 for(const other of [{...row,sha256:null},{...row,target:'/usr/bin/curl'},{...row,source:'/etc/foxhole/secret'},
  {...row,source:'/tmp/foxhole-owned/../secret'}])assert.throws(()=>model.ledger({...ledger(),mounts:[other]},marker));
});
test('nested, duplicate and unknown mutable mount roles fail closed',()=>{
 for(const rows of [[mount(),mount()],[mount('/usr/libexec/foxhole-test'),mount('/usr/libexec/foxhole-test/child')]])
  assert.throws(()=>model.ledger({...ledger(),mounts:rows},marker));
 for(const path of ['/etc/config/foxhole','/etc/nftables.d/30-foxhole-mobile.nft','/lib/apk/db/installed',
  '/usr/libexec/foxhole/engines','/etc/foxhole/state.json'])assert.equal(model.public_path(path),false);
});
test('mount table requires one actual mount, refusing an existing stack',()=>{
 const line='12 1 0:42 / /usr/share/foxhole ro,relatime - tmpfs tmpfs rw\n';
 const rows=model.mounts(line);assert.equal(model.one_mount(rows,'/usr/share/foxhole').id,12);
 assert.throws(()=>model.one_mount(model.mounts(line+line.replace(/^12/,'13')),'/usr/share/foxhole'));
 assert.throws(()=>model.one_mount(rows,'/www/foreign'));
});
test('every previous non-BASE native package identity must remain exact',()=>{
 const before=[packageRow('foxhole-openwrt-client','1.0.1-r1'),packageRow('libc','1-r1')];
 const after=[packageRow('foxhole-openwrt-client','1.0.2-r1'),packageRow('libc','1-r1')];
 assert.equal(model.package_fence(before,after,'1.0.1-r1','1.0.2-r1'),1);
 for(const changed of [[after[0]],[...after,packageRow('unexpected','1-r1')],[after[0],packageRow('libc','2-r1')],
  [after[0],{...after[1],status:['available']}],[...after,after[1]]])
  assert.throws(()=>model.package_fence(before,changed,'1.0.1-r1','1.0.2-r1'));
});
test('native world changes only the BASE pin',()=>{
 assert.equal(model.world_fence('libc=1\nfoxhole-openwrt-client=1.0.1-r1\n',
  'foxhole-openwrt-client><X1abc\nlibc=1\n'),true);
 assert.throws(()=>model.world_fence('libc=1\nfoxhole-openwrt-client=1\n','libc=2\nfoxhole-openwrt-client=2\n'));
 assert.throws(()=>model.world_fence('libc=1\n','libc=1\n'));
});

function actualFunction(name,bindings){
 const found=service.match(new RegExp(`^function ${name}\\([^]*?^};`,'m'));assert.ok(found,name);
 return new Function(...Object.keys({...builtins,...bindings}),`${adapt(found[0])}\nreturn ${name};`)(...Object.values({...builtins,...bindings}));
}
test('rollback restores exactly successful unmounts, in reverse order; it never invents missing entries',()=>{
 const events=[],journal={bootstrap:{oldRaw:'old-boot-descriptor',newRaw:'new-boot-descriptor'},unmounted:[{target:'/old-one',source:'/source-one'}],mounted:[{target:'/new-one'},{target:'/new-two'}],created:[],restarted:false};
 let bootDescriptor=journal.bootstrap.newRaw;
 const rollback=actualFunction('rollback',{model,verify_mount:row=>events.push(['verify',row.target]),
  command:argv=>events.push(argv),replace:()=>{},fs:{},mount_rows:()=>[],bind:(from,to)=>events.push(['restore',from,to]),
  restore_marker:()=>events.push(['marker']),bootstrap:{restore:value=>{assert.equal(value,journal.bootstrap);assert.equal(bootDescriptor,value.newRaw);bootDescriptor=value.oldRaw;events.push(['boot-restore']);}},
  start_services:()=>{assert.equal(bootDescriptor,journal.bootstrap.oldRaw);events.push(['start-current-desired']);},update_native:{require_package_ready:(storage,version)=>events.push(['ready',storage,version])},stop_services:()=>{throw Error('unexpected');}});
 rollback(journal,'journal','1.0.9-r2');
 assert.deepEqual(events.at(-1),['ready','RAM','1.0.9-r2']);
 assert.deepEqual(events.filter(row=>row[0]=='/bin/umount').map(row=>row[1]),['/new-two','/new-one']);
 assert.deepEqual(events.filter(row=>row[0]=='restore'),[['restore','/source-one','/old-one']]);
 assert.equal(journal.phase,'ROLLED_BACK');assert.deepEqual(journal.unmounted,[]);
 assert.ok(events.findIndex(row=>row[0]=='boot-restore')<events.findIndex(row=>row[0]=='start-current-desired'));
});
test('rollback fault does not claim a completed rollback or restart services',()=>{
 const journal={unmounted:[{target:'/old'}],mounted:[{target:'/new'}],created:[],restarted:false,phase:'QUIESCED'};
 const rollback=actualFunction('rollback',{model,verify_mount:()=>{},command:()=>{throw Error('busy');},replace:()=>{},fs:{},
  mount_rows:()=>[],bind:()=>{},restore_marker:()=>{},start_services:()=>{throw Error('must not start');}});
 assert.throws(()=>rollback(journal,'journal'),/busy/);assert.equal(journal.phase,'QUIESCED');assert.equal(journal.mounted.length,1);
});
test('rollback quiesces restarted new consumers before removing their mounts',()=>{
 const events=[],journal={bootstrap:{oldRaw:'old-boot-descriptor',newRaw:'new-boot-descriptor'},unmounted:[],mounted:[{target:'/new'}],created:[],restarted:true};
 let bootDescriptor=journal.bootstrap.newRaw;
 const rollback=actualFunction('rollback',{model,verify_mount:()=>{},command:()=>events.push('unmount'),replace:()=>{},fs:{},
  mount_rows:()=>[],bind:()=>{},restore_marker:()=>{},bootstrap:{restore:value=>{assert.equal(value,journal.bootstrap);assert.equal(bootDescriptor,value.newRaw);bootDescriptor=value.oldRaw;events.push('boot-restore');}},
  start_services:()=>{assert.equal(bootDescriptor,journal.bootstrap.oldRaw);events.push('start-current');},update_native:{require_package_ready:()=>{}},stop_services:()=>events.push('quiesce')});
 rollback(journal,'journal');assert.deepEqual(events,['quiesce','unmount','boot-restore','start-current']);
});
test('rollback is incomplete if the restored management API remains unavailable',()=>{
 const journal={unmounted:[],mounted:[],created:[],restarted:false,phase:'ACTIVE'};
 const rollback=actualFunction('rollback',{model,replace:()=>{},fs:{},mount_rows:()=>[],restore_marker:()=>{},
  bootstrap:{restore:()=>{}},start_services:()=>{},update_native:{require_package_ready:()=>{throw Error('incompatible');}}});
 assert.throws(()=>rollback(journal,'journal','1.0.9-r2'),/incompatible/);
 assert.equal(journal.phase,'ACTIVE');
});
test('actual job guard rejects revoked principal and Stop before commit, permits authoritative Stop after commit',()=>{
 const state={revision:8,activeServerId:'selected'},bound={routerId:'router',stateRevision:8,activeProfileId:'selected',stateWithoutStop:'state',registrySha256:sha('{}'),worldSha256:sha('world')};
 const principal={kind:'pair'},job={jobId:'job',revision:2,state:'INSTALLING',atomicPackagePhase:true,mutationStarted:true,
  bootId:'boot',routerId:'router',worker:{pid:123},principal,owner:sha(JSON.stringify(principal)),stopIntent:1,
  plan:{binding:bound,routerId:'router',bootId:'boot',expiresAtUptimeMs:100}};
 let revoked=false,stop=1;
 const guard=actualFunction('guard',{backup:{guard:()=>{}},decode:()=>job,profile:()=>state,intent:()=>stop,
  boot:()=> 'boot',now:()=>1,same:(a,b)=>JSON.stringify(a)==JSON.stringify(b),engine:{update_process_snapshot:()=>({}),update_principal_current:()=>!revoked},
  engines:{worker_current:()=>true},digest:{sha256:sha},backup_model:{without_stop:()=> 'state'},registry:{read:()=>({})},raw:()=> 'world',JOB:'job',fail:()=>{throw Error('rejected');}});
 guard(job,false);revoked=true;assert.throws(()=>guard(job,false));revoked=false;
 stop=2;state.activeServerId=null;state.revision=9;assert.throws(()=>guard(job,false));guard(job,true);
 state.activeServerId='stale-saved-profile';assert.throws(()=>guard(job,true));
});
test('capture retains owned-process drainers, disables scripts/hooks and uses genuine private cache admission',()=>{
 assert.match(command,/--root-tmpfs --no-network --cache-dir \.foxhole-apk-cache --scripts=no --commit-hooks=no/);
 assert.doesNotMatch(command,/allow-untrusted|force-non-repository|ulimit|killall|pkill/);
 assert.match(command,/registered|register/);assert.match(command,/wait_owned/);
 assert.match(service,/ram_backing\(rows,previous.root,0\)/);
 assert.match(service,/copy_database\(previous.root,work\+'\/upper'\)/);
 assert.doesNotMatch(service,/replace\(JOB|write\(JOB|update_locked\(|\/etc\/init.d\/uhttpd/);
});
test('existing BASE path guard already admits every new installed helper without widening it',()=>{
 const updates=readFileSync(new URL('usr/share/foxhole/update-model.uc',root),'utf8');
 const body=updates.match(/^export function base_path\([^]*?^};/m);assert.ok(body);
 const basePath=new Function(...Object.keys(builtins),`${adapt(body[0])}\nreturn base_path;`)(...Object.values(builtins));
 for(const path of ['usr/libexec/foxhole-ram-switch','usr/libexec/foxhole-ram-switch-command',
  'usr/share/foxhole/ram-switch-model.uc','usr/share/foxhole/ram-switch-service.uc'])assert.equal(basePath(path),true,path);
});
test('all new Ucode files pass a source-adapted grammar check; native Ucode compilation remains separate',()=>{
 for(const body of [source,service])assert.doesNotThrow(()=>new Function(adapt(body)));
 const inline=[...command.matchAll(/ucode -e '([^]*?)' --/g)].map(row=>row[1]);assert.ok(inline.length);
 for(const body of inline)assert.doesNotThrow(()=>new Function(adapt(body)));
 for(const body of [source,service,...inline])for(const row of body.matchAll(/\{\d+,(\d+)\}/g))assert.ok(+row[1]<=255);
});

function copyDatabaseFixture(failChmod=false){
 const lower='/tmp/previous/root',upper='/tmp/candidate/switch/upper',directories=new Map(),writes=[],chmods=[];
 const original={type:'file',uid:0,nlink:1,mode:0o100644,size:8};
 const fs={glob:()=>[lower+'/lib/apk/db/installed'],lstat:path=>path.startsWith(lower)?original:{type:'directory',mode:directories.get(path)},
  basename:path=>path.split('/').at(-1),chmod:(path,mode)=>{chmods.push(path);if(failChmod)return false;directories.set(path,mode);return true;}};
 const copy=actualFunction('copy_database',{fs,fail:()=>{throw Error('rejected');},memory:()=>{},
  mkdir:(path,mode)=>directories.set(path,mode&~0o077),raw:path=>path.endsWith('/world')?'world\n':'database',
  write:(path,text,mode)=>writes.push({path,text,mode})});
 return{copy,lower,upper,directories,writes,chmods};
}
test('isolated native DB directories keep requested mode under private operator umask077',()=>{
 const h=copyDatabaseFixture();assert.equal(h.copy(h.lower,h.upper),8);
 for(const part of ['/lib','/lib/apk','/lib/apk/db','/etc','/etc/apk'])assert.equal(h.directories.get(h.upper+part),0o755,part);
 assert.ok(h.chmods.every(path=>path.startsWith(h.upper+'/')));
 assert.deepEqual(h.writes.map(row=>row.text),['database','world\n']);
});
test('failed directory mode restoration rejects the stage before copying package DB data',()=>{
 const h=copyDatabaseFixture(true);assert.throws(()=>h.copy(h.lower,h.upper),/rejected/);assert.deepEqual(h.writes,[]);
});

// OverlayFS xino=off reports the overlay device for directories
// and upper device for files.
function cacheCleanupFixture(mutate = () => {}, lowerPresent = false) {
 const dir='/tmp/foxhole/ram-updates/candidates/candidate-'+ 'a'.repeat(32);
 const cache=dir+'/root/.foxhole-apk-cache', upper=dir+'/switch/upper/.foxhole-apk-cache', archive=dir+'/base.apk';
 const overlay={major:0,minor:37}, backing={major:0,minor:18};
 const node=(type,inode,dev,size=0)=>({type,inode,dev,size,uid:0,gid:0,mode:type==='directory'?0o700:0o644,nlink:1,mtime:1,ctime:1});
 const merged=node('directory',100,overlay),physical=node('directory',200,backing),input=node('file',300,backing,8);
 physical.nlink=2; // Actual xino=off directory pair: merged nlink=1, owned upper nlink=2.
 const nodes=new Map([[cache,merged],[upper,physical],[archive,input]]);
 for(const [name,ino,bytes] of [['package.apk',400,8],['installed',401,633]]) {
  nodes.set(cache+'/'+name,node('file',ino,backing,bytes));nodes.set(upper+'/'+name,node('file',ino,backing,bytes));
 }
 const deleted=[];mutate({nodes,cache,upper,archive,overlay,backing});
 const parent=p=>p.slice(0,p.lastIndexOf('/')), children=p=>[...nodes.keys()].filter(n=>parent(n)===p);
 const fs={lstat:p=>nodes.get(p)||null,dirname:parent,basename:p=>p.slice(p.lastIndexOf('/')+1),lsdir:p=>children(p).map(n=>n.slice(p.length+1)),
  glob:p=>p.endsWith('/.*')?[]:children(p.slice(0,-2)),
  unlink(p){deleted.push(p);if(nodes.get(p)?.inode===nodes.get(archive)?.inode)nodes.get(archive).nlink-=1;nodes.delete(p);if(p.startsWith(cache+'/'))nodes.delete(upper+p.slice(cache.length));return true;},
  rmdir(p){if(children(p).length)return false;deleted.push(p);nodes.delete(p);if(p===cache){if(lowerPresent)nodes.set(upper,{...physical,type:'char',mode:0,size:0,nlink:2});else nodes.delete(upper);}return true;}};
 const start=service.indexOf('function clear_native_cache('),end=service.indexOf('\nfunction process_role',start);
 const text=service.slice(start,end);
 const run=new Function(...Object.keys(builtins),'fs','same','facts','mount_rows','fail',adapt(text)+';return clear_native_cache;')(
  ...Object.values(builtins),fs,(a,b)=>JSON.stringify(a)===JSON.stringify(b),JSON.stringify,()=>[],()=>{throw Error('rejected');});
 return {run:()=>run(cache,merged,archive,input,4096,upper,physical,{present:lowerPresent}),deleted,nodes,cache,upper};
}
test('RAM cache cleanup accepts only the declared physical upper backing on xino=off OverlayFS',()=>{
 const f=cacheCleanupFixture();f.run();assert.equal(f.nodes.has(f.cache),false);assert.equal(f.nodes.has(f.upper),false);assert.equal(f.deleted.length,3);
});
test('RAM cache cleanup validates all backing identities before deleting any file',()=>{
 for(const change of [
  f=>f.nodes.get(f.cache+'/installed').dev={major:0,minor:99},
  f=>f.nodes.get(f.upper+'/installed').inode=999,
  f=>f.nodes.get(f.upper+'/installed').dev={major:0,minor:99},
  f=>f.nodes.get(f.cache+'/installed').nlink=2,
  f=>f.nodes.get(f.upper+'/installed').uid=1000,
  f=>f.nodes.get(f.cache+'/installed').mode=0o666,
  f=>f.nodes.get(f.cache+'/installed').type='link',
  f=>f.nodes.set(f.upper+'/unrepresented', {...f.nodes.get(f.upper+'/installed'),inode:888}),
 ]) {const f=cacheCleanupFixture(change);assert.throws(f.run);assert.deepEqual(f.deleted,[]);}
});

test('RAM cache cleanup preserves the exact input archive when apk temporarily hardlinks it',()=>{
 const f=cacheCleanupFixture(({nodes,cache,upper,archive})=>{
  const input=nodes.get(archive);input.nlink=2;nodes.set(cache+'/package.apk',input);nodes.set(upper+'/package.apk',input);
 });f.run();assert.equal(f.nodes.size,1);assert.equal([...f.nodes.values()][0].nlink,1);
});
test('RAM cache cleanup refuses unexplained input archive hardlinks before deletion',()=>{
 const f=cacheCleanupFixture(({nodes,archive})=>nodes.get(archive).nlink=2);assert.throws(f.run);assert.deepEqual(f.deleted,[]);
});

test('inherited read-only cache is hidden only by a kernel whiteout after deleting the fully owned merged view',()=>{
 const f=cacheCleanupFixture(()=>{},true);f.run();assert.equal(f.nodes.has(f.cache),false);assert.equal(f.nodes.get(f.upper).type,'char');assert.equal(f.nodes.get(f.upper).mode,0);
});
