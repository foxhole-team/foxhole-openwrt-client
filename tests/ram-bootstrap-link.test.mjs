import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname } from 'node:path';
import { functionBody } from './helpers.mjs';
const read=n=>readFileSync(new URL('../package/foxhole-openwrt-client/root/'+n,import.meta.url),'utf8');
const source=read('usr/share/foxhole/ram-bootstrap-link.uc'),update=read('usr/share/foxhole/ram-update-service.uc');
const switching=read('usr/share/foxhole/ram-switch-service.uc'),helper=read('usr/libexec/foxhole-ram-recovery-command');
const sha=s=>createHash('sha256').update(s).digest('hex'),clone=v=>JSON.parse(JSON.stringify(v));
const builtins={type:v=>v==null?'null':Array.isArray(v)?'array':typeof v=='boolean'?'bool':Number.isInteger(v)?'int':typeof v,
 length:v=>typeof v=='string'?Buffer.byteLength(v):Array.isArray(v)?v.length:Object.keys(v).length,
 keys:Object.keys,match:(v,r)=>String(v).match(r),index:(v,x)=>v.indexOf(x),push:(v,x)=>v.push(x),
 split:(v,x)=>v.split(x),replace:(v,a,b)=>v.replace(a,b),substr:(v,a,b)=>v.substr(a,b),sprintf:(_f,v)=>JSON.stringify(v),digest:{sha256:sha},json:JSON.parse};
const adapt=s=>s.replace(/^import .*\n/gm,'').replace(/^export /gm,'').replace(/for\(let (\w+) in /g,'for(let $1 of ').replaceAll('[[:cntrl:]]','[\\u0000-\\u001f\\u007f]');
const model=new Function(...Object.keys(builtins),'updates',adapt(read('usr/share/foxhole/ram-update-model.uc'))+';return {fail,sha,integer,version,compare,signer_sha256,reserve_bytes};')(...Object.values(builtins),{fail:r=>{throw new Error(r);}});
const BOOT='/etc/foxhole/ram-update/boot.json',BANK='/tmp/foxhole-ram-stage-boot-v1/bank.apk',TRUST='/etc/foxhole/ram-update/bootstrap';
const key=readFileSync(new URL('../config/foxhole-openwrt-apk.pem',import.meta.url),'utf8'),bank='signed-bank',apk='signed-next-base';
const desc=()=>({schema:1,kind:'foxhole-ram-bootstrap-v1',artifact:{url:'https://example.test/bank.apk',bytes:bank.length,sha256:sha(bank)},version:'1.0.2-r1',baseVersion:'1.0.2-r1',arch:'aarch64_cortex-a53',target:'mediatek/filogic',osRelease:'25.12.5',baseSha256:'a'.repeat(64),signerPemSha256:sha(key),caFileSha256:null,recoveryOrigin:'https://example.test/recovery/'});
function fixture(){
 const files=new Map([[BOOT,JSON.stringify(desc())],[TRUST+'/keys/signer.pem',key],[BANK,bank],['/tmp/foxhole-ram-active.json',JSON.stringify({schema:1,phase:'active',storage:'RAM',version:'1.0.2-r1',baseSha256:'a'.repeat(64)})]]);
 const calls=[],writes=[],captures=[];let bankInode=30,redirect=false,badFetch=false,sequence=0,api;
 const fs={dirname,lstat:p=>files.has(p)?{type:'file',uid:0,gid:0,mode:0o600,nlink:1,size:files.get(p).length,dev:{major:0,minor:1},inode:p==BANK?bankInode:20,mtime:1,ctime:1}:{type:'directory',uid:0,mode:p=='/tmp'?0o1777:p.startsWith('/etc/foxhole')||p.startsWith('/tmp/foxhole')?0o700:0o755},readfile:p=>files.get(p),unlink:p=>files.delete(p)};
 const store={read:p=>files.get(p)??null,write:(p,v)=>{writes.push(p);files.set(p,v);},directory_metadata:v=>v?.type=='directory'&&v.mode==0o700,file_metadata:v=>v?.type=='file'&&v.mode==0o600};
 const capture=(op)=>{
  calls.push(op);const path='/tmp/foxhole/ram-updates/recovery-io-'+(++sequence).toString(16).padStart(32,'0');
  const stdout=op=='bank'?sha(bank)+'  '+BANK+'\n':badFetch?'wrong-candidate':apk,stderr=op=='fetch'&&redirect?'Redirected to another endpoint':'';
  files.set(path,stdout);files.set(path+'.err',stderr);
  const value={code:0,stdout,stderr,clean:true,outputs:[path,path+'.err'].map(path=>({path,identity:api.identity(fs.lstat(path))})),parentIdentity:api.directory_identity(fs.lstat('/tmp/foxhole/ram-updates'))};
  captures.push(value);return value;
 };
 const values={...builtins,fs,store,model,capture};
 api=new Function(...Object.keys(values),adapt(source).replace('function capture(','function captured_native_not_executed(')+';return {descriptor,recovery_overlay,prove,recheck,journal,before_quiesce,commit,restore,journal_valid,flash_required_bytes,identity,directory_identity};')(...Object.values(values));
 return {api,files,calls,writes,captures,redirect:()=>{redirect=true;},badFetch:()=>{badFetch=true;},changeBank:()=>{bankInode++;}};
}
const candidate=()=>({version:'1.0.2-r2',sha256:sha(apk),bytes:apk.length});
test('boot-installed signer path is reused by the later RAM overlay transaction',()=>{
 const loader=readFileSync(new URL('../tools/ram-bootstrap.uc',import.meta.url),'utf8');
 assert.match(loader,/write\(model.trust\+'\/keys\/signer.pem',pem\)/);
 const f=fixture();assert.ok(f.api.prove(candidate(),sha('metadata')));
});
test('descriptor keeps pinned bank and requires exact direct monotonic recovery overlay',()=>{
 const f=fixture(),next=f.api.recovery_overlay(desc(),'1.0.2-r2',sha(apk),apk.length);
 assert.equal(next.artifact.url,'https://example.test/recovery/foxhole-openwrt-client-1.0.2-r2.apk');assert.equal(f.api.descriptor({...desc(),overlay:next}).artifact.sha256,sha(bank));
 for(const mutate of [d=>delete d.recoveryOrigin,d=>d.recoveryOrigin='http://example.test/',d=>d.recoveryOrigin='https://example.test/x?y=1',d=>d.overlay={...next,baseVersion:'1.0.2-r1'},d=>d.overlay={...next,artifact:{...next.artifact,sha256:'b'.repeat(64)}},d=>d.overlay={...next,artifact:{...next.artifact,url:'https://example.test/other.apk'}}]){const value=desc();mutate(value);assert.throws(()=>f.api.descriptor(value));}
});
test('missing descriptor, redirect and changed bank fail before any descriptor write',()=>{
 let f=fixture();f.files.delete(BOOT);assert.throws(()=>f.api.prove(candidate(),sha('metadata')),/RAM_STAGE_UNAVAILABLE/);assert.equal(f.calls.length,0);
 f=fixture();f.redirect();assert.throws(()=>f.api.prove(candidate(),sha('metadata')),/DOWNLOAD_FAILED/);assert.equal(f.writes.length,0);
 f=fixture();const p=f.api.prove(candidate(),sha('metadata'));f.changeBank();assert.throws(()=>f.api.recheck(p,candidate(),sha('metadata')));assert.equal(f.writes.length,0);
});
test('proof binds exact raw descriptor, bank and candidate metadata',()=>{
 const f=fixture(),p=f.api.prove(candidate(),sha('metadata'));assert.equal(f.api.recheck(p,candidate(),sha('metadata')),true);assert.throws(()=>f.api.recheck(p,candidate(),sha('other')));
 f.files.set(BOOT,JSON.stringify({...desc(),recoveryOrigin:'https://example.test/another/'}));assert.throws(()=>f.api.recheck(p,candidate(),sha('metadata')));assert.equal(f.writes.length,0);
});
test('metadata-only commit is idempotent and rollback restores exact old descriptor',()=>{
 const f=fixture(),p=f.api.prove(candidate(),sha('metadata')),j=f.api.journal(p,candidate(),sha('metadata')),old=f.files.get(BOOT);
 f.api.before_quiesce(j);f.api.commit(j);f.api.commit(j);assert.equal(JSON.parse(f.files.get(BOOT)).baseVersion,'1.0.2-r1');assert.equal(JSON.parse(f.files.get(BOOT)).overlay.baseVersion,'1.0.2-r2');assert.deepEqual(f.writes,[BOOT]);
 f.api.restore(j);f.api.restore(j);assert.equal(f.files.get(BOOT),old);assert.deepEqual(f.writes,[BOOT,BOOT]);assert.ok(f.api.flash_required_bytes>=524288+8192);
 f.files.set(BOOT,'{}');assert.throws(()=>f.api.commit(j));assert.throws(()=>f.api.restore(j));assert.equal(f.files.get(BOOT),'{}');
});
test('descriptor journal cannot alter baseline or exceed bounded JSON',()=>{
 const f=fixture(),p=f.api.prove(candidate(),sha('metadata')),j=f.api.journal(p,candidate(),sha('metadata')),a=clone(j),v=JSON.parse(a.newRaw);v.baseSha256='c'.repeat(64);a.newRaw=JSON.stringify(v);a.newSha256=sha(a.newRaw);
 assert.throws(()=>f.api.journal_valid(a));assert.throws(()=>f.api.journal_valid({...j,oldRaw:' '.repeat(8193)}));
 const noOverlay=clone(j);noOverlay.newRaw=noOverlay.oldRaw;noOverlay.newSha256=noOverlay.oldSha256;assert.throws(()=>f.api.journal_valid(noOverlay));
});
test('recovery admission precedes publish/stop and descriptor commit/restore precede restart',()=>{
 assert.ok(update.indexOf('bootstrap.prove(')<update.indexOf("write(directory+'/receipt.json'"));assert.match(update,/verified_candidate\(candidate\);\n if\(!switch_available/);
 assert.ok(switching.indexOf('bootstrap.before_quiesce(')<switching.indexOf('stop_services(journal,journal_path);guard'));
 assert.match(switching,/replace\(MARKER,journal.newMarker,4096\).*\n  bootstrap.commit\(journal.bootstrap\);/);assert.match(switching,/restore_marker\(journal\);bootstrap.restore\(journal.bootstrap\);start_services\(journal\)/);
 assert.doesNotMatch(source,/engine\.update_locked|write\(JOB|curl|no-check-certificate/);
 assert.match(helper,/exec \/etc\/foxhole\/ram-update\/bootstrap\/foxhole-ram-fetch --ca-certificate/);
 assert.doesNotMatch(helper,/\/bin\/uclient-fetch|root-tmpfs=true|no-check-certificate|curl|ulimit -f/);
});
function cacheFixture(hardlink=false){
 const path='/tmp/candidate/root/.foxhole-apk-cache',archive='/tmp/candidate/base.apk',dev={major:0,minor:1};let inode=40;
 const nodes=new Map([[archive,{type:'file',uid:0,gid:0,mode:0o600,size:100,inode:10,dev,mtime:1,ctime:1}]]);
 const fs={dirname,basename:p=>p.split('/').at(-1),lstat:p=>{const v=nodes.get(p);if(!v)return null;return {...v,nlink:v.type=='file'?[...nodes.values()].filter(n=>n.type=='file'&&n.inode==v.inode).length:2};},
 glob:pattern=>[...nodes.keys()].filter(p=>dirname(p)==pattern.slice(0,-(pattern.endsWith('/.*')?3:2))&&(pattern.endsWith('/.*')?p.split('/').at(-1).startsWith('.'):!p.split('/').at(-1).startsWith('.'))),unlink:p=>nodes.delete(p),rmdir:p=>![...nodes.keys()].some(n=>dirname(n)==p)&&nodes.delete(p)};
 const clear=new Function('fs','same','facts','fail','length','push','match',`return function clear_native_cache(path,created,archive,input,maximum) ${functionBody(switching,'clear_native_cache').replace(/for\(let (\w+) in /g,'for(let $1 of ')}`)(fs,(a,b)=>JSON.stringify(a)==JSON.stringify(b),v=>JSON.stringify(v),()=>{throw new Error('refused');},v=>v.length,(a,v)=>a.push(v),(v,r)=>v.match(r));
 const create=()=>{nodes.set(path,{type:'directory',uid:0,gid:0,mode:0o700,inode:++inode,dev});const created=fs.lstat(path),input=fs.lstat(archive);nodes.set(path+'/base.apk',hardlink?{...nodes.get(archive)}:{...nodes.get(archive),inode:++inode});return {created,input};};
 return {path,archive,nodes,fs,create,run:v=>clear(path,v.created,archive,v.input,1024)};
}
test('fresh cache cleanup supports repeat generations and restores source hardlink count',()=>{
 for(const linked of [false,true]){const f=cacheFixture(linked);for(let i=0;i<2;i++){f.run(f.create());assert.equal(f.fs.lstat(f.path),null);assert.equal(f.fs.lstat(f.archive).nlink,1);}}
});
test('cache whole-tree validation refuses symlink/foreign hardlink before deletion',()=>{
 for(const mutate of [v=>({...v,type:'link'}),v=>({...v,uid:1})]){const f=cacheFixture(),s=f.create();f.nodes.set(f.path+'/bad',mutate({...f.nodes.get(f.archive),inode:99}));assert.throws(()=>f.run(s));assert.ok(f.nodes.has(f.path+'/base.apk'));}
 const f=cacheFixture(),s=f.create();f.nodes.set('/tmp/foreign',{...f.nodes.get(f.archive),inode:99});f.nodes.set(f.path+'/bad',{...f.nodes.get('/tmp/foreign')});assert.throws(()=>f.run(s));assert.ok(f.nodes.has('/tmp/foreign'));
 assert.ok(switching.indexOf("fs.chmod(work+'/upper'")<switching.indexOf("'lowerdir='+journal.lower"));assert.ok(switching.indexOf('clear_native_cache(cache,cache_created')<switching.indexOf("let after=json(native('query'"));
});

test('actual rollback restores exact boot descriptor before restarting current consumers',()=>{
 const f=fixture(),p=f.api.prove(candidate(),sha('metadata')),j=f.api.journal(p,candidate(),sha('metadata')),old=f.files.get(BOOT);f.api.commit(j);
 const events=[],journal={bootstrap:j,unmounted:[],mounted:[],created:[],restarted:true};
 const rollback_actions=new Function('length','push',`return function rollback_actions(unmounted,mounted) ${functionBody(read('usr/share/foxhole/ram-switch-model.uc'),'rollback_actions')}`)(v=>v.length,(a,v)=>a.push(v));
 const bindings={...builtins,model:{rollback_actions},fs:{},filter:(a,f)=>a.filter(f),replace:()=>{},mount_rows:()=>[],
 verify_mount:()=>{},command:()=>{},bind:()=>{},restore_marker:()=>events.push('marker'),bootstrap:f.api,
 stop_services:()=>events.push('quiesce'),start_services:()=>{assert.equal(f.files.get(BOOT),old);events.push('start-current');},fail:()=>{throw new Error('refused');}};
 const rollback=new Function(...Object.keys(bindings),`return function rollback(journal,path) ${adapt(functionBody(switching,'rollback'))}`)(...Object.values(bindings));
 rollback(journal,'journal');assert.equal(journal.phase,'ROLLED_BACK');assert.deepEqual(events,['quiesce','marker','start-current']);
 f.files.set(BOOT,'{}');events.length=0;assert.throws(()=>rollback({...journal,phase:'ACTIVE'},'journal'));assert.ok(!events.includes('start-current'));
});

test('stage initializes signed destination root ACL before native extract preserves it and full payload verification',()=>{
 const directory='/tmp/foxhole/ram-updates/candidates/candidate-'+ '1'.repeat(32),archive=directory+'/base.apk';
 const bytes='signed-fixture-base',payload='safe',events=[],nodes=new Map();
 const document={info:{'installed-size':4},paths:[{name:'',acl:{mode:0o755},files:[]},{name:'etc',acl:{mode:0o755},files:[{name:'fixture.conf',acl:{mode:0o644},size:4,hash:sha(payload)}]}]};
 const stop=new Error('verified-boundary'),fs={lstat:p=>nodes.get(p)||null,chmod:(p,mode)=>{assert.ok(events.includes('signed-metadata'));assert.equal(p,directory+'/root');nodes.get(p).mode=mode;events.push('root-acl');return true;}};
 const raw=p=>p=='key'?key:p==archive?bytes:p==directory+'/root/etc/fixture.conf'?payload:(()=>{throw Error('unexpected read');})();
 const verifyBindings={...builtins,fs,raw,parents:()=>{},fail:()=>{throw Error('invalid payload');}};
 const fullVerify=new Function(...Object.keys(verifyBindings),`return function verify_payload(directory,document) ${adapt(functionBody(update,'verify_payload'))}`)(...Object.values(verifyBindings));
 const values={...builtins,fs,raw,KEY:'key',candidate_directory:()=>directory,
 store:{directory:p=>{nodes.set(p,{type:'directory',uid:0,mode:0o700});},write:()=>{}},
 model:{signer_sha256:sha(key),maximum_apk_bytes:8388608,reserve_bytes:0,metadata:v=>{assert.equal(v.paths[0].acl.mode,0o755);events.push('signed-metadata');}},
 memory:()=>67108864,min:Math.min,int:Math.trunc,admit:()=>{},filter:(a,f)=>a.filter(f),verify_dependencies:()=>{},
 native_command:op=>{if(op=='dump')return JSON.stringify(document);if(op=='extract'){assert.equal(nodes.get(directory+'/root').mode,0o755);assert.equal(nodes.get(directory).mode,0o700);events.push('extract-preserves-root');nodes.set(directory+'/root/etc',{type:'directory',uid:0,mode:0o755});nodes.set(directory+'/root/etc/fixture.conf',{type:'file',uid:0,nlink:1,mode:0o644,size:4});}return '';},
 verify_payload:(at,v)=>{fullVerify(at,v);assert.equal(nodes.get(directory).mode,0o700);events.push('full-payload-verified');throw stop;},fail:()=>{throw Error('invalid stage');}};
 const stage=new Function(...Object.keys(values),`return function stage_candidate(archive,manifest,id) ${adapt(functionBody(update,'stage_candidate'))}`)(...Object.values(values));
 assert.throws(()=>stage(archive,{version:'1.0.2-r2',bytes:bytes.length,sha256:sha(bytes)},'fixture'),e=>e===stop);
 assert.deepEqual(events,['signed-metadata','root-acl','extract-preserves-root','full-payload-verified']);
});

function captureFixture(mode='success') {
 const root='/tmp/foxhole/ram-updates',nodes=new Map(),reads=[];let inode=100;
 const put=(path,text,type='file',permissions=0o600)=>nodes.set(path,{type,uid:0,gid:0,mode:permissions,nlink:1,size:Buffer.byteLength(text),dev:{major:0,minor:1},inode:++inode,mtime:1,ctime:1,text});
 for(const path of ['/','/tmp','/tmp/foxhole',root,'/usr','/usr/libexec','/usr/share','/usr/share/foxhole'])put(path,'','directory',path=='/tmp'?0o1777:path.startsWith('/tmp/foxhole')?0o700:0o755);
 put('/usr/libexec/foxhole-ram-recovery-command','fixed-helper', 'file',0o755);put('/usr/share/foxhole/engine-capture.uc','fixed-utility','file',0o644);
 const fs={dirname,lstat:p=>{const n=nodes.get(p);if(!n)return null;const {text,...info}=n;return {...info};},
  readfile:p=>{if(p=='/proc/meminfo')return 'MemAvailable: 1048576 kB\n';if(p=='/dev/urandom')return '0'.repeat(16);if(p.includes('/recovery-io-'))reads.push(p);return nodes.get(p)?.text;},
  unlink:p=>nodes.delete(p),rmdir:p=>![...nodes.keys()].some(n=>n!=p&&dirname(n)==p)&&nodes.delete(p)};
 const store={directory:p=>{if(!nodes.has(p))put(p,'','directory',0o700);},write:(p,text)=>put(p,text),
  directory_metadata:n=>n?.type=='directory'&&n.uid==0&&n.mode==0o700,file_metadata:n=>n?.type=='file'&&n.uid==0&&n.nlink==1&&n.mode==0o600};
 const system=argv=>{const output=argv[2],io=dirname(argv[1]);put(output,'candidate-bytes',mode=='refused'?'link':'file');if(mode!='missing')put(output+'.err',mode=='exit'?'bounded-failure':'');if(mode=='unknown')put(io+'/owner.json','unknown-owner');return mode=='exit'?124:mode=='unknown'?1:0;};
 const values={...builtins,fs,store,model,system,hexenc:s=>Buffer.from(s).toString('hex')};
 const api=new Function(...Object.keys(values),adapt(source)+';return {capture,discard};')(...Object.values(values));
 return {api,nodes,reads,run:()=>api.capture('fetch',['https://example.test/recovery/foxhole-openwrt-client-1.0.2-r2.apk','system','1.0.2-r2'],128,1000,'{}')};
}
test('actual capture retains failed, missing, refused and unknown-owner raws without alternative reads',()=>{
 for(const mode of ['exit','missing','refused','unknown']){const f=captureFixture(mode);
  if(mode=='refused')assert.throws(()=>f.run());else {const result=f.run();assert.throws(()=>f.api.discard(result));if(mode=='unknown')assert.equal(result.clean,false);}
  const outputs=[...f.nodes.keys()].filter(p=>p.includes('/recovery-io-'));assert.ok(outputs.length>0);
  if(mode=='unknown'||mode=='refused'||mode=='missing')assert.equal(f.reads.length,0);
 }
});
test('actual discard deletes only accepted stable pairs and validates both raw identities first',()=>{
 let f=captureFixture(),result=f.run();assert.ok(result.clean);assert.equal(result.code,0);assert.ok(result.outputs.every(row=>f.nodes.has(row.path)));
 f.api.discard(result);assert.ok(result.outputs.every(row=>!f.nodes.has(row.path)));
 for(const changed of ['raw','parent']){f=captureFixture();result=f.run();
  if(changed=='raw')f.nodes.get(result.outputs[1].path).inode++;else f.nodes.get('/tmp/foxhole/ram-updates').inode++;
  assert.throws(()=>f.api.discard(result));assert.ok(result.outputs.every(row=>f.nodes.has(row.path)));
 }
});
test('consumer admission preserves semantic failure raws and discards only admitted bank and recovery pairs',()=>{
 for(const fail of ['redirect','hash']){const f=fixture();if(fail=='redirect')f.redirect();else f.badFetch();assert.throws(()=>f.api.prove(candidate(),sha('metadata')),/DOWNLOAD_FAILED/);
  assert.ok(f.captures[0].outputs.every(row=>!f.files.has(row.path)));assert.ok(f.captures[1].outputs.every(row=>f.files.has(row.path)));
 }
 const f=fixture();f.api.prove(candidate(),sha('metadata'));assert.equal(f.captures.length,2);assert.ok(f.captures.every(c=>c.outputs.every(row=>!f.files.has(row.path))));
});
