import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {dirname} from 'node:path';
const source=readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/server-install-native.uc',import.meta.url),'utf8');
const adapted=source.replace(/^import .*;\n/gm,'').replace(/^export /gm,'').replace(/for \(let (\w+) in /g,'for (let $1 of ');
function fixture(){
 const hash='a'.repeat(64),events=[];let hashCalls=0;const header=Buffer.alloc(200);header.write('\x7fELF',0,'latin1');header[4]=2;header[5]=1;header.writeUInt16LE(183,18);header.writeUInt32LE(64,32);header.writeUInt16LE(56,54);header.writeUInt16LE(1,56);header.writeUInt32LE(1,64);
 const info={type:'file',uid:0,gid:0,nlink:1,mode:0o755,size:200,inode:3,dev:{major:1,minor:1},mtime:1,ctime:1};
 const builtin={fs:{dirname,lstat:path=>path.endsWith('/hysteria')?({...info}):({type:'directory',uid:0,gid:0,mode:0o755,dev:{major:1,minor:1},inode:path==='/'?1:2}),open:()=>({read:()=>header.toString('latin1'),close(){}})},digest:{},store:{},model:{},state_model:{},native:{native_cas:h=>'sha256-160:'+h.slice(0,40)},packages:{},engine:{},ram:{},registry:{hash_file:()=>{hashCalls++;return hash;},capture:args=>{events.push(args);return ''; }},
 type:x=>x==null?'null':Array.isArray(x)?'array':Number.isInteger(x)?'int':typeof x==='boolean'?'bool':typeof x,keys:Object.keys,length:x=>x?.length??0,match:(s,re)=>s.match(re),substr:(s,a,n)=>s.substr(a,n),ord:s=>s.charCodeAt(0),index:(a,x)=>a.indexOf(x),split:(s,d)=>s.split(d),trim:s=>s.trim(),b64dec:s=>Buffer.from(s,'base64').toString('latin1'),hexenc:s=>Buffer.from(s,'latin1').toString('hex'),filter:(a,f)=>a.filter(f),push:(a,x)=>a.push(x),sprintf:(_f,x)=>JSON.stringify(x),die:x=>{throw Error(x);}};
 const api=new Function(...Object.keys(builtin),`${adapted};return {identities,payload,unchanged,verify_binary,apk};`)(...Object.values(builtin));return {api,header,info,hash,events,get hashCalls(){return hashCalls;}};
}
test('native identities preserve actual CAS type and reject malformed/duplicate installed records',()=>{
 const f=fixture(),hash=Buffer.alloc(20,1).toString('base64');const block=`P:base\nV:1.0.7-r1\nA:noarch\nC:Q1${hash}\nf:S\n`;
 assert.equal(f.api.identities(block).base.cas,'sha256-160:'+'01'.repeat(20));assert.equal(f.api.identities(block.replace('f:S','f:')).base.cas,'sha1:'+'01'.repeat(20));
 assert.throws(()=>f.api.identities(block+'\n'+block));assert.throws(()=>f.api.identities(block.replace('Q1'+hash,'invalid')));
});
test('native SERVER transaction cannot alter BASE/Core identities or include unplanned packages',()=>{
 const f=fixture(),base={name:'foxhole-openwrt-client',version:'1.0.7-r1',arch:'noarch',cas:'retained'};
 const before={[base.name]:base};const item={name:'hysteria-server-ram',version:'2.12.2-r5',architecture:'aarch64_cortex-a53',nativeId:f.hash};
 const server={name:item.name,version:item.version,arch:item.architecture,cas:'sha256-160:'+f.hash.slice(0,40)};const after={...before,[item.name]:server};
 f.api.unchanged(before,after,[item.name],{packages:[item]});
 for(const bad of [{...after,[base.name]:{...base,cas:'changed'}},{[item.name]:server},{...after,kernel:server},{...after,[item.name]:{...server,version:'old'}}])assert.throws(()=>f.api.unchanged(before,bad,[item.name],{packages:[item]}));
});
test('static server proof rejects wrong architecture, writable/linked executables and dynamic loader',()=>{
 const f=fixture(),descriptor={architecture:'aarch64_cortex-a53',server:{binaryBytes:200,binarySha256:f.hash}};
 assert.equal(f.api.verify_binary('/owned/hysteria',descriptor),'/owned/hysteria');
 for(const bad of [{uid:1},{nlink:2},{type:'link'},{mode:0o777},{size:201}]){const old={...f.info};Object.assign(f.info,bad);assert.throws(()=>f.api.verify_binary('/owned/hysteria',descriptor));Object.assign(f.info,old);}
 f.info.ctime++;f.header.writeUInt16LE(62,18);assert.throws(()=>f.api.verify_binary('/owned/hysteria',descriptor));f.header.writeUInt16LE(183,18);
 f.info.ctime++;f.header.writeUInt32LE(3,64);assert.throws(()=>f.api.verify_binary('/owned/hysteria',descriptor));f.header.writeUInt32LE(1,64);
 f.info.ctime++;f.header.writeUInt32LE(65536,32);assert.throws(()=>f.api.verify_binary('/owned/hysteria',descriptor));assert.deepEqual(f.events,[]);
});
test('native APK mutations always use the explicit isolated root, fixed trust and offline script-free mode',()=>{
 const f=fixture();f.api.apk('/owned/root','aarch64_cortex-a53','/owned/keys','/owned/repositories',['add','--initdb','hysteria-server-ram=2.12.2-r5']);
 const args=f.events[0];assert.equal(args[0],'/usr/bin/apk');assert.deepEqual(args.slice(1,3),['--root','/owned/root']);assert.ok(args.includes('--no-network'));assert.ok(args.includes('--no-scripts'));assert.ok(args.includes('--keys-dir'));assert.ok(!args.includes('--allow-untrusted'));assert.ok(!args.includes('--force'));
});
test('APK payload cannot smuggle hooks, unknown files, permissions or executable hashes',()=>{
 const f=fixture(),item={name:'hysteria',version:'2.12.2-r6',architecture:'aarch64_cortex-a53',installedBytes:200,payload:[{path:'usr/bin/hysteria',bytes:200,sha256:f.hash,mode:0o755,target:null}]};
 const doc={info:{name:item.name,version:item.version,arch:item.architecture,'installed-size':200},paths:[{name:'usr/bin',acl:{user:'root',group:'root',mode:0o755},files:[{name:'hysteria',size:200,hash:f.hash,acl:{user:'root',group:'root',mode:0o755}}]}]};
 f.api.payload(doc,item);
 for(const mutate of [x=>x.scripts={postinstall:'evil'},x=>x.triggers=['*'],x=>x.paths[0].files[0].hash='wrong',x=>x.paths[0].files[0].acl.mode=0o777,x=>x.paths[0].files.push({...x.paths[0].files[0],name:'unplanned'})]){const bad=structuredClone(doc);mutate(bad);assert.throws(()=>f.api.payload(bad,item));}
});

test('unchanged immutable server facts avoid repeated full binary hashing and invalidate on replacement',()=>{const f=fixture(),d={architecture:'aarch64_cortex-a53',server:{binaryBytes:200,binarySha256:f.hash}};f.api.verify_binary('/owned/hysteria',d);f.api.verify_binary('/owned/hysteria',d);assert.equal(f.hashCalls,1);f.info.ctime++;f.api.verify_binary('/owned/hysteria',d);assert.equal(f.hashCalls,2);});

test('read-only APK query and fetch retain trust/offline options without add-only flags',()=>{
 for(const command of ['query','fetch']){const f=fixture();f.api.apk('/owned/root','aarch64_cortex-a53','/owned/keys','/owned/repositories',[command,'hysteria-server-ram=2.12.2-r5']);const args=f.events[0];assert.ok(!args.includes('--no-scripts'));assert.ok(args.includes('--no-network'));assert.ok(args.includes('--keys-dir'));assert.ok(!args.includes('--allow-untrusted'));}
});
