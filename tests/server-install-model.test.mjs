import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
const source=readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/server-install-model.uc',import.meta.url),'utf8');
const adapt=s=>s.replace(/^import .*;\n/gm,'').replace(/^export /gm,'').replace(/for \(let (\w+) in /g,'for (let $1 of ');
const api=new Function('digest','type','keys','length','index','match','filter','push','substr','sprintf','die',`${adapt(source)};return {entry,catalog,missing,make_plan,admit};`)(
 {sha256:s=>createHash('sha256').update(s).digest('hex')},x=>x==null?'null':Array.isArray(x)?'array':Number.isInteger(x)?'int':typeof x==='boolean'?'bool':typeof x,
 Object.keys,x=>x?.length??0,(a,x)=>a.indexOf(x),(s,re)=>s.match(re),(a,f)=>a.filter(f),(a,x)=>a.push(x),(s,a,n)=>s.substr(a,n),(_f,x)=>JSON.stringify(x),x=>{throw Error(x);});
const hash='a'.repeat(64),tag='v1.0.7';
const asset=(file,role,bytes=100)=>({file,role,bytes,sha256:hash,url:`https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/${tag}/${file}`});
function fixture(){return {schema:1,kind:'server-install-entry-v1',architecture:'aarch64_cortex-a53',target:'mediatek/filogic',openwrtRelease:'25.12.5',storage:'RAM',releaseTag:tag,sourceCatalogSha256:hash,sourceBudgetSha256:hash,
 server:{name:'hysteria-server-ram',version:'2.12.2-r5',binarySha256:hash,binaryBytes:200,executableSha256:hash,producerSha256:hash,securityReceiptSha256:hash,runtimeMemoryBytes:1024,staticExecutable:true},
 packages:[{name:'hysteria-server-ram',version:'2.12.2-r5',architecture:'aarch64_cortex-a53',file:'server.apk',sha256:hash,archiveBytes:100,installedBytes:300,nativeId:hash,indexFile:'server.adb',keyFiles:['foxhole.pem'],depends:[],payload:[
 {path:'usr/bin/hysteria',bytes:20,sha256:hash,mode:0o755,target:null},
 {path:'usr/share/foxhole/hysteria-producer.json',bytes:20,sha256:hash,mode:0o644,target:null}]}],
 assets:[asset('server.apk','package'),asset('server.adb','index'),asset('foxhole.pem','key',50),asset('server.bin','binary',200)],
 memoryEvidence:{schema:1,type:'conservative',description:'Accepted measured fixture, not a release descriptor',runtimeMemoryBytes:1024,acceptedForRelease:true},flashReserveBytes:16777216,ramReserveBytes:16777216};}
const binding=()=>({architecture:'aarch64_cortex-a53',target:'mediatek/filogic',openwrtRelease:'25.12.5',nativeDbSha256:hash,worldSha256:hash,owner:hash,catalogSha256:hash,stateRevision:7,bootId:'00000000-0000-0000-0000-000000000001',databaseBytes:1000,flashAvailableBytes:1e9,ramAvailableBytes:1e9});
test('empty embedded catalog is honest and cannot invent a server',()=>assert.equal(api.catalog({schema:1,kind:'verified-server-install-catalog-v1',entries:[]}).entries.length,0));
test('server-only descriptor rejects Core, BASE, kernel, arbitrary roots and host path escape',()=>{
 for(const mutate of [x=>x.packages[0].name='foxcore-engine-hysteria2-ram-'+hash,x=>x.packages[0].name='foxhole-openwrt-client',x=>x.packages[0].name='kernel',x=>x.packages[0].payload[0].path='usr/../../etc/foxhole/state.json',x=>x.packages[0].payload[0].target='/etc/foxhole/state.json']){const x=fixture();mutate(x);assert.throws(()=>api.entry(x));}
});
test('entry binds target, full executable, producer, security receipt, TLS origin and exact bytes',()=>{
 assert.equal(api.entry(fixture()).server.name,'hysteria-server-ram');
 for(const mutate of [x=>x.target='x86/64',x=>x.server.staticExecutable=false,x=>x.server.securityReceiptSha256=null,x=>x.assets[0].bytes=99,x=>x.assets[0].url='http://untrusted/server.apk',x=>x.packages[0].payload[0].sha256='b'.repeat(64)]){const x=fixture();mutate(x);assert.throws(()=>api.entry(x));}
});
test('only exact verified cache bytes reduce remaining download; resource reservations remain',()=>{
 const full=api.make_plan(fixture(),binding(),{},{});assert.equal(full.downloadBytes,450);
 const cached=api.make_plan(fixture(),binding(),{},{[hash]:200});assert.equal(cached.downloadBytes,250);
 assert.equal(full.budget.stagingBytes,cached.budget.stagingBytes);assert.equal(full.budget.reservedRamBytes,16777216);
 assert.throws(()=>api.make_plan(fixture(),{...binding(),ramAvailableBytes:16777216},{},{}),/no_space/);
});
test('server dependencies cannot upgrade or replace preexisting host identities',()=>{
 const existing={'hysteria-server-ram':{version:'2.12.2-r5',arch:'aarch64_cortex-a53',cas:'sha256-160:'+hash.slice(0,40)}};
 assert.deepEqual(api.missing(fixture(),existing),[]);
 assert.throws(()=>api.missing(fixture(),{'hysteria-server-ram':{...existing['hysteria-server-ram'],version:'2.12.1-r1'}}),/dependency_conflict/);
 const x=fixture();x.packages[0].depends=['missing-dependency'];assert.throws(()=>api.entry(x));
});
test('confirmation rejects changed principal, boot, database, revision, artifact plan or consent',()=>{
 const b=binding(),plan=api.make_plan(fixture(),b,{},{}),request={revision:7,confirmed:true,planSha256:plan.planSha256};
 assert.equal(api.admit(plan,request,b),plan);
 for(const field of ['owner','bootId','nativeDbSha256','worldSha256','stateRevision'])assert.throws(()=>api.admit(plan,request,{...b,[field]:field==='stateRevision'?8:'changed'}),/stale_plan/);
 assert.throws(()=>api.admit(plan,{...request,confirmed:false},b),/stale_plan/);assert.throws(()=>api.admit(plan,{...request,confirmed:1},b),/stale_plan/);
 assert.throws(()=>api.admit({...plan,downloadBytes:0},request,b));
});

function prerequisiteFixture(){
 const x=fixture();x.packages[0].preinstalledOnly=false;x.packages[0].depends=['libc'];
 x.packages.push({name:'libc',version:'1.2.5-r1',architecture:x.architecture,file:'libc.apk',sha256:hash,
  archiveBytes:50,installedBytes:100,nativeId:hash,indexFile:'server.adb',keyFiles:['foxhole.pem'],
  depends:[],payload:[],preinstalledOnly:true});
 x.assets.push(asset('libc.apk','package',50));return x;
}
test('BASE prerequisites are exact installed identities and are never installed or upgraded by SERVER',()=>{
 const x=prerequisiteFixture(),installed={libc:{version:'1.2.5-r1',arch:x.architecture,cas:'sha256-160:'+hash.slice(0,40)}};
 assert.deepEqual(api.missing(x,installed),['hysteria-server-ram']);
 assert.throws(()=>api.make_plan(x,binding(),{},{}),/dependency_conflict/);
 assert.throws(()=>api.missing(x,{libc:{...installed.libc,version:'1.2.4-r1'}}),/dependency_conflict/);
});
test('only the server can be added and the server itself cannot be marked preinstalled-only',()=>{
 const x=prerequisiteFixture();x.packages[1].preinstalledOnly=false;assert.throws(()=>api.entry(x));
 const y=fixture();y.packages[0].preinstalledOnly=true;assert.throws(()=>api.entry(y));
});

test('dependency indexes are fetched for native resolution but prerequisite APKs are never downloaded',()=>{
 const x=prerequisiteFixture();x.packages[1].indexFile='libc.adb';x.packages[1].keyFiles=['openwrt.pem'];
 x.assets.push(asset('libc.adb','index'),asset('openwrt.pem','key',50));
 const installed={libc:{version:'1.2.5-r1',arch:x.architecture,cas:'sha256-160:'+hash.slice(0,40)}};
 const plan=api.make_plan(x,binding(),installed,{}),names=plan.assets.map(a=>a.file);
 assert.ok(names.includes('libc.adb'));assert.ok(names.includes('openwrt.pem'));assert.ok(!names.includes('libc.apk'));
 assert.deepEqual(plan.additions,['hysteria-server-ram']);
});

test('25.12.6 server metadata cannot reuse a25.12.5 live-firmware binding',()=>{
 const value=fixture();value.openwrtRelease='25.12.6';
 assert.equal(api.make_plan(value,{...binding(),openwrtRelease:'25.12.6'},{},{}).descriptor.openwrtRelease,'25.12.6');
 assert.throws(()=>api.make_plan(value,binding(),{},{}));
 assert.throws(()=>api.make_plan(fixture(),{...binding(),openwrtRelease:'25.12.6'},{},{}));
 assert.throws(()=>api.entry({...value,openwrtRelease:'25.12.7'}));
});
