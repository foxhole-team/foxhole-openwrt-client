import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
const source=await readFile(new URL('../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/backup-panel.js',import.meta.url),'utf8');
const {parseBackup,BackupPanel,MAX_BACKUP_BYTES}=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
const make=()=>({schema:1,kind:'foxhole-settings-backup-v1',createdAtUnixMs:1700000000000,state:{schema:1,revision:4,activeServerId:null,settings:{standaloneAccess:true},countries:[],devices:[],sites:[],servers:[],clients:[]},panel:{mode:'runtime',telemetry_interval:'5',standalone:'1',lan_devices:null,dns_via_tunnel:null,preserve_loopback_socks:null,tun_mtu:'1500'},autoUpdate:{enabled:false}});
let passed=0;
const bad=v=>assert.throws(()=>parseBackup(typeof v==='string'?v:JSON.stringify(v)),e=>e.code==='backup_invalid');
assert.deepEqual(parseBackup(JSON.stringify(make())),{...make(),panel:{...make().panel,mobile_devices:null}});passed++;
{
 const value=make();value.panel.mobile_devices=['br-lan','br-vpn'];
 assert.deepEqual(parseBackup(JSON.stringify(value)).panel.mobile_devices,value.panel.mobile_devices);passed++;
 for(const devices of [[],['br-lan','br-lan'],['*'],['br-lan" accept'],Array.from({length:9},(_,i)=>'br-'+i)]) {
  value.panel.mobile_devices=devices;bad(value);passed++;
 }
}
for(const mutate of [v=>v.kind='other',v=>delete v.panel,v=>v.panel.tun_mtu='9000',v=>v.panel.standalone='0',v=>v.state.clients=Array(513).fill({}),v=>v.auth={hash:'synthetic'},v=>v.autoUpdate.enabled='true']){const v=make();mutate(v);bad(v);passed++;}
for(const raw of ['{','{"__proto__":{}}',' '.repeat(MAX_BACKUP_BYTES+1),'я'.repeat(MAX_BACKUP_BYTES/2+1)]){bad(raw);passed++;}
Object.defineProperty(globalThis,'crypto',{value:webcrypto,configurable:true});
globalThis.location={protocol:'https:'};
let confirmAnswer=false;
globalThis.window={confirm:()=>confirmAnswer};
const realSetTimeout=globalThis.setTimeout,realClearTimeout=globalThis.clearTimeout;
globalThis.setTimeout=()=>123;globalThis.clearTimeout=()=>{};
const summary={schema:1,backupSha256:'a'.repeat(64),revision:4,confirmationRequired:true,reconnectRequired:true,servers:0,clients:0,devices:0,sites:0,countries:0};
const file=()=>({size:JSON.stringify(make()).length,text:async()=>JSON.stringify(make())});
let calls=[],restored=0,notices=[];
const build=call=>{let p=new BackupPanel({call:async(a,b)=>{calls.push(a);return call(a,b);},text:k=>k,scope:()=>1,revision:()=>4,notice:t=>notices.push(t),restored:async()=>{restored++;}});p.render=()=>{};p.supported=true;return p;};
let panel=build(()=>summary);
assert.equal(await panel.save(),false);assert.equal(calls.length,0);passed++;
await assert.rejects(()=>panel.restore({size:MAX_BACKUP_BYTES+1,text:async()=>''}),e=>e.code==='backup_invalid');assert.equal(calls.length,0);passed++;
assert.equal(await panel.restore(file()),false);assert.deepEqual(calls,['backup.validate']);passed++;
confirmAnswer=true;calls=[];let id;
panel=build((action,payload)=>{if(action==='backup.validate')return summary;if(action==='backup.apply'){id=payload.requestId;throw new Error('lost response');}if(action==='backup.status')return {schema:1,jobId:id,state:'COMMITTED'};throw new Error('unexpected');});
assert.equal(await panel.restore(file()),true);assert.equal(calls.filter(a=>a==='backup.apply').length,1);assert.equal(restored,1);assert.equal(panel.uncertain,null);passed++;
calls=[];window.showSaveFilePicker=async()=>{throw Object.assign(new Error('denied'),{name:'NotAllowedError'});};
assert.equal(await panel.save(),false);assert.equal(calls.length,0);passed++;delete window.showSaveFilePicker;
calls=[];let committed=false;
panel=build((action,payload)=>{if(action==='backup.validate')return summary;if(action==='backup.apply'){id=payload.requestId;return {schema:1,jobId:id,state:'PREPARED'};}if(action==='backup.status')return {schema:1,jobId:id,state:committed?'COMMITTED':'APPLYING'};throw new Error('unexpected');});
assert.equal(await panel.restore(file()),false);assert.equal(panel.uncertain,id);committed=true;await panel.status();assert.equal(panel.uncertain,null);assert.equal(calls.filter(a=>a==='backup.apply').length,1);passed++;
calls=[];panel=build((action,payload)=>action==='backup.validate'?summary:{schema:1,jobId:payload.requestId,state:'CANCELLED'});
assert.equal(await panel.restore(file()),false);assert.equal(panel.uncertain,null);assert.equal(notices.at(-1),'backup.cancelled');passed++;
calls=[];let resolveRead;const delayed={size:100,text:()=>new Promise(resolve=>{resolveRead=resolve;})};panel=build(()=>{throw new Error('must not call');});
const pending=panel.restore(delayed);panel.close();resolveRead(JSON.stringify(make()));assert.equal(await pending,false);assert.equal(calls.length,0);passed++;

calls=[];
const legacy=new BackupPanel({call:async action=>{calls.push(action);return {schema:1,product:'foxhole',installed:true};},text:k=>k,scope:()=>1,revision:()=>4,notice:()=>{},restored:async()=>{}});
assert.equal(await legacy.capability(),false);
await assert.rejects(()=>legacy.save(),e=>e.code==='backup_unavailable');
await assert.rejects(()=>legacy.restore(file()),e=>e.code==='backup_unavailable');
await assert.rejects(()=>legacy.status(),e=>e.code==='backup_unavailable');
assert.throws(()=>legacy.choose(),e=>e.code==='backup_unavailable');
assert.deepEqual(calls,['package.status']);passed++;
calls=[];
const capable=new BackupPanel({call:async action=>{calls.push(action);return {schema:1,product:'foxhole',installed:true,backupSupported:true};},text:k=>k,scope:()=>1,revision:()=>4,notice:()=>{},restored:async()=>{}});
assert.equal(await capable.capability(),true);assert.equal(capable.supported,true);assert.deepEqual(calls,['package.status']);passed++;
let finishCapability;
const stale=new BackupPanel({call:()=>new Promise(resolve=>{finishCapability=resolve;}),text:k=>k,scope:()=>1,revision:()=>4,notice:()=>{},restored:async()=>{}});
const waiting=stale.capability();stale.close();finishCapability({schema:1,product:'foxhole',installed:true,backupSupported:true});
assert.equal(await waiting,false);assert.equal(stale.supported,false);passed++;
globalThis.setTimeout=realSetTimeout;globalThis.clearTimeout=realClearTimeout;

console.log('Focused backup frontend checks:',passed,'PASS');
