import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { createHash } from 'node:crypto';

const root = new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/',import.meta.url);
function functions(name) {
 const source=readFileSync(new URL(name,root),'utf8').replace(/^import .*;$/gm,'').replace(/^export /gm,'');
 return source.replace(/for\s*\(let (\w+) in /g,'for (let $1 of ');
}
function fixture(mode='FLASH'){
 const audit=[], queue=[], base={name:'foxhole-openwrt-client',version:'1.0.9-r2',arch:'noarch'};
 const state={host:mode==='FLASH'?base:null,ram:mode==='RAM'?{version:base.version,identity:'generation-a'}:null,
  boot:'boot-a',world:'original-world',db:'original-db',startup:['S17foxhole-ram-restore'],result:'(1/1) Purging foxhole-openwrt-client (1.0.9-r2)\nOK: 1 MiB in 1 packages',busy:false};
 const io={boot:()=>state.boot,host:()=>state.host,ram:()=>state.ram,world:()=>state.world,database:()=>state.db,
  startups:()=>[...state.startup],simulation:()=>state.result,guard:()=>{if(state.busy)throw Error('BUSY');},
  removeFlash:()=>{audit.push('removeFlash');state.host=null;},disableStartup:n=>{audit.push(n);state.startup=state.startup.filter(x=>x!==n);},
  flashGuard:()=>{},finishFlash:()=>true,sameRetained:()=>true,retained:()=>({network:'unchanged'}),afterDisable:()=>audit.push('sync')};
 const ctx=vm.createContext({digest:{sha256:x=>createHash('sha256').update(x).digest('hex')},sprintf:(_f,x)=>JSON.stringify(x),
  length:x=>x.length,keys:Object.keys,index:(x,v)=>x.indexOf(v),type:x=>typeof x==='boolean'?'bool':typeof x,
  engines:{purge_only:(raw,names,rows)=>raw.split('\n').filter(x=>x.startsWith('(')).join('\n')===
   '(1/1) Purging foxhole-openwrt-client ('+rows[names[0]].version+')'},die:s=>{throw Error(s);}});
 vm.runInContext(functions('package-removal.uc'),ctx);return {ctx,io,state,audit};
}
test('preview leaves native and managed deployments untouched; explicit matching role is mandatory',()=>{
 for(const mode of ['FLASH','RAM']){
  const f=fixture(mode),p=f.ctx.plan(f.io);
  assert.equal(p.mode,mode);assert.deepEqual(f.audit,[]);
  for(const choice of ['',mode==='RAM'?'FLASH':'RAM'])assert.throws(()=>f.ctx.apply(f.io,p.token,choice),/UNCONFIRMED/);
  assert.deepEqual(f.audit,[]);
 }
});
test('flash accepts just the BASE native purge and returns its readback',()=>{
 const f=fixture(),p=f.ctx.plan(f.io);assert.equal(f.ctx.apply(f.io,p.token,'FLASH').status,'REMOVED');
 assert.deepEqual(f.audit,['removeFlash']);assert.equal(f.ctx.plan(f.io).mode,'ABSENT');
 const other=fixture();other.state.result='(1/2) Purging foxhole-openwrt-client (1.0.9-r2)\n(2/2) Purging dnsmasq-full (1.0-r1)';
 assert.throws(()=>other.ctx.plan(other.io),/PACKAGE_CHANGES/);assert.deepEqual(other.audit,[]);
});
test('RAM disables only the observed boot role and reports reboot and underlying FLASH independently',()=>{
 for(const mixed of [false,true]){
  const f=fixture('RAM');if(mixed)f.state.host={name:'foxhole-openwrt-client',version:'1.0.8-r2',arch:'noarch'};
  const p=f.ctx.plan(f.io);assert.equal(p.hostVersion,mixed?'1.0.8-r2':null);
  assert.equal(f.ctx.apply(f.io,p.token,'RAM').status,'REBOOT_REQUIRED');
  assert.deepEqual(f.audit,['S17foxhole-ram-restore','sync']);assert.ok(f.state.ram);
  assert.equal(f.state.host?.version??null,mixed?'1.0.8-r2':null);
 }
});
test('retries refuse a stale boot, generation, package world, or startup role, busy requests have no effects',()=>{
 for(const [mode,key,value] of [['RAM','boot','boot-b'],['RAM','ram',{version:'1.0.10-r1',identity:'another'}],['RAM','startup',[]],
   ['FLASH','world','new-world'],['FLASH','db','new-db'],['FLASH','busy',true]]){
  const f=fixture(mode),p=f.ctx.plan(f.io); f.state[key]=value;
  assert.throws(()=>f.ctx.apply(f.io,p.token,mode),/STALE|BUSY/);assert.deepEqual(f.audit,[]);
 }
});

test('LuCI requires a separate confirmation and routes RAM completion to the stock restart page', async()=>{
 const src=readFileSync(new URL('../package/foxhole-openwrt-client/htdocs/luci-static/resources/view/foxhole/remove.js',import.meta.url),'utf8');
 for(const mode of ['FLASH','RAM']){
  const calls=[],modals=[];let status;
  function E(tag,attrs={},kids=[]){const node={tag,attrs,kids:Array.isArray(kids)?kids:[kids],events:{},textContent:'',
   replaceChildren(...v){this.kids=v;},append(...v){this.kids.push(...v);},addEventListener(k,f){this.events[k]=f;}};
   if(attrs.role==='status')status=node;return node;}
  const rpc={declare:s=>async(...args)=>{calls.push([s.method,...args]);return s.method==='remove_package_apply'?
   {status:mode==='RAM'?'REBOOT_REQUIRED':'REMOVED'}:{};}};
  const ui={showModal:(title,children)=>modals.push(children.at(-1).kids),hideModal:()=>{}};
  const ctx={rpc,ui,E,setTimeout,clearTimeout,request:{},document:{documentElement:{lang:'en'}},view:{extend:v=>v},L:{hasViewPermission:()=>true,url:(...p)=>'/'+p.join('/')}};
  const view=vm.runInNewContext('(function(){'+src+'})()',ctx);
  const tree=view.render([{}, {mode,version:'1.0.9-r2',token:'a'.repeat(64),hostVersion:null}]);
  await new Promise(resolve=>setImmediate(resolve));
  const content=tree.kids[1],button=content.kids.at(-1);assert.equal(calls.length,0);
  await button.events.click();assert.equal(calls.length,0);await modals.at(-1)[0].events.click();assert.equal(calls.length,0);
  await button.events.click();await modals.at(-1)[2].events.click();
  assert.deepEqual(calls,[['remove_package_apply','a'.repeat(64),mode]]);
  if(mode==='RAM')assert.equal(content.kids.at(-1).attrs.href,'/admin/system/reboot');else assert.equal(status.textContent,'remove.done');
 }
});

test('only the LuCI admin object exposes removal and the CLI in all eight maintained READMEs is packaged',()=>{
 const base=new URL('../',import.meta.url),read=n=>readFileSync(new URL(n,base),'utf8');
 const acl=JSON.parse(read('package/foxhole-openwrt-client/root/usr/share/rpcd/acl.d/luci-app-foxhole.json'));
 assert.deepEqual(acl['luci-app-foxhole-remove'].read.ubus['foxhole.admin'],['remove_package_plan']);
 assert.deepEqual(acl['luci-app-foxhole-remove'].write.ubus['foxhole.admin'],['remove_package_apply']);
 assert.ok(!JSON.stringify(acl['luci-app-foxhole']).includes('remove_package'));
 for(const name of ['README.md',...['ru','de','fr','es','ja','zh','ar'].map(x=>'docs/README.'+x+'.md')])
  assert.ok(read(name).includes('```sh\n/usr/libexec/foxhole-uninstall\n```'),name);
 const mk=read('package/foxhole-openwrt-client/Makefile');for(const f of ['foxhole-uninstall','package-removal.uc','view/foxhole/remove.js'])assert.ok(mk.includes(f),f);
});

test('RAM actuator refuses unowned, writable or missing live mounts and startup link drift', async()=>{
 const {functionBody}=await import('./helpers.mjs');
 const script=readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/libexec/foxhole-uninstall',import.meta.url),'utf8');
 const src='/tmp/stage/root/usr/libexec/foxhole-uninstall',dst='/usr/libexec/foxhole-uninstall',mark='/tmp/foxhole-ram-active.json';
 const role={source:src,target:dst,dev:{major:0,minor:22},inode:11,type:'file'},bind={target:dst,options:'ro,relatime'};
 const seen={marker:true,binding:bind},info={uid:0,inode:11,type:'file',dev:role.dev};
 const marker={schema:1,phase:'active',storage:'RAM',stage:'/tmp/stage',mountLedger:'/etc/x',version:'1.0.9-r2'};
 const c=vm.createContext({MARKER:mark,ram_switch:{ram_backing:()=>{if(seen.disk===true)throw Error('unverified backing');}},ram_model:{mounts:()=>seen.binding?[seen.binding]:[],public_path:()=>true,stage:()=>true,ledger_path:()=>true,
    ledger:()=>({mounts:[role]}),one_mount:()=>{if(!seen.binding)throw Error('missing');return seen.binding;}},
   fs:{readfile:()=>'',lstat:x=>x===mark?(seen.marker?{type:'file'}:null):info},
   checked:p=>p===mark?JSON.stringify(marker):'{}',json:JSON.parse,match:(x,re)=>x.match(re),
   index:(a,x)=>a.indexOf(x),split:(s,a)=>s.split(a),sprintf:(_f,x)=>JSON.stringify(x),
   digest:{sha256:()=> 'bound'},stop:s=>{throw Error(s);}});
 vm.runInContext(`function ram() ${functionBody(script,'ram').replace(/for\s*\(let (\w+) in /g,'for (let $1 of ')}`,c);
 assert.equal(c.ram().identity,'bound');seen.disk=true;assert.throws(()=>c.ram(),/backing/);seen.disk=false;
 seen.binding={target:dst,options:'rw,errors=remount-ro'};assert.throws(()=>c.ram(),/UNVERIFIED/);
 seen.binding=null;assert.throws(()=>c.ram());seen.binding=bind;seen.marker=false;assert.throws(()=>c.ram(),/UNVERIFIED/);
 seen.binding=null;assert.equal(c.ram(),null);
 const f=fixture('RAM'),p=f.ctx.plan(f.io);let reads=0;
 f.io.startups=()=>++reads===1?['S17foxhole-ram-restore']:['S99foxhole-ram-bootstrap'];
 f.io.disableStartup=link=>{assert.equal(link,'S17foxhole-ram-restore');throw Error('STALE');};
 assert.throws(()=>f.ctx.apply(f.io,p.token,'RAM'),/STALE/);assert.deepEqual(f.audit,[]);
});

test('a lost removal reply offers a fresh plan instead of replaying the write',async()=>{
 const src=readFileSync(new URL('../package/foxhole-openwrt-client/htdocs/luci-static/resources/view/foxhole/remove.js',import.meta.url),'utf8');
 const calls=[],modals=[];let status;
 const E=(tag,attrs={},kids=[])=>{const n={tag,attrs,kids:Array.isArray(kids)?kids:[kids],events:{},
  replaceChildren(...v){this.kids=v;},append(...v){this.kids.push(...v);},addEventListener(k,f){this.events[k]=f;}};
  if(attrs.role==='status')status=n;return n;};
 const rpc={declare:spec=>async()=>{calls.push(spec.method);if(spec.method==='remove_package_apply')throw Error('lost reply');return {mode:'ABSENT'};}};
 const view=vm.runInNewContext('(function(){'+src+'})()', {rpc,setTimeout,clearTimeout,request:{},view:{extend:x=>x},ui:{showModal:(_title,kids)=>modals.push(kids.at(-1).kids),hideModal(){}},E,L:{hasViewPermission:()=>true}});
 const tree=view.render([{}, {mode:'FLASH',token:'a'.repeat(64),version:'1.0.9-r1'}]),content=tree.kids[1];
 await new Promise(resolve=>setImmediate(resolve));
 await content.kids.at(-1).events.click();await modals.at(-1)[2].events.click();
 const retry=content.kids[0];assert.equal(retry.kids[0],'remove.retry');await retry.events.click();
 assert.deepEqual(calls,['remove_package_apply','remove_package_plan']);assert.equal(status.textContent,'remove.absent');
});

test('DNS cleanup removes its own symlink and preserves a foreign file and link',async()=>{
 const {mkdtemp,writeFile,symlink,lstat,readFile,rm}=await import('node:fs/promises');
 const {execFileSync}=await import('node:child_process'),{tmpdir}=await import('node:os'),{join}=await import('node:path');
 const shell=readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/libexec/foxhole-dnsmasq',import.meta.url),'utf8');
 const fn=shell.match(/^cleanup_instance\(\) \{[\s\S]*?^\}/m)[0];
 const dir=await mkdtemp(join(tmpdir(),'foxhole-dns-cleanup-')),link=join(dir,'foxhole');
 try{
  const run=()=>execFileSync('/bin/sh',['-c',`managed_file="$1/owned"; removed_link=0; failed=0
instance_confdir() { echo "$1"; }
has_mount() { return 1; }
${fn}
cleanup_instance "$1"
printf '%s' "$removed_link"`,'test',dir],{encoding:'utf8'});
  await writeFile(link,'owner directive');assert.equal(run(),'0');assert.equal(await readFile(link,'utf8'),'owner directive');await rm(link);
  await symlink(join(dir,'foreign'),link);assert.equal(run(),'0');assert.ok((await lstat(link)).isSymbolicLink());await rm(link);
  await symlink(join(dir,'owned'),link);assert.equal(run(),'1');await assert.rejects(lstat(link),{code:'ENOENT'});
 }finally{await rm(dir,{recursive:true});}
});
