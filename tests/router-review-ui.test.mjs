import assert from 'node:assert/strict';
import test from 'node:test';
import * as model from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/frontend-model.js';
import * as charts from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/charts.js';
import { bindVerticalDismiss } from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/ui-controller.js';
import { functionBody, read, panelRoot } from './helpers.mjs';

test('About keeps independently verified empty Core module facts without requiring updates status', () => {
  const value = model.packageMetadata({schema:1,product:'foxhole',installed:true,version:'1.0.7-r1',storage:'RAM',installedModules:[]});
  assert.deepEqual(value.installedModules, []);
  assert.equal(value.storage,'RAM');
  assert.equal(model.packageMetadata({schema:1,product:'foxhole',installed:true,version:'1.0.7-r1',storage:'RAM'}).installedModules,null);
});
test('About reports a verified standalone Hysteria component alongside managed modules', async () => {
  const base={schema:1,product:'foxhole',installed:true,version:'1.0.9-r2',storage:'RAM',installedModules:[]};
  const hysteriaComponent={version:'2.12.2',storage:'RAM'};
  const metadata=model.packageMetadata({...base,hysteriaComponent});
  assert.deepEqual(metadata.hysteriaComponent,hysteriaComponent);
  assert.deepEqual(metadata.installedModules,[]);
  assert.throws(()=>model.packageMetadata({...base,hysteriaComponent:{...hysteriaComponent,version:'<script>'}}));
});
test('About rejects fabricated module identities, duplicate slots and invalid versions', () => {
  const base={schema:1,product:'foxhole',installed:true,version:'1.0.7-r1',storage:'RAM'};
  const row={id:'vless',version:'1.0.4',packageVersion:'1.0.4-r6',storage:'RAM'};
  for(const installedModules of [[{...row,id:'unknown'}],[row,row],[{...row,version:'<script>'}],[{...row,storage:'HOST'}]])
    assert.throws(()=>model.packageMetadata({...base,installedModules}));
});
test('modal chrome hides empty footers and routes dismiss gestures to the parent view', async () => {
  const app = await read(`${panelRoot}/app.js`);
  const shell = await read(`${panelRoot}/shell.html`);
  assert.doesNotMatch(app + shell, /modal-back|action\.back/);
  assert.match(functionBody(app, 'renderModalChrome'), /footer\.hidden = actions\.length === 0/);
  assert.match(app, /case 'modal-dismiss': await back\(\)/);
  assert.match(app, /if \(!popups\.closeActive\(\)\) void back\(\)/);
  assert.match(app, /bindVerticalDismiss\(handle, 1, canSwipeModal, \(\) => void back\(\)\)/);
  assert.match(functionBody(app, 'renderModalChrome'), /data-modal-close[^\n]*hidden = pinSetupRequired/);
});
test('chart missing intervals preserve outage/reboot boundaries without adding numeric measurements', () => {
  const end=2000000000000,start=end-60000;
  const data=[{time:start,a:10,b:40},{time:start+15000,a:20,b:41},
    {time:start+30000,a:null,b:null},{time:end,a:30,b:42,breakBefore:true}];
  assert.equal(typeof charts.missingIntervals,'function');
  assert.deepEqual(charts.missingIntervals(data,['a','b'],start,end),[{start:start+15000,end}]);
  assert.equal(data[2].a,null);
});
test('partial CPU unavailability does not invent zero or mark RAM as missing', () => {
  const end=2000000000000,start=end-30000;
  const data=[{time:start,a:10,b:40},{time:start+15000,a:null,b:41},{time:end,a:30,b:42}];
  assert.equal(typeof charts.missingIntervals,'function');
  assert.deepEqual(charts.missingIntervals(data,['a','b'],start,end),[]);
});
test('status heading is keyboard-clickable and independent from its range selector', async () => {
  const html=await read(`${panelRoot}/shell.html`);
  assert.ok(/<button[^>]*data-status-heading[^>]*data-action="toggle-section"/.test(html));
  const app=await read(`${panelRoot}/app.js`);
  assert.match(functionBody(app,'setSectionCollapsed'),/data-status-heading/);
});

test('stale chart samples do not remain displayed as current CPU or memory', () => {
  const end=2000000000000;
  const view=Object.assign(Object.create(charts.Charts.prototype),{meta:{cpu:{textContent:''},ram:{textContent:''}},latest:()=>null});
  view.updateMeta('wrt',[{time:end-120000,cpu:75,ram:92}],end);
  assert.equal(view.meta.cpu.textContent,'—%');
  assert.equal(view.meta.ram.textContent,'—%');
});

test('package.status keeps authoritative deployment when independent module verification is unavailable', async () => {
  const source=await read('package/foxhole-openwrt-client/root/usr/share/rpcd/ucode/foxhole.uc');
  const factory=(modules,homeServerEnabled=false,deployment=()=>({version:'1.0.7-r1',storage:'RAM'}))=>new Function('state_record','server_mode','auth_record','update_service','license_required','LICENSE_VERSION','type','length','match','trim',
    `return function(request) ${functionBody(source,'package_status').replace(/\bfor \(let (\w+) in /g,'for (let $1 of ')}`)(()=>({homeServerEnabled}),{enabled:state=>state.homeServerEnabled},()=>({changed:true}),
      {deployment,installed_modules:modules},()=>false,1,x=>typeof x,x=>x?.length??0,(s,re)=>s.match(re),s=>s.trim());
  const empty=factory(()=>[])({});
  const broken=factory(()=>{throw Error('unexpected module lookup');},false,()=>{throw Error('update_package_verification_failed');})({});
  assert.equal(broken.product,'foxhole');assert.equal(broken.installed,true);assert.equal(broken.pinConfigured,true);
  assert.equal(broken.packageUpdates,false);assert.equal(broken.updateVerificationUnavailable,true);
  assert.equal(broken.version,null);assert.equal(broken.storage,null);assert.equal(broken.installedModules,null);
  assert.equal(empty.updateVerificationUnavailable,false);
  assert.equal(empty.storage,'RAM');assert.deepEqual(empty.installedModules,[]);assert.equal(empty.homeServerEnabled,false);
  const unavailable=factory(()=>{throw Error('engine_package_verification_failed');},true)({});
  assert.equal(unavailable.version,'1.0.7-r1');assert.equal(unavailable.storage,'RAM');assert.equal(unavailable.installedModules,null);assert.equal(unavailable.homeServerEnabled,true);
});

test('About facts never fall back to an older update-job module list', async () => {
  const source=await read(`${panelRoot}/app.js`);
  const facts=new Function('installedPackage','updatePanel',`return function() ${functionBody(source,'versionFacts')}`)(
    {version:'1.0.7-r1',storage:'RAM',installedModules:null},
    {current:{currentVersion:'1.0.6-r1',installedModules:[{id:'vless',version:'1.0.3',storage:'RAM'}]}})();
  assert.equal(facts.modules,null);
  assert.equal(facts.version,'1.0.7-r1');
});

test('package discovery exposes only sanitized firmware/model/architecture and excludes board identifiers',async()=>{
 const source=await read('package/foxhole-openwrt-client/root/usr/share/rpcd/ucode/foxhole.uc');
 const build=board=>new Function('state_record','server_mode','auth_record','update_service','license_required','LICENSE_VERSION','type','length','match','trim','index','ubus','fs','ord',
  `return function(request) ${functionBody(source,'package_status').replace(/\bfor \(let (\w+) in /g,'for (let $1 of ')}`)(()=>({homeServerEnabled:false}),{enabled:state=>state.homeServerEnabled},()=>({changed:true}),{deployment:()=>({storage:'RAM',version:'1.0.7-r1'}),installed_modules:()=>[]},()=>false,1,
  x=>typeof x,x=>x?.length??0,(s,re)=>s.match(re),s=>s.trim(),(a,x)=>a.indexOf(x),{connect:()=>({call:()=>board,disconnect(){}})},
  {lstat:()=>({type:'file',uid:0,nlink:1,mode:0o644,size:20}),readfile:()=> 'aarch64_cortex-a53\n'},(value,index=0)=>value.charCodeAt(index));
 const value=build({model:'Cudy WR3000 v1',release:{description:'OpenWrt 25.12.5'},serial:'private-serial',mac:'private-mac',address:'private-address'})({});
 assert.deepEqual(value.routerInfo,{schema:1,firmwareVersion:'OpenWrt 25.12.5',model:'Cudy WR3000 v1',architecture:'aarch64_cortex-a53'});
 assert.doesNotMatch(JSON.stringify(value),/private-serial|private-mac|private-address/);
 for(const invalid of ['bad\0model','bad\nmodel','bad\x7fmodel','<script>'])assert.equal(build({model:invalid,release:{description:'OpenWrt 25.12.5'}})({}).routerInfo.model,null);
 const sanitized=build({model:'<script>',release:{description:'bad\nversion'}})({});assert.equal(sanitized.routerInfo.model,null);assert.equal(sanitized.routerInfo.firmwareVersion,null);assert.equal(sanitized.storage,'RAM');
});

test('router status adds only a parsed LAN literal address and keeps hardware facts when LAN discovery fails', async()=>{
 const source=await read('package/foxhole-openwrt-client/root/usr/share/rpcd/ucode/foxhole.uc');
 const build=(lan,failLan=false)=>new Function('state_record','server_mode','auth_record','update_service','license_required','LICENSE_VERSION','type','length','match','trim','index','ubus','fs','iptoarr','arrtoip','ord',
  `return function(request) ${functionBody(source,'package_status').replace(/\bfor \(let (\w+) in /g,'for (let $1 of ')}`)(()=>({homeServerEnabled:false}),{enabled:state=>state.homeServerEnabled},()=>({changed:true}),
  {deployment:()=>({storage:'RAM',version:'1.0.7-r2'}),installed_modules:()=>[]},()=>false,1,
  x=>x==null?'null':Array.isArray(x)?'array':typeof x,x=>x?.length??0,(s,re)=>s.match(re),s=>s.trim(),(a,x)=>a.indexOf(x),
  {connect:()=>({call:(object)=>{if(object==='system')return {model:'Cudy WR3000 v1',release:{description:'OpenWrt 25.12.5'}};if(failLan)throw Error('LAN not available');return lan;},disconnect(){}})},
  {lstat:()=>({type:'file',uid:0,nlink:1,mode:0o644,size:20}),readfile:()=> 'aarch64_cortex-a53\n'},
  x=>x==='10.66.66.10'?[10,66,66,10]:x==='2001:db8::1'?[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1]:null,
  bytes=>bytes.length===4?bytes.join('.'):'2001:db8::1',(value,index=0)=>value.charCodeAt(index))({});
 assert.equal(build({up:true,'ipv4-address':[{address:'10.66.66.10'}]}).routerInfo.lanAddress,'10.66.66.10');
 assert.equal(build({up:true,'ipv6-address':[{address:'2001:db8::1'}]}).routerInfo.lanAddress,'2001:db8::1');
 for(const address of ['router.example','10.66.66.999','10.66.66.10:8443','127.0.0.1;bad','<script>','fe80::1%br-lan'])
  assert.equal(build({up:true,'ipv4-address':[{address}]}).routerInfo.lanAddress,undefined);
 assert.equal(build({up:false,'ipv4-address':[{address:'10.66.66.10'}]}).routerInfo.lanAddress,undefined);
 const unavailable=build(null,true);assert.equal(unavailable.routerInfo.model,'Cudy WR3000 v1');assert.equal(unavailable.routerInfo.firmwareVersion,'OpenWrt 25.12.5');
 assert.equal(unavailable.routerInfo.lanAddress,undefined);
});

test('public package metadata request never forwards a session token absent from its RPC schema', async () => {
 const source=await read(`${panelRoot}/app.js`),sent=[];
 const call=new Function('request','token',`return async function(action,payload={}) ${functionBody(source.replace('async function api(action, payload = {})','async function api(action, payload)'),'api')}`)(async(action,payload)=>{sent.push({action,payload});return {};},'fixture-session');
 await call('package.status');await call('state');
 assert.deepEqual(sent[0],{action:'package.status',payload:{}});
 assert.equal(sent[1].payload.token,'fixture-session');
});

test('server toggle supplies the complete declared RPC wire fields on both enable and disable', async () => {
 const source=await read(`${panelRoot}/app.js`);
 for(const enabled of [false,true]){
  const sent=[],state={revision:7,settings:{}},views=[{name:enabled?'vpn-server-enable':'vpn-server-disable',data:{plan:{planSha256:'a'.repeat(64)}}}];
  const toggle=new Function('draftSaving','views','operation','api','state','applyState','draft','toast','t','back','renderSettings','PanelError',`return async function(enabled,removeComponent=false) ${functionBody(source,'setVpnServer')}`)(false,views,async fn=>fn(),async(action,payload)=>{sent.push({action,payload});return {schema:1};},state,()=>{},null,()=>{},x=>x,async()=>{},()=>{},Error);
  await toggle(enabled);
  assert.deepEqual(Object.keys(sent[0].payload).sort(),['confirmed','enabled','planSha256','removeComponent','revision']);
  assert.equal(sent[0].payload.confirmed,enabled);assert.equal(sent[0].payload.removeComponent,false);
  assert.equal(sent[0].payload.planSha256,enabled?'a'.repeat(64):'');
 }
});


test('modal header carries compact Manage and Close while configurations remain keyboard buttons', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const header = shell.split('<header class="modal-header">')[1].split('</header>')[0];
  assert.match(header, /class="modal-header-actions"[\s\S]*data-action="open-networks"[^>]*data-i18n-aria-label="action.manage"/);
  assert.match(header, /data-action="modal-dismiss"[^>]*data-i18n-aria-label="action.close"/);
  assert.match(shell, /<button class="server-control-card" type="button" data-action="edit-server" data-server-control-card>/);
  assert.match(shell, /<button class="server-control-card" type="button" data-action="manage-client" data-client-control-card>/);
  const app = await read(`${panelRoot}/app.js`);
  assert.ok(header.indexOf('data-modal-manage') < header.indexOf('data-modal-close'));
  assert.match(functionBody(app, 'renderServerControl'), /desired \? 'stop-server' : 'connect-server'/);
  assert.match(functionBody(app, 'renderServerControl'), /if \(!metrics.childElementCount\) metrics.append\(serverMetricGrid\(server\)\)/);
});

test('PIN bootstrap offers localized Russian and English loading before the app draws', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  assert.ok(shell.indexOf('pin-locale.js') < shell.indexOf('id="pin-gate"'));
  assert.match(shell, /lang="ru" class="pin-loading-ru">Загрузка/);
  assert.match(shell, /lang="en" class="pin-loading-en">Loading/);
  assert.match(shell, /id="pin-input" disabled/);
  const css = await read(`${panelRoot}/app.css`);
  assert.match(css, /html:lang\(ru\) \.pin-loading-en, html:not\(:lang\(ru\)\) \.pin-loading-ru/);
});


test('mobile dismiss intent requires a permitted primary touch and dominant vertical movement', () => {
  const surface = new EventTarget();
  let accepted = true, closed = 0;
  bindVerticalDismiss(surface,1,() => accepted,() => closed++);
  const emit = (type, x, y, pointerType = 'touch') => surface.dispatchEvent(Object.assign(new Event(type), {
    pointerType, pointerId:1, isPrimary:true, clientX:x, clientY:y
  }));
  emit('pointerdown', 4, 8); emit('pointerup', 8, 84);
  assert.equal(closed,1);
  emit('pointerdown', 0, 0); emit('pointerup', 70, 56);
  emit('pointerdown', 0, 0, 'mouse'); emit('pointerup', 0, 90, 'mouse');
  emit('pointerdown', 0, 90); emit('pointerup', 0, 0);
  emit('pointerdown', 0, 0); emit('pointercancel', 0, 0); emit('pointerup', 0, 90);
  accepted=false;
  emit('pointerdown', 0, 0); emit('pointerup', 0, 90);
  assert.equal(closed,1);
});
