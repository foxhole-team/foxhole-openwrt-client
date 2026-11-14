import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { normalizeSettings } from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/frontend-model.js';
import { functionBody, read, panelRoot, rpcPath } from './helpers.mjs';
const source=readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/server-mode.uc',import.meta.url),'utf8');
const adapt=s=>s.replace(/^import .*;\n/gm,'').replace(/^export /gm,'');
const policy=new Function('digest','type','match','json','sprintf','die',`${adapt(source)}; return {enabled,require_enabled,plan,change,settings};`)(
  {sha256:s=>createHash('sha256').update(s).digest('hex')},x=>x==null?'null':Array.isArray(x)?'array':Number.isInteger(x)?'int':typeof x==='boolean'?'bool':typeof x,
  (s,re)=>s.match(re),JSON.parse,(_f,x)=>JSON.stringify(x),x=>{throw Error(x);});
const fact={schema:1,protocol:'hysteria2',kind:'verified-legacy-server',version:'2.8.2',binarySha256:'a'.repeat(64),binaryBytes:21495970};
const state=()=>({revision:7,settings:{language:'ru',vpnServerEnabled:false},clients:[{id:'client-000000000001',secret:'preserved'}],other:'preserved'});
test('fresh and older settings default server OFF, explicit true survives normalization',()=>{
  for(const value of [{},{vpnServerEnabled:false},{vpnServerEnabled:'true'}])assert.equal(normalizeSettings(value).vpnServerEnabled,false);
  assert.equal(normalizeSettings({vpnServerEnabled:true}).vpnServerEnabled,true);
  assert.equal(policy.enabled({settings:{}}),false);assert.throws(()=>policy.require_enabled(state()),/vpn_server_disabled/);
});
test('verified reusable component yields exact zero-download plan; absent component stays unavailable',()=>{
  const reuse=policy.plan(state(),fact);assert.equal(reuse.downloadBytes,0);assert.equal(reuse.available,true);assert.equal(reuse.component.version,'2.8.2');
  assert.equal(reuse.component.binarySha256,fact.binarySha256);assert.equal(reuse.action,'reuse');
  for(const bad of [null,{...fact,kind:'core-client'},{...fact,binarySha256:'guessed'},{...fact,binaryBytes:0}]){
    const plan=policy.plan(state(),bad);assert.equal(plan.available,false);assert.equal(plan.downloadBytes,null);
  }
});
test('enable requires explicit confirmation bound to current revision and verified component',()=>{
  const before=state(), plan=policy.plan(before,fact);
  for(const args of [{enabled:true,revision:7,confirmed:1,planSha256:plan.planSha256},{enabled:true,revision:7},{enabled:true,revision:7,confirmed:false,planSha256:plan.planSha256},{enabled:true,revision:6,confirmed:true,planSha256:plan.planSha256},{enabled:true,revision:7,confirmed:true,planSha256:'b'.repeat(64)}])assert.throws(()=>policy.change(before,args,fact));
  assert.throws(()=>policy.change(before,{enabled:true,revision:7,confirmed:true,planSha256:plan.planSha256},null),/vpn_server_unavailable/);
  const next=policy.change(before,{enabled:true,revision:7,confirmed:true,planSha256:plan.planSha256},fact);
  assert.equal(next.settings.vpnServerEnabled,true);assert.equal(next.revision,8);assert.deepEqual(next.clients,before.clients);assert.equal(before.settings.vpnServerEnabled,false);
});
test('disable preserves clients and unrelated settings and does not require downloads or a plan',()=>{
  const before=state();before.settings.vpnServerEnabled=true;
  const next=policy.change(before,{enabled:false,revision:7},null);
  assert.equal(next.settings.vpnServerEnabled,false);assert.deepEqual(next.clients,before.clients);assert.equal(next.other,before.other);assert.equal(next.settings.language,'ru');
});
test('cancel is read-only: a plan never changes state and has no download or native execution',()=>{
  const before=state(),copy=structuredClone(before);policy.plan(before,fact);policy.plan(before,null);assert.deepEqual(before,copy);
  assert.doesNotMatch(functionBody(source,'plan'),/system\(|download\(|write\(/);
});
test('server API/service gates reject disabled inbound paths and stale listeners cannot start',async()=>{
  const rpc=await read(rpcPath);for(const name of ['save_client','update_client','get_client','client_access'])assert.match(functionBody(rpc,name),/server_mode.require_enabled/);
  assert.match(functionBody(rpc,'phone_provision'),/createRemote[\s\S]*server_mode.require_enabled/);
  assert.match(functionBody(rpc,'settings_call'),/server_mode.settings/);
  for(const name of ['foxhole-inbound','foxhole-inbound-services']){
    const init=await read(`package/foxhole-openwrt-client/root/etc/init.d/${name}`);assert.match(init.slice(init.indexOf('start_service()')),/foxhole-server-enabled/);
  }
  const worker=await read('package/foxhole-openwrt-client/root/usr/libexec/foxhole-inbound');assert.match(worker,/if \(!server_mode.enabled\(state\)\)/);assert.match(worker,/publish_ports\(\[\]\)/);
});
test('clients hidden by backend setting and confirmation is separate from generic autosave',async()=>{
  const app=await read(`${panelRoot}/app.js`),html=await read(`${panelRoot}/shell.html`);
  assert.match(html,/data-vpn-server-section[^>]*hidden/);assert.match(html,/data-vpn-server-toggle/);
  assert.match(functionBody(app,'renderLists'),/vpnServerEnabled/);assert.match(functionBody(app,'setVpnServer'),/confirmed: enabled \|\| removeComponent/);
  assert.match(html,/https:\/\/github.com\/apernet\/hysteria/);
});

test('generic settings cannot enable or disable server implicitly and old clients preserve explicit state',()=>{const current=state();current.settings.vpnServerEnabled=true;assert.equal(policy.settings(current,{language:'en'}),true);assert.equal(policy.settings(current,{vpnServerEnabled:true}),true);assert.throws(()=>policy.settings(current,{vpnServerEnabled:false}),/confirmation_required/);assert.throws(()=>policy.settings(state(),{vpnServerEnabled:true}),/confirmation_required/);});

test('server switch follows kill switch and two-column settings require real adequate content width',async()=>{const html=await read(`${panelRoot}/shell.html`),css=await read(`${panelRoot}/app.css`);const view=html.split('id="tpl-settings-home"')[1].split('</template>')[0];assert.ok(view.indexOf('for="kill-switch"')<view.indexOf('data-vpn-server-toggle'));assert.ok(view.indexOf('data-vpn-server-toggle')<view.indexOf('data-action="open-exceptions"'));assert.match(css,/@container settings-view \(min-width: 760px\)/);assert.match(css,/grid-template-columns: repeat\(2, minmax\(0, 1fr\)\)/);});
