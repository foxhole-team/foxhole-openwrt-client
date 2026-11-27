import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { isIPv4 } from 'node:net';
import test from 'node:test';
import vm from 'node:vm';
import { functionBody, read, panelRoot } from './helpers.mjs';
import { normalizeSettings } from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/frontend-model.js';

const base = new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/', import.meta.url);
const catalogText = readFileSync(new URL('game-routing.json', base), 'utf8');
const catalog = JSON.parse(catalogText);
const digest = value => createHash('sha256').update(value).digest('hex');
function runtime(raw = catalogText) {
  const source = readFileSync(new URL('runtime-model.uc', base), 'utf8').replace(/^import .*;$/gm, '').replace(/^export /gm, '')
    .replace(/\bfor\s*\(let (\w+) in /g, 'for (let $1 of ');
  const builtins = { fs:{ lstat: () => ({ type:'file', uid:0, nlink:1, mode:0o644, size:raw.length }), readfile: () => raw },
    digest:{sha256:digest}, length:value=>value?.length ?? 0, type:value=>Number.isInteger(value)?'int':typeof value,
    iptoarr:value=>value.split('.'), filter:(values,fn)=>values.filter(fn), join:(separator,values)=>values.join(separator),
    map:(values,fn)=>values.map(fn), push:(values,...items)=>values.push(...items), match:(value,re)=>value.match(re),
    split:(value,re)=>value.split(re), json:JSON.parse, die:code=>{throw Error(code);} };
  return new Function(...Object.keys(builtins), `${source}\nreturn {games_enabled,game_targets,nft_config,dnsmasq_config};`)(...Object.values(builtins));
}
const enabled = (settings = {}, countries = [{code:'DE',route:'direct'}]) => ({settings:{localRules:true,localScope:'all',gamesDirect:true,killSwitch:true,...settings},countries,
  devices:[{id:'device-000000000001',route:'vpn',address:'192.168.1.3'}]});
const options = { interfaces:['br-lan'], dnsUid:453, connected:true };

test('complete snapshot is bound to official game sources and admits only exact service tuples', () => {
  assert.equal(catalog.sdrIpv4Udp.length, 220);
  assert.equal(new Set(catalog.sdrIpv4Udp.map(row=>row[0])).size, 220);
  assert.ok(catalog.sdrIpv4Udp.every(([address,from,to])=>isIPv4(address)&&from>0&&to>=from&&to<=65535&&to-from<128));
  assert.deepEqual(Object.keys(catalog.valve), ['570','730']);
  assert.equal(catalog.epicFortnite.latencyHosts.length, 16);
  assert.equal(catalog.riotDirect.asn, 6507);
  assert.equal(catalog.riotDirect.visiblePrefixCount, 37);
  assert.deepEqual(catalog.riotDirect.udpPorts, [[5000,5500],[7000,8000]]);
  assert.ok(catalog.epicFortnite.latencyHosts.every(host=>/^ping-[a-z]+\.ds\.on\.epicgames\.com$/.test(host)));
  assert.equal(runtime().game_targets().sdr.length, 220);
  assert.equal(runtime().game_targets().latency.length, 16);
  assert.equal(runtime(catalogText.replace('101.206.160.192','127.0.0.1')).game_targets(), null);
});

test('game exceptions run only on a connected all-LAN direct-country policy and honor explicit VPN', () => {
  const plan = runtime(), games = plan.game_targets();
  const nft = plan.nft_config(enabled(), {...options,games});
  assert.match(nft, /type ipv4_addr \. inet_service\n\s+flags interval/);
  assert.match(nft, /101\.206\.160\.192 \. 27015-27044/);
  assert.match(nft, /ip daddr \. udp dport @game_sdr4 jump mark_direct/);
  assert.match(nft, /ip daddr \. udp dport @game_riot4 jump mark_direct/);
  assert.match(nft, /ip6 daddr \. udp dport @game_riot6 jump mark_direct/);
  assert.match(nft, /104\.160\.128\.0\/19 \. 5000-5500/);
  assert.match(nft, /ip daddr @game_ping4 icmp type echo-request jump mark_direct/);
  assert.match(nft, /ip6 daddr @game_ping6 icmpv6 type echo-request jump mark_direct/);
  const selected = nft.split('chain selected_rules {')[1].split('}')[0];
  assert.doesNotMatch(selected, /@game_/);
  assert.match(nft, /ip saddr 192\.168\.1\.3 goto selected_rules[\s\S]*jump scoped_rules[\s\S]*@game_sdr4/);
  assert.match(nft, /ip daddr @site_vpn4 jump mark_vpn/);
  for (const state of [enabled({gamesDirect:false}),enabled({localRules:false}),enabled({localScope:'selected'}),enabled({},[]),enabled({},[{code:'DE',route:'vpn'}])])
    assert.doesNotMatch(plan.nft_config(state,{...options,games}), /@game_/);
  assert.doesNotMatch(plan.nft_config(enabled(),{...options,bootstrap:true,games}), /@game_/);
  assert.doesNotMatch(plan.nft_config(enabled(),{...options,connected:false,games}), /@game_/);
  const dns = plan.dnsmasq_config([], games.latency);
  assert.match(dns, /nftset=\/ping-de\.ds\.on\.epicgames\.com\/4#inet#foxhole#game_ping4,6#inet#foxhole#game_ping6/);
  assert.doesNotMatch(dns, /nftset=\/ds\.on\.epicgames\.com\//);
});

test('old API clients preserve the stored opt-out and frontend defaults stay explicit', async () => {
  assert.equal(normalizeSettings({}).gamesDirect, true);
  assert.equal(normalizeSettings({gamesDirect:false}).gamesDirect, false);
  const source = await read('package/foxhole-openwrt-client/root/usr/share/rpcd/ucode/foxhole.uc');
  const state = { revision:2, settings:{gamesDirect:false,standaloneAccess:true} };
  const scope = vm.createContext({ engine_service:{guard_mutation(){}},session(){}, valid_revision:input=>input,
    locked:fn=>fn(), state_record:()=>state, runtime_model:{ runtime_fingerprint:()=>'' },
    model:{validate_settings:input=>({settings:{gamesDirect:true,...input.settings}})},
    server_mode:{settings:()=>false}, exists:(object,key)=>Object.hasOwn(object,key),
    replace_state:(live,_revision,checked)=>Object.assign(live,checked), public_state:current=>current,
    fail:code=>{throw Error(code);} });
  vm.runInContext(`function settings_call(request) ${functionBody(source,'settings_call')}`,scope);
  assert.equal(scope.settings_call({args:{revision:2,settings:{}}}).settings.gamesDirect,false);
  assert.equal(scope.settings_call({args:{revision:2,settings:{gamesDirect:true}}}).settings.gamesDirect,true);
  const shell = await read(`${panelRoot}/shell.html`);
  assert.match(shell, /href="#icon-gamepad"[\s\S]*class="switch"><input id="games-direct"[^>]*data-setting="gamesDirect"/);
});

test('games has one Settings toggle and routing remains reachable from Add', async () => {
  const app = await read(`${panelRoot}/app.js`);
  const body = functionBody(app, 'renderRules');
  assert.match(body, /routeCell\.append\(inlineRuleRoute\(type, id, route\)\)/);
  assert.match(body, /actionButton\(remove, 'trash', 'action\.delete', id\)/);
  assert.doesNotMatch(body, /gamesDirect|countryGamesToggle/);
  const shell = await read(`${panelRoot}/shell.html`);
  assert.equal([...shell.matchAll(/data-setting="gamesDirect"/g)].length, 1);
  assert.equal([...shell.matchAll(/data-action="open-exceptions"/g)].length, 1);
  assert.match(shell, /id="add-choice-routes"[^>]*data-action="open-exceptions"/);
  assert.doesNotMatch(app, /subscription_hint|data-subscription-hint/);
  assert.doesNotMatch(shell, /server\.subscription_hint|data-subscription-hint/);
});

test('directional icons use angular strokes and reinstall has balanced distinct arrows', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  for (const id of ['chevron','back','download','upload','play','refresh','reinstall'])
    assert.match(shell, new RegExp(`<symbol id="icon-${id}" viewBox="0 0 24 24" stroke-linecap="square" stroke-linejoin="miter">`));
  assert.match(shell, /id="icon-reinstall"[\s\S]*M4 11V7h15m-3-3 3 3-3 3M20 13v4H5m3-3-3 3 3 3/);
  assert.match(shell, /id="icon-refresh"[\s\S]*M20 6v5h-5M20 11l-5-5H8l-4 4v6l4 4h8l4-4/);
  assert.match(shell, /data-action="logs-refresh"[^>]*data-i18n-aria-label="logs.refresh"[\s\S]*?href="#icon-refresh"/);
  const panel = await read(`${panelRoot}/engine-panel.js`);
  assert.match(panel, /'engines\.reinstall', 'reinstall'/);
  assert.match(panel, /setAttribute\('aria-label', label\)/);
  const css = await read(`${panelRoot}/app.css`);
  assert.match(css, /\.help-chevron \{[^}]*rotate\(90deg\)[^}]*transition: transform/);
  assert.match(css, /\.help-disclosure\[open\] > summary \.help-chevron \{ transform: rotate\(-90deg\)/);
});

test('retrying a game-only save applies only the checkbox to freshly loaded rules', async () => {
  const app = await read(`${panelRoot}/app.js`);
  const previous = { revision:2, settings:{gamesDirect:true}, countries:[{code:'RU',route:'direct'}], devices:[], sites:[] };
  const latest = { revision:3, settings:{gamesDirect:true,killSwitch:true}, countries:[{code:'DE',route:'vpn'}], devices:[], sites:[] };
  let calls = 0;
  const context = vm.createContext({state:previous,draft:{...previous,settings:{gamesDirect:false}},draftSaving:false,draftSaved:0,
    draftChange:1,draftGeneralChange:0,draftGamesChange:1,draftSession:1,draftNoticeKey:'settings.saved', clone:structuredClone,
    storage:{set(){}}, t:value=>value,toast(){},syncGamesControls(){},refreshDraftView(){},errorText:err=>err.code,
    settingsDraft:()=>structuredClone(context.state), applyState:state=>{context.state=state;},
    api:async(method,payload)=>{
      if (method === 'state') return latest;
      if (++calls === 1) throw {code:'revision_conflict'};
      assert.equal(payload.revision,3);
      assert.deepEqual(payload.countries, latest.countries);
      assert.deepEqual(payload.settings, {gamesDirect:false,killSwitch:true});
      return {...payload,revision:4};
    }});
  vm.runInContext(`async function persistDraft() ${functionBody(app,'persistDraft')}`,context);
  await context.persistDraft();
  assert.equal(calls,2);
  assert.equal(context.draft.settings.gamesDirect,false);
  assert.equal(context.draft.revision,4);
});


test('editing route rules alone does not transmit a stale games preference', async () => {
  const app = await read(`${panelRoot}/app.js`);
  const previous = { revision:2, settings:{gamesDirect:true}, countries:[{code:'RU',route:'direct'}], devices:[], sites:[] };
  const context = vm.createContext({state:previous,draft:{...previous,countries:[]},draftSaving:false,draftSaved:0,
    draftChange:1,draftGeneralChange:1,draftGamesChange:0,draftSession:1,draftNoticeKey:'settings.saved', clone:structuredClone,
    storage:{set(){}},t:value=>value,toast(){},syncGamesControls(){},errorText:err=>err.code,
    applyState:state=>{context.state=state;},api:async(method,payload)=>{
      assert.equal(method,'settings');
      assert.deepEqual(payload.countries,[]);
      assert.equal(Object.hasOwn(payload.settings,'gamesDirect'),false);
      return {...payload,revision:3,settings:{gamesDirect:false}};
    }});
  vm.runInContext(`async function persistDraft() ${functionBody(app,'persistDraft')}`,context);
  await context.persistDraft();
  assert.equal(context.draft.revision,3);
  assert.equal(context.draft.settings.gamesDirect,false);
});
