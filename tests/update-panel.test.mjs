import test from 'node:test';
import assert from 'node:assert/strict';
import { updateStatus, updateJob, updatePlan, UpdatePanel, availabilityLabel, updateBadgeKey } from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/update-panel.js';

const H = 'a'.repeat(64), B = 'b'.repeat(64);
function status() {
  return { schema: 1, supported: true, routerId: H, revision: 2, currentVersion: '1.0.0-r3',
    availableVersion: '1.0.1-r1', availability: 'AVAILABLE', lastCheckedAtUnixMs: 2000000000000,
    failureReason: null, busy: false, autoUpdate: { enabled: false, intervalSeconds: 86400,
      lastAttemptAtUnixMs: null, nextCheckAtUnixMs: null, suspendedReason: null },
    installedModules: [{ id: 'vless', storage: 'RAM', version: '1.0.0' }],
    activeOwnJob: null, lastOwnJob: null, activeAutomaticJob: null };
}
function job() {
  return { schema: 1, routerId: H, jobId: `update-job-${'b'.repeat(32)}`, planId: `update-plan-${'a'.repeat(32)}`,
    operation: 'APPLY', automatic: false, state: 'QUEUED', step: 'PREPARING', progressPercent: 0,
    revision: 3, failureReason: null, previousConnectionRestored: null };
}

test('menu badge distinguishes a verified update from verified current and never trusts Core-only evidence', () => {
  assert.equal(updateBadgeKey(status()), 'updates.badge_available');
  const current = { ...status(), availability: 'CURRENT', availableVersion: status().currentVersion };
  assert.equal(updateBadgeKey(current), null);
  for (const value of [{ ...current, lastCheckedAtUnixMs: null }, { ...current, busy: true },
    { ...current, availability: 'CHECK_FAILED' },
    { ...current, availability: 'NOT_CHECKED', coreAvailability: 'CURRENT', coreCohortSha256: H }])
    assert.equal(updateBadgeKey(value), null);
});
test('a delayed settings summary cannot paint an already reopened menu', async t => {
  const badge = () => ({ dataset:{}, hidden:true, isConnected:true, textContent:'',
    parentElement:{ setAttribute(){}, removeAttribute(){} } });
  const first = badge(), next = badge();
  let active = first, reply;
  const document = globalThis.document;
  globalThis.document = { querySelector: () => active };
  t.after(() => { globalThis.document = document; });
  const panel = new UpdatePanel({ call: () => new Promise(resolve => { reply = resolve; }), scope: () => 1, text: key => key });
  const pending = panel.summary();
  first.isConnected = false;
  active = next;
  reply(status()); await pending;
  assert.ok(next.hidden);
  assert.equal(next.textContent, '');
});

test('unchecked update availability adds no redundant status copy and never becomes CURRENT', () => {
  const value = { ...status(), availability: 'NOT_CHECKED', availableVersion: null };
  assert.equal(availabilityLabel(updateStatus(value), () => assert.fail('No unchecked label requested')), '');
  assert.equal(value.availability, 'NOT_CHECKED');
  for (const [availability, key] of [['CURRENT', 'up_to_date'], ['CHECK_FAILED', 'check_failed'], ['AVAILABLE', 'available'], ['UNSUPPORTED', 'unsupported']])
    assert.equal(availabilityLabel({ ...status(), availability, currentVersion:'1.0.9-r2', availableVersion:availability==='AVAILABLE'?'1.0.10-r1':'1.0.9-r2', lastCheckedAtUnixMs:1234, failureReason:null }, key => key), `updates.${key}`);
});
test('unverified and failed check statuses never become current', () => {
  for (const availability of ['NOT_CHECKED', 'CHECK_FAILED', 'UNSUPPORTED']) {
    const value = status(); Object.assign(value, { availability, availableVersion: null, supported: availability !== 'UNSUPPORTED',
      failureReason: availability === 'CHECK_FAILED' ? 'RELEASE_UNAVAILABLE' : null });
    assert.equal(updateStatus(value).availability, availability);
  }
  const value = status(); value.availability = 'CURRENT';
  assert.throws(() => updateStatus(value));
});
test('Core-only current preserves an unchecked BASE and uses a scoped label', () => {
  const value = { ...status(), availability: 'NOT_CHECKED', availableVersion: null,
    coreAvailability: 'CURRENT', coreCohortSha256: H, coreCohortRelay: 1 };
  assert.equal(availabilityLabel(updateStatus(value), key => key), 'updates.core_up_to_date');
  assert.equal(value.availability, 'NOT_CHECKED');
  for (const mutate of [v => { v.coreAvailability = 'FIRMWARE'; },
    v => { v.coreCohortSha256 = null; }, v => { v.coreCohortRelay = 2; }]) {
    const changed = structuredClone(value); mutate(changed); assert.throws(() => updateStatus(changed));
  }
});
test('unknown failure, cadence and automatic owner references fail closed', () => {
  for (const mutate of [v => { v.failureReason = 'UNKNOWN'; }, v => { v.autoUpdate.intervalSeconds = 1; },
    v => { v.autoUpdate.suspendedReason = 'PAIR_REVOKED'; }, v => { v.activeAutomaticJob = job(); }]) {
    const value = status(); mutate(value); assert.throws(() => updateStatus(value));
  }
});
test('manual job cannot impersonate automatic work or another router', () => {
  assert.equal(updateJob(job(), H).automatic, false);
  const value = job(); value.automatic = true; assert.throws(() => updateJob(value, H));
  assert.throws(() => updateJob(job(), B));
});
test('stale async response cannot update a different selected router', async () => {
  let resolve, router = 'router-a';
  const panel = new UpdatePanel({ call: () => new Promise(done => { resolve = done; }),
    text: x => x, element: () => null, show: async () => {}, scope: () => router, error: () => {} });
  panel.current = status(); panel.render = () => {};
  const pending = panel.action('check'); router = 'router-b'; resolve({ ...job(), operation: 'CHECK', planId: null });
  await pending; assert.equal(panel.job, null);
});

test('active legacy block is actionable on AVAILABLE but cannot masquerade as unsupported or CURRENT', () => {
  const value = status(); value.failureReason = 'LEGACY_CONNECTION_ACTIVE';
  value.autoUpdate.suspendedReason = 'LEGACY_CONNECTION_ACTIVE';
  assert.equal(updateStatus(value).supported, true);
  value.availability = 'CURRENT'; value.availableVersion = value.currentVersion;
  assert.throws(() => updateStatus(value));
});

test('unsupported equivalence and failed-check cause are strict across producers', () => {
  for (const mutate of [v => { v.supported = false; }, v => { v.currentVersion = null; },
    v => { v.availability = 'UNSUPPORTED'; },
    v => { v.availability = 'CHECK_FAILED'; v.failureReason = null; }]) {
    const value = status(); mutate(value); assert.throws(() => updateStatus(value));
  }
});

test('unavailable update status offers a pinned read-only retry without enabling installation', t => {
  const {panel,root,primary}=view(t);
  panel.render();
  assert.equal(root.children.some(node=>node.tag==='button'),false);
  assert.equal(primary.dataset.action,'update-check');
  assert.equal(primary.textContent,'updates.check');
  assert.equal(primary.disabled,false);
});

test('current wording and badge require a checked supported target and matching installed identity',()=>{
 const v={...status(),availability:'CURRENT',currentVersion:'1.0.9-r2',availableVersion:'1.0.9-r2',failureReason:null,lastCheckedAtUnixMs:1234};
 for(const delta of [{supported:false},{availableVersion:'1.0.8-r2'},{currentVersion:null,availableVersion:null},{lastCheckedAtUnixMs:null},{failureReason:'PACKAGE_VERIFICATION_FAILED'}]){
  const invalid={...v,...delta};
  assert.notEqual(availabilityLabel(invalid,key=>key),'updates.up_to_date');
  assert.equal(updateBadgeKey(invalid),null);
 }
 assert.equal(availabilityLabel(v,key=>key),'updates.up_to_date');
});

function view(t, call = async () => assert.fail('unexpected RPC')) {
  const element = (tag, className = '', textContent = '') => ({tag, className, textContent, dataset:{}, children:[],
    listeners:{}, replaceChildren(...nodes){this.children=nodes;}, append(...nodes){this.children.push(...nodes);},
    setAttribute(key,value){this[key]=value;}, addEventListener(key,fn){this.listeners[key]=fn;}});
  const root=element('section'), primary=element('button'), label=element('span'), use=element('use'), previous=globalThis.document;
  primary.querySelector=q=>q==='[data-i18n]'?label:use;
  Object.defineProperty(primary,'textContent',{get:()=>label.textContent});
  globalThis.document={querySelector:q=>q==='[data-update-detail]'?root:q==='[data-update-primary]'?primary:null};
  t.after(()=>{globalThis.document=previous;});
  const panel=new UpdatePanel({call, text:key=>key, element, icon:name=>element('svg','',name), scope:()=>1, error:()=>{}});
  const nodes=()=>{const all=[];function walk(n){all.push(n);n.children.forEach(walk);}walk(root);walk(primary);return all;};
  return {panel,nodes,root,primary};
}
const currentStatus = () => ({...status(),availability:'CURRENT',availableVersion:status().currentVersion});
function automatic(state,progressPercent=32) {
  return {state,progressPercent,automatic:true,operation:'CHECK',step:'DOWNLOADING_INDEX',failureReason:null};
}
test('idle confirmed CURRENT uses a shared check mark and has one pinned check action', t=>{
 const {panel,nodes}=view(t);panel.current=currentStatus();panel.current.lastOwnJob={...job(),state:'SUCCEEDED',progressPercent:100};panel.render();
 assert.deepEqual(nodes().filter(n=>n.tag==='button').map(n=>[n.dataset.action,n.textContent]),[['update-check','updates.check']]);
 assert.equal(nodes().filter(n=>n.tag==='input'&&n.type==='checkbox').length,1);
 const result=nodes().find(n=>n.className==='update-result');
 assert.ok(result.children.some(n=>n.className==='success-mark'&&n.children[0].textContent==='check'));
 assert.ok(result.children.some(n=>n.textContent==='updates.up_to_date'));assert.ok(!nodes().some(n=>n.tag==='progress'||n.textContent==='100%'));
 for(const v of [status(),{...currentStatus(),lastCheckedAtUnixMs:null},{...currentStatus(),busy:true},
  {...currentStatus(),availability:'NOT_CHECKED',coreAvailability:'CURRENT',coreCohortSha256:H}]){
  panel.current=v;panel.render();assert.ok(!nodes().some(n=>n.className==='success-mark'||n.textContent==='updates.up_to_date'));
 }
});
test('only a real active DOWNLOADING job gets a bar; automatic activity wins over prior own work', t=>{
 const {panel,nodes}=view(t);const previous={...job(),state:'SUCCEEDED',progressPercent:100};
 for(const phase of ['QUEUED','VERIFYING','CHECKING','INSTALLING','RECONNECTING','DOWNLOADING']){
  panel.current={...currentStatus(),lastOwnJob:previous,activeAutomaticJob:automatic(phase),busy:true};
  panel.job=previous;panel.render();
  const progress=nodes().filter(n=>n.tag==='progress');assert.equal(progress.length,phase==='DOWNLOADING'?1:0);
  assert.ok(nodes().some(n=>n.textContent==='updates.state_'+phase.toLowerCase()));
  assert.ok(!nodes().some(n=>n.textContent==='100%'||n.className==='success-mark'||n.textContent==='updates.up_to_date'));
  if(progress.length)assert.equal(progress[0].value,32);
 }
 panel.current={...status(),activeOwnJob:{...job(),state:'DOWNLOADING',step:'DOWNLOADING_PACKAGE'},busy:true};panel.job={...panel.current.activeOwnJob,progressPercent:48};
 panel.render();assert.equal(nodes().find(n=>n.tag==='progress').value,48);
});
test('checking release metadata never shows transfer progress; index and package transfers do', t=>{
 const {panel,nodes}=view(t);
 for(const own of [true,false]){
  for(const [step,percent] of [['CHECKING_RELEASE',5],['DOWNLOADING_INDEX',10],['DOWNLOADING_PACKAGE',20]]){
   const active=own?{...job(),state:'DOWNLOADING',step,progressPercent:percent}:{...automatic('DOWNLOADING',percent),step};
   panel.current={...status(),busy:true,activeOwnJob:own?active:null,activeAutomaticJob:own?null:active};
   panel.job=own?active:null;panel.render();
   const bars=nodes().filter(n=>n.tag==='progress'),labels=nodes().filter(n=>n.className==='update-progress-label');
   if(step==='CHECKING_RELEASE'){
    assert.equal(bars.length,0);assert.equal(labels.length,0);
   }else{
    assert.deepEqual(bars.map(bar=>bar.value),[percent]);assert.deepEqual(labels.map(label=>label.textContent),[percent+'%']);
   }
  }
 }
});
test('raw apply cannot be requested via the status action handler and lost writes are reconciled by reads',async t=>{
 const calls=[];let lose=true;
 const {panel,nodes}=view(t,async (name,body)=>{
  calls.push([name,body]);if(lose)throw Error('lost');
  return name==='updates.status'?status():{...status(),revision:3,autoUpdate:{...status().autoUpdate,enabled:true}};
 });
 panel.current=status();
 await panel.action('apply',{confirmed:true});await panel.action('plan');await panel.action('anything');
 await panel.action('settings',{autoUpdateEnabled:'true'});assert.equal(calls.length,0);
 await panel.action('check');assert.equal(panel.uncertain,true);assert.ok(nodes().find(n=>n.tag==='input').disabled);
 await panel.action('settings',{autoUpdateEnabled:true});assert.equal(calls.length,1);
 lose=false;await panel.action('check');assert.deepEqual(calls.map(c=>c[0]),['updates.check','updates.status']);
 await panel.action('settings',{autoUpdateEnabled:true,expectedRevision:999,arbitrary:true});
 assert.deepEqual(calls.at(-1),['updates.settings',{autoUpdateEnabled:true,expectedRevision:2}]);
 panel.close();
});
test('unavailable retry is read-only and a duplicate click while reading sends nothing',async t=>{
 let finish;const calls=[];const {panel,nodes}=view(t,name=>{calls.push(name);return new Promise(r=>{finish=r;});});
 panel.render();const pending=panel.action('check');await panel.action('check');
 assert.deepEqual(calls,['updates.status']);assert.ok(nodes().find(n=>n.tag==='button').disabled);
 finish(currentStatus());await pending;assert.equal(panel.current.availability,'CURRENT');panel.close();
});

test('session prefetch coalesces a status read and never reuses it for another router session',async t=>{
 let scope=1,finish;const calls=[];
 const {panel,nodes}=view(t,action=>{calls.push(action);return new Promise(done=>{finish=done;});});
 panel.scope=()=>scope;
 const warm=panel.warm(),open=panel.open();
 assert.deepEqual(calls,['updates.status']);
 finish(currentStatus());await Promise.all([warm,open]);
 panel.close();
 const next=panel.open();
 assert.ok(nodes().some(n=>n.className==='success-mark'),'verified status is shown while revalidating');
 assert.ok(nodes().filter(n=>n.tag==='button').every(n=>n.disabled));
 scope=2;finish(currentStatus());await next;assert.equal(panel.cached(),null);
});
test('background release check obeys opt-out, recency, suspension and busy gates and issues no apply',async t=>{
 for(const delta of [{},{enabled:false},{busy:true},{suspendedReason:'UNSUPPORTED_TARGET'},{recent:true}]){
  const calls=[],v={...currentStatus(),lastCheckedAtUnixMs:delta.recent?Date.now():1,busy:!!delta.busy};
  v.autoUpdate={...v.autoUpdate,enabled:delta.enabled!==false,suspendedReason:delta.suspendedReason||null};
  const {panel}=view(t,async action=>{calls.push(action);if(action==='updates.check')return {...job(),planId:null,operation:'CHECK'};return v;});
  await panel.warm();await panel.warm();
  assert.deepEqual(calls,Object.keys(delta).length?['updates.status']:['updates.status','updates.check','updates.status']);
 }
});
test('available has a download glyph, while current and unknown do not advertise an update',t=>{
 const {panel,nodes}=view(t);panel.current=status();panel.render();
 assert.ok(nodes().some(n=>n.className==='download-mark'&&n.children[0].textContent==='download'));
 for(const v of [currentStatus(),{...status(),currentVersion:status().availableVersion},{...status(),lastCheckedAtUnixMs:null}])assert.equal(updateBadgeKey(v),null);
 assert.equal(updateBadgeKey({...status(),currentVersion:status().availableVersion,coreAvailability:'AVAILABLE',coreCohortSha256:H}),'updates.badge_available');
});

test('only a confirmed available version marks both fields and says that a software update is required',t=>{
 const {panel,nodes}=view(t);
 for (const [value,confirmed] of [[status(),true],[currentStatus(),false],[{...status(),lastCheckedAtUnixMs:null},false],
  [{...status(),busy:true},false],[{...status(),availability:'CHECK_FAILED',failureReason:'PACKAGE_VERIFICATION_FAILED'},false]]) {
  panel.current=value;panel.render();
  assert.deepEqual(nodes().filter(n=>n.className==='is-update-available').map(n=>[n.tag,n.textContent]),
   confirmed ? [['dt','updates.available_version'],['dd',value.availableVersion]] : []);
  assert.equal(nodes().some(n=>n.textContent==='updates.required'),confirmed);
 }
});

function installPlan() {
 const s=status();return {schema:1,routerId:s.routerId,revision:s.revision,
  fromVersion:s.currentVersion,toVersion:s.availableVersion,engineIds:['vless'],
  planId:'update-plan-'+B.slice(0,32),planSha256:B,bootId:'fixture-boot',expiresAtUptimeMs:50000,
  confirmationRequired:true,impact:'RECONNECT_REQUIRED',
  changes:[{id:'foxhole',fromVersion:s.currentVersion,toVersion:s.availableVersion,storage:null}],
  budget:{downloadBytes:1024,stagingBytes:2048,flashRequiredBytes:4000,ramRequiredBytes:4000,flashAvailableBytes:8000,ramAvailableBytes:8000}};
}
test('install requires the exact available plan, explicit confirmation and matching apply job', async t=>{
 for(const confirmed of [false,true]){
  const s=status(),p=installPlan(),calls=[];let confirms=0;
  const {panel,primary,root}=view(t,async (name,data)=>{
   calls.push([name,data]);
   if(name==='updates.plan')return p;
   if(name==='updates.apply')return {...job(),planId:p.planId};
   return currentStatus();
  });
  panel.confirmPlan=message=>{confirms++;assert.ok(message.includes(p.fromVersion+' → '+p.toVersion));return confirmed;};
  panel.current=s;panel.render();
  assert.equal(primary.dataset.action,'update-install');
  assert.equal(root.children.some(n=>n.tag==='button'||n.textContent==='updates.auto_detail'),false);
  await panel.install();
  assert.equal(confirms,1);
  assert.deepEqual(calls.map(row=>row[0]),confirmed?['updates.plan','updates.apply','updates.status']:['updates.plan']);
  if(confirmed)assert.deepEqual(calls[1][1],{planId:p.planId,planSha256:p.planSha256,expectedRevision:p.revision,confirmed:true});
 }
});
test('a foreign, stale, over-budget or expanded plan never reaches confirmation',async t=>{
 const s=status();
 for(const change of [{routerId:B},{revision:3},{planSha256:'bad'},{toVersion:'2.0.0-r1'},
  {confirmationRequired:false},{engineIds:[]},{impact:'KEEP_ACTIVE'},
  {changes:[{id:'wireguard',fromVersion:'1.0',toVersion:'1.1',storage:'RAM'}]},
  {budget:{...installPlan().budget,ramAvailableBytes:1}}]){
  assert.throws(()=>updatePlan({...installPlan(),...change},s));
 }
 let confirms=0;const calls=[];
 const {panel,primary}=view(t,async action=>{calls.push(action);return {...installPlan(),revision:17};});
 panel.current=s;panel.confirmPlan=()=>{confirms++;return true;};
 await panel.install();assert.deepEqual(calls,['updates.plan']);assert.equal(confirms,0);assert.equal(primary.dataset.action,'update-check');
});
test('lost apply acknowledgement never sends apply twice or accepts another session',async t=>{
 const s=status(),p=installPlan(),calls=[];
 const {panel}=view(t,async action=>{calls.push(action);if(action==='updates.plan')return p;if(action==='updates.apply')throw Error('lost');return s;});
 panel.current=s;panel.confirmPlan=()=>true;await panel.install();await panel.install();
 await panel.action('check');assert.deepEqual(calls,['updates.plan','updates.apply','updates.status']);
 let done,scope=1;const late=view(t,action=>{assert.equal(action,'updates.plan');return new Promise(r=>{done=r;});}).panel;
 late.scope=()=>scope;late.current=s;late.confirmPlan=()=>assert.fail('stale confirmation');const pending=late.install();
 scope++;done(p);await pending;
});
