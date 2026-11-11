import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { read, packageRoot, functionBody } from './helpers.mjs';
import { initializeUpdatePolicy } from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/update-panel.js';

const source = await read(`${packageRoot}/root/usr/share/foxhole/update-model.uc`);
function model() {
 const scope = vm.createContext({
  type: value => value === null ? 'null' : Array.isArray(value) ? 'array' :
   typeof value === 'boolean' ? 'bool' : Number.isInteger(value) ? 'int' : typeof value,
  length: value => value.length, match: (value, regex) => value.match(regex), keys: Object.keys,
  index: (values, value) => values.indexOf(value), lc: value => value.toLowerCase(),
  die: reason => { throw new Error(reason); }
 });
 for (const [name, args] of [['fail', 'reason'], ['safe_int', 'value'], ['policy', 'value'],
  ['fresh_setup', 'auth,state,pairs,configured']])
  vm.runInContext(`function ${name}(${args}) ${functionBody(source, name)}`, scope);
 return scope;
}
function fresh() {
 return { auth: { changed: false, bootstrapBootId: 'synthetic-boot', bootstrapExpiresUptimeMs: 10000 },
  state: { schema: 1, revision: 0, activeServerId: null, countries: [], devices: [], sites: [], servers: [], clients: [] },
  pairs: { schema: 1, devices: [] } };
}
function status(configured, enabled = false, revision = 2) {
 return { schema: 1, supported: true, routerId: 'a'.repeat(64), revision,
  currentVersion: '1.0.6-r1', availableVersion: null, availability: 'NOT_CHECKED', lastCheckedAtUnixMs: null,
  failureReason: null, busy: false, installedModules: [], activeOwnJob: null, lastOwnJob: null,
  activeAutomaticJob: null, autoUpdate: { enabled, configured, intervalSeconds: 86400,
   lastAttemptAtUnixMs: null, nextCheckAtUnixMs: null, suspendedReason: null } };
}
test('only fresh first-PIN setup without a stored policy can offer the initial choice', () => {
 const value = fresh(), m = model();
 assert.equal(m.fresh_setup(value.auth, value.state, value.pairs, false), true);
 assert.equal(m.fresh_setup(value.auth, value.state, value.pairs, true), false);
 assert.equal(m.policy(null).enabled, false);
});
test('legacy missing policy, configured auth, reset and prior owner records remain untouched', () => {
 for (const mutate of [value => { delete value.auth.bootstrapBootId; },
  value => { value.auth.changed = true; }, value => { value.auth.resetPending = true; },
  value => { value.state.revision = 1; }, value => { value.state.servers = [{ id: 'existing' }]; },
  value => { value.pairs.devices = [{ id: 'existing' }]; }]) {
  const value = fresh(); mutate(value);
  assert.equal(model().fresh_setup(value.auth, value.state, value.pairs, false), false);
 }
});
test('fresh web setup persists the selected ON default or explicit OFF through authenticated Settings', async () => {
 for (const enabled of [true, false]) {
  const calls = [];
  const result = await initializeUpdatePolicy(true, enabled, async (action, payload) => {
   calls.push({ action, payload });
   return action === 'updates.status' ? status(false) : status(true, enabled, 3);
  });
  assert.equal(result.initialized, true);
  assert.deepEqual(calls, [{ action: 'updates.status', payload: undefined },
   { action: 'updates.settings', payload: { expectedRevision: 2, autoUpdateEnabled: enabled } }]);
 }
});
test('existing opt-out or an unknown legacy policy never triggers an initialization write', async () => {
 for (const configured of [true, undefined]) {
  const calls = [];
  const result = await initializeUpdatePolicy(true, true, async action => {
   calls.push(action); return status(configured);
  });
  assert.equal(result.initialized, false); assert.deepEqual(calls, ['updates.status']);
 }
 let calls = 0;
 await initializeUpdatePolicy(false, true, async () => { calls++; });
 assert.equal(calls, 0);
});
test('a concurrent policy change wins its revision and failed initialization is not replayed', async () => {
 const calls = [], failure = new Error('update_stale_session');
 await assert.rejects(initializeUpdatePolicy(true, true, async action => {
  calls.push(action);
  if (action === 'updates.status') return status(false);
  throw failure;
 }), error => error === failure);
 assert.deepEqual(calls, ['updates.status', 'updates.settings']);
});
test('the fresh web choice is selected separately above unchecked license acceptance', async () => {
 const shell = await read(`${packageRoot}/htdocs/luci-static/resources/foxhole/shell.html`);
 const template = shell.match(/<template id="tpl-pin-change"[\s\S]*?<\/template>/)[0];
 assert.match(template, /type="checkbox"[^>]+data-initial-auto-update[^>]+checked/);
 const consent = template.match(/<input[^>]+data-license-accept[^>]*>/)[0];
 assert.doesNotMatch(consent, /\bchecked\b/);
 assert.ok(template.indexOf('data-initial-auto-update') < template.indexOf('data-license-accept'));
 const app = await read(`${packageRoot}/htdocs/luci-static/resources/foxhole/app.js`);
 assert.match(app, /result\.autoUpdateSetupEligible === true && pinSetupRequired/);
 assert.match(app, /initializeUpdatePolicy\(true, autoUpdates, api\)/);
 assert.match(app, /openView\('updates', \{\}, true\)/);
});
