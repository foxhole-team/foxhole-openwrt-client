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
 for (const [name, args] of [['fail', 'reason'], ['safe_int', 'value'], ['initial_owner_policy', 'auth'],
  ['policy', 'value,auth'], ['empty_install', 'state,pairs'], ['first_owner_choice', 'auth,offered,requested,configured'],
  ['fresh_setup', 'auth,state,pairs,configured']])
  vm.runInContext(`function ${name}(${args}) ${functionBody(source, name).replace(/for \(let (\w+) in /g, 'for (let $1 of ')}`, scope);
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
test('the first owner commits the effective choice while bootstrap and unclaimed legacy remain off', () => {
 const m = model(), original = fresh().auth;
 for (const offered of [true, false, null]) {
  for (const requested of [true, false, null]) {
   const saved = m.first_owner_choice(original, offered, requested, false);
   const enabled = offered === null ? null : offered && requested !== false;
   assert.equal(saved, enabled);
   assert.equal(m.policy(null, original).enabled, false);
   const owner = { changed: true, initialPackageAutoUpdate: saved };
   assert.equal(m.policy(null, owner).enabled, enabled === true);
   assert.equal(m.first_owner_choice(owner, true, !enabled, false), enabled);
   assert.equal(m.first_owner_choice(original, offered, requested, true), null);
  }
 }
 const storedOff = { schema: 1, revision: 6, enabled: false, lastAttemptAtUnixMs: null };
 assert.equal(m.policy(storedOff, { changed: true, initialPackageAutoUpdate: true }), storedOff);
 assert.equal(m.first_owner_choice({ changed: false, resetPending: true, initialPackageAutoUpdate: false }, true, true, false), false);
 assert.throws(() => m.policy(null, { changed: true, initialPackageAutoUpdate: 'false' }), /recovery_required/);
});

test('legacy web setup persists the selected choice through authenticated Settings', async () => {
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

test('the modern panel sends the first choice with the PIN in one request and preserves the legacy flow', async () => {
 const app = await read(`${packageRoot}/htdocs/luci-static/resources/foxhole/app.js`);
 for (const atomic of [true, false]) {
  for (const offered of [true, false]) {
   for (const selected of [true, false]) {
    const calls = [], fallback = [];
    const form = { classList: { remove() {} }, reset() {} };
    const elements = { '[data-pin-change-form]': form, '[data-new-pin]': { value: '123456' },
     '[data-repeat-pin]': { value: '123456' }, '[data-license-accept]': { checked: true },
     '[data-initial-auto-update]': { checked: selected } };
    const context = vm.createContext({ $: key => elements[key], token: null, pinSetupRequired: true,
     licenseRequired: true, licenseRequiredVersion: 1, LICENSE_VERSION: 1, autoUpdateSetupEligible: offered,
     initialAutoUpdateSupported: atomic, operation: async fn => fn(), t: value => value, toast() {},
     openView: async () => {}, poll() {}, api: async (action, payload) => {
      calls.push({ action, payload });
      return { token: 'b'.repeat(64), autoUpdateSetupEligible: offered };
     }, initializeUpdatePolicy: async (eligible, enabled) => fallback.push([eligible, enabled]) });
    vm.runInContext(`async function savePin() ${functionBody(app, 'savePin')}`, context);
    await context.savePin();
    assert.deepEqual(JSON.parse(JSON.stringify(calls)), [{ action: 'pin.change', payload: {
     newPin: '123456', ...(atomic && offered ? { initialAutoUpdateEnabled: selected } : {}),
     licenseAccepted: true, licenseVersion: 1 } }]);
    assert.deepEqual(fallback, !atomic && offered ? [[true, selected]] : []);
   }
  }
 }
});
