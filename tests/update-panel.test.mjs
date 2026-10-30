import test from 'node:test';
import assert from 'node:assert/strict';
import { updateStatus, updatePlan, updateJob, UpdatePanel } from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/update-panel.js';

const H = 'a'.repeat(64), B = 'b'.repeat(64);
function status() {
  return { schema: 1, supported: true, routerId: H, revision: 2, currentVersion: '1.0.0-r3',
    availableVersion: '1.0.1-r1', availability: 'AVAILABLE', lastCheckedAtUnixMs: 2000000000000,
    failureReason: null, busy: false, autoUpdate: { enabled: false, intervalSeconds: 86400,
      lastAttemptAtUnixMs: null, nextCheckAtUnixMs: null, suspendedReason: null },
    installedModules: [{ id: 'vless', storage: 'RAM', version: '1.0.0' }],
    activeOwnJob: null, lastOwnJob: null, activeAutomaticJob: null };
}
function plan() {
  return { schema: 1, routerId: H, revision: 2, planId: `update-plan-${'a'.repeat(32)}`,
    planSha256: B, fromVersion: '1.0.0-r3', toVersion: '1.0.1-r1', engineIds: ['vless'],
    changes: [{ id: 'foxhole', fromVersion: '1.0.0-r3', toVersion: '1.0.1-r1', storage: null }],
    impact: 'RECONNECT_REQUIRED', confirmationRequired: true, bootId: 'synthetic-boot', expiresAtUptimeMs: 300000,
    budget: Object.fromEntries(['downloadBytes', 'stagingBytes', 'flashRequiredBytes', 'flashAvailableBytes',
      'ramRequiredBytes', 'ramAvailableBytes', 'reservedBytes'].map(k => [k, 100])) };
}
function job() {
  return { schema: 1, routerId: H, jobId: `update-job-${'b'.repeat(32)}`, planId: plan().planId,
    operation: 'APPLY', automatic: false, state: 'QUEUED', step: 'PREPARING', progressPercent: 0,
    revision: 3, failureReason: null, previousConnectionRestored: null };
}
test('unverified and failed check statuses never become current', () => {
  for (const availability of ['NOT_CHECKED', 'CHECK_FAILED', 'UNSUPPORTED']) {
    const value = status(); Object.assign(value, { availability, availableVersion: null, supported: availability !== 'UNSUPPORTED',
      failureReason: availability === 'CHECK_FAILED' ? 'RELEASE_UNAVAILABLE' : null });
    assert.equal(updateStatus(value).availability, availability);
  }
  const value = status(); value.availability = 'CURRENT';
  assert.throws(() => updateStatus(value));
});
test('unknown failure, cadence and automatic owner references fail closed', () => {
  for (const mutate of [v => { v.failureReason = 'UNKNOWN'; }, v => { v.autoUpdate.intervalSeconds = 1; },
    v => { v.autoUpdate.suspendedReason = 'PAIR_REVOKED'; }, v => { v.activeAutomaticJob = job(); }]) {
    const value = status(); mutate(value); assert.throws(() => updateStatus(value));
  }
});
test('BASE replacement requires explicit reconnect and exact status versions', () => {
  assert.equal(updatePlan(plan(), status()).impact, 'RECONNECT_REQUIRED');
  for (const mutate of [v => { v.impact = 'KEEP_ACTIVE'; }, v => { v.fromVersion = '0.1.0-r41'; },
    v => { v.changes[0].storage = 'FLASH'; }]) {
    const value = plan(); mutate(value); assert.throws(() => updatePlan(value, status()));
  }
});
test('module-only update accepts exact equal BASE and preserves selected RAM', () => {
  const current = status(); current.availableVersion = current.currentVersion;
  const value = plan(); value.toVersion = current.currentVersion;
  value.changes = [{ id: 'vless', storage: 'RAM', fromVersion: '1.0.0', toVersion: '1.0.1' }];
  value.impact = 'KEEP_ACTIVE'; assert.equal(updatePlan(value, current), value);
  value.changes[0].storage = 'FLASH'; assert.throws(() => updatePlan(value, current));
});
test('empty plan, extra installed scope and extra budget fields are refused', () => {
  for (const mutate of [v => { v.changes = []; }, v => { v.engineIds.push('wireguard'); },
    v => { v.budget.allowUntrusted = 1; }, v => { v.budget.ramRequiredBytes = -1; }]) {
    const value = plan(); mutate(value); assert.throws(() => updatePlan(value, status()));
  }
});
test('manual job cannot impersonate automatic work or another router', () => {
  assert.equal(updateJob(job(), H).automatic, false);
  const value = job(); value.automatic = true; assert.throws(() => updateJob(value, H));
  assert.throws(() => updateJob(job(), B));
});
test('lost APPLY response prevents a second write until status recovery', async () => {
  const calls = [], panel = new UpdatePanel({ call: async (name) => { calls.push(name); throw new Error('lost-response'); },
    text: x => x, element: () => null, show: async () => {}, scope: () => 'router-a', error: () => {} });
  panel.current = status(); panel.plan = plan(); panel.render = () => {};
  await panel.apply(); await panel.apply();
  assert.deepEqual(calls, ['updates.apply']); assert.equal(panel.uncertain, true);
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
