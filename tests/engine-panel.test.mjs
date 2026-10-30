import assert from 'node:assert/strict';
import test from 'node:test';
import { EnginePanel, engineStatus, enginePlan } from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/engine-panel.js';

const status = () => ({ schema: 1, routerId: 'a'.repeat(64), catalogSha256: 'b'.repeat(64),
  revision: 7, busy: false, entries: [{ id: 'vless', installed: false, availability: 'AVAILABLE' }] });
const plan = () => ({ schema: 1, routerId: 'a'.repeat(64), revision: 7, operation: 'ADD',
  planId: `engine-plan-${'c'.repeat(32)}`, planSha256: 'd'.repeat(64), engineIds: ['vless'],
  impact: 'KEEP_ACTIVE', expiresAtUptimeMs: 301000, bootId: 'synthetic-boot',
  confirmationRequired: true, changes: [{ id: 'vless', storage: 'FLASH' }],
  budget: Object.fromEntries(['downloadBytes', 'stagingBytes', 'flashRequiredBytes',
    'ramRequiredBytes', 'flashAvailableBytes', 'ramAvailableBytes', 'reservedBytes'].map((key) => [key, 1])) });

test('engine controls accept known signed-catalog status only', () => {
  assert.equal(engineStatus(status()).entries[0].id, 'vless');
  for (const changed of [{ ...status(), revision: true },
    { ...status(), entries: [{ id: '../../sh', installed: true, availability: 'AVAILABLE' }] },
    { ...status(), entries: [...status().entries, ...status().entries] }])
    assert.throws(() => engineStatus(changed));
});

test('a plan for another router/revision/protocol or malformed resource budget is refused', () => {
  assert.equal(enginePlan(plan(), status(), 'ADD', 'vless').impact, 'KEEP_ACTIVE');
  for (const changed of [{ ...plan(), routerId: 'f'.repeat(64) }, { ...plan(), revision: 8 },
    { ...plan(), engineIds: ['wireguard'] }, { ...plan(), confirmationRequired: false },
    { ...plan(), budget: { ...plan().budget, ramRequiredBytes: -1 } }])
    assert.throws(() => enginePlan(changed, status(), 'ADD', 'vless'));
});

test('closing the sheet detaches a late response without issuing a remote cancellation', async () => {
  let resolve, renders = 0;
  const calls = [];
  const panel = new EnginePanel({ scope: () => 1, call: (action) => {
    calls.push(action); return new Promise((done) => { resolve = done; });
  }, error: (error) => { throw error; } });
  panel.renderList = () => { renders += 1; };
  const opened = panel.open();
  panel.close();
  resolve(status());
  await opened;
  assert.equal(renders, 0);
  assert.deepEqual(calls, ['engines.status']);
});
