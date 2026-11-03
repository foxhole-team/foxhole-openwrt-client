import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import vm from 'node:vm';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { LogsPanel, parseLogSnapshot } from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/logs-panel.js';
import { balanced } from './helpers.mjs';
const snapshot = () => ({ schema: 1, collectedAtUnixMs: 1700000000000, memAvailableKiB: 20000, uptimeSeconds: 100,
  runtime: { phase: 'connected', error: null }, package: { available: true, events: [] },
  core: { available: false, eventsAvailable: true, events: [] }, kernel: { available: true, events: [] } });
test('log panel rejects malformed records and oversized event lists', () => {
  assert.equal(parseLogSnapshot(snapshot()).schema, 1);
  const value = snapshot(); value.kernel.events = Array(33).fill({}); assert.throws(() => parseLogSnapshot(value));
  const malformed = snapshot(); malformed.package.events = [{ event: '<script>', engine: 'core', exitStatus: 1 }];
  assert.throws(() => parseLogSnapshot(malformed));
});
test('closing log modal discards a late request and cached session data', async () => {
  globalThis.document = { querySelector: () => null };
  let finish;
  const panel = new LogsPanel({ call: () => new Promise(resolve => { finish = resolve; }), text: x => x, scope: () => 1 });
  const request = panel.open(); panel.close(); finish(snapshot()); await request;
  assert.equal(panel.value, null); assert.equal(panel.loading, false);
});
test('new log RPC authorizes before running the log reader', () => {
  const source = readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/rpcd/ucode/foxhole.uc', import.meta.url), 'utf8');
  const marker = source.indexOf('const methods ='), registry = balanced(source, source.indexOf('{', marker));
  let reads = 0;
  const context = vm.createContext({ call: (_name, request, fn) => fn(request),
    session: request => { if (request.args.token !== 'accepted') throw Error('unauthorized'); },
    logs: { status: () => { reads++; return { schema: 1 }; } } });
  const methods = vm.runInContext('(' + registry + ')', context);
  assert.throws(() => methods['diagnostics.logs'].call({ args: { token: 'rejected' } })); assert.equal(reads, 0);
  assert.equal(methods['diagnostics.logs'].call({ args: { token: 'accepted' } }).schema, 1); assert.equal(reads, 1);
});
test('owned capture refuses arbitrary log arguments before starting a command', () => {
  const helper = new URL('../package/foxhole-openwrt-client/root/usr/libexec/foxhole-engine-command-v2', import.meta.url);
  for (const argv of [['/sbin/logread', '-f'], ['/sbin/logread', '-l', '128', '-e', 'secret'], ['/bin/dmesg', '/etc/shadow']]) {
    const result = spawnSync('/bin/sh', [helper.pathname, '/tmp/foxhole/engine-command-logs-test', '4096', '1000', ...argv], { timeout: 3000 });
    assert.equal(result.status, 1); assert.equal(existsSync('/tmp/foxhole/engine-command-logs-test'), false);
  }
});

test('TLS failure remains a distinct visible log error', async () => {
  globalThis.document = { querySelector: () => null };
  const panel = new LogsPanel({ call: async () => { throw { code: 'tls_required' }; }, text: x => x, scope: () => 1 });
  await panel.open(); assert.equal(panel.failed, true); assert.equal(panel.failureCode, 'tls_required');
});
