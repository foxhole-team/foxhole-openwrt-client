import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import vm from 'node:vm';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { LogsPanel, parseLogSnapshot, parseJournalSnapshot } from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/logs-panel.js';
import { balanced } from './helpers.mjs';
const snapshot = () => ({ schema: 1, collectedAtUnixMs: 1700000000000, memAvailableKiB: 20000, uptimeSeconds: 100,
  runtime: { phase: 'connected', error: null }, package: { available: true, events: [] },
  core: { available: false, eventsAvailable: true, events: [] }, kernel: { available: true, events: [] } });
const journalSnapshot = (sequence = 10, hasMore = false) => ({ schema: 2, storage: 'FLASH', available: true, reason: null,
  retentionSeconds: 2592000, sharePercent: 2, limitBytes: 65536, reserveBytes: 1048576,
  totalRecords: 10, droppedRecords: 0, hasMore, beforeSequence: sequence,
  entries: [{ sequence, observedAtUnixMs: 1700000000000, source: 'package',
    event: { event: 'tunnel_exited', time: null, engine: 'core', exitStatus: 137 } }], snapshot: snapshot() });
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
  const request = panel.open(); panel.close(); finish(journalSnapshot()); await request;
  assert.equal(panel.value, null); assert.equal(panel.loading, false);
});

test('FLASH journal renders the versioned archive and loads older entries with a stable cursor', async () => {
  globalThis.document = { querySelector: () => null };
  const calls = [];
  const panel = new LogsPanel({ call: async (method, args) => { calls.push({ method, args });
    return journalSnapshot(args.beforeSequence ? 9 : 10, !args.beforeSequence); },
    text: x => x, scope: () => 1, storage: () => 'FLASH' });
  await panel.open(); await panel.refresh(true);
  assert.deepEqual(panel.archive.entries.map(x => x.sequence), [10, 9]);
  assert.deepEqual(calls.map(x => x.args.beforeSequence), [0, 10]);
  assert.ok(calls.every(x => x.method === 'diagnostics.journal'));
  panel.close();
});

test('journal parser rejects duplicate sequence IDs and unsafe observation timestamps', () => {
  assert.equal(parseJournalSnapshot(journalSnapshot()).available, true);
  const duplicate = journalSnapshot(); duplicate.entries.push(duplicate.entries[0]);
  assert.throws(() => parseJournalSnapshot(duplicate));
  const unsafe = journalSnapshot(); unsafe.entries[0].observedAtUnixMs = 8640000000000001;
  assert.throws(() => parseJournalSnapshot(unsafe));
});
test('new log RPC authorizes before running the log reader', () => {
  const source = readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/rpcd/ucode/foxhole.uc', import.meta.url), 'utf8');
  const marker = source.indexOf('const methods ='), registry = balanced(source, source.indexOf('{', marker));
  let reads = 0;
  const context = vm.createContext({ call: (_name, request, fn) => fn(request),
    session: request => { if (request.args.token !== 'accepted') throw Error('unauthorized'); },
    update_service: { deployment: () => ({ storage: 'FLASH' }) },
    logs: { status: () => { reads++; return { schema: 1 }; } } });
  const methods = vm.runInContext('(' + registry + ')', context);
  assert.throws(() => methods['diagnostics.logs'].call({ args: { token: 'rejected' } })); assert.equal(reads, 0);
  assert.equal(methods['diagnostics.logs'].call({ args: { token: 'accepted' } }).schema, 1); assert.equal(reads, 1);
});

test('journal RPC authorizes before reading or extending the FLASH ring', () => {
  const source = readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/rpcd/ucode/foxhole.uc', import.meta.url), 'utf8');
  const marker = source.indexOf('const methods ='), registry = balanced(source, source.indexOf('{', marker));
  let reads = 0;
  const context = vm.createContext({ call: (_name, request, fn) => fn(request),
    session: request => { if (request.args.token !== 'accepted') throw Error('unauthorized'); },
    update_service: { deployment: () => ({ storage: 'FLASH' }) },
    logs: { journal_status: () => { reads++; return { schema: 2 }; } } });
  const methods = vm.runInContext('(' + registry + ')', context);
  assert.throws(() => methods['diagnostics.journal'].call({ args: { token: 'rejected', beforeSequence: 0 } }));
  assert.equal(reads, 0);
  assert.equal(methods['diagnostics.journal'].call({ args: { token: 'accepted', beforeSequence: 0 } }).schema, 2);
  assert.equal(reads, 1);
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
  await panel.open(); assert.equal(panel.failed, true); assert.equal(panel.failureCode, 'tls_required'); panel.close();
});

test('RAM journal shows recent typed rows and refreshes only while open and visible', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  globalThis.document = { querySelector: () => null, hidden: false };
  const value = { ...journalSnapshot(), storage: 'RAM', available: false, reason: 'RAM_DISABLED',
    entries: [], totalRecords: 0, beforeSequence: 0, snapshot: { ...snapshot(), recent: [
      { event: 'tunnel_connected', engine: 'hysteria', observedAtUnixMs: 1700000000000, exitStatus: null }
    ] } };
  const calls = [];
  const panel = new LogsPanel({ call: async method => { calls.push(method); return value; }, text: x => x, scope: () => 1 });
  const first = panel.open();
  assert.deepEqual(calls, ['diagnostics.journal']);
  t.mock.timers.tick(599);
  await Promise.resolve();
  assert.equal(panel.loading, true);
  t.mock.timers.tick(1);
  await first;
  assert.equal(panel.ramDisabled, true);
  assert.deepEqual(panel.value.recent, value.snapshot.recent);
  t.mock.timers.tick(6000);
  assert.equal(calls.length, 2);
  await new Promise(setImmediate);
  document.hidden = true;
  panel.visibilityChanged();
  t.mock.timers.tick(6000);
  assert.equal(calls.length, 2);
  document.hidden = false;
  panel.visibilityChanged();
  assert.equal(calls.length, 3);
  panel.close();
  t.mock.timers.tick(6000);
  assert.equal(calls.length, 3);
});

test('RAM journal rejects oversized or untyped lifecycle events', () => {
  const value = snapshot();
  const row = { event: 'tunnel_exited', engine: 'core', observedAtUnixMs: 1700000000000, exitStatus: 137 };
  value.recent = [row];
  assert.equal(parseLogSnapshot(value).recent.length, 1);
  value.recent = Array(11).fill(row); assert.throws(() => parseLogSnapshot(value));
  value.recent = [{ ...row, event: 'secret' }]; assert.throws(() => parseLogSnapshot(value));
});

test('RAM backend never launches collectors even with ample free RAM', () => {
  const source = readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/log-service.uc', import.meta.url), 'utf8');
  let captures = 0;
  const fixture = new Function('fs', 'registry', 'model', 'time', 'match', 'filter',
    source.replace(/^import .*;$/gm, '').replace(/^export /gm, '') + ';return {status};')(
    { readfile: path => path === '/proc/meminfo' ? 'MemAvailable: 65536 kB\n' : '100.0 200.0', lstat: () => null },
    { capture: () => { captures++; return ''; } },
    { package_events: () => [], kernel_events: () => [], core_status: () => ({ available: false }),
      runtime_status: () => ({ phase: null, error: null }) },
    () => 1700000000, (x, re) => x.match(re), (a, fn) => a.filter(fn));
  const result = fixture.status('RAM');
  assert.equal(captures, 0);
  assert.equal(result.package.available, false);
  assert.equal(result.kernel.available, false);
});
