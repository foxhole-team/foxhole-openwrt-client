import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { panelRoot, plain, read } from './helpers.mjs';

async function harness(mode = 'embedded') {
  const source = await read(`${panelRoot}/bridge.js`);
  const listeners = new Map();
  const sent = [];
  const fetches = [];
  const timers = new Map();
  const origin = 'http://router.invalid';
  let sequence = 0;
  const parent = { postMessage: (...args) => sent.push(plain(args)) };
  const window = { parent, addEventListener: (name, callback) => listeners.set(name, callback) };
  if (mode !== 'embedded') window.parent = window;
  const context = { window, parent: window.parent,
    location: { origin, protocol: mode === 'file' ? 'file:' : 'http:' },
    AbortController,
    fetch: (...args) => new Promise((resolve, reject) => {
      fetches.push({ args, resolve, reject });
    }),
    clearTimeout: (id) => timers.delete(id),
    setTimeout(callback) { timers.set(++sequence, callback); return sequence; } };
  vm.createContext(context);
  vm.runInContext(`${source.replace(/\bexport /g, '')}\n` +
    'globalThis.api = { request, cancelPending };', context, { timeout: 1000 });
  return { ...context.api, sent, fetches, timers, parent, origin,
    receive(data, overrides = {}) {
      listeners.get('message')({ origin, source: parent, data, ...overrides });
    } };
}

test('bridge resolves only the matching same-origin host response', async () => {
  const bridge = await harness();
  const request = bridge.request('state', { token: 'fixture-token' });
  const [message, target] = bridge.sent[0];
  assert.equal(target, bridge.origin);
  assert.equal(message.source, 'foxhole-panel');
  const response = { source: 'foxhole-host', id: message.id, result: { revision: 3 } };
  bridge.receive(response, { origin: 'https://foreign.invalid' });
  bridge.receive(response, { source: {} });
  bridge.receive({ ...response, id: 'unknown' });
  bridge.receive({ ...response, source: 'other' });
  assert.equal(bridge.timers.size, 1);
  bridge.receive(response);
  assert.deepEqual(plain(await request), { revision: 3 });
  assert.equal(bridge.timers.size, 0);
});

test('bridge exposes bounded error codes and cancels pending work', async () => {
  const bridge = await harness();
  const failed = bridge.request('state');
  const failedCheck = assert.rejects(failed, { code: 'revision_conflict' });
  bridge.receive({ source: 'foxhole-host', id: bridge.sent[0][0].id,
    error: { code: 'revision_conflict' } });
  await failedCheck;
  const cancelled = bridge.request('state');
  const cancelledCheck = assert.rejects(cancelled, { code: 'locked' });
  bridge.cancelPending();
  await cancelledCheck;
  assert.equal(bridge.timers.size, 0);
});

test('bridge timeout fails closed and local files cannot call RPC', async () => {
  const bridge = await harness();
  const expired = bridge.request('state');
  const expiredCheck = assert.rejects(expired, { code: 'unavailable' });
  [...bridge.timers.values()][0]();
  await expiredCheck;
  const local = await harness('file');
  await assert.rejects(local.request('state'), { code: 'host_required' });
  assert.equal(local.sent.length, 0);
  assert.equal(local.fetches.length, 0);
});

test('standalone bridge uses same-origin JSON gateway', async () => {
  const bridge = await harness('direct');
  const response = bridge.request('state', { token: 'fixture-token' });
  assert.equal(bridge.sent.length, 0);
  assert.equal(bridge.fetches.length, 1);
  const [url, options] = bridge.fetches[0].args;
  assert.equal(url, '/cgi-bin/foxhole');
  assert.equal(options.method, 'POST');
  assert.equal(options.credentials, 'same-origin');
  assert.deepEqual(JSON.parse(options.body), {
    action: 'state', payload: { token: 'fixture-token' }
  });
  bridge.fetches[0].resolve({ ok: true,
    json: async () => ({ revision: 4 }) });
  assert.deepEqual(plain(await response), { revision: 4 });
});

test('standalone bridge keeps gateway errors bounded and aborts on lock', async () => {
  const bridge = await harness('direct');
  const denied = bridge.request('state');
  bridge.fetches[0].resolve({ ok: false,
    json: async () => ({ _foxhole_error: 'luci_required' }) });
  await assert.rejects(denied, { code: 'luci_required' });
  const cancelled = bridge.request('state');
  const signal = bridge.fetches[1].args[1].signal;
  bridge.cancelPending();
  await assert.rejects(cancelled, { code: 'locked' });
  assert.equal(signal.aborted, true);
});
