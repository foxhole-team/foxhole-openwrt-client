import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { read, panelRoot, functionBody } from './helpers.mjs';

const source = await read(`${panelRoot}/app.js`);
const tree = () => ({ children: [], append(...items) {
  this.children.push(...items);
} });

function harness() {
  const notices = [];
  const context = vm.createContext({
    token: 'fixture', pinSetupRequired: false,
    state: { runtime: {}, servers: [{ id: 'one', name: 'VPN SERVER 01' }] },
    runtimeNoticeKey: null, connectedNoticeKey: null,
    connectionNoticeStarted: 0, now: 100,
    element: (tag, className, text) => ({ ...tree(), tag, className, text }),
    document: { createElement: tree, createTextNode: (text) => text },
    t: (key, values) => ({ key, values }),
    regionName: (code) => code, countryFlagPath: (code) => `${code}.svg`,
    errorText: (error) => error.code,
    toast: (message, kind) => notices.push({ message, kind })
  });
  vm.runInContext(`Date.now = () => now;
    function renderRuntimeNotice() ${functionBody(source, 'renderRuntimeNotice')}`,
  context);
  return {
    notices,
    update(runtime, now = context.now) {
      context.now = now;
      context.state.runtime = runtime;
      vm.runInContext('renderRuntimeNotice()', context);
    }
  };
}

const connected = { phase: 'connected', connected: true,
  activeServerId: 'one', desiredServerId: 'one', country: 'NL' };

test('connection popup carries name and flag once per connection', () => {
  const h = harness();
  h.update(connected);
  h.update(connected);
  assert.equal(h.notices.length, 1);
  const notice = h.notices[0].message;
  assert.equal(notice.children[0].text.values.name, 'VPN SERVER 01');
  assert.equal(notice.children[1].children[0].src, 'NL.svg');
  h.update({ phase: 'disconnected', connected: false });
  h.update(connected);
  assert.equal(h.notices.length, 3);
});

test('connection popup waits briefly for country without polling spam', () => {
  const h = harness();
  h.update({ ...connected, country: '' });
  h.update({ ...connected, country: '' }, 5100);
  assert.equal(h.notices.length, 0);
  h.update(connected, 6100);
  assert.equal(h.notices.length, 1);
  h.update(connected, 12100);
  assert.equal(h.notices.length, 1);
});

test('missing country cannot suppress connection notice indefinitely', () => {
  const h = harness();
  h.update({ ...connected, country: '' });
  h.update({ ...connected, country: '' }, 10100);
  assert.equal(h.notices.length, 1);
  h.update(connected, 15100);
  assert.equal(h.notices.length, 1);
});

test('runtime error is announced once and recovery can announce again', () => {
  const h = harness();
  const error = { phase: 'error', connected: false, error: 'runtime_failed' };
  h.update(error);
  h.update(error);
  assert.equal(h.notices.length, 1);
  assert.equal(h.notices[0].kind, 'error');
  h.update(connected);
  h.update(error);
  assert.equal(h.notices.length, 3);
});
