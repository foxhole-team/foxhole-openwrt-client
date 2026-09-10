import assert from 'node:assert/strict';
import test from 'node:test';
import {
  maskIpv4, maskMac, ModelError, normalizeMac, normalizeSitePattern,
  normalizedState, validAddress, normalizeSettings, countryCode,
  serverCountryCode
} from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/frontend-model.js';
import {
  Charts, decimateSeries, formatBytes
} from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/charts.js';

test('frontend model normalizes MAC and IP input without DOM state', () => {
  assert.equal(normalizeMac('02-11-22-33-44-55'), '02:11:22:33:44:55');
  assert.equal(normalizeMac('01:11:22:33:44:55'), null);
  assert.equal(normalizeMac('00:00:00:00:00:00'), null);
  assert.equal(maskMac('021122334455aa'), '02:11:22:33:44:55');
  assert.equal(maskIpv4('192168001001'), '192.');
  assert.equal(maskIpv4('192.168.1.1/128'), '192.168.1.1/12');
  assert.equal(validAddress('192.168.1.1/32'), true);
  assert.equal(validAddress('192.168.1.1/33'), false);
  assert.equal(validAddress('2001:db8::1/128'), true);
  assert.equal(validAddress('2001:db8::1/129'), false);
});

test('site patterns preserve the accepted host-only contract', () => {
  assert.equal(normalizeSitePattern('https://Example.COM/'), 'example.com');
  assert.equal(normalizeSitePattern('||example.com^'), 'example.com');
  assert.equal(normalizeSitePattern('*.example.com'), '*.example.com');
  assert.throws(() => normalizeSitePattern('https://example.com/path'),
    (error) => error instanceof ModelError &&
      error.code === 'site_path_unsupported');
  assert.throws(() => normalizeSitePattern('localhost'),
    (error) => error instanceof ModelError && error.code === 'invalid_site');
});

test('state normalization is deterministic and keeps runtime fail-closed', () => {
  const state = normalizedState({
    schema: 1,
    settings: { language: 'en', theme: 'light' },
    countries: ['us', { code: 'US', route: 'vpn' },
      { code: 'DE', route: 'vpn' }],
    devices: [{ id: 'one', address: '192.168.1.2', route: 'direct' }],
    sites: [{ id: 'site', pattern: 'example.com', route: 'vpn' }],
    servers: [], clients: []
  });
  assert.deepEqual(state.countries, [
    { code: 'US', route: 'direct' },
    { code: 'DE', route: 'vpn' }
  ]);
  assert.equal(state.settings.language, 'en');
  assert.equal(state.settings.theme, 'light');
  assert.deepEqual(state.runtime, {
    mode: 'runtime', phase: 'disconnected', connected: false,
    enforced: false, activeServerId: null, desiredServerId: null,
    interface: null, error: null, since: null, address: '', country: '',
    latency: null
  });
});

test('chart decimation bounds paint work and preserves extrema', () => {
  const data = Array.from({ length: 1000 }, (_, index) => ({
    time: index,
    a: index === 501 ? 10000 : index % 17,
    b: null
  }));
  const reduced = decimateSeries(data, 'a', 0, 999, 100);
  assert.ok(reduced.length <= 200);
  assert.ok(reduced.some((item) => item.a === 10000));
  assert.equal(reduced[0].time, 0);
  assert.equal(reduced.at(-1).time, 999);
  assert.equal(formatBytes(1024, true), '1.0 KB/s');
});

test('chart windows use sorted bounds without scanning old samples', () => {
  const charts = Object.create(Charts.prototype);
  charts.samples = Array.from({ length: 1000 }, (_, time) => ({ time }));
  assert.deepEqual(charts.pointsBetween(400, 403).map((item) => item.time),
    [400, 401, 402, 403]);
  assert.equal(charts.pointsBetween(998).length, 2);
  assert.equal(charts.pointsBetween(1001).length, 0);
});

test('unchanged telemetry history is normalized only once', (t) => {
  const now = 2000000000000;
  t.mock.method(Date, 'now', () => now);
  let reads = 0;
  const history = Array.from({ length: 1000 }, (_, index) => new Proxy({
    t: now - (999 - index) * 300000,
    cpu: index % 100,
    ram: 40,
    wanRx: index * 4096,
    wanTx: index * 2048,
    wanLatency: 15
  }, {
    get(target, key) {
      reads += 1;
      return target[key];
    }
  }));
  const charts = Object.create(Charts.prototype);
  Object.assign(charts, {
    samples: [], historyRevision: null, maintenanceAt: 0, draw() {}
  });
  charts.update({ history, sample: { time: now, cpu: 1 } });
  assert.ok(reads > history.length);
  reads = 0;
  charts.update({ history, sample: { time: now + 1, cpu: 2 } });
  assert.ok(reads < 10);
  assert.equal(charts.samples.at(-1).time, now + 1);
});

test('chart resize observer ignores height-only animation frames', () => {
  const charts = Object.create(Charts.prototype);
  let draws = 0;
  charts.observedWidths = new WeakMap();
  charts.draw = () => { draws += 1; };
  const target = {};
  charts.handleResize([{ target, contentRect: { width: 320, height: 100 } }]);
  charts.handleResize([{ target, contentRect: { width: 320, height: 50 } }]);
  charts.handleResize([{ target, contentRect: { width: 321, height: 50 } }]);
  assert.equal(draws, 2);
});

test('unchanged VPN chart context does not schedule a repaint', () => {
  const charts = Object.create(Charts.prototype);
  let draws = 0;
  Object.assign(charts, {
    vpn: { connected: false, serverId: null, name: '', address: '',
      country: '' },
    syncVpnMeta() {},
    draw() { draws += 1; }
  });
  charts.setVpnContext();
  charts.setVpnContext({ address: '192.0.2.1' });
  assert.equal(draws, 0);
  charts.setVpnContext({ connected: true, serverId: 'one' });
  assert.equal(draws, 1);
});

test('router status hiding defaults off and requires a boolean', () => {
  for (const hideRouterStatus of [undefined, null, false, 1, 'true']) {
    assert.equal(normalizeSettings({ hideRouterStatus }).hideRouterStatus,
      false);
  }
  assert.equal(normalizeSettings({ hideRouterStatus: true })
    .hideRouterStatus, true);
});

test('country labels use supported flags and never borrow another VPN', () => {
  assert.equal(countryCode('de'), 'DE');
  for (const code of ['ZZ', '', '../../us', 'US1'])
    assert.equal(countryCode(code), '');
  const server = { id: 'one' };
  const runtime = { connected: true, activeServerId: 'one', country: 'NL' };
  assert.equal(serverCountryCode(server, runtime), 'NL');
  assert.equal(serverCountryCode({ id: 'two' }, runtime), '');
  assert.equal(serverCountryCode(server, { ...runtime, connected: false }), '');
  assert.equal(serverCountryCode({ ...server, country: 'DE' }), 'DE');
});

test('chart axis formats follow the locale without repeated construction', (t) => {
  const priorDocument = globalThis.document;
  globalThis.document = { documentElement: { lang: 'ru' } };
  t.after(() => { globalThis.document = priorDocument; });
  const original = Intl.DateTimeFormat;
  let constructions = 0;
  t.mock.method(Intl, 'DateTimeFormat', function (...args) {
    constructions += 1;
    return new original(...args);
  });
  const charts = Object.create(Charts.prototype);
  const time = Date.UTC(2026, 8, 5, 12, 34);
  const periods = [86400000, 604800000];
  for (const lang of ['ru', 'en']) {
    document.documentElement.lang = lang;
    for (let draw = 0; draw < 20; draw += 1) {
      for (const duration of periods) {
        const actual = charts.axisFormatter(duration).format(time);
        const options = duration > 86400000
          ? { day: '2-digit', month: '2-digit' }
          : { hour: '2-digit', minute: '2-digit', hour12: false };
        assert.equal(actual, new original(lang, options).format(time));
      }
    }
  }
  assert.equal(constructions, 4);
});

test('router totals ignore missing counters and counter resets', (t) => {
  const now = 2000000000000;
  t.mock.method(Date, 'now', () => now);
  const charts = Object.create(Charts.prototype);
  charts.period = '24h';
  charts.samples = [
    { time: now - 8000, wan: { rx: 100, tx: 20 } },
    { time: now - 6000, wan: { rx: 300, tx: 20 } },
    { time: now - 2000, wan: { rx: 1500, tx: 20 } },
    { time: now, wan: { rx: 50, tx: null } }
  ];
  const stats = charts.stats();
  assert.deepEqual(stats.wan.rx, { total: 1400,
    average: 1400 / 6, peak: 300 });
  assert.deepEqual(stats.wan.tx, { total: 0, average: 0, peak: 0 });
  assert.deepEqual(stats.lan.rx, { total: null, average: null, peak: null });
  assert.equal(stats.latest, charts.samples.at(-1));
});
