import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Charts, chartDomain, continuousSamples, decimateSeries, segmentSeries }
  from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/charts.js';

const HOUR = 3600000, DAY = 24 * HOUR;
test('all four charts use the same selected day/week/month time domain', () => {
  const charts = Object.create(Charts.prototype), end = 2000000000000;
  const canvas = { closest: () => ({}) };
  charts.updateMeta = () => {};
  for (const period of ['24h', '7d', '30d']) {
    charts.period = period;
    const bounds = [];
    charts.pointsBetween = (...range) => { bounds.push(range); return []; };
    for (const id of ['wrt', 'network', 'wan-latency', 'vpn-latency']) charts.render(canvas, id, end);
    const { start } = chartDomain(period, end);
    assert.deepEqual(bounds, Array.from({ length: 4 }, () => [start, end]));
  }
});
test('valid sparse hourly preview samples form one line without adding samples or zeros', () => {
  const end = 2000000000000;
  const points = Array.from({ length: 12 }, (_, n) => ({ time: end - DAY + n * HOUR, a: 10 + n }));
  const before = structuredClone(points), line = segmentSeries(points, 'a', end);
  assert.equal(new Set(line.map(point => point.segment)).size, 1);
  assert.deepEqual(line.map(({ segment, ...point }) => point), points);
  assert.deepEqual(points, before);
});
test('explicit missing values, a large observed outage and known reboot remain separate segments', () => {
  const end = 2000000000000;
  const points = Array.from({ length: 9 }, (_, n) => ({ time: end - DAY + n * HOUR, a: 10 }));
  points[3].a = null;
  for (let n = 6; n < points.length; n++) points[n].time += 4 * HOUR;
  points[8].breakBefore = true;
  const line = segmentSeries(points, 'a', end);
  assert.equal(line[3].a, null);
  assert.notEqual(line[2].segment, line[4].segment);
  assert.notEqual(line[5].segment, line[6].segment);
  assert.notEqual(line[7].segment, line[8].segment);
});
test('decimation preserves continuity from source samples instead of treating reduced point spacing as data loss', () => {
  const end = 2000000000000, start = end - 30 * DAY;
  const points = Array.from({ length: 8000 }, (_, n) => ({ time: start + n * 300000, a: n % 13 }));
  const visible = decimateSeries(segmentSeries(points, 'a', end), 'a', start, end, 30);
  assert.ok(visible.length <= 60);
  assert.equal(new Set(visible.map(point => point.segment)).size, 1);
  assert.ok(visible.some((point, n) => n && point.time - visible[n - 1].time > 360000));
});
test('decimation never joins two source segments inside one pixel bucket', () => {
  const end = 2000000000000;
  const points = Array.from({ length: 100 }, (_, n) => ({ time: end - 10000 + n * 10, a: n === 50 ? null : n }));
  const visible = decimateSeries(segmentSeries(points, 'a', end), 'a', end - DAY, end, 1);
  const known = visible.filter(point => point.a != null);
  assert.ok(visible.some(point => point.a === null));
  assert.equal(new Set(known.map(point => point.segment)).size, 2);
});
test('traffic rates never average across known reboot, counter reset or device replacement', () => {
  const charts = Object.create(Charts.prototype);
  const previous = { time: 1000, uptime: 20000, wan: { device: 'wan', rx: 100 } };
  const current = { time: 2000, uptime: 20001, wan: { device: 'wan', rx: 200 } };
  assert.equal(charts.rate(previous, current, 'wan', 'rx'), 100);
  assert.equal(continuousSamples(previous, { ...current, uptime: 1 }), false);
  assert.equal(charts.rate(previous, { ...current, uptime: 1 }, 'wan', 'rx'), null);
  assert.equal(charts.rate(previous, { ...current, wan: { device: 'other', rx: 200 } }, 'wan', 'rx'), null);
  assert.equal(charts.rate(previous, { ...current, wan: { device: 'wan', rx: 0 } }, 'wan', 'rx'), null);
});
test('desktop settings uses content height bounded by the viewport and preserves mobile overflow', () => {
  const css = readFileSync(new URL('../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/app.css', import.meta.url), 'utf8');
  assert.match(css, /@media \(min-width: 721px\)[^]*?\.modal:is\(\.view-settings-home, \.view-interface-settings, \.view-pairings\)\[open\] \{ height: fit-content; max-height: calc\(var\(--viewport-height\) - 48px\); \}/);
  assert.match(css, /\.modal:is\(\.view-settings-home, \.view-interface-settings, \.view-pairings\) \.modal-stage \{ flex: 0 1 auto; \}/);
  assert.match(css, /\.modal-stage \{[^}]*min-height: 0;[^}]*overflow-y: auto;/);
  assert.match(css, /@media \(max-width: 720px\)/);
});
test('paired desktop modal fits the table within bounded viewport margins', () => {
  const css = readFileSync(new URL('../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/app.css', import.meta.url), 'utf8');
  const rule = css.match(/\.modal\.view-pairings \{ width: min\(calc\(100% - ([0-9]+)px\), ([0-9]+)px\); \}/);
  assert.ok(rule);
  const margin = Number(rule[1]), maximum = Number(rule[2]);
  const minimumTable = Number(css.match(/\.pairing-table \{[^}]*min-width: ([0-9]+)rem/)[1]) * 16;
  for (const viewport of [721, 800, 1024, 1440, 2560]) {
    const width = Math.min(viewport - margin, maximum);
    assert.ok(width <= viewport - margin);
    assert.ok(width - 28 >= minimumTable, 'Desktop panel padding must leave room for the table');
  }
  assert.match(css, /\.pairing-scroll \{ overflow-x: auto;/);
});
