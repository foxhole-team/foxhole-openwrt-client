import { countryCode as country, countryFlagPath }
  from './frontend-model.js?v=0.1.0-r41-ui1';

const periods = { '24h': 86400000, '7d': 604800000, '30d': 2592000000 };
const number = (value) => value == null || value === '' || !Number.isFinite(Number(value)) ? null : Number(value);
export function setCountryLabel(node, value) {
  if (!node) return;
  const code = country(value);
  if (node.dataset.countryCode === code) {
    node.hidden = !code;
    return;
  }
  node.dataset.countryCode = code;
  node.replaceChildren();
  if (code) {
    const image = document.createElement('img');
    image.src = countryFlagPath(code);
    image.alt = '';
    image.width = 16;
    image.height = 12;
    node.append(image, document.createTextNode(code));
  }
  node.hidden = !code;
}

function setText(node, value) {
  if (node && node.textContent !== value) node.textContent = value;
}

function snapshot(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const time = number(value.time ?? value.t);
  if (time == null) return null;
  const iface = (key) => {
    const raw = value[key];
    if (!raw && value[`${key}Rx`] == null) return null;
    return {
      device: String(raw?.device || ''),
      address: String(raw?.address || ''),
      country: country(raw?.country ?? value[`${key}Country`]),
      rx: number(raw?.rx ?? value[`${key}Rx`]),
      tx: number(raw?.tx ?? value[`${key}Tx`])
    };
  };
  return {
    time,
    uptime: number(value.uptime),
    load: number(value.load),
    cpu: number(value.cpu),
    ram: number(value.ram),
    memory: value.memory || null,
    wan: iface('wan'),
    lan: iface('lan'),
    latency: {
      wan: number(value.latency?.wan ?? value.wanLatency),
      vpn: number(value.latency?.vpn ?? value.vpnLatency),
      serverId: value.latency?.serverId ?? value.vpnServerId ?? null
    }
  };
}

function historyRevision(history) {
  if (!history.length) return '0';
  const stamp = (value) => number(value?.time ?? value?.t) ?? '';
  return `${history.length}:${stamp(history[0])}:${stamp(history.at(-1))}`;
}

function normalizeSamples(values, now) {
  const cutoff = now - periods['30d'];
  const recent = now - 900000;
  const map = new Map();
  for (const raw of values) {
    const point = snapshot(raw);
    if (!point || point.time < cutoff || point.time > now + 60000) continue;
    const key = point.time >= recent ? point.time :
      Math.floor(point.time / 300000) * 300000;
    map.set(key, point);
  }
  return [...map.values()].sort((left, right) =>
    left.time - right.time).slice(-9000);
}

function insertSample(samples, point, cutoff) {
  let low = 0;
  let high = samples.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (samples[middle].time < point.time) low = middle + 1;
    else high = middle;
  }
  if (samples[low]?.time === point.time) samples[low] = point;
  else samples.splice(low, 0, point);
  low = 0;
  high = samples.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (samples[middle].time < cutoff) low = middle + 1;
    else high = middle;
  }
  if (low || samples.length > 9000)
    return samples.slice(Math.max(low, samples.length - 9000));
  return samples;
}

export function formatBytes(value, rate = false) {
  if (value == null || !Number.isFinite(value)) return '—';
  const units = rate ? ['B/s', 'KB/s', 'MB/s', 'GB/s'] : ['B', 'KB', 'MB', 'GB'];
  let amount = Math.max(0, value);
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index += 1; }
  return `${amount.toFixed(index ? 1 : 0)} ${units[index]}`;
}

export function decimateSeries(data, key, start, end, buckets) {
  if (data.length <= buckets * 2) return data;
  const selected = [];
  let bucket = -1;
  let values = [];
  const flush = () => {
    if (!values.length) return;
    let low = values[0];
    let high = values[0];
    for (const item of values) {
      if (item[key] < low[key]) low = item;
      if (item[key] > high[key]) high = item;
    }
    if (low.time <= high.time) selected.push(low, high);
    else selected.push(high, low);
    values = [];
  };
  for (const item of data) {
    if (item[key] == null) {
      flush();
      if (selected.at(-1)?.[key] != null) selected.push(item);
      continue;
    }
    const nextBucket = Math.min(buckets - 1, Math.max(0,
      Math.floor((item.time - start) / Math.max(1, end - start) * buckets)));
    if (bucket !== nextBucket) {
      flush();
      bucket = nextBucket;
    }
    values.push(item);
  }
  flush();
  return selected.filter((item, index, items) =>
    index === 0 || item !== items[index - 1]);
}

export class Charts {
  constructor(translate) {
    this.translate = translate;
    this.samples = [];
    this.period = '24h';
    this.vpn = {
      connected: false, serverId: null, name: '', address: '', country: ''
    };
    this.frame = 0;
    this.historyRevision = null;
    this.maintenanceAt = 0;
    this.colors = null;
    this.observedWidths = new WeakMap();
    this.canvases = Object.fromEntries(
      [...document.querySelectorAll('[data-chart]')].map((node) =>
        [node.dataset.chart, node]));
    this.meta = Object.fromEntries(Object.entries({
      cpu: '[data-meta-cpu]', ram: '[data-meta-ram]',
      rx: '[data-meta-rx]', tx: '[data-meta-tx]',
      wanAddress: '[data-meta-wan-address]',
      wanCountry: '[data-meta-wan-country]',
      vpnAddress: '[data-meta-vpn-address]',
      vpnCountry: '[data-meta-vpn-country]'
    }).map(([key, selector]) => [key, document.querySelector(selector)]));
    if ('ResizeObserver' in window) {
      this.observer = new ResizeObserver((entries) =>
        this.handleResize(entries));
      Object.values(this.canvases).forEach((canvas) =>
        this.observer.observe(canvas.parentElement));
    } else window.addEventListener('resize', () => this.draw());
  }

  update(payload) {
    const now = Date.now();
    const cutoff = now - periods['30d'];
    const recent = now - 900000;
    const history = Array.isArray(payload?.history) ? payload.history : [];
    const revision = historyRevision(history);
    const historyChanged = revision !== this.historyRevision;
    const maintain = now >= this.maintenanceAt;
    const point = snapshot(payload?.sample);
    if (historyChanged || maintain) {
      this.samples = normalizeSamples([
        ...this.samples, ...(historyChanged ? history : []), point
      ], now);
      this.historyRevision = revision;
      this.maintenanceAt = now + 300000;
    } else if (point && point.time >= cutoff && point.time <= now + 60000) {
      this.samples = point.time < recent
        ? normalizeSamples([...this.samples, point], now)
        : insertSample(this.samples, point, cutoff);
    } else {
      return;
    }
    this.draw();
  }

  clear() {
    this.samples = [];
    this.historyRevision = null;
    this.maintenanceAt = 0;
    this.draw();
  }
  setPeriod(value) {
    const next = periods[value] ? value : '24h';
    if (next === this.period) return;
    this.period = next;
    this.draw();
  }
  setVpnContext(value = {}) {
    const next = {
      connected: value.connected === true,
      serverId: value.serverId || null,
      name: String(value.name || ''),
      address: String(value.address || ''),
      country: country(value.country)
    };
    const seriesChanged = next.connected !== this.vpn.connected ||
      next.serverId !== this.vpn.serverId;
    this.vpn = next;
    this.syncVpnMeta();
    if (seriesChanged) this.draw();
  }
  latest() { return this.samples[this.samples.length - 1] || null; }

  handleResize(entries) {
    let changed = false;
    for (const entry of entries) {
      const width = Math.round(entry.contentRect.width * 100) / 100;
      if (this.observedWidths.get(entry.target) === width) continue;
      this.observedWidths.set(entry.target, width);
      changed = true;
    }
    if (changed) this.draw();
  }

  pointsBetween(start, end = Number.POSITIVE_INFINITY) {
    let low = 0;
    let high = this.samples.length;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (this.samples[middle].time < start) low = middle + 1;
      else high = middle;
    }
    const first = low;
    high = this.samples.length;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (this.samples[middle].time <= end) low = middle + 1;
      else high = middle;
    }
    return this.samples.slice(first, low);
  }

  rate(previous, current, key, direction) {
    const before = number(previous?.[key]?.[direction]);
    const after = number(current?.[key]?.[direction]);
    const seconds = previous ? (current.time - previous.time) / 1000 : 0;
    if (before == null || after == null || seconds <= 0 || after < before) return null;
    return (after - before) / seconds;
  }

  stats() {
    const cutoff = Date.now() - periods[this.period];
    const points = this.pointsBetween(cutoff);
    const result = { latest: this.latest(), wan: {}, lan: {} };
    for (const key of ['wan', 'lan']) {
      for (const direction of ['rx', 'tx']) {
        let total = 0;
        let elapsed = 0;
        let peak = null;
        for (let i = 1; i < points.length; i += 1) {
          const rate = this.rate(points[i - 1], points[i], key, direction);
          if (rate == null) continue;
          const seconds = (points[i].time - points[i - 1].time) / 1000;
          total += rate * seconds;
          elapsed += seconds;
          peak = Math.max(peak ?? 0, rate);
        }
        result[key][direction] = {
          total: peak == null ? null : total,
          average: elapsed ? total / elapsed : null,
          peak
        };
      }
    }
    return result;
  }

  rateSeries(key, direction, duration = 360000) {
    const cutoff = Date.now() - duration;
    const points = this.pointsBetween(cutoff);
    const values = [];
    for (let index = 1; index < points.length; index += 1) {
      const value = this.rate(points[index - 1], points[index], key,
        direction);
      if (value != null) values.push({ time: points[index].time, value });
    }
    return values;
  }

  syncVpnMeta(latest = this.latest()) {
    if (!this.meta) return;
    setText(this.meta.vpnAddress, this.vpn.address || '—');
    setCountryLabel(this.meta.vpnCountry, this.vpn.country);
    if (latest) {
      setText(this.meta.wanAddress, latest.wan?.address || '—');
      setCountryLabel(this.meta.wanCountry, latest.wan?.country);
    }
  }

  invalidateStyles() {
    this.colors = null;
    this.draw();
  }

  setSuspended(value) {
    this.suspended = value;
    if (value && this.frame) {
      cancelAnimationFrame(this.frame);
      this.frame = 0;
    }
    if (!value) this.draw();
  }

  getColors() {
    if (!this.colors) {
      const style = getComputedStyle(document.documentElement);
      this.colors = {
        label: style.getPropertyValue('--chart-label').trim(),
        grid: style.getPropertyValue('--chart-grid-line').trim(),
        color: [style.getPropertyValue('--chart-a').trim(),
          style.getPropertyValue('--chart-b').trim()],
        mono: [style.getPropertyValue('--chart-mono-a').trim(),
          style.getPropertyValue('--chart-mono-b').trim()]
      };
    }
    return this.colors;
  }

  axisFormatter(duration) {
    const locale = document.documentElement.lang;
    if (this.axisLocale !== locale) {
      this.axisLocale = locale;
      this.axisFormats = {};
    }
    const period = duration > periods['24h'] ? 'date' : 'time';
    return this.axisFormats[period] ||= new Intl.DateTimeFormat(locale,
      period === 'date' ? { day: '2-digit', month: '2-digit' }
        : { hour: '2-digit', minute: '2-digit', hour12: false });
  }

  draw() {
    if (this.frame || this.suspended || document.hidden) return;
    this.frame = requestAnimationFrame(() => {
      this.frame = 0;
      const styles = this.getColors();
      const now = Date.now();
      for (const [id, canvas] of Object.entries(this.canvases))
        this.render(canvas, id, now, styles);
    });
  }

  updateMeta(id, points) {
    const latest = points.at(-1) || this.latest();
    if (id === 'wrt') {
      setText(this.meta?.cpu, latest?.cpu == null
        ? '—%' : `${Math.round(latest.cpu)}%`);
      setText(this.meta?.ram, latest?.ram == null
        ? '—%' : `${Math.round(latest.ram)}%`);
      return;
    }
    if (id === 'network') {
      const previous = points.at(-2);
      const rx = this.rate(previous, latest, 'wan', 'rx');
      const tx = this.rate(previous, latest, 'wan', 'tx');
      setText(this.meta?.rx, formatBytes(rx, true));
      setText(this.meta?.tx, formatBytes(tx, true));
      return;
    }
    this.syncVpnMeta(latest);
  }

  render(canvas, id, end = Date.now(), styles = null) {
    const latency = id === 'wan-latency' || id === 'vpn-latency';
    const duration = id === 'wrt' || latency ? periods[this.period] : 780000;
    const start = end - duration;
    const points = this.pointsBetween(start, end);
    if (canvas.closest('.is-collapsed')) {
      this.updateMeta(id, points);
      return;
    }
    if (!canvas.clientWidth) return;
    const ratio = window.devicePixelRatio || 1;
    const width = Math.max(180, canvas.clientWidth);
    const height = Math.max(80, canvas.clientHeight);
    const pixelWidth = Math.round(width * ratio);
    const pixelHeight = Math.round(height * ratio);
    if (canvas.width !== pixelWidth) canvas.width = pixelWidth;
    if (canvas.height !== pixelHeight) canvas.height = pixelHeight;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, width, height);
    const key = 'wan';
    const data = points.map((point, index) => ({
      time: point.time,
      a: id === 'wrt' ? point.cpu : id === 'wan-latency'
        ? point.latency?.wan : id === 'vpn-latency'
          ? this.vpn.connected && point.latency?.serverId === this.vpn.serverId
            ? point.latency?.vpn : null
          : this.rate(points[index - 1], point, key, 'rx'),
      b: id === 'wrt' ? point.ram : latency ? null
        : this.rate(points[index - 1], point, key, 'tx')
    }));
    let peak = 0;
    for (const item of data)
      peak = Math.max(peak, item.a || 0, item.b || 0);
    const maximum = id === 'wrt' ? 100 : latency
      ? Math.max(10, Math.ceil(peak / 10) * 10) : Math.max(1024, peak);
    const pad = { left: id === 'wrt' ? 31 : latency ? 43 : 58,
      right: 7, top: 12, bottom: 19 };
    const plotWidth = width - pad.left - pad.right;
    const plotHeight = height - pad.top - pad.bottom;
    const x = (time) => pad.left + (time - start) / duration * plotWidth;
    const y = (value) => pad.top + plotHeight * (1 - Math.min(1, Math.max(0, value / maximum)));
    styles ||= this.getColors();
    ctx.font = '8px "JetBrains Mono", monospace';
    ctx.fillStyle = styles.label;
    ctx.strokeStyle = styles.grid;
    ctx.lineWidth = 1;
    for (let i = 0; i <= 3; i += 1) {
      const value = maximum * (1 - i / 3);
      const lineY = pad.top + plotHeight * i / 3;
      ctx.beginPath(); ctx.moveTo(pad.left, lineY); ctx.lineTo(width - pad.right, lineY); ctx.stroke();
      const label = id === 'wrt' ? `${Math.round(value)}%` : latency
        ? `${Math.round(value)} ms` : formatBytes(value, true);
      ctx.fillText(label, 1, lineY + 3);
    }
    const timeFormat = this.axisFormatter(duration);
    for (let i = 0; i <= 4; i += 1) {
      const lineX = pad.left + plotWidth * i / 4;
      ctx.beginPath(); ctx.moveTo(lineX, pad.top); ctx.lineTo(lineX, height - pad.bottom); ctx.stroke();
      const label = timeFormat.format(start + duration * i / 4);
      const textWidth = ctx.measureText(label).width;
      ctx.fillText(label, Math.max(pad.left, Math.min(width - pad.right - textWidth, lineX - textWidth / 2)), height - 3);
    }
    const gray = document.documentElement.classList.contains('theme-charts-gray');
    const colors = gray ? styles.mono : styles.color;
    (latency ? ['a'] : ['a', 'b']).forEach((series, index) => {
      const visible = decimateSeries(data, series, start, end,
        Math.max(1, Math.ceil(plotWidth)));
      ctx.strokeStyle = colors[index];
      ctx.lineWidth = 1.15;
      ctx.beginPath();
      let previous = null;
      for (const item of visible) {
        if (item[series] == null) { previous = null; continue; }
        const maxGap = duration >= periods['24h'] ? 360000 : 20000;
        if (!previous || item.time - previous.time > maxGap) ctx.moveTo(x(item.time), y(item[series]));
        else ctx.lineTo(x(item.time), y(item[series]));
        previous = item;
      }
      ctx.stroke();
      if (visible.length <= 160) {
        ctx.fillStyle = colors[index];
        for (const item of visible) {
          if (item[series] == null) continue;
          ctx.beginPath();
          ctx.arc(x(item.time), y(item[series]), .9, 0, Math.PI * 2);
          ctx.fill();
        }
      }
    });
    const hasData = data.some((item) => item.a != null || item.b != null);
    canvas.closest('[data-chart-card]').classList.toggle('has-data', hasData);
    this.updateMeta(id, points);
  }
}
