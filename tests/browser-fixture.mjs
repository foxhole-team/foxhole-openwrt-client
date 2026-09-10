import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defaultSettings } from '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/frontend-model.js';

// Isolated UI data; never proxy requests to a router.
const root = fileURLToPath(new URL(
  '../package/foxhole-openwrt-client/htdocs/luci-static/resources/foxhole/',
  import.meta.url));
const legacy = process.argv.includes('--legacy-popups');
const profile = process.argv.includes('--profile');
const longRules = process.argv.includes('--long-rules');
let firstRun = process.argv.includes('--first-run');
const port = longRules ? 8097 : firstRun ? 8096 : profile ? 8095 : legacy ? 8093 : 8092;
const state = {
  schema: 1, revision: 0,
  settings: { ...defaultSettings, theme: 'light' },
  servers: [{ id: 'server-fixture', name: 'VPN SERVER 01',
    endpoint: 'vpn.example.invalid:443', protocol: 'hysteria2',
    country: 'NL', metrics: {} }],
  clients: [{ id: 'client-fixture', name: 'UI fixture phone',
    deviceType: 'smartphone', serverId: 'server-fixture', metrics: {} }],
  countries: [{ code: 'DE', route: 'vpn' }],
  devices: [{ id: 'device-fixture', name: 'Fixture device',
    address: '192.0.2.1', route: 'direct' }],
  sites: [{ id: 'site-fixture', pattern: 'example.invalid', route: 'direct' }],
  runtime: { mode: 'runtime', phase: 'connected', connected: true,
    enforced: true, activeServerId: 'server-fixture',
    desiredServerId: 'server-fixture',
    country: 'NL', address: '198.51.100.1', latency: 20 }
};
if (longRules) state.sites = Array.from({ length: 24 }, (_, index) => ({
  id: `site-fixture-${index}`, pattern: `example${index}.invalid`,
  route: index % 2 ? 'vpn' : 'direct'
}));
let samples = 0;
const exportClient = (client) => ({
  ...client, uri: `hysteria2://ui-fixture@vpn.example.invalid:443/#${encodeURIComponent(client.name)}`,
  qrSvg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><path d="M1 1h3v3H1zM6 1h3v3H6zM1 6h3v3H1zM6 6h3v3H6z"/></svg>'
});

function request(action, payload) {
  if (action === 'unlock') return {
    token: 'ui-fixture', state, pinChangeRequired: firstRun
  };
  if (action === 'pin.change') {
    firstRun = false;
    return { token: 'ui-fixture-next' };
  }
  if (action === 'state') return state;
  if (action === 'telemetry') {
    samples += 1;
    return { available: true, runtime: state.runtime,
      sample: { time: Date.now(), cpu: samples % 25,
      ram: 30, wan: { address: '192.0.2.2', country: 'US',
        rx: samples * 1024, tx: samples * 512 },
      vpn: { address: '198.51.100.1', country: 'NL',
        rx: samples * 2048, tx: samples * 1024 },
      latency: { wan: 14, vpn: 20, serverId: 'server-fixture' } } };
  }
  if (action === 'settings') {
    if (payload.revision !== state.revision)
      return { _foxhole_error: 'revision_conflict' };
    for (const key of ['settings', 'countries', 'devices', 'sites'])
      if (payload[key]) state[key] = payload[key];
    state.revision += 1;
    return state;
  }
  if (action === 'client.get' || action === 'client.update') {
    const client = state.clients.find((item) => item.id === payload.id);
    if (!client) return { _foxhole_error: 'not_found' };
    if (action === 'client.get') return { export: exportClient(client) };
    if (payload.revision !== state.revision)
      return { _foxhole_error: 'revision_conflict' };
    client.name = payload.name;
    state.revision += 1;
    return { state, client: exportClient(client) };
  }
  if (action === 'client.save') {
    const client = { id: `client-fixture-${state.revision++}`,
      name: payload.name, deviceType: payload.deviceType,
      serverId: 'server-fixture', metrics: {} };
    state.clients.push(client);
    return { state, client: exportClient(client) };
  }
  if (action === 'server.test') return {
    valid: /^h(?:y2|ysteria2):\/\//.test(payload.config)
  };
  if (action === 'server.save') {
    if (payload.revision !== state.revision)
      return { _foxhole_error: 'revision_conflict' };
    if (!/^h(?:y2|ysteria2):\/\//.test(payload.config))
      return { _foxhole_error: 'invalid_config' };
    if (!payload.name?.trim() || [...payload.name.trim()].length > 13)
      return { _foxhole_error: 'invalid_name' };
    let server = state.servers.find((item) => item.id === payload.id);
    if (!server) {
      server = { id: `server-fixture-${state.revision}`,
        endpoint: 'vpn.example.invalid:443', protocol: 'hysteria2',
        country: 'NL', metrics: {} };
      state.servers.push(server);
    }
    server.name = payload.name.trim();
    server.config = payload.config;
    state.revision += 1;
    return state;
  }
  if (action === 'server.get') {
    const server = state.servers.find((item) => item.id === payload.id);
    return server ? { ...server, config: server.config ||
      'hysteria2://ui-fixture@vpn.example.invalid:443/#UI%20fixture' } :
      { _foxhole_error: 'not_found' };
  }
  if (action === 'server.start' || action === 'server.stop') {
    if (payload.revision !== state.revision)
      return { _foxhole_error: 'revision_conflict' };
    const connected = action === 'server.start';
    state.revision += 1;
    state.runtime = {
      ...state.runtime,
      phase: connected ? 'connected' : 'disconnected',
      connected, enforced: connected,
      activeServerId: connected ? payload.id : null,
      desiredServerId: connected ? payload.id : null,
      country: connected ? 'NL' : '',
      address: connected ? '198.51.100.1' : '',
      latency: connected ? 20 : null
    };
    return state;
  }
  if (action === 'device.list') return { devices: [] };
  if (action === 'lock') return {};
  return { _foxhole_error: 'unavailable' };
}

const mime = { '.html': 'text/html', '.js': 'text/javascript',
  '.json': 'application/json', '.css': 'text/css',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ttf': 'font/ttf' };
createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://127.0.0.1');
    res.setHeader('cache-control', 'no-store');
    if (profile && url.pathname === '/ui-profile.js') {
      res.setHeader('content-type', 'text/javascript');
      res.end(await readFile(new URL('./ui-profile.js', import.meta.url)));
      return;
    }
    if (url.pathname === '/cgi-bin/foxhole') {
      let body = '';
      for await (const chunk of req) {
        body += chunk;
        if (body.length > 300000) throw new Error();
      }
      const { action, payload } = JSON.parse(body);
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(request(action, payload)));
      return;
    }
    const path = url.pathname === '/foxhole.html' ? 'shell.html'
      : url.pathname.replace(/^\/luci-static\/resources\/foxhole\//, '');
    const file = resolve(root, path);
    if (!file.startsWith(root)) throw new Error();
    let data = await readFile(file);
    if (legacy && path === 'ui-controller.js') data = data.toString()
      .replace("typeof menu.showPopover === 'function'", 'false');
    if (path === 'shell.html') data = data.toString()
      .replace('<title>FoxHole OpenWRT Client</title>', '<title>UI FIXTURE — no router</title>')
      .replace('data-i18n="auth.pin_prompt"', '')
      .replace('data-i18n="brand.name"', '')
      .replace('<body>', '<body><p>UI FIXTURE — synthetic data, any four digits</p>');
    if (profile && path === 'shell.html') data = data.toString()
      .replace('</body>', '<script src="/ui-profile.js"></script></body>');
    res.setHeader('content-type', mime[extname(file)] || 'application/octet-stream');
    res.end(data);
  } catch {
    res.writeHead(404).end();
  }
}).listen(port, '127.0.0.1', () => {
  console.log(`Isolated UI fixture: http://127.0.0.1:${port}/foxhole.html`);
});
