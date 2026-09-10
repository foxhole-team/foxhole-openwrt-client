import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { functionBody, hostHarness, modelPath, packageRoot, panelRoot,
  plain, read, rpcMethods } from './helpers.mjs';

const readMethods = ['unlock', 'lock', 'state', 'telemetry', 'server.test',
  'server.get', 'client.get', 'device.resolve', 'device.list'];
const writeMethods = ['settings', 'server.save', 'server.delete',
  'server.start', 'server.stop', 'client.save', 'client.update', 'client.access',
  'client.delete', 'pin.change'];

test('LuCI declarations match RPC names, arguments and ACL scopes', async () => {
  const host = await hostHarness();
  const methods = await rpcMethods();
  const acl = JSON.parse(await read(`${packageRoot}/root/usr/share/rpcd/acl.d/luci-app-foxhole.json`));
  const scope = acl['luci-app-foxhole'];
  assert.deepEqual(Object.keys(acl), ['luci-app-foxhole', 'luci-app-foxhole-pin']);
  assert.deepEqual(acl['luci-app-foxhole-pin'].write.ubus,
    { 'foxhole.admin': ['set_pin'] });
  assert.deepEqual([...host.declarations.keys()].sort(), Object.keys(methods).sort());
  assert.deepEqual([...scope.read.ubus.foxhole].sort(), [...readMethods].sort());
  assert.deepEqual([...scope.write.ubus.foxhole].sort(), [...writeMethods].sort());
  assert.deepEqual([...readMethods, ...writeMethods].sort(), Object.keys(methods).sort());
  assert.deepEqual(Object.keys(scope.read).sort(), ['ubus', 'uci']);
  assert.deepEqual(Object.keys(scope.write).sort(), ['ubus', 'uci']);
  assert.deepEqual(Object.keys(scope.read.ubus), ['foxhole']);
  assert.deepEqual(Object.keys(scope.write.ubus), ['foxhole']);
  assert.deepEqual(scope.read.uci, ['foxhole']);
  assert.deepEqual(scope.write.uci, ['foxhole']);
  assert.ok(!JSON.stringify(acl).includes('*'));
  for (const [name, declaration] of host.declarations) {
    assert.equal(declaration.object, 'foxhole', name);
    assert.ok(Array.isArray(declaration.params), `${name}: positional LuCI params`);
    assert.deepEqual(declaration.params, Object.keys(methods[name].args), name);
    if (name !== 'unlock') assert.ok(declaration.params.includes('token'), name);
  }
});

test('host projects payload fields into positional RPC arguments', async () => {
  const host = await hostHarness();
  for (const [action, declaration] of host.declarations) {
    assert.ok(Array.isArray(declaration.params), action);
    const payload = Object.fromEntries(declaration.params.map((key, index) => [key, `value-${index}`]));
    payload.unexpected = 'ignored';
    await host.send({ source: 'foxhole-panel', id: `request-${action}`, action, payload });
    const call = host.calls.at(-1);
    assert.equal(call.method, action);
    assert.deepEqual(call.args, declaration.params.map((key) => payload[key]), action);
    assert.equal(host.replies.at(-1)[1], host.origin);
  }
});

test('host rejects foreign origins, frames and malformed messages', async () => {
  const host = await hostHarness();
  const message = { source: 'foxhole-panel', id: 'test-request', action: 'state', payload: {} };
  await host.send(message, { origin: 'https://foreign.invalid' });
  await host.send(message, { source: {} });
  for (const data of [null, {}, { ...message, source: 'other' },
    { ...message, action: 'unknown' }, { ...message, id: 'x'.repeat(129) },
    { ...message, payload: [] }, { ...message, payload: 'bad' },
    { ...message, payload: { text: 'x'.repeat(300001) } }]) {
    await host.send(data);
  }
  assert.equal(host.calls.length, 0);
  assert.equal(host.replies.length, 0);
});

test('public state exposes profile metadata without credentials', async () => {
  const source = await read(modelPath);
  const body = functionBody(source, 'public_state');
  const project = vm.runInNewContext(`(function(state, runtime) ${body})`, {
    map: (values, fn) => values.map(fn)
  }, { timeout: 1000 });
  const state = {
    schema: 1, revision: 7, activeServerId: null,
    settings: { language: 'ru' },
    countries: [], devices: [], sites: [], auth: 'fixture-private',
    servers: [{ id: 'server-000000000001', name: 'Example',
      endpoint: 'router.invalid:443', config: 'fixture-private',
      auth: 'fixture-private', tls: { key: 'fixture-private' } }],
    clients: [{ id: 'client-000000000001', name: 'Phone',
      deviceType: 'smartphone', serverId: null, uri: 'fixture-private',
      config: 'fixture-private', token: 'fixture-private' }]
  };
  const result = plain(project(state));
  assert.deepEqual(Object.keys(result).sort(), ['schema', 'revision', 'settings',
    'countries', 'devices', 'sites', 'servers', 'clients', 'runtime'].sort());
  assert.deepEqual(Object.keys(result.servers[0]).sort(),
    ['id', 'name', 'endpoint', 'state', 'protocol', 'metrics'].sort());
  assert.deepEqual(result.servers[0].metrics,
    { received: 0, sent: 0, averageLatency: null, ping: null });
  assert.equal(result.servers[0].protocol, 'hysteria2');
  assert.deepEqual(Object.keys(result.clients[0]).sort(),
    ['id', 'name', 'deviceType', 'serverId', 'provisioned',
      'metrics', 'allowLan'].sort());
  assert.deepEqual(result.clients[0].metrics,
    { received: 0, sent: 0, lastConnected: null });
  assert.ok(!JSON.stringify(result).includes('fixture-private'));
  assert.deepEqual(result.runtime, {
    mode: 'runtime', phase: 'disconnected', connected: false,
    enforced: false, activeServerId: null, desiredServerId: null,
    error: null
  });
});

test('browser persistence is limited to presentation preferences', async () => {
  const source = await read(`${panelRoot}/app.js`);
  const writes = [...source.matchAll(/storage\.set\(([^,]+),/g)].map((match) => match[1]);
  assert.ok(writes.length >= 2);
  for (const key of writes) {
    assert.ok(["'language'", "'period'", "'theme'", "'plainHeadings'", "'rules.filter'", '`chart.${id}`',
      '`section.${id}`'].includes(key), key);
  }
  assert.doesNotMatch(source, /sessionStorage|indexedDB|document\.cookie/);
});

test('standalone gateway is bounded and uses the same RPC allowlist', async () => {
  const source = await read(`${packageRoot}/root/www/cgi-bin/foxhole`);
  const methods = await rpcMethods();
  const block = source.match(/const ACTIONS = \[([\s\S]*?)\];/);
  assert.ok(block);
  const actions = [...block[1].matchAll(/'([^']+)'/g)]
    .map((match) => match[1]).sort();
  assert.deepEqual(actions, Object.keys(methods).sort());
  assert.match(source, /MAX_BODY = 300000/);
  assert.match(source, /CONTENT_LENGTH/);
  assert.match(source, /HTTP_SEC_FETCH_SITE/);
  assert.match(source, /origin && origin != expected/);
  assert.match(source, /standalone_enabled\(\)/);
  assert.match(source, /connection\.call\('foxhole'/);
  assert.doesNotMatch(source, /Access-Control-Allow-Origin/i);
});

test('server control invokes revisioned runtime RPC methods', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const app = await read(`${panelRoot}/app.js`);
  const methods = await rpcMethods();
  assert.match(shell, /id="tpl-server-control"/);
  assert.match(app,
    /'server-control': \{[\s\S]*action: 'connect-server'[\s\S]*marker: 'serverToggle'/);
  assert.match(app,
    /action\.marker === 'serverToggle'\) button\.dataset\.serverToggle/);
  assert.match(app,
    /row\.dataset\.action = type === 'server'[\s\S]*'open-server-control'/);
  assert.match(app,
    /button\.dataset\.action = desired \? 'stop-server' : 'connect-server'/);
  assert.match(app, /api\(stop \? 'server\.stop' : 'server\.start'/);
  assert.deepEqual(Object.keys(methods['server.start'].args),
    ['token', 'revision', 'id']);
  assert.deepEqual(Object.keys(methods['server.stop'].args),
    ['token', 'revision']);
});

test('dashboard separates WAN traffic from latency series', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const charts = await read(`${panelRoot}/charts.js`);
  assert.match(shell, /data-chart-card="network"/);
  assert.match(shell, /data-i18n="chart\.wan"/);
  assert.match(shell, /data-chart-card="wan-latency"/);
  assert.match(shell, /data-chart-card="vpn-latency"/);
  assert.doesNotMatch(shell, /chart-card is-wide/);
  assert.match(shell, /data-i18n="chart\.wan_latency"/);
  assert.match(charts, /point\.latency\?\.wan/);
  assert.match(charts, /point\.latency\?\.serverId === this\.vpn\.serverId/);
  assert.match(charts,
    /const duration = id === 'wrt' \|\| latency \? periods\[this\.period\]/);
  assert.doesNotMatch(shell, /day_average/);
  assert.match(charts,
    /if \(canvas\.closest\('\.is-collapsed'\)\) \{\s*this\.updateMeta\(id, points\)/);
});

test('package root entry and browser cache key follow the release', async () => {
  const makefile = await read(`${packageRoot}/Makefile`);
  const defaults = await read(`${packageRoot}/root/etc/uci-defaults/99-foxhole-openwrt-client`);
  const shell = await read(`${panelRoot}/shell.html`);
  const app = await read(`${panelRoot}/app.js`);
  const version = makefile.match(/^PKG_VERSION:=(.+)$/m)?.[1];
  const release = makefile.match(/^PKG_RELEASE:=(.+)$/m)?.[1];
  const cacheKey = `${version}-r${release}`;
  const postinst = makefile.match(/define Package\/foxhole-openwrt-client\/postinst([\s\S]*?)endef/)?.[1];
  assert.equal(cacheKey, '0.1.0-r41');
  assert.match(makefile, /\$\(1\)\/www\/foxhole\.html/);
  assert.match(defaults, /panel_index='foxhole\.html'/);
  assert.match(defaults, /legacy_index='luci-static\/resources\/foxhole\/shell\.html'/);
  assert.doesNotMatch(postinst, /uci-defaults/);
  assert.match(shell, new RegExp(`app\\.css\\?v=${cacheKey}`));
  assert.match(shell, new RegExp(`app\\.js\\?v=${cacheKey}`));
  assert.match(shell, new RegExp(`foxhole\\.png\\?v=${cacheKey}`));
  assert.match(app, new RegExp(`bridge\\.js\\?v=${cacheKey}`));
  assert.match(app, new RegExp(`charts\\.js\\?v=${cacheKey}`));
  assert.match(app, new RegExp(`frontend-model\\.js\\?v=${cacheKey}`));
  assert.match(app, new RegExp(`ui-controller\\.js\\?v=${cacheKey}`));
});

test('package installs one supervised Hysteria routing runtime', async () => {
  const makefile = await read(`${packageRoot}/Makefile`);
  const init = await read(`${packageRoot}/root/etc/init.d/foxhole-runtime`);
  const supervisor = await read(
    `${packageRoot}/root/usr/libexec/foxhole-supervisor`);
  const controller = await read(
    `${packageRoot}/root/usr/libexec/foxhole-runtime`);
  const policy = await read(
    `${packageRoot}/root/usr/share/foxhole/runtime-model.uc`);
  for (const dependency of ['hysteria', 'kmod-tun', 'ip-full',
    'nftables-json', 'firewall4', 'jsonfilter']) {
    assert.match(makefile, new RegExp(`\\+${dependency}`), dependency);
  }
  for (const path of ['etc/init.d/foxhole-runtime',
    'usr/libexec/foxhole-runtime', 'usr/libexec/foxhole-supervisor',
    'usr/libexec/foxhole-dnsmasq', 'usr/share/foxhole/runtime-model.uc',
    'usr/share/nftables.d/chain-pre/forward/30-foxhole.nft']) {
    assert.ok(makefile.includes(path), path);
  }
  assert.match(init, /USE_PROCD=1/);
  assert.match(init, /procd_set_param command "\$supervisor"/);
  assert.match(supervisor, /\/usr\/bin\/hysteria client -c "\$config"/);
  assert.match(supervisor, /"\$controller" probe/);
  assert.match(controller, /runtime\.route_commands/);
  assert.match(controller, /\[NFT, '-c', '-f', POLICY_PATH\]/);
  assert.match(policy, /meta mark set meta mark \| ' \+ MARK/);
  assert.match(policy, /config\.tun =/);
  assert.doesNotMatch(supervisor, /logger|logread|set -x/);
});

test('modal actions use one accessible native dialog flow', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const app = await read(`${panelRoot}/app.js`);
  const css = await read(`${panelRoot}/app.css`);
  const flow = await read(`${panelRoot}/ui-controller.js`);
  assert.match(shell,
    /<dialog id="modal-shell"[\s\S]*data-modal-stage[\s\S]*data-modal-footer[\s\S]*<\/dialog>/);
  assert.equal([...shell.matchAll(/data-modal-footer/g)].length, 1);
  assert.doesNotMatch(shell, /sheet-footer|modal-backdrop|modal-header-nav/);
  assert.match(shell,
    /tpl-add-choice[\s\S]*add\.client[\s\S]*id="add-choice-routes"[\s\S]*data-action="open-exceptions"[\s\S]*action\.open_routes/);
  assert.match(app, /const modalDefinitions = \{/);
  for (const view of ['add-choice', 'server-config', 'server-control',
    'client-device', 'client-control', 'settings-home',
    'interface-settings', 'exceptions', 'manual-address',
    'network-management', 'pin-change', 'confirm-delete',
    'router-stats']) {
    assert.match(app, new RegExp(`['"]?${view}['"]?: \\{`), view);
  }
  for (const action of ['modal-back', 'modal-close', 'save-server',
    'generate-client', 'manage-client', 'save-manual-address',
    'save-pin', 'confirm-delete', 'delete-client']) {
    assert.match(app, new RegExp(`action: '${action}'`), action);
  }
  assert.match(app,
    /case 'open-exceptions':\s*if \(!draft\) beginSettingsDraft\(\);\s*await openView\('exceptions'\)/);
  assert.match(app, /function syncPinSaveState\(\)/);
  assert.match(app,
    /case 'manage-client': await loadEntity\('client', id\)/);
  assert.match(flow, /this\.dialog\.showModal\(\)/);
  assert.match(flow, /this\.dialog\.close\(\)/);
  assert.match(flow, /getAnimations\?\.\(\)/);
  assert.match(flow, /animation\.finished/);
  assert.doesNotMatch(flow, /startHeight|targetHeight|is-resizing/);
  assert.match(flow, /classList\.add\('is-opening'\)[\s\S]*showModal/);
  assert.doesNotMatch(css, /\.modal\[open\]\s*\{[^}]*animation:/);
  assert.match(css, /\.modal\.is-opening \{[^}]*animation: modal-in/);
  assert.doesNotMatch(css,
    /\.modal\.is-opening::backdrop|\.modal\.is-closing::backdrop/);
  assert.doesNotMatch(css,
    /@keyframes (?:modal|sheet)-(?:in|out) \{[^}]*opacity:/);
  assert.doesNotMatch(flow, /setTimeout|\bdelay\b/);
  assert.match(app, /dialog\.addEventListener\('cancel'/);
  assert.doesNotMatch(app, /button:not\(:disabled\)[\s\S]*event\.key !== 'Tab'/);
  assert.match(css, /\.outline-button\.is-close \{ background: transparent/);
  assert.doesNotMatch(shell, /action\.cancel/);
  assert.match(css, /\.modal-footer \{[^}]*border-top:/);
  assert.doesNotMatch(css, /is-transitioning|is-leaving/);
  assert.match(css,
    /\.modal-panel \{ width: 100%; padding: 13px 13px 13px; \}/);
  assert.doesNotMatch(css, /--popup-reserve/);
  assert.match(css, /\.popup-surface\[data-popup-menu\] \{ position: fixed/);
  assert.doesNotMatch(css, /modal-resize/);
  assert.doesNotMatch(flow,
    /this\.dialog\.getBoundingClientRect\(\);\s*this\.dialog\.classList/);
  assert.match(css,
    /@media \(max-width: 720px\) and \(pointer: coarse\)/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(css, /\.add-choice-routes \{ margin-top: 9px/);
  assert.doesNotMatch(css, /\.setting-icon \{[^}]*align-self: flex-start/);
  assert.doesNotMatch(css, /\.switch \{[^}]*align-self: flex-start/);
  assert.match(css, /\.switch i::after \{[^}]*top: 50%/);
  assert.match(css, /\.switch input:checked \+ i::after \{[^}]*translate\(17px, -50%\)/);
  assert.doesNotMatch(shell, /class="setting-row is-subrow"/);
  assert.match(css, /\.chart-grid \{ grid-template-columns: repeat\(2/);
});

test('help uses the shared modal without another overlay', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const app = await read(`${panelRoot}/app.js`);
  const css = await read(`${panelRoot}/app.css`);
  assert.doesNotMatch(shell, /help-root|modal-help|icon-help|data-help/);
  assert.doesNotMatch(app, /openHelp|closeHelp|helpButton/);
  assert.doesNotMatch(css, /\.help-(?:backdrop|button|dialog)/);
  assert.match(shell, /id="tpl-help"/);
  assert.match(app, /action: 'open-help', icon: 'info'/);
  assert.doesNotMatch(shell, /data-i18n="[^"]*_copy"/);
});

test('DHCP picker and native LuCI access setting are packaged', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const app = await read(`${panelRoot}/app.js`);
  const rpc = await read(`${packageRoot}/root/usr/share/rpcd/ucode/foxhole.uc`);
  const makefile = await read(`${packageRoot}/Makefile`);
  const menu = JSON.parse(await read(`${packageRoot}/root/usr/share/luci/menu.d/luci-app-foxhole.json`));
  assert.match(shell, /data-dhcp-device-list/);
  assert.match(shell, /data-action="open-manual-address"/);
  assert.match(app, /api\('device\.list'\)/);
  assert.match(rpc, /fs\.readfile\('\/tmp\/dhcp\.leases'/);
  assert.match(makefile, /view\/foxhole\/settings\.js/);
  assert.equal(menu['admin/services/foxhole/access'].action.path,
    'foxhole/settings');
});

test('FoxHole themes, WAN metadata and section controls are explicit', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const app = await read(`${panelRoot}/app.js`);
  const charts = await read(`${panelRoot}/charts.js`);
  const css = await read(`${panelRoot}/app.css`);
  const rpc = await read(
    `${packageRoot}/root/usr/share/rpcd/ucode/foxhole.uc`);
  const makefile = await read(`${packageRoot}/Makefile`);
  assert.match(shell, /data-setting="theme"/);
  assert.doesNotMatch(shell, /data-setting="darkStyle"/);
  assert.match(shell, /data-setting="darkCharts"/);
  assert.match(shell,
    /id="foxhole-style"[^>]*data-setting="plainHeadings"[^>]*data-setting-inverted/);
  assert.match(shell,
    /tpl-interface-settings[\s\S]*data-action="open-pin-change"/);
  assert.match(css, /html\.theme-light/);
  assert.doesNotMatch(shell, /\sstyle=/);
  assert.doesNotMatch(app, /\.style\b/);
  assert.match(css, /data-closed-size="0"/);
  assert.match(css, /html\.theme-plain-headings/);
  assert.match(css,
    /\.pin-brand \{[^}]*text-transform: uppercase/);
  assert.doesNotMatch(css,
    /view-(?:server-control|client-control)[^{]*\{[^}]*height:/);
  assert.doesNotMatch(css,
    /\.modal\.view-(?:add-choice|client-device)[^{]*\{[^}]*height:/);
  assert.match(app,
    /storage\.get\('plainHeadings'\) === '1'/);
  assert.match(app,
    /node\.hasAttribute\('data-setting-inverted'\)[\s\S]*!Boolean\(value\)/);
  assert.match(app,
    /input\.hasAttribute\([\s\S]*'data-setting-inverted'\) \? !value : value/);
  assert.match(css,
    /\.route-picker-trigger \{[^}]*align-content: center;[^}]*line-height: 1\.2/);
  assert.doesNotMatch(css,
    /\.route-picker-trigger \{[^}]*padding: 8px 0 8px 12px/);
  assert.match(css,
    /\.rule-inline-route \.route-picker-trigger \{[^}]*padding: 4px 6px/);
  assert.doesNotMatch(css,
    /\.setting-icon svg \{[^}]*height:/);
  assert.doesNotMatch(css, /html\.theme-ui-gray/);
  assert.match(css, /--primary-bg: #fff/);
  assert.match(css, /html\.theme-light[\s\S]*--primary-bg: #303842/);
  assert.match(css, /\.vpn-button \{ background: transparent/);
  assert.doesNotMatch(css, /html\.theme-dark \.vpn-button/);
  assert.match(css,
    /--topbar-gutter: max\(clamp\(9px, 2vw, 22px\), calc\(\(100% - 1056px\) \/ 2\)\)/);
  assert.match(css,
    /max\(var\(--topbar-gutter\), env\(safe-area-inset-right\)\)/);
  assert.match(shell,
    /id="settings-button"[\s\S]*?<use href="#icon-settings"\/>/);
  assert.match(css, /h1, h2, h3 \{[^}]*text-transform: uppercase/);
  assert.match(shell, /data-meta-wan-address/);
  assert.match(shell, /data-meta-wan-country/);
  assert.match(shell, /data-meta-vpn-address/);
  assert.doesNotMatch(shell, /data-meta-wan-latency/);
  assert.match(charts, /function setCountryLabel\(node, value\)/);
  assert.match(charts, /image\.src = countryFlagPath\(code\)/);
  assert.doesNotMatch(charts, /fromCodePoint/);
  const sampler = await read(`${packageRoot}/root/usr/libexec/foxhole-probe`);
  assert.match(sampler,
    /TRACE_URL = 'https:\/\/cloudflare\.com\/cdn-cgi\/trace'/);
  assert.match(rpc, /country: network.country/);
  assert.doesNotMatch(functionBody(rpc, 'telemetry_sample'), /popen|ping|fetch/);
  assert.match(makefile, /\+uclient-fetch \+ca-bundle/);
  assert.match(shell, /data-i18n="router\.history"/);
  assert.match(app, /charts\.rateSeries\(key, direction\)/);
  assert.match(app, /function rateSparkline\(series\)/);
  assert.match(shell, /data-section-toggle="status"/);
  assert.match(shell, /data-section-toggle="servers"/);
  assert.match(shell, /data-section-toggle="clients"/);
  assert.match(app, /function setSectionCollapsed\(id, collapsed\)/);
  assert.match(app, /function sizeCompactSelect\(select\)/);
  assert.doesNotMatch(css, /\.compact-select\.is-expanded/);
  assert.doesNotMatch(app, /classList\.add\('is-expanded'\)/);
  assert.doesNotMatch(app, /navigator\.userAgent|mobile-sheet-platform/);
  assert.doesNotMatch(css, /mobile-sheet-platform|modal-backdrop/);
  assert.match(css,
    /@media \(max-width: 720px\) and \(pointer: coarse\)/);
  assert.match(css,
    /\.modal-footer\.layout-server-config \[data-action="test-server"\] \{[^}]*grid-column: 1 \/ -1/);
  assert.doesNotMatch(css, /backdrop-filter|will-change/);
  assert.match(css, /select \{ padding-right: 30px; \}/);
  assert.match(app,
    /\$\('\[data-period-control\]'\)\.hidden = collapsed/);
});

test('empty VPN sections are compact one-line information rows', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const app = await read(`${panelRoot}/app.js`);
  const css = await read(`${panelRoot}/app.css`);
  const ru = JSON.parse(await read(`${panelRoot}/locales/ru.json`));
  const en = JSON.parse(await read(`${panelRoot}/locales/en.json`));
  assert.match(shell, /id="icon-info"/);
  assert.match(shell,
    /data-empty-state="servers"[\s\S]*href="#icon-info"/);
  assert.match(shell,
    /data-empty-state="clients"[\s\S]*href="#icon-info"/);
  assert.match(app, /'empty-state is-entity-empty'/);
  assert.match(css,
    /\.empty-state\.is-entity-empty \{[^}]*min-height: 51px/);
  assert.match(css,
    /\.empty-state\.is-entity-empty strong \{[^}]*white-space: nowrap/);
  assert.match(css,
    /\.client-metrics \.metric small \{[^}]*white-space: normal/);
  assert.equal(ru['clients.empty_title'], 'Клиенты VPN еще не добавлены');
  assert.equal(ru['servers.empty_title'], 'Серверы VPN еще не добавлены');
  assert.equal(en['clients.empty_title'],
    'VPN clients have not been added yet');
});

test('scope and theme choices use local icon assets without emoji', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const css = await read(`${panelRoot}/app.css`);
  const ru = JSON.parse(await read(`${panelRoot}/locales/ru.json`));
  const en = JSON.parse(await read(`${panelRoot}/locales/en.json`));
  assert.equal(ru['scope.all'], 'Вся сеть');
  assert.equal(ru['scope.selected'], 'Выбранные устройства');
  assert.equal(en['scope.all'], 'Entire network');
  assert.equal(en['scope.selected'], 'Selected devices');
  assert.match(shell, /data-scope-icon data-asset-icon="world"/);
  assert.match(shell, /data-theme-icon data-asset-icon="moon"/);
  assert.match(shell, /data-language-flag[^>]*assets\/flags\/ru\.svg/);
  assert.match(shell,
    /data-setting-picker data-popup[\s\S]*data-action="toggle-popup"/);
  assert.match(shell,
    /data-action="select-setting-option"[\s\S]*data-value="selected"/);
  assert.match(css, /assets\/tabler\/moon\.svg/);
  assert.match(css, /assets\/tabler\/devices\.svg/);
  assert.match(css,
    /\.setting-picker-menu \{[^}]*right: 0;[^}]*width: max-content/);
  assert.doesNotMatch(css, /\.setting-picker\.is-open[^}]*width:/);
});

test('site direction and all destructive actions are explicit', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const app = await read(`${panelRoot}/app.js`);
  const model = await read(`${panelRoot}/frontend-model.js`);
  const flow = await read(`${panelRoot}/ui-controller.js`);
  const css = await read(`${panelRoot}/app.css`);
  const ru = JSON.parse(await read(`${panelRoot}/locales/ru.json`));
  assert.match(shell,
    /data-site-form[\s\S]*name="route"[\s\S]*data-route="vpn"[\s\S]*data-route="direct"/);
  assert.match(shell,
    /data-country-form[\s\S]*data-country-route[\s\S]*data-route="vpn"[\s\S]*data-route="direct"/);
  assert.match(shell,
    /data-selected-device-form[\s\S]*device-rule-line[\s\S]*data-device-picker[\s\S]*data-address-route/);
  assert.match(shell,
    /data-country-route[^>]*value="direct"|value="direct"[^>]*data-country-route/);
  assert.match(shell,
    /data-address-route[^>]*value="direct"|value="direct"[^>]*data-address-route/);
  assert.match(shell,
    /data-site-route[^>]*value="direct"|value="direct"[^>]*data-site-route/);
  assert.match(shell, /data-device-add disabled/);
  assert.match(shell, /data-site-add disabled/);
  assert.match(app,
    /'confirm-delete': \{[\s\S]*action: 'confirm-delete'[\s\S]*label: 'action\.confirm'/);
  assert.match(app, /if \(name === 'trash'\) button\.classList\.add\('is-danger'\)/);
  assert.match(app,
    /case 'remove-country':[\s\S]*openView\('confirm-delete'/);
  assert.match(app,
    /case 'remove-address':[\s\S]*openView\('confirm-delete'/);
  assert.match(app, /case 'remove-site':[\s\S]*openView\('confirm-delete'/);
  assert.match(css, /\.view-confirm-delete \.modal-heading-icon/);
  assert.doesNotMatch(app, /case 'edit-(?:address|country|site)'/);
  assert.doesNotMatch(shell, /tpl-rule-route|data-rule-route-select/);
  assert.match(app,
    /case 'select-route':[\s\S]*input\.matches\('\[data-rule-inline\]'\)[\s\S]*selectedRule\([\s\S]*queueDraftSave\('exceptions\.rule_saved'\)/);
  assert.match(css,
    /\.modal\.view-exceptions \{ width: min\(calc\(100% - 48px\), 840px\)/);
  assert.match(css,
    /\.modal\.view-exceptions \.modal-panel \{[^}]*repeat\(2/);
  assert.match(css,
    /@media \(max-width: 720px\) and \(pointer: coarse\)[\s\S]*\.modal\.view-exceptions \.country-picker \{ width: 100%/);
  assert.match(shell, /data-country-options/);
  assert.doesNotMatch(shell,
    /<label for="site-input"[^>]*exceptions\.site_label/);
  assert.match(css,
    /\.site-rule-line:focus-within \{ border-color: var\(--accent\)/);
  assert.match(css,
    /\.site-rule-line \.text-input \{[^}]*border-radius: 15px 0 0 15px;[^}]*box-shadow: none/);
  assert.match(css,
    /\.empty-state\.is-rule-empty \{[^}]*min-height: 48px/);
  assert.match(css,
    /\.modal-heading-icon \{[^}]*width: 23px; height: 23px/);
  assert.equal(ru['settings.local_scope'], 'Область применения правил');
  assert.equal(ru['add.title'], 'Управление VPN-сетями');
  assert.equal(ru['add.server'], 'Добавить VPN-сервер');
  assert.equal(ru['add.client'], 'Добавить VPN-клиент');
  assert.equal(ru['exceptions.address_title'], 'Добавить устройство');
  assert.equal(ru['exceptions.site_title'], 'Добавить web адрес');
  assert.match(css,
    /\.group-heading \{[^}]*gap: 6px;[^}]*margin-bottom: 13px/);
  assert.match(css,
    /\.group-heading \.setting-icon \{[^}]*translateY\(-2px\)/);
  assert.ok(shell.indexOf('for="local-scope"') <
    shell.indexOf('for="local-rules"'));
  assert.match(shell,
    /tpl-interface-settings[\s\S]*data-language[\s\S]*data-setting="theme"/);
  assert.doesNotMatch(shell,
    /tpl-settings-home[\s\S]*data-language[\s\S]*tpl-interface-settings/);
  assert.doesNotMatch(shell, /data-prevent-leak|name="preventLeak"/);
  assert.doesNotMatch(app, /preventLeak|syncLeakField/);
  assert.doesNotMatch(JSON.stringify(ru), /prevent_leak/);
  assert.match(shell, /data-setting="killSwitch"/);
  assert.match(css, /\.route-picker-menu \{[^}]*position: absolute/);
  assert.match(css,
    /\.popup-surface\[data-popup-menu\]\.is-above \{[^}]*transform-origin: bottom right/);
  assert.doesNotMatch(css,
    /\.modal\.has-open-popup \.modal-stage[^{]*\{[^}]*overflow: visible/);
  assert.match(flow, /menu\.showPopover\(\)/);
  assert.match(flow,
    /naturalWidth: null, naturalHeight: null/);
  assert.match(flow,
    /naturalHeight == null[\s\S]*menu\.offsetWidth[\s\S]*menu\.offsetHeight/);
  assert.doesNotMatch(flow.slice(flow.indexOf('export class PopupController')),
    /--popup-reserve|scrollTop|scrollIntoView/);
  assert.doesNotMatch(flow, /scrollIntoView/);
  assert.match(flow, /reposition\(\)[\s\S]*trigger\.isConnected/);
  assert.match(css,
    /\.rule-inline-route \{[^}]*align-self: center;[^}]*width: var\(--route-control-width, 88px\)/);
  assert.match(shell,
    /saved-rules-toolbar[\s\S]*data-rule-filter[\s\S]*data-section-toggle="saved-rules"[\s\S]*exceptions\.column_name[\s\S]*exceptions\.column_route[\s\S]*exceptions\.column_actions[\s\S]*data-rule-table="saved"/);
  assert.match(css, /\.saved-rules-toolbar \{ position: sticky; top: 0;/);
  assert.match(shell,
    /data-rule-filter[\s\S]*value="all"[\s\S]*value="country"[\s\S]*value="address"[\s\S]*value="site"/);
  assert.doesNotMatch(shell,
    /data-rule-table="(?:countries|devices|sites)"/);
  assert.match(css,
    /\.rule-table-head,[\s\S]*\.rule-row \{[^}]*grid-template-columns:/);
  assert.match(css,
    /\.rule-route-cell \{[^}]*justify-self: stretch;[^}]*justify-content: flex-end;[^}]*text-align: right;/);
  assert.match(css,
    /\.modal\.view-exceptions \.settings-group:nth-child\(n \+ 3\) \{[^}]*grid-column: 1 \/ -1;[^}]*padding-top: 16px;[^}]*border-top:/);
  assert.match(css,
    /\.rule-name-cell > \.country-flag \{[^}]*width: 16px; height: 16px/);
  assert.equal(ru['exceptions.saved_rules'], 'Сохранённые правила');
  assert.equal(ru['exceptions.filter_all'], 'Все правила');
  assert.equal(ru['exceptions.no_saved_rules'],
    'Правила ещё не добавлены');
  assert.doesNotMatch(app,
    /copy\.append\(element\('small', '', country\.code\)\)/);
  assert.doesNotMatch(app, /siteFavicon|google\.com\/s2\/favicons/);
  assert.match(shell,
    /Content-Security-Policy[^>]*img-src 'self' data:;/);
  assert.doesNotMatch(shell,
    /Content-Security-Policy[^>]*img-src[^>]*https:/);
  assert.match(model,
    /function networkDeviceIcon\(device\)[\s\S]*return 'gamepad'/);
  assert.match(app,
    /input\.matches\('\[data-rule-filter\]'\)[\s\S]*storage\.set\('rules\.filter', ruleFilter\)[\s\S]*renderRules\(\)/);
  assert.match(shell,
    /icon-mobile[\s\S]*icon-tablet[\s\S]*icon-monitor[\s\S]*icon-laptop[\s\S]*icon-tv[\s\S]*icon-gamepad/);
  assert.match(css,
    /\.device-picker-menu \{[^}]*right: 0;[^}]*left: 0;[^}]*width: 100%/);
  assert.match(shell,
    /data-client-type[\s\S]*value="smartphone"[\s\S]*value="tablet"[\s\S]*value="computer"/);
  assert.match(shell,
    /class="client-name-line"[\s\S]*data-client-name[\s\S]*class="setting-picker client-type-picker"/);
  assert.doesNotMatch(shell,
    /<label for="client-name"[^>]*data-i18n="client\.name_label"/);
  assert.match(css,
    /\.client-name-line \{[^}]*grid-template-columns: minmax\(0, 1fr\) auto;[^}]*border:/);
  assert.match(css,
    /\.client-type-picker \{[^}]*border-left: 1px solid var\(--line\)/);
  assert.doesNotMatch(shell, /data-pin-guidance|error\.pin_mismatch/);
  assert.doesNotMatch(app, /data-pin-guidance/);
  assert.match(shell, /data-client-form[^>]*novalidate/);
  assert.match(app, /syncSiteAddState\(\)/);
  assert.match(app, /add\.disabled = !selected\.length/);
});

test('top notifications expose success and error states', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const app = await read(`${panelRoot}/app.js`);
  const css = await read(`${panelRoot}/app.css`);
  const ru = JSON.parse(await read(`${panelRoot}/locales/ru.json`));
  const en = JSON.parse(await read(`${panelRoot}/locales/en.json`));
  assert.match(shell,
    /data-toast[\s\S]*data-toast-icon[\s\S]*data-toast-text/);
  assert.match(app, /function toast\(message, kind = 'success'\)/);
  assert.match(app, /#icon-close' : '#icon-check/);
  assert.match(app, /node\.className = `toast is-\$\{kind\}`/);
  assert.match(css,
    /\.toast \{[^}]*top: max\(16px, env\(safe-area-inset-top\)\)/);
  assert.match(css, /\.toast\.is-success \{[^}]*var\(--success\)/);
  assert.match(css, /\.toast\.is-error \{[^}]*var\(--danger\)/);
  assert.equal(ru['exceptions.rule_saved'], 'Правило сохранено');
  assert.equal(en['exceptions.rule_deleted'], 'Rule deleted');
});

test('status hiding is presentational and client export actions are explicit', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const app = await read(`${panelRoot}/app.js`);
  const css = await read(`${panelRoot}/app.css`);
  assert.match(shell, /data-setting="hideRouterStatus"/);
  assert.equal([...shell.matchAll(/\bdata-router-status\b/g)].length, 2);
  assert.match(functionBody(app, 'appearance'),
    /node\.hidden = next\.hideRouterStatus/);
  const poll = functionBody(app, 'poll');
  assert.match(poll, /api\('telemetry'\)/);
  assert.match(poll, /charts\.update\(payload\)/);
  assert.doesNotMatch(poll, /hideRouterStatus/);
  assert.doesNotMatch(app, /'server\.saved'|entity-endpoint|data-server-control-endpoint/);
  assert.match(app, /setCountryLabel\(country, serverCountryCode\(item, state\.runtime\)\)/);
  assert.match(shell, /data-modal-country/);
  assert.match(shell, /data-server-control-country/);
  assert.match(shell, /success-mark[\s\S]*data-client-result-title[\s\S]*edit-client-name/);
  assert.match(css, /\.result-heading \{ display: grid; justify-items: center/);
  assert.match(shell, /output-actions[\s\S]*regenerate-client-config[\s\S]*copy-client-config/);
  assert.match(app, /case 'regenerate-client-config':\s*await openView\('confirm-regenerate'\)/);
  assert.match(functionBody(app, 'regenerateClient'), /api\('client\.get'/);
  assert.match(functionBody(app, 'saveClientName'), /api\('client\.update'/);
  assert.match(shell, /address-rule-title[\s\S]*href="#icon-devices"/);
  assert.match(app, /const countryOptionStates = new WeakMap\(\)/);
  assert.doesNotMatch(app,
    /for \(const button of \$\$\('\[data-code\]', list\)\)/);
  assert.match(css,
    /\.country-option \{[^}]*content-visibility: auto/);
});

test('settings views share one bounded modal height with scrollable help', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const css = await read(`${panelRoot}/app.css`);
  for (const name of ['settings-home', 'interface-settings']) {
    const template = shell.split(`id="tpl-${name}"`)[1].split('</template>')[0];
    assert.equal([...template.matchAll(/class="setting-row\b/g)].length, 6);
  }
  assert.match(css, /\.modal:is\(\.view-settings-home, \.view-interface-settings\) \{ --modal-base-height: 28rem; \}/);
  assert.match(css, /\.modal-stage \{ flex: 1;/);
  assert.match(css, /\.modal \{[^}]*max-height: calc\(var\(--viewport-height\) - 36px\)/);
});

test('route triggers and options carry distinct VPN and direct icons', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const app = await read(`${panelRoot}/app.js`);
  const css = await read(`${panelRoot}/app.css`);
  assert.equal([...shell.matchAll(/<svg data-route-icon\b/g)].length, 4);
  for (const [route, icon] of [['vpn', 'shield'], ['direct', 'globe']]) {
    const pattern = new RegExp(`data-route="${route}"[^>]*><svg[^>]*><use href="#icon-${icon}"`, 'g');
    assert.equal([...shell.matchAll(pattern)].length, 4);
  }
  assert.match(functionBody(app, 'syncRoutePicker'), /data-route-icon/);
  assert.match(functionBody(app, 'inlineRuleRoute'), /routeIcon\.dataset\.routeIcon/);
  assert.match(css, /\.route-picker-trigger > svg:last-child \{ transform: rotate\(90deg\)/);
});
