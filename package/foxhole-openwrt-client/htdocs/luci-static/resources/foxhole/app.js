import { hasHost, request, cancelPending, PanelError } from './bridge.js?v=0.1.0-r41-ui1';
import { Charts, formatBytes, setCountryLabel } from './charts.js?v=0.1.0-r41-ui1';
import {
  clientDeviceIcon, clientDeviceType, clone, countryCodes,
  countryFlagPath, finite, maskIpv4, maskMac, networkDeviceIcon,
  normalizeMac, normalizeRuntime, normalizeSitePattern, normalizedState,
  randomId,
  serverCountryCode,
  validAddress
} from './frontend-model.js?v=0.1.0-r41-ui1';
import {
  ModalFlow, PopupController, waitForMotion
} from './ui-controller.js?v=0.1.0-r41-ui1';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const storage = {
  get(key) { try { return localStorage.getItem(`foxhole.${key}`); } catch { return null; } },
  set(key, value) { try { localStorage.setItem(`foxhole.${key}`, value); } catch {} }
};
const dictionary = {};
let language = storage.get('language') === 'en' ? 'en' : 'ru';
let preferredTheme = storage.get('theme') === 'light' ? 'light' : 'dark';
let preferredPlainHeadings = storage.get('plainHeadings') === '1';
let token = null;
let pinSetupRequired = false;
let state = null;
let draft = null;
let draftChange = 0;
let draftSaved = 0;
let draftSaving = false;
let draftSession = 0;
let draftNoticeKey = null;
let dhcpDevices = [];
let busy = false;
let pollTimer = 0;
let polling = false;
let failures = 0;
let epoch = 0;
let toastTimer = 0;
let runtimeNoticeKey = null;
let connectedNoticeKey = null;
let connectionNoticeStarted = 0;
const storedRuleFilter = storage.get('rules.filter');
let ruleFilter = ['country', 'address', 'site'].includes(storedRuleFilter)
  ? storedRuleFilter : 'all';
let telemetryAvailable = null;
let dhcpLoading = false;
let dhcpLoaded = false;
let dhcpFailed = false;

function t(key, values = {}) {
  let text = dictionary[language]?.[key] ?? dictionary.en?.[key] ?? key;
  for (const [name, value] of Object.entries(values)) text = text.replaceAll(`{${name}}`, String(value));
  return text;
}

const charts = new Charts(t);
const selectSizingRoots = new Set();
let selectSizingFrame = 0;
let lastAppearance = null;
let renderedEntities = '';

function translate(root = document) {
  for (const node of $$('[data-i18n]', root)) node.textContent = t(node.dataset.i18n);
  for (const attribute of ['placeholder', 'title', 'aria-label']) {
    for (const node of $$(`[data-i18n-${attribute}]`, root)) {
      node.setAttribute(attribute, t(node.getAttribute(`data-i18n-${attribute}`)));
    }
  }
  selectSizingRoots.add(root);
  if (!selectSizingFrame) {
    selectSizingFrame = requestAnimationFrame(() => {
      selectSizingFrame = 0;
      for (const item of selectSizingRoots) sizeCompactSelects(item);
      selectSizingRoots.clear();
    });
  }
}

let selectMeasure;
const selectWidths = [56, 68, 80, 96, 112, 132, 156, 190, 224];

function selectTextWidth(select, text) {
  selectMeasure ||= document.createElement('canvas').getContext('2d');
  const style = getComputedStyle(select);
  selectMeasure.font = style.font;
  const padding = Number.parseFloat(style.paddingLeft) +
    Number.parseFloat(style.paddingRight) + 2;
  return Math.ceil(selectMeasure.measureText(text).width + padding);
}

function sizeCompactSelect(select) {
  const selected = select.selectedOptions[0]?.textContent?.trim() || '';
  const closed = Math.max(54, selectTextWidth(select, selected));
  const bucket = (width) => {
    const index = selectWidths.findIndex((candidate) => width <= candidate);
    return String(index < 0 ? selectWidths.length - 1 : index);
  };
  select.dataset.closedSize = bucket(closed);
}

function sizeCompactSelects(root = document) {
  for (const select of $$('select.compact-select', root))
    sizeCompactSelect(select);
}

function errorText(error) {
  const key = `error.${error?.code || 'unavailable'}`;
  return dictionary[language]?.[key] ? t(key) : t('error.unavailable');
}

function icon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#icon-${name}`);
  svg.append(use);
  svg.setAttribute('aria-hidden', 'true');
  return svg;
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

function flagImage(code, className = 'country-flag', deferred = false) {
  const image = element('img', className);
  const source = countryFlagPath(code);
  if (deferred) image.dataset.flagSrc = source;
  else image.src = source;
  image.alt = '';
  image.width = 16;
  image.height = 12;
  image.loading = 'lazy';
  return image;
}

function actionButton(action, name, label, id) {
  const button = element('button', 'icon-button compact-icon');
  if (name === 'trash') button.classList.add('is-danger');
  button.type = 'button';
  button.dataset.action = action;
  if (id) button.dataset.id = id;
  button.setAttribute('aria-label', t(label));
  button.title = t(label);
  button.append(icon(name));
  return button;
}

const backAction = {
  action: 'modal-back', icon: 'back', label: 'action.back', tone: 'muted'
};
const closeAction = {
  action: 'modal-close', icon: 'close', label: 'action.close', tone: 'close'
};

const modalDefinitions = {
  'add-choice': {
    icon: 'shield', actions: () => [closeAction, {
      action: 'open-networks', icon: 'settings', label: 'action.manage',
      tone: 'accent'
    }]
  },
  'server-config': {
    icon: 'server', layout: 'server-config', actions: () => [{
      action: 'test-server', icon: 'activity', label: 'action.test'
    }, backAction, {
      action: 'save-server', icon: 'check', label: 'action.save',
      tone: 'accent'
    }]
  },
  'server-control': {
    icon: 'server', actions: () => [closeAction, {
      action: 'connect-server', icon: 'play', label: 'action.connect',
      tone: 'accent', marker: 'serverToggle'
    }]
  },
  'client-device': {
    icon: 'mobile', actions: (view) => {
      if (!view.data?.export) return [backAction, {
        action: 'generate-client', icon: 'chevron', label: 'action.next',
        tone: 'accent'
      }];
      if (view.data.managed) return [backAction, {
        action: 'delete-client', icon: 'trash', label: 'action.delete',
        tone: 'danger', id: view.data.id
      }];
      return [backAction, {
        action: 'modal-close', icon: 'check', label: 'action.done',
        tone: 'accent'
      }];
    }
  },
  'client-control': {
    icon: 'mobile', actions: (view) => [closeAction, {
      action: 'manage-client', icon: 'settings', label: 'action.manage',
      tone: 'accent', id: view.data.id
    }]
  },
  'settings-home': {
    icon: 'settings', actions: () => [{
      action: 'open-help', icon: 'info', label: 'help.title'
    }, closeAction]
  },
  'interface-settings': {
    icon: 'moon', actions: () => [backAction, closeAction]
  },
  exceptions: {
    icon: 'globe', actions: () => [backAction, closeAction]
  },
  'manual-address': {
    icon: 'devices', actions: () => [backAction, {
      action: 'save-manual-address', icon: 'plus', label: 'action.add',
      tone: 'accent'
    }]
  },
  'network-management': {
    icon: 'settings', actions: () => [backAction, closeAction]
  },
  'pin-change': {
    icon: 'key', actions: () => [pinSetupRequired ? {
      action: 'lock', icon: 'lock', label: 'action.lock'
    } : backAction, {
      action: 'save-pin', icon: 'check', label: 'action.save',
      tone: 'accent', disabled: true
    }]
  },
  'confirm-delete': {
    icon: 'trash', actions: () => [backAction, {
      action: 'confirm-delete', icon: 'trash', label: 'action.confirm',
      tone: 'danger'
    }]
  },
  'confirm-regenerate': {
    icon: 'refresh', actions: () => [backAction, {
      action: 'confirm-regenerate', icon: 'refresh', label: 'action.confirm',
      tone: 'accent'
    }]
  },
  'router-stats': {
    icon: 'activity', actions: () => [closeAction]
  },
  help: {
    icon: 'info', actions: () => views.length > 1
      ? [backAction, closeAction] : [closeAction]
  }
};

function modalDefinition(view) {
  return modalDefinitions[view.name] || {
    icon: 'shield', actions: () => [closeAction]
  };
}

function renderModalChrome(view) {
  const definition = modalDefinition(view);
  const template = $(`#tpl-${view.name}`);
  const titleKey = view.data?.titleKey ||
    template?.content.firstElementChild?.dataset.titleKey || 'modal.title';
  $('[data-modal-title]').textContent = t(titleKey);
  const server = view.name === 'server-config'
    ? state?.servers.find((item) => item.id === view.data.id) : null;
  setCountryLabel($('[data-modal-country]'),
    server ? serverCountryCode(server, state.runtime) : '');
  $('[data-modal-icon]').setAttribute('href',
    `#icon-${definition.icon}`);
  const clientExport = view.name === 'client-device' && view.data?.export;
  const dialog = $('#modal-shell');
  dialog.className = `modal view-${view.name}${clientExport
    ? ' has-client-export' : ''}`;

  const footer = $('[data-modal-footer]');
  footer.className = `modal-footer layout-${definition.layout || 'default'}`;
  const actions = definition.actions(view);
  footer.classList.toggle('is-single', actions.length === 1);
  footer.replaceChildren(...actions.map((action) => {
    const button = element('button', `outline-button${action.tone
      ? ` is-${action.tone}` : ''}`);
    button.type = 'button';
    button.dataset.action = action.action;
    if (action.id) button.dataset.id = action.id;
    if (action.marker === 'serverToggle') button.dataset.serverToggle = '';
    button.disabled = action.disabled === true;
    const label = element('span', '', t(action.label));
    label.dataset.i18n = action.label;
    button.append(icon(action.icon), label);
    return button;
  }));
}

function prepareModalView(view) {
  renderModalChrome(view);
  const stage = $('[data-modal-stage]');
  translate(stage.firstElementChild);
  if (view.name === 'settings-home' ||
      view.name === 'interface-settings') renderSettings();
  if (view.name === 'exceptions') renderExceptions();
  if (view.name === 'manual-address') syncManualFields();
  if (view.name === 'network-management') renderManagement();
  if (view.name === 'server-config') {
    $('[data-server-config]').value = view.data.config || '';
    $('[data-server-name]').value = [...(view.data.name ??
      t('server.default_name'))].slice(0, 13).join('');
  }
  if (view.name === 'server-control') renderServerControl(view.data);
  if (view.name === 'client-device') renderClientView(view.data);
  if (view.name === 'client-control') renderClientControl(view.data);
  if (view.name === 'confirm-delete')
    $('[data-delete-name]').textContent = view.data.item.name;
  if (view.name === 'router-stats') renderRouterStats();
  if (view.name === 'pin-change') {
    $('[data-pin-setup-copy]').hidden = !pinSetupRequired;
    syncPinSaveState();
  }
  syncViewport();
}

function finishModal() {
  presentToast();
  popups.closeAll();
  charts.setSuspended(false);
  renderLists();
  if (!draft) return;
  draft = null;
  draftSession += 1;
  if (state) appearance(state.settings);
}

const modal = new ModalFlow({
  dialog: $('#modal-shell'),
  stage: $('[data-modal-stage]'),
  title: $('[data-modal-title]'),
  createPanel: (view) => {
    const template = $(`#tpl-${view.name}`);
    if (!template) throw new Error(`Unknown modal view: ${view.name}`);
    return template.content.firstElementChild.cloneNode(true);
  },
  prepare: prepareModalView,
  closed: finishModal
});
const views = modal.views;
const popups = new PopupController($('#modal-shell'));

function latency(value) {
  const amount = finite(value);
  return amount == null ? '—' : `${amount.toFixed(amount < 10 ? 1 : 0)} ms`;
}

function metric(label, value, name) {
  const cell = element('span', 'metric');
  cell.dataset.metric = label;
  const caption = element('small');
  caption.append(icon(name), element('span', '', t(label)));
  cell.append(caption, element('strong', '', value));
  return cell;
}

function serverMetrics(server) {
  const values = server.metrics || {};
  return [
    ['server.received', formatBytes(finite(values.received) ?? 0), 'download'],
    ['server.sent', formatBytes(finite(values.sent) ?? 0), 'upload'],
    ['server.average_latency', latency(values.averageLatency), 'clock'],
    ['server.ping', latency(values.ping), 'activity'],
    ['server.protocol', server.protocol === 'hysteria2'
      ? 'Hysteria 2' : '—', 'shield']
  ];
}

function serverMetricGrid(server) {
  const grid = element('div', 'metrics server-metrics');
  grid.append(...serverMetrics(server).map((values) => metric(...values)));
  return grid;
}

function lastConnection(value) {
  if (value == null) return t('client.never');
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return t('client.never');
  return new Intl.DateTimeFormat(language, {
    dateStyle: 'short', timeStyle: 'short'
  }).format(date);
}

function appearance(settings, renderEntities = true) {
  const next = {
    language: settings.language === 'en' ? 'en' : 'ru',
    theme: settings.theme === 'light' ? 'light' : 'dark',
    darkCharts: settings.darkCharts === true,
    plainHeadings: settings.plainHeadings === true,
    hideRouterStatus: settings.hideRouterStatus === true
  };
  const first = !lastAppearance;
  const languageChanged = first || next.language !== lastAppearance.language;
  const chartsChanged = first || next.theme !== lastAppearance.theme ||
    next.darkCharts !== lastAppearance.darkCharts || languageChanged;
  language = next.language;
  preferredTheme = next.theme;
  document.documentElement.lang = language;
  document.documentElement.classList.toggle('theme-light',
    preferredTheme === 'light');
  document.documentElement.classList.toggle('theme-dark',
    preferredTheme === 'dark');
  document.documentElement.classList.remove('theme-ui-gray');
  document.documentElement.classList.toggle('theme-charts-gray',
    next.darkCharts);
  document.documentElement.classList.toggle('theme-plain-headings',
    next.plainHeadings);
  for (const node of $$('[data-router-status]'))
    node.hidden = next.hideRouterStatus;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content',
    preferredTheme === 'light' ? '#CBCACA' : '#000000');
  storage.set('theme', preferredTheme);
  preferredPlainHeadings = next.plainHeadings;
  storage.set('plainHeadings', preferredPlainHeadings ? '1' : '0');
  if (languageChanged) {
    translate();
    if (modal.current) renderModalChrome(modal.current);
    if (renderEntities && state) renderLists();
    renderRuntimeNotice();
  }
  if (chartsChanged) charts.invalidateStyles();
  else if (next.hideRouterStatus !== lastAppearance?.hideRouterStatus)
    charts.draw();
  lastAppearance = next;
}

function hideToast() {
  const node = $('[data-toast]');
  if (node.hidePopover && node.matches(':popover-open'))
    node.hidePopover();
  node.hidden = true;
}

function presentToast() {
  const node = $('[data-toast]');
  if (node.hidden) return;
  if (node.hidePopover && node.matches(':popover-open'))
    node.hidePopover();
  ($('#modal-shell').open ? $('#modal-shell') : document.body)
    .append(node);
  node.showPopover?.();
}

function toast(message, kind = 'success') {
  clearTimeout(toastTimer);
  const node = $('[data-toast]');
  $('[data-toast-text]', node).replaceChildren(message);
  $('[data-toast-icon]', node).setAttribute('href', kind === 'error'
    ? '#icon-close' : '#icon-check');
  node.className = `toast is-${kind}`;
  node.hidden = false;
  presentToast();
  toastTimer = setTimeout(hideToast, 5000);
}

function setBusy(value) {
  busy = value;
  for (const node of $$('button, input, textarea, select', $('#modal-shell'))) {
    if (value) { node.dataset.wasDisabled = String(node.disabled); node.disabled = true; }
    else { node.disabled = node.dataset.wasDisabled === 'true'; delete node.dataset.wasDisabled; }
  }
  $('#modal-shell').setAttribute('aria-busy', String(value));
}

async function api(action, payload = {}) {
  const response = await request(action, { ...payload, token });
  return response;
}

function applyState(next) {
  if (!next || next.schema !== 1 || !next.settings || !Array.isArray(next.servers) || !Array.isArray(next.clients)) throw new PanelError('unavailable');
  state = normalizedState(next);
  syncVpnContext();
  if (!draft) appearance(state.settings, false);
  renderLists();
  renderRuntimeNotice();
}

function syncVpnContext() {
  const activeId = state.runtime?.activeServerId || null;
  const desiredId = state.runtime?.desiredServerId || null;
  const selected = state.servers.find((item) => item.id ===
    (activeId || desiredId)) ||
    state.servers.at(-1) || null;
  charts.setVpnContext({
    connected: Boolean(state.runtime?.connected && activeId),
    serverId: activeId || selected?.id || null,
    name: selected?.name || '',
    address: state.runtime?.address || '',
    country: state.runtime?.country || ''
  });
}

function applyRuntime(next, sample = null) {
  if (!state || !next) return;
  state.runtime = normalizeRuntime(next);
  const active = state.servers.find((item) =>
    item.id === state.runtime.activeServerId);
  if (active && sample?.vpn) {
    active.metrics = {
      ...active.metrics,
      received: finite(sample.vpn.rx) ?? active.metrics?.received ?? 0,
      sent: finite(sample.vpn.tx) ?? active.metrics?.sent ?? 0,
      averageLatency: state.runtime.latency,
      ping: state.runtime.latency
    };
  }
  syncVpnContext();
  renderLists();
  const current = views.at(-1);
  if (current?.name === 'server-control') renderServerControl(current.data);
  renderRuntimeNotice();
}

function entityRenderKey() {
  return JSON.stringify({
    language,
    runtime: [state.runtime?.phase, state.runtime?.activeServerId,
      state.runtime?.desiredServerId, state.runtime?.country,
      state.runtime?.error],
    servers: state.servers.map((item) => [item.id, item.name,
      item.protocol, item.country]),
    clients: state.clients.map((item) => [item.id, item.name,
      item.deviceType])
  });
}

function renderLists() {
  if (!state || $('#modal-shell').open) return;
  const renderKey = entityRenderKey();
  if (renderKey === renderedEntities) {
    for (const server of state.servers) {
      const row = $(`[data-server-list] [data-id="${server.id}"]`);
      if (!row) continue;
      for (const [label, value] of serverMetrics(server)) {
        const node = $(`[data-metric="${label}"] strong`, row);
        if (node && node.textContent !== value) node.textContent = value;
      }
    }
    return;
  }
  renderedEntities = renderKey;
  for (const type of ['server', 'client']) {
    const items = state[`${type}s`];
    const list = $(`[data-${type}-list]`);
    const fragment = document.createDocumentFragment();
    if (!items.length) {
      const empty = element('div', 'empty-state is-entity-empty');
      empty.append(icon('info'));
      empty.append(element('strong', '', t(`${type}s.empty_title`)));
      fragment.append(empty);
      list.replaceChildren(fragment);
      continue;
    }
    for (const item of items) {
      const row = element('button', `entity-row ${type}-row`);
      row.type = 'button';
      row.dataset.action = type === 'server'
        ? 'open-server-control' : 'open-client-control';
      row.dataset.id = item.id;
      const identity = element('div', 'entity-identity');
      identity.append(icon(type === 'server' ? 'server' :
        clientDeviceIcon(item.deviceType)));
      identity.append(element('strong', 'entity-name', item.name));
      const active = type === 'server' && state.runtime?.connected &&
        state.runtime?.activeServerId === item.id;
      const desired = type === 'server' &&
        state.runtime?.desiredServerId === item.id;
      const status = element('span', 'entity-status',
        t(type === 'server' ? active ? 'server.connected' :
          desired ? `server.${state.runtime.phase}` : 'server.stopped' :
          'client.inactive'));
      row.classList.toggle('is-active', Boolean(active));
      status.classList.toggle('is-online', Boolean(active));
      status.classList.toggle('is-offline', type === 'server' &&
        !active && (!desired || state.runtime.phase === 'disconnected'));
      if (type === 'server') {
        const country = element('span', 'inline-country');
        setCountryLabel(country, serverCountryCode(item, state.runtime));
        identity.append(country);
        const main = element('span', 'entity-main');
        main.append(identity);
        main.append(status);
        row.append(main, serverMetricGrid(item));
      } else {
        row.append(identity, status);
      }
      fragment.append(row);
    }
    list.replaceChildren(fragment);
  }
}

function renderRuntimeNotice() {
  if (!token || !state || pinSetupRequired) return;
  const runtime = state.runtime;
  const key = [runtime.phase, runtime.activeServerId,
    runtime.desiredServerId, runtime.since, runtime.error].join(':');
  if (key !== runtimeNoticeKey) {
    const previous = runtimeNoticeKey;
    runtimeNoticeKey = key;
    connectionNoticeStarted = Date.now();
    if (!runtime.connected) connectedNoticeKey = null;
    if (!runtime.connected && (previous || runtime.error)) {
      toast(runtime.error ? errorText({ code: runtime.error }) :
        t(`dashboard.runtime_${runtime.phase}`),
      ['error', 'blocked'].includes(runtime.phase) ? 'error' : 'info');
    }
  }
  if (!runtime.connected || connectedNoticeKey === key ||
      (!runtime.country && Date.now() - connectionNoticeStarted < 10000))
    return;
  connectedNoticeKey = key;
  const server = state.servers.find((item) =>
    item.id === runtime.activeServerId);
  const notice = element('span', 'connection-notice');
  notice.append(element('strong', '', t('server.connected_notice', {
    name: server?.name || t('server.default_name')
  })));
  const details = element('span', 'connection-notice-details');
  if (runtime.country) {
    const flag = document.createElement('img');
    flag.src = countryFlagPath(runtime.country);
    flag.alt = '';
    flag.width = 16;
    flag.height = 12;
    details.append(flag, document.createTextNode(
      `${regionName(runtime.country)} · `));
  }
  details.append(element('span', 'connection-notice-status',
    t('server.connected')));
  notice.append(details);
  toast(notice);
}

async function openView(name, data = {}, reset = false) {
  if (busy || modal.transitioning) return;
  popups.closeAll();
  if (reset) {
    if (draft && name !== 'settings-home') {
      draft = null;
      draftSession += 1;
      appearance(state.settings);
    }
  }
  charts.setSuspended(true);
  await modal.open(name, data, reset);
  presentToast();
}

async function back() {
  if (busy || modal.transitioning || pinSetupRequired) return;
  popups.closeAll();
  await modal.back();
}

async function closeModal() {
  if (busy || modal.transitioning || pinSetupRequired) return;
  popups.closeAll();
  await modal.close();
}

function renderSettings() {
  if (!draft) return;
  for (const node of $$('[data-setting]')) {
    const value = draft.settings[node.dataset.setting];
    if (node.type === 'checkbox') {
      node.checked = node.hasAttribute('data-setting-inverted')
        ? !Boolean(value) : Boolean(value);
    }
    else node.value = value;
  }
  const languageSelect = $('[data-language]');
  if (languageSelect) languageSelect.value = draft.settings.language;
  const languageFlag = $('[data-language-flag]');
  if (languageFlag)
    languageFlag.src = countryFlagPath(draft.settings.language === 'en'
      ? 'GB' : 'RU');
  const themeIcon = $('[data-theme-icon]');
  if (themeIcon) themeIcon.dataset.assetIcon =
    draft.settings.theme === 'light' ? 'sun' : 'moon';
  const scopeIcon = $('[data-scope-icon]');
  if (scopeIcon) scopeIcon.dataset.assetIcon =
    draft.settings.localScope === 'selected' ? 'devices' : 'world';
  syncSettingPickers($('[data-modal-stage]'));
}

function renderServerControl(data) {
  const server = state.servers.find((item) => item.id === data.id);
  if (!server) return;
  const active = Boolean(state.runtime?.connected &&
    state.runtime?.activeServerId === server.id);
  const desired = state.runtime?.desiredServerId === server.id;
  $('[data-server-control-name]').textContent = server.name;
  setCountryLabel($('[data-server-control-country]'),
    serverCountryCode(server, state.runtime));
  const status = $('[data-server-control-status]');
  const label = t(active ? 'server.connected' : desired ?
    `server.${state.runtime.phase}` : 'server.stopped');
  if (status.textContent !== label) status.textContent = label;
  status.classList.toggle('is-online', active);
  status.classList.toggle('is-offline', !active &&
    (!desired || state.runtime.phase === 'disconnected'));
  $('[data-server-control-metrics]').replaceChildren(
    serverMetricGrid(server));
  for (const button of $$('[data-server-toggle]')) {
    button.dataset.id = server.id;
    button.dataset.action = desired ? 'stop-server' : 'connect-server';
    button.classList.toggle('is-danger', desired);
    button.classList.toggle('is-accent', !desired);
    button.querySelector('span').textContent = t(desired
      ? 'action.stop' : 'action.connect');
    button.querySelector('use').setAttribute('href', desired
      ? '#icon-stop' : '#icon-play');
  }
}

function renderClientControl(data) {
  const client = state.clients.find((item) => item.id === data.id);
  if (!client) return;
  $('[data-client-control-name]').textContent = client.name;
  const type = clientDeviceType(client.deviceType);
  $('[data-client-control-type]').textContent = t(`client.${type}`);
  $('[data-client-control-icon] use').setAttribute('href',
    `#icon-${clientDeviceIcon(type)}`);
  $('[data-client-incoming]').textContent = formatBytes(
    finite(client.metrics?.received) ?? 0);
  $('[data-client-outgoing]').textContent = formatBytes(
    finite(client.metrics?.sent) ?? 0);
  $('[data-client-last-connection]').textContent = lastConnection(
    client.metrics?.lastConnected);
}

const regionCaches = new Map();
const countryOptionStates = new WeakMap();
const countryFlagFrames = new WeakMap();
const countryOptionHeight = 42;

function regionCache() {
  if (regionCaches.has(language)) return regionCaches.get(language);
  let displayNames = null;
  try {
    displayNames = new Intl.DisplayNames([language], { type: 'region' });
  } catch {}
  const items = countryCodes.map((code) => ({
    code, label: displayNames?.of(code) || code
  })).sort((left, right) => left.label.localeCompare(
    right.label, language));
  const result = {
    items,
    labels: new Map(items.map((item) => [item.code, item.label]))
  };
  regionCaches.set(language, result);
  return result;
}

function regionName(code) {
  return regionCache().labels.get(code) || code;
}

function loadVisibleCountryFlags(list) {
  countryFlagFrames.delete(list);
  const first = Math.max(0,
    Math.floor(list.scrollTop / countryOptionHeight) - 2);
  const count = Math.ceil(list.clientHeight / countryOptionHeight) + 4;
  for (let index = first;
    index < Math.min(list.children.length, first + count); index += 1) {
    const image = $('[data-flag-src]', list.children[index]);
    if (!image) continue;
    image.src = image.dataset.flagSrc;
    delete image.dataset.flagSrc;
  }
}

function queueVisibleCountryFlags(list) {
  if (!list || countryFlagFrames.has(list)) return;
  countryFlagFrames.set(list, requestAnimationFrame(() =>
    loadVisibleCountryFlags(list)));
}

function syncRoutePicker(picker) {
  if (!picker) return;
  const input = $('[data-route-value]', picker);
  const route = input?.value === 'direct' ? 'direct' : 'vpn';
  if (input) input.value = route;
  $('[data-route-icon] use', picker)?.setAttribute('href',
    `#icon-${route === 'direct' ? 'globe' : 'shield'}`);
  const current = $('[data-route-current]', picker);
  if (current) {
    current.dataset.i18n = `route.${route}`;
    current.textContent = t(current.dataset.i18n);
  }
  for (const option of $$('[data-route]', picker))
    option.setAttribute('aria-selected', String(option.dataset.route === route));
}

function syncSettingPicker(picker) {
  if (!picker) return;
  const input = $('select', picker);
  const current = $('[data-setting-current]', picker);
  const selected = input?.selectedOptions[0];
  if (current) current.textContent = selected?.textContent?.trim() || '';
  for (const option of $$('[data-value]', picker))
    option.setAttribute('aria-selected', String(option.dataset.value ===
      input?.value));
  const typeIcon = $('[data-client-type-icon] use', picker);
  if (typeIcon) typeIcon.setAttribute('href',
    `#icon-${clientDeviceIcon(input?.value)}`);
}

function syncSettingPickers(root = document) {
  for (const picker of $$('[data-setting-picker]', root))
    syncSettingPicker(picker);
}

function syncRoutePickers(root = document) {
  for (const picker of $$('[data-route-picker]', root))
    syncRoutePicker(picker);
}

function setCountrySelection(code = '') {
  const input = $('[data-country-input]');
  const value = $('[data-country-selection]');
  if (!input || !value) return;
  input.value = countryCodes.includes(code) ? code : '';
  value.replaceChildren();
  if (input.value) {
    value.append(flagImage(input.value),
      element('span', '', regionName(input.value)),
      element('small', '', input.value));
  } else {
    value.textContent = t('exceptions.country_placeholder');
  }
  $('[data-country-add]').disabled = !input.value;
}

function renderCountryOptions(force = false) {
  const list = $('[data-country-options]');
  if (!list || !draft) return;
  const selected = $('[data-country-input]')?.value || '';
  const saved = new Set(draft.countries.map((item) => item.code));
  if (list.dataset.language !== language) {
    if (!force) return;
    const fragment = document.createDocumentFragment();
    for (const { code, label } of regionCache().items) {
      const button = element('button', 'country-option');
      button.type = 'button';
      button.dataset.action = 'select-country';
      button.dataset.code = code;
      button.setAttribute('role', 'option');
      button.disabled = saved.has(code);
      const active = selected === code;
      button.classList.toggle('is-selected', active);
      button.setAttribute('aria-selected', String(active));
      button.append(flagImage(code, 'country-flag', true),
        element('span', '', label),
        element('small', '', code));
      fragment.append(button);
    }
    list.replaceChildren(fragment);
    list.dataset.language = language;
    list.addEventListener('scroll', () =>
      queueVisibleCountryFlags(list), { passive: true });
    countryOptionStates.set(list, { saved, selected });
    return;
  }
  const prior = countryOptionStates.get(list) || {
    saved: new Set(), selected: ''
  };
  for (const code of new Set([...prior.saved, ...saved])) {
    if (prior.saved.has(code) === saved.has(code)) continue;
    const button = $(`[data-code="${code}"]`, list);
    if (button) button.disabled = saved.has(code);
  }
  for (const code of new Set([prior.selected, selected])) {
    if (!code) continue;
    const button = $(`[data-code="${code}"]`, list);
    if (!button) continue;
    const active = selected === code;
    button.classList.toggle('is-selected', active);
    button.setAttribute('aria-selected', String(active));
  }
  countryOptionStates.set(list, { saved, selected });
}

function renderExceptions() {
  if (!draft) return;
  setSectionCollapsed('saved-rules',
    storage.get('section.saved-rules') === '1');
  const filter = $('[data-rule-filter]');
  if (filter) {
    filter.value = ruleFilter;
  }
  setCountrySelection();
  syncRoutePickers($('[data-modal-stage]'));
  renderRules();
  renderDevicePicker();
  syncSiteAddState();
  void loadDhcpDevices();
}

function inlineRuleRoute(type, id, route) {
  const picker = element('span', 'route-picker rule-inline-route');
  picker.dataset.routePicker = '';
  picker.dataset.popup = '';
  const input = element('input');
  input.type = 'hidden';
  input.value = route;
  input.dataset.routeValue = '';
  input.dataset.ruleInline = '';
  input.dataset.ruleType = type;
  input.dataset.ruleId = id;
  const trigger = element('button', 'route-picker-trigger');
  trigger.type = 'button';
  trigger.dataset.action = 'toggle-popup';
  trigger.dataset.popupTrigger = '';
  trigger.setAttribute('aria-expanded', 'false');
  trigger.setAttribute('aria-label', t('exceptions.route_label'));
  const current = element('span');
  current.dataset.routeCurrent = '';
  const routeIcon = icon(route === 'direct' ? 'globe' : 'shield');
  routeIcon.dataset.routeIcon = '';
  trigger.append(routeIcon, current, icon('chevron'));
  picker.append(input, trigger);
  syncRoutePicker(picker);
  return picker;
}

function prepareRuleMenu(picker) {
  if (!picker?.matches('.rule-inline-route') ||
      $('[data-popup-menu]', picker)) return;
  const menu = element('div', 'route-picker-menu rule-route-menu');
  menu.dataset.routeMenu = '';
  menu.dataset.popupMenu = '';
  menu.hidden = true;
  menu.setAttribute('role', 'listbox');
  for (const option of ['vpn', 'direct']) {
    const button = element('button');
    button.append(icon(option === 'direct' ? 'globe' : 'shield'),
      element('span', '', t(`route.${option}`)));
    button.type = 'button';
    button.dataset.action = 'select-route';
    button.dataset.route = option;
    button.setAttribute('role', 'option');
    menu.append(button);
  }
  picker.append(menu);
  syncRoutePicker(picker);
}

function renderRules() {
  const list = $('[data-saved-rule-list]');
  const table = $('[data-rule-table="saved"]');
  if (!list || !table || !draft) return;
  list.replaceChildren();
  const append = (type, id, name, symbol, details, route, remove) => {
    const row = element('div', 'rule-row');
    row.dataset.ruleType = type;
    row.dataset.ruleId = id;
    const copy = element('span', 'rule-copy', name);
    if (details) copy.append(element('small', '', details));
    const identity = element('span', 'rule-name-cell');
    identity.append(symbol, copy);
    const routeCell = element('span', 'rule-route-cell');
    routeCell.append(inlineRuleRoute(type, id, route));
    const actions = element('span', 'rule-actions');
    actions.append(actionButton(remove, 'trash', 'action.delete', id));
    row.append(identity, routeCell, actions);
    list.append(row);
  };
  if (ruleFilter === 'all' || ruleFilter === 'country') {
    for (const country of draft.countries) {
      append('country', country.code, regionName(country.code),
        flagImage(country.code), '', country.route, 'remove-country');
    }
  }
  if (ruleFilter === 'all' || ruleFilter === 'address') {
    for (const device of draft.devices) {
      const label = device.name || device.address || device.mac;
      const details = [device.address, device.mac].filter((value) =>
        value && value !== label).join(' · ');
      append('address', device.id, label, icon(networkDeviceIcon(device)),
        details, device.route, 'remove-address');
    }
  }
  if (ruleFilter === 'all' || ruleFilter === 'site') {
    for (const site of draft.sites) {
      append('site', site.id, site.pattern, icon('globe'), '',
        site.route, 'remove-site');
    }
  }
  const total = draft.countries.length + draft.devices.length +
    draft.sites.length;
  const visible = list.childElementCount;
  table.classList.toggle('is-empty', !visible);
  list.classList.toggle('is-empty', !visible);
  $('[data-rule-table-head]').hidden = !visible ||
    $('[data-section-toggle="saved-rules"]').getAttribute('aria-expanded') === 'false';
  if (!visible) {
    const empty = element('div',
      'empty-state is-entity-empty is-rule-empty');
    empty.append(icon('info'), element('strong', '',
      t(total ? 'exceptions.no_filtered_rules' :
        'exceptions.no_saved_rules')));
    list.append(empty);
  }
  renderCountryOptions();
}

function addCountry() {
  const code = $('[data-country-input]').value;
  if (!countryCodes.includes(code) ||
      draft.countries.some((item) => item.code === code)) return;
  const route = $('[data-country-route]').value === 'vpn' ? 'vpn' : 'direct';
  draft.countries.push({ code, route });
  setCountrySelection();
  popups.setOpen($('[data-country-picker]'), false);
  renderRules();
  queueDraftSave('exceptions.rule_saved');
}

function routeRulesView() {
  return modal.find('exceptions');
}

function selectedDeviceMacs() {
  const view = routeRulesView();
  if (!view) return [];
  view.data.selectedDevices ||= [];
  return view.data.selectedDevices;
}

function renderDevicePicker() {
  const list = $('[data-dhcp-device-list]');
  const value = $('[data-device-selection]');
  if (!list || !value) return;
  const selected = selectedDeviceMacs();
  list.replaceChildren();
  if (dhcpLoading) {
    list.append(element('p', 'list-empty', t('exceptions.devices_loading')));
  } else if (!dhcpDevices.length) {
    list.append(element('p', 'list-empty', t(dhcpFailed
      ? 'exceptions.devices_unavailable' : 'exceptions.no_devices')));
  }
  for (const device of dhcpDevices) {
    const row = element('label', 'device-table-row');
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = device.mac;
    input.checked = selected.includes(device.mac);
    input.dataset.dhcpDevice = '';
    const deviceName = element('span', 'device-name');
    deviceName.append(icon(networkDeviceIcon(device)),
      element('span', 'device-name-text', device.name));
    row.append(input, deviceName,
      element('span', '', device.address), element('span', '', device.mac));
    list.append(row);
  }
  syncDevicePickerSelection();
  popups.invalidate(list.closest('[data-popup]'));
}

function syncDevicePickerSelection() {
  const value = $('[data-device-selection]');
  if (!value) return;
  const selected = selectedDeviceMacs();
  for (const input of $$('[data-dhcp-device]')) {
    const checked = selected.includes(input.value);
    input.checked = checked;
    input.closest('.device-table-row')?.classList.toggle('is-selected',
      checked);
  }
  const names = selected.map((mac) =>
    dhcpDevices.find((item) => item.mac === mac)?.name || mac);
  value.textContent = names.length ? names.join(' · ') :
    t('exceptions.device_placeholder');
  const add = $('[data-device-add]');
  if (add) add.disabled = !selected.length;
}

function syncSiteAddState() {
  const input = $('[data-site-input]');
  const add = $('[data-site-add]');
  if (input && add) add.disabled = !input.value.trim();
}

async function loadDhcpDevices() {
  if (dhcpLoading || dhcpLoaded || !token) return;
  dhcpLoading = true;
  dhcpFailed = false;
  renderDevicePicker();
  try {
    const result = await api('device.list');
    dhcpDevices = (Array.isArray(result?.devices) ? result.devices : [])
      .map((item) => ({
        name: String(item.name || item.address || '').slice(0, 64),
        address: String(item.address || ''),
        mac: normalizeMac(item.mac)
      }))
      .filter((item) => item.name && validAddress(item.address) && item.mac);
    dhcpLoaded = true;
  } catch {
    dhcpFailed = true;
  } finally {
    dhcpLoading = false;
    renderDevicePicker();
  }
}

function addSelectedDevices() {
  const form = $('[data-selected-device-form]');
  const selected = selectedDeviceMacs();
  if (!selected.length) throw new PanelError('device_required');
  const route = form.elements.route.value === 'direct' ? 'direct' : 'vpn';
  let added = 0;
  for (const mac of selected) {
    const device = dhcpDevices.find((item) => item.mac === mac);
    if (!device || draft.devices.some((item) => item.mac === mac)) continue;
    draft.devices.push({
      id: randomId('device'), name: device.name,
      address: device.address, mac, bindMac: true, route
    });
    added += 1;
  }
  if (!added) throw new PanelError('duplicate_rule');
  routeRulesView().data.selectedDevices = [];
  popups.setOpen($('[data-device-picker]').closest('[data-popup]'), false);
  renderRules();
  renderDevicePicker();
  queueDraftSave('exceptions.rule_saved');
  return true;
}

function syncManualFields() {
  const form = $('[data-manual-device-form]');
  if (!form) return;
  const mac = form.elements.kind.value === 'mac';
  const input = form.elements.value;
  input.value = mac ? maskMac(input.value) : maskIpv4(input.value);
  input.maxLength = mac ? 17 : 18;
  input.inputMode = mac ? 'text' : 'decimal';
  input.placeholder = t(mac ? 'exceptions.mac_placeholder' :
    'exceptions.ip_placeholder');
  $('[data-manual-bind-row]').hidden = mac;
  form.elements.bindMac.disabled = mac;
  syncRoutePickers(form);
}

function selectedRule(data) {
  if (!draft || !data) return null;
  if (data.type === 'country') return draft.countries.find((item) =>
    item.code === data.id);
  if (data.type === 'address') return draft.devices.find((item) =>
    item.id === data.id);
  if (data.type === 'site') return draft.sites.find((item) =>
    item.id === data.id);
  return null;
}

async function saveManualDevice() {
  let saved = false;
  await operation(async () => {
    const form = $('[data-manual-device-form]');
    const kind = form.elements.kind.value;
    const value = form.elements.value.value.trim();
    const route = form.elements.route.value === 'direct' ? 'direct' : 'vpn';
    let address = null, mac = null;
    let bindMac = kind === 'mac' || form.elements.bindMac.checked;
    if (kind === 'mac') {
      mac = normalizeMac(value);
      if (!mac) throw new PanelError('invalid_mac');
    } else {
      address = value;
      if (!validAddress(address)) throw new PanelError('invalid_address');
      if (bindMac) {
        const result = await api('device.resolve', { address });
        mac = normalizeMac(result?.mac);
        if (!mac) throw new PanelError('mac_not_found');
      }
    }
    const duplicate = draft.devices.some((item) =>
      mac ? item.mac === mac : item.address === address);
    if (duplicate) throw new PanelError('duplicate_rule');
    draft.devices.push({
      id: randomId('device'), name: value, address, mac, bindMac,
      route
    });
    queueDraftSave('exceptions.rule_saved');
    saved = true;
    return true;
  });
  if (saved) await back();
}

function addSite() {
  const form = $('[data-site-form]');
  const pattern = normalizeSitePattern(form.elements.pattern.value);
  const route = form.elements.route.value === 'direct' ? 'direct' : 'vpn';
  if (draft.sites.some((site) => site.pattern.toLowerCase() === pattern.toLowerCase())) {
    throw new PanelError('duplicate_site');
  }
  draft.sites.push({ id: randomId('site'), pattern, route });
  form.elements.pattern.value = '';
  syncSiteAddState();
  renderRules();
  queueDraftSave('exceptions.rule_saved');
  return true;
}

function renderManagement() {
  const view = views[views.length - 1];
  const selected = view.data.tab || 'servers';
  for (const type of ['server', 'client']) {
    const list = $(`[data-management-${type}s]`);
    list.replaceChildren();
    for (const item of state[`${type}s`]) {
      const row = element('div', 'management-row');
      row.append(icon(type === 'server' ? 'server' :
        clientDeviceIcon(item.deviceType)));
      const name = element('span', 'management-name');
      const title = element('span', 'server-title');
      title.append(element('strong', '', item.name));
      if (type === 'server') {
        const country = element('span', 'inline-country');
        setCountryLabel(country, serverCountryCode(item, state.runtime));
        title.append(country);
      }
      name.append(title);
      if (type === 'client') name.append(element('small', '',
        t(item.provisioned ? 'client.ready' : 'client.inactive')));
      const actions = element('div', 'row-actions');
      actions.append(actionButton(type === 'server' ? 'edit-server' : 'view-client', type === 'server' ? 'edit' : 'eye', type === 'server' ? 'action.edit' : 'action.view', item.id));
      actions.append(actionButton(`delete-${type}`, 'trash', 'action.delete', item.id));
      row.append(name, actions);
      list.append(row);
    }
    if (!state[`${type}s`].length) list.append(element('div', 'empty-state is-compact', t(`${type}s.empty_title`)));
    $(`[data-${type}-count]`).textContent = state[`${type}s`].length;
  }
  for (const button of $$('[data-network-tab]')) {
    const active = button.dataset.networkTab === selected;
    button.setAttribute('aria-selected', String(active));
    button.classList.toggle('is-active', active);
    button.tabIndex = active ? 0 : -1;
  }
  for (const panel of $$('[data-network-panel]')) panel.hidden = panel.dataset.networkPanel !== selected;
}

function safeQr(markup) {
  if (typeof markup !== 'string' || markup.length > 500000) return null;
  const parsed = new DOMParser().parseFromString(markup, 'image/svg+xml');
  if (parsed.querySelector('parsererror') || parsed.documentElement.localName !== 'svg') return null;
  const tags = new Set(['svg', 'g', 'rect', 'path', 'title']);
  const attributes = new Set(['xmlns', 'version', 'viewBox', 'width', 'height', 'x', 'y', 'd', 'fill', 'stroke', 'stroke-width', 'shape-rendering', 'transform', 'rx', 'ry']);
  for (const node of [parsed.documentElement, ...parsed.documentElement.querySelectorAll('*')]) {
    if (!tags.has(node.localName)) { node.remove(); continue; }
    for (const attribute of [...node.attributes]) {
      if (!attributes.has(attribute.name) || /url\s*\(|javascript:|data:/i.test(attribute.value)) node.removeAttribute(attribute.name);
    }
  }
  parsed.documentElement.setAttribute('shape-rendering', 'crispEdges');
  parsed.documentElement.setAttribute('preserveAspectRatio', 'xMidYMid meet');
  return document.importNode(parsed.documentElement, true);
}

function renderClientView(data) {
  const exported = data.export;
  if (!exported) {
    $('[data-client-name]').value = data.name || '';
    $('[data-client-type]').value = clientDeviceType(data.deviceType);
    syncSettingPicker($('[data-client-type]').closest(
      '[data-setting-picker]'));
    return;
  }
  $('[data-client-form]').hidden = true;
  $('[data-client-result]').hidden = false;
  $('[data-client-result-name]').textContent = exported.name;
  $('[data-client-lan-row]').hidden = !exported.provisioned || !exported.lanAccessConfigurable;
  $('[data-client-lan]').checked = exported.allowLan === true;
  $('[data-client-config]').textContent = exported.config || exported.uri || '';
  const qr = safeQr(exported.qrSvg);
  const qrFrame = $('[data-client-qr]');
  qrFrame.replaceChildren(...(qr ? [qr] : []));
  qrFrame.hidden = !qr;
  if (!qr) toast(t('client.qr_unavailable'), 'error');
  setClientNameEditing(false);
}

function setClientNameEditing(editing) {
  const form = $('[data-client-rename-form]');
  if (!form) return;
  form.hidden = !editing;
  $('[data-client-result-title]').hidden = editing;
  $('[data-action="regenerate-client-config"]').disabled = editing;

  if (editing) {
    const input = $('[data-client-rename-input]');
    input.value = modal.current.data.export.name;
    input.focus({ preventScroll: true });
    input.select();
  }
}

async function saveClientName() {
  const view = modal.current;
  if (view?.name !== 'client-device' || !view.data.export) return;
  let exported;
  await operation(async () => {
    const name = $('[data-client-rename-input]').value.trim();
    if (!name || name.length > 48 || /[\u0000-\u001f\u007f]/.test(name))
      throw new PanelError('invalid_name');
    const result = await api('client.update', {
      revision: state.revision, id: view.data.export.id, name
    });
    applyState(result.state);
    if (draft) draft.revision = state.revision;
    exported = result.client;
  });
  if (!exported) return;
  view.data.export = exported;
  renderClientView(view.data);
  $('[data-action="edit-client-name"]').focus({ preventScroll: true });
  toast(t('client.renamed'));
}

async function regenerateClient() {
  const clientView = modal.find('client-device');
  if (!clientView?.data.export) return;
  let exported;
  await operation(async () => {
    const result = await api('client.get', { id: clientView.data.export.id });
    exported = result.export;
  });
  if (!exported) return;
  clientView.data.export = exported;
  await back();
  toast(t('client.regenerated'));
}

function settingsDraft(source = state) {
  return {
    revision: source.revision,
    settings: clone(source.settings),
    countries: clone(source.countries),
    devices: clone(source.devices),
    sites: clone(source.sites)
  };
}

function beginSettingsDraft() {
  draftSession += 1;
  draft = settingsDraft();
  draftChange = 0;
  draftSaved = 0;
  draftNoticeKey = null;
}

function refreshDraftView() {
  const name = views.at(-1)?.name;
  appearance(draft?.settings || state.settings);
  if (name === 'settings-home' || name === 'interface-settings')
    renderSettings();
  if (name === 'exceptions') renderExceptions();
}

async function persistDraft() {
  if (!draft || draftSaving || draftSaved >= draftChange) return;
  const session = draftSession;
  draftSaving = true;
  let retried = false;
  try {
    while (draft && session === draftSession &&
        draftSaved < draftChange) {
      const version = draftChange;
      const noticeKey = draftNoticeKey;
      const payload = clone(draft);
      try {
        const next = await api('settings', {
          revision: payload.revision,
          settings: payload.settings,
          countries: payload.countries,
          devices: payload.devices,
          sites: payload.sites
        });
        applyState(next);
        if (!draft || session !== draftSession) break;
        draft.revision = state.revision;
        draftSaved = version;
        if (draftSaved >= draftChange && noticeKey) {
          toast(t(noticeKey));
          draftNoticeKey = null;
        }
        retried = false;
        storage.set('language', state.settings.language);

      } catch (error) {
        if (error.code === 'revision_conflict' && !retried) {
          retried = true;
          try {
            applyState(await api('state'));
            if (draft && session === draftSession)
              draft.revision = state.revision;
            continue;
          } catch {}
        }
        const text = errorText(error);
        toast(text, 'error');
        if (draft && session === draftSession) {
          draft = settingsDraft();
          draftSaved = draftChange;
          refreshDraftView();
        }
        break;
      }
    }
  } finally {
    draftSaving = false;
    if (draft && draftSaved < draftChange) void persistDraft();
  }
}

function queueDraftSave(noticeKey = 'settings.saved') {
  if (!draft) return;
  draftNoticeKey = noticeKey;
  draftChange += 1;
  void persistDraft();
}

async function testServer() {
  await operation(async () => {

    toast(t('server.testing'), 'info');
    const result = await api('server.test', { config: $('[data-server-config]').value });

    toast(t(result.valid ? 'server.test_valid' : 'server.test_invalid'),
      result.valid ? 'success' : 'error');
  });
}

async function saveServer() {
  await operation(async () => {
    const view = views[views.length - 1];
    const name = $('[data-server-name]').value.trim();
    if (!name) throw new PanelError('invalid_name');
    const next = await api('server.save', {
      revision: state.revision, name,
      config: $('[data-server-config]').value,
      ...(view.data.id ? { id: view.data.id } : {})
    });
    applyState(next);
    if (draft) draft.revision = state.revision;
    toast(t('server.saved_notice'));
    return true;
  }, true);
}

async function controlServer(id, stop) {
  await operation(async () => {
    const next = await api(stop ? 'server.stop' : 'server.start', {
      revision: state.revision,
      ...(!stop ? { id } : {})
    });
    applyState(next);
    const current = views.at(-1);
    if (current?.name === 'server-control') renderServerControl(current.data);
    return true;
  });
  if (token) void poll();
}

async function createClient() {
  let exported;
  await operation(async () => {
    const form = $('[data-client-form]');
    const name = form.elements.name.value.trim();
    const deviceType = form.elements.deviceType.value;
    if (!name || name.length > 48 || /[\u0000-\u001f\u007f]/.test(name)) throw new PanelError('invalid_name');
    const result = await api('client.save', { revision: state.revision, name, deviceType, ...(state.servers[0] ? { serverId: state.servers[0].id } : {}) });
    applyState(result.state);
    if (draft) draft.revision = state.revision;
    exported = result.client;
  });
  if (exported) {
    views[views.length - 1].data = { export: exported, titleKey: 'client.export_title' };
    await modal.repaint();
    toast(t('client.saved_notice'));
  }
}

async function savePin() {
  const form = $('[data-pin-change-form]');
  const first = $('[data-new-pin]').value;
  const repeat = $('[data-repeat-pin]').value;
  if (!/^\d{4}$/.test(first) || first !== repeat) {
    form.classList.remove('is-error');
    void form.offsetWidth;
    form.classList.add('is-error');
    toast(t('error.pin_mismatch'), 'error');
    return;
  }
  form.classList.remove('is-error');
  const setup = pinSetupRequired;
  let saved = false;
  await operation(async () => {
    const result = await api('pin.change', { newPin: first });
    token = result.token;
    pinSetupRequired = false;
    $('[data-pin-change-form]').reset();
    saved = true;
  });
  if (!saved) return;
  toast(t('pin_change.success'));
  if (setup) {
    await openView('help', {}, true);
    void poll();
  } else await back();
}

function syncPinSaveState() {
  const first = $('[data-new-pin]')?.value || '';
  const repeat = $('[data-repeat-pin]')?.value || '';
  const disabled = !first && !repeat;
  const save = $('[data-modal-footer] [data-action="save-pin"]');
  if (save) save.disabled = disabled;
  $('[data-pin-change-form]')?.classList.remove('is-error');
}

function setSectionCollapsed(id, collapsed) {
  const button = $(`[data-section-toggle="${id}"]`);
  const body = $(`[data-section-body="${id}"]`);
  if (!button || !body) return;
  const key = collapsed ? 'action.expand' : 'action.collapse';
  button.classList.toggle('is-collapsed', collapsed);
  button.setAttribute('aria-expanded', String(!collapsed));
  button.setAttribute('aria-label', t(key));
  button.title = t(key);
  button.dataset.i18nTitle = key;
  button.dataset.i18nAriaLabel = key;
  const label = $('[data-i18n]', button);
  if (label) {
    label.dataset.i18n = key;
    label.textContent = t(key);
  }
  body.classList.toggle('is-collapsed', collapsed);
  body.closest('.entity-section')?.classList.toggle('is-collapsed',
    collapsed);
  body.inert = collapsed;
  body.setAttribute('aria-hidden', String(collapsed));
  storage.set(`section.${id}`, collapsed ? '1' : '0');
  if (id === 'saved-rules' && $('[data-rule-table-head]'))
    $('[data-rule-table-head]').hidden = collapsed ||
      $('[data-rule-table="saved"]')?.classList.contains('is-empty');
  if (id === 'status') {
    $('[data-period-control]').hidden = collapsed;
    $('.intro').classList.toggle('is-collapsed', collapsed);
    charts.draw();
  }
}

async function operation(task, closeOnSuccess = false) {
  if (busy) return;
  setBusy(true);

  let success = false;
  try { success = await task(); }
  catch (error) {
    if (error.code === 'revision_conflict') {
      try { applyState(await api('state')); } catch {}
    }
    if (error.code === 'locked' || error.code === 'unauthorized' ||
        error.code === 'luci_required') localLock();
    else {
      const text = errorText(error);
      toast(text, 'error');
    }
  } finally { setBusy(false); }
  if (closeOnSuccess && success) {
    if (views.length > 1 && views.some((view) => view.name === 'network-management')) await back();
    else await closeModal();
  }
}

async function loadEntity(type, id) {
  let data;
  await operation(async () => { data = await api(`${type}.get`, { id }); });
  if (!data) return;
  await openView(type === 'server' ? 'server-config' : 'client-device', type === 'server'
    ? { id: data.id, name: data.name, config: data.config,
      titleKey: 'server.edit_title' }
    : { export: data.export || data, id: data.id || id, managed: true,
      titleKey: 'client.export_title' });
}

async function deleteEntity() {
  const { type, item } = views[views.length - 1].data;
  if (type === 'country') {
    draft.countries = draft.countries.filter((entry) => entry.code !== item.id);
  } else if (type === 'address') {
    draft.devices = draft.devices.filter((entry) => entry.id !== item.id);
  } else if (type === 'site') {
    draft.sites = draft.sites.filter((entry) => entry.id !== item.id);
  }
  if (['country', 'address', 'site'].includes(type)) {
    queueDraftSave('exceptions.rule_deleted');
    await back();
    return;
  }
  let deleted = false;
  await operation(async () => {
    if (type === 'server' || type === 'client') {
      const next = await api(`${type}.delete`, {
        revision: state.revision, id: item.id
      });
      applyState(next);
      if (draft) draft.revision = state.revision;
    } else {
      throw new PanelError('unavailable');
    }
    deleted = true;
    return true;
  });
  if (!deleted) return;
  toast(t('delete.success'));
  const parent = views.at(-2);
  if (parent?.name === 'server-control' || parent?.name === 'client-control' ||
      (parent?.name === 'client-device' && parent.data?.managed))
    await closeModal();
  else await back();
}

async function copyConfig() {
  const config = $('[data-client-config]').textContent;
  try {
    if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(config);
    else {
      const field = element('textarea', 'copy-buffer');
      field.value = config;
      $('#modal-shell').append(field);
      field.select();
      const copied = document.execCommand('copy');
      field.remove();
      if (!copied) throw new Error();
    }
    toast(t('client.copied'));
  } catch { toast(t('error.copy_failed'), 'error'); }
}

function renderRouterStats() {
  if (!$('[data-router-metrics]')) return;
  const stats = charts.stats();
  const latest = stats.latest;
  const metrics = $('[data-router-metrics]');
  metrics.replaceChildren();
  const uptime = latest?.uptime == null ? '—' : t('router.uptime_value', { hours: Math.floor(latest.uptime / 3600), minutes: Math.floor(latest.uptime % 3600 / 60) });
  const values = { uptime, load: latest?.load == null ? '—' : latest.load.toFixed(2), cpu: latest?.cpu == null ? '—' : `${latest.cpu.toFixed(1)}%`, ram: latest?.ram == null ? '—' : `${latest.ram.toFixed(1)}%` };
  for (const [key, value] of Object.entries(values)) {
    const card = element('div', 'router-metric');
    card.append(element('small', '', t(`router.${key}`)), element('strong', '', value));
    metrics.append(card);
  }
  for (const key of ['wan', 'lan']) {
    const body = $(`[data-interface-stats="${key}"]`);
    body.replaceChildren();
    for (const direction of ['rx', 'tx']) {
      const row = element('tr');
      row.append(element('th', '', t(`router.${direction}`)));
      row.append(element('td', '', formatBytes(stats[key][direction].total)));
      row.append(element('td', '', formatBytes(stats[key][direction].average, true)));
      row.append(element('td', '', formatBytes(stats[key][direction].peak, true)));
      const chart = element('td', 'router-history');
      chart.append(rateSparkline(charts.rateSeries(key, direction)));
      row.append(chart);
      body.append(row);
    }
  }
}

function rateSparkline(series) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.classList.add('router-sparkline');
  svg.setAttribute('viewBox', '0 0 72 24');
  svg.setAttribute('aria-hidden', 'true');
  const line = document.createElementNS('http://www.w3.org/2000/svg',
    'polyline');
  const values = series.map((item) => item.value);
  const peak = Math.max(1, ...values);
  const start = series[0]?.time || Date.now() - 360000;
  const end = Math.max(start + 1, series.at(-1)?.time || Date.now());
  line.setAttribute('points', series.map((item) => {
    const x = 1 + (item.time - start) / (end - start) * 70;
    const y = 22 - item.value / peak * 20;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' '));
  svg.append(line);
  return svg;
}

function stopPolling() { clearTimeout(pollTimer); pollTimer = 0; }

async function poll() {
  stopPolling();
  if (!token || document.hidden || polling) return;
  polling = true;
  const currentEpoch = epoch;
  try {
    const payload = await api('telemetry');
    if (currentEpoch !== epoch) return;
    if (payload.available !== true && telemetryAvailable !== false)
      toast(t('dashboard.no_telemetry'), 'error');
    telemetryAvailable = payload.available === true;
    if (payload.runtime) applyRuntime(payload.runtime, payload.sample);
    if (telemetryAvailable) charts.update(payload);
    failures = 0;
    renderRouterStats();
  } catch (error) {
    if (currentEpoch !== epoch) return;
    if (error.code === 'locked' || error.code === 'unauthorized' ||
        error.code === 'luci_required') localLock();
    else if (++failures === 1)
      toast(t('dashboard.stale_notice'), 'error');
  } finally {
    polling = false;
    renderRuntimeNotice();
    if (token && !document.hidden) pollTimer = setTimeout(poll, Math.min(60000, 5000 * 2 ** Math.min(failures, 4)));
  }
}

function localLock() {
  clearTimeout(toastTimer);
  hideToast();
  runtimeNoticeKey = connectedNoticeKey = null;
  epoch += 1;
  token = null;
  pinSetupRequired = false;
  state = null;
  draft = null;
  popups.closeAll();
  modal.reset();
  stopPolling();
  cancelPending();
  charts.clear();
  charts.setSuspended(false);
  dhcpDevices = [];
  dhcpLoaded = false;
  dhcpLoading = false;
  dhcpFailed = false;
  telemetryAvailable = null;
  failures = 0;
  $('#app-shell').hidden = true;
  $('#app-shell').inert = false;
  $('#pin-gate').hidden = false;
  $('#pin-input').value = '';
  $('#pin-input').disabled = !hasHost;
  $$('[data-pin-dot]').forEach((dot) => dot.classList.remove('is-filled'));
  $('#pin-gate').classList.remove('is-loading', 'is-unlocking', 'is-error');
  $('#pin-prompt').textContent = t('auth.pin_prompt');
}

async function unlock(event) {
  event.preventDefault();
  if (!hasHost || $('#pin-input').disabled) return;
  const pin = $('#pin-input').value;
  if (!/^\d{4}$/.test(pin)) return;
  $('#pin-input').disabled = true;
  $('#pin-gate').classList.add('is-loading');
  $('#pin-prompt').textContent = t('auth.loading');
  try {
    const result = await request('unlock', { pin });
    token = result.token;
    pinSetupRequired = result.pinChangeRequired === true;
    if (!token) throw new PanelError('unavailable');
    applyState(result.state);
    $('#app-shell').hidden = false;
    $('#pin-gate').classList.add('is-unlocking');
    await waitForMotion($('.pin-card'));
    $('#pin-gate').hidden = true;
    $('#pin-input').value = '';
    epoch += 1;
    if (pinSetupRequired) await openView('pin-change', {
      titleKey: 'pin_setup.title'
    }, true);
    else await poll();
  } catch (error) {
    localLock();
    if (error.code === 'invalid_pin') {
      void $('#pin-gate').offsetWidth;
      $('#pin-gate').classList.add('is-error');
      setTimeout(() => $('#pin-gate').classList.remove('is-error'), 520);
    }
    toast(errorText(error), 'error');
    $('#pin-input').focus();
  }
}

async function perform(action, target) {
  if (action === 'lock') {
    const sessionToken = token;
    localLock();
    try { await request('lock', { token: sessionToken }); } catch (error) { toast(errorText(error), 'error'); }
    return;
  }
  if (busy || modal.transitioning) return;
  const id = target.dataset.id;
  switch (action) {
    case 'scroll-top': $('#app-shell').scrollTo({ top: 0, behavior: 'smooth' }); break;
    case 'toggle-section': {
      const section = target.dataset.sectionToggle;
      setSectionCollapsed(section,
        target.getAttribute('aria-expanded') === 'true');
      break;
    }
    case 'open-add': await openView('add-choice', {}, true); break;
    case 'open-settings':
      beginSettingsDraft();
      await openView('settings-home', {}, true); break;
    case 'add-server': await openView('server-config'); break;
    case 'add-client': await openView('client-device'); break;
    case 'open-server-control': await openView('server-control', { id }, true); break;
    case 'open-client-control': await openView('client-control', { id }, true); break;
    case 'manage-client': await loadEntity('client', id); break;
    case 'modal-close': await closeModal(); break;
    case 'modal-back': await back(); break;
    case 'save-server': await saveServer(); break;
    case 'save-pin': await savePin(); break;
    case 'save-manual-address': await saveManualDevice(); break;
    case 'generate-client': await createClient(); break;
    case 'open-exceptions':
      if (!draft) beginSettingsDraft();
      await openView('exceptions'); break;
    case 'open-networks': await openView('network-management'); break;
    case 'open-manual-address': await openView('manual-address'); break;
    case 'toggle-popup': {
      const popup = target.closest('[data-popup]');
      prepareRuleMenu(popup);
      const countryPicker = popup?.matches('[data-country-picker]');
      if (countryPicker && !popup.classList.contains('is-open'))
        renderCountryOptions(true);
      popups.toggle(target);
      if (countryPicker && popup.classList.contains('is-open'))
        queueVisibleCountryFlags($('[data-country-options]', popup));
      break;
    }
    case 'select-country':
      setCountrySelection(target.dataset.code);
      popups.setOpen(popups.popupFor(target), false);
      renderCountryOptions();
      break;
    case 'select-setting-option': {
      const picker = popups.popupFor(target);
      const input = $('select', picker);
      input.value = target.dataset.value;
      popups.setOpen(picker, false);
      syncSettingPicker(picker);
      input.dispatchEvent(new Event('change', { bubbles: true }));
      break;
    }
    case 'select-route': {
      const picker = popups.popupFor(target);
      const input = $('[data-route-value]', picker);
      input.value = target.dataset.route === 'direct' ? 'direct' : 'vpn';
      popups.setOpen(picker, false);
      syncRoutePicker(picker);
      if (input.matches('[data-rule-inline]')) {
        const rule = selectedRule({
          type: input.dataset.ruleType,
          id: input.dataset.ruleId
        });
        if (rule) {
          rule.route = input.value;
          queueDraftSave('exceptions.rule_saved');
        }
      }
      break;
    }
    case 'open-pin-change': await openView('pin-change'); break;
    case 'open-interface-settings': await openView('interface-settings'); break;
    case 'open-help': await openView('help'); break;
    case 'open-router-stats': await openView('router-stats', {}, true); break;
    case 'test-server': await testServer(); break;
    case 'connect-server': await controlServer(id, false); break;
    case 'stop-server': await controlServer(id, true); break;
    case 'copy-client-config': await copyConfig(); break;
    case 'edit-client-name': setClientNameEditing(true); break;
    case 'cancel-client-rename': setClientNameEditing(false); break;
    case 'regenerate-client-config':
      await openView('confirm-regenerate'); break;
    case 'confirm-regenerate': await regenerateClient(); break;
    case 'edit-server': await loadEntity('server', id); break;
    case 'view-client': await loadEntity('client', id); break;
    case 'delete-server': case 'delete-client': {
      const type = action.split('-')[1];
      const item = state[`${type}s`].find((entry) => entry.id === id);
      if (item) await openView('confirm-delete', { type, item });
      break;
    }
    case 'confirm-delete': await deleteEntity(); break;
    case 'remove-country': {
      await openView('confirm-delete', {
        type: 'country', item: { id, name: regionName(id) }
      });
      break;
    }
    case 'remove-address': {
      const entry = draft.devices.find((item) => item.id === id);
      if (entry) await openView('confirm-delete', {
        type: 'address',
        item: { ...entry, name: entry.name || entry.address || entry.mac }
      });
      break;
    }
    case 'remove-site': {
      const entry = draft.sites.find((item) => item.id === id);
      if (entry) await openView('confirm-delete', {
        type: 'site', item: { ...entry, name: entry.pattern }
      });
      break;
    }
  }
}

document.addEventListener('click', (event) => {
  popups.closeOutside(event.target);
  const row = event.target.closest('.setting-row');
  if (row && !event.target.closest('button, a, input, select, label')) {
    const input = row.querySelector('input[type="checkbox"]');
    if (input && !input.disabled) input.click();
  }
  const target = event.target.closest('[data-action]');
  if (!target || target.type === 'submit') return;
  event.preventDefault();
  void perform(target.dataset.action, target);
});

document.addEventListener('submit', (event) => {
  const form = event.target;
  if (form.matches('[data-pin-form]')) { void unlock(event); return; }
  event.preventDefault();
  if (busy || modal.transitioning || !token) return;
  if (form.matches('[data-server-form]')) void saveServer();
  if (form.matches('[data-client-form]')) void createClient();
  if (form.matches('[data-client-rename-form]')) void saveClientName();
  if (form.matches('[data-country-form]')) addCountry();
  if (form.matches('[data-selected-device-form]')) {
    void operation(addSelectedDevices);
  }
  if (form.matches('[data-manual-device-form]')) void saveManualDevice();
  if (form.matches('[data-site-form]')) void operation(addSite);
  if (form.matches('[data-pin-change-form]')) void savePin();
});

document.addEventListener('input', (event) => {
  const input = event.target;
  if (input.id === 'pin-input') {
    $('#pin-gate').classList.remove('is-error');
    input.value = input.value.replace(/\D/g, '').slice(0, 4);
    $$('[data-pin-dot]').forEach((dot, index) => dot.classList.toggle('is-filled', index < input.value.length));
    if (input.value.length === 4) $('#pin-form').requestSubmit();
  }
  const current = views[views.length - 1];
  if (current?.name === 'server-config') {
    if (input.matches('[data-server-config]'))
      current.data.config = input.value;
    if (input.matches('[data-server-name]'))
      current.data.name = input.value;
  }
  if (current?.name === 'client-device' && input.matches('[data-client-name]')) current.data.name = input.value;
  if (input.matches('[data-manual-value]')) {
    input.value = $('[data-manual-kind]').value === 'mac'
      ? maskMac(input.value) : maskIpv4(input.value);
  }
  if (input.matches('[data-site-input]')) syncSiteAddState();
  if (input.matches('[data-new-pin], [data-repeat-pin]')) {
    input.value = input.value.replace(/\D/g, '').slice(0, 4);
    syncPinSaveState();
  }
});

document.addEventListener('change', (event) => {
  const input = event.target;
  if (input.matches('[data-client-lan]')) {
    const view = modal.current;
    if (!view?.data?.export) return;
    input.disabled = true;
    void operation(async () => {
      const result = await api('client.access', {
        revision: state.revision, id: view.data.export.id,
        allowLan: input.checked
      });
      applyState(result.state);
      view.data.export = result.client;
      toast(t('client.access_saved'));
    }).finally(() => {
      input.checked = view.data.export.allowLan === true;
      input.disabled = false;
    });
  }
  if (input.matches('select.compact-select')) {
    sizeCompactSelect(input);
  }
  if (input.matches('[data-rule-filter]')) {
    ruleFilter = ['country', 'address', 'site'].includes(input.value)
      ? input.value : 'all';
    storage.set('rules.filter', ruleFilter);
    renderRules();
  }
  if (input.matches('[data-period]')) { charts.setPeriod(input.value); storage.set('period', input.value); renderRouterStats(); }
  if (input.matches('[data-setting]') && draft) {
    const value = input.type === 'checkbox' ? input.checked : input.value;
    draft.settings[input.dataset.setting] = input.hasAttribute(
      'data-setting-inverted') ? !value : value;
    appearance(draft.settings);
    renderSettings();
    queueDraftSave();
  }
  if (input.matches('[data-language]') && draft) {
    draft.settings.language = input.value;
    appearance(draft.settings);
    renderSettings();
    queueDraftSave();
  }
  if (input.name === 'deviceType' && views.length) views[views.length - 1].data.deviceType = input.value;
  if (input.matches('[data-manual-kind]')) syncManualFields();
  if (input.matches('[data-dhcp-device]')) {
    const selected = selectedDeviceMacs();
    const index = selected.indexOf(input.value);
    if (input.checked && index < 0) selected.push(input.value);
    if (!input.checked && index >= 0) selected.splice(index, 1);
    syncDevicePickerSelection();
  }
});

for (const button of $$('[data-chart-toggle]')) {
  const id = button.dataset.chartToggle;
  const card = button.closest('[data-chart-card]');
  const setCollapsed = (value) => {
    card.classList.toggle('is-collapsed', value);
    button.setAttribute('aria-expanded', String(!value));
    const panel = $(`#chart-panel-${id}`);
    panel.inert = value;
    panel.setAttribute('aria-hidden', String(value));
    storage.set(`chart.${id}`, value ? '1' : '0');
    charts.draw();
  };
  setCollapsed(storage.get(`chart.${id}`) === '1');
  button.addEventListener('click', () => setCollapsed(!card.classList.contains('is-collapsed')));
}

for (const button of $$('[data-section-toggle]')) {
  const id = button.dataset.sectionToggle;
  setSectionCollapsed(id, storage.get(`section.${id}`) === '1');
}

document.addEventListener('click', (event) => {
  const tab = event.target.closest('[data-network-tab]');
  if (tab && views.length) { views[views.length - 1].data.tab = tab.dataset.networkTab; renderManagement(); }
});

const dialog = $('#modal-shell');
dialog.addEventListener('cancel', (event) => {
  event.preventDefault();
  if (!popups.closeActive()) void back();
});
dialog.addEventListener('click', (event) => {
  if (event.target !== dialog) return;
  const bounds = dialog.getBoundingClientRect();
  const outside = event.clientX < bounds.left ||
    event.clientX > bounds.right || event.clientY < bounds.top ||
    event.clientY > bounds.bottom;
  if (outside) void closeModal();
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' &&
      event.target.closest('[data-client-rename-form]')) {
    event.preventDefault();
    setClientNameEditing(false);
    $('[data-action="edit-client-name"]').focus({ preventScroll: true });
    return;
  }
  if (popups.keydown(event)) return;
  if (event.target.matches('canvas[data-action]') && ['Enter', ' '].includes(event.key)) {
    event.preventDefault();
    void perform(event.target.dataset.action, event.target);
  }
  if (event.target.matches('[data-network-tab]') && ['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
    event.preventDefault();
    const tabs = $$('[data-network-tab]');
    const index = tabs.indexOf(event.target);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1
      : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
    tabs[next].click();
    tabs[next].focus();
  }
});

function syncViewport() {
  const visual = window.visualViewport;
  const editing = document.activeElement?.matches('input:not([type="checkbox"]):not([type="radio"]), textarea');
  const keyboard = Boolean(editing && visual && window.innerHeight - visual.height > 100);
  document.documentElement.classList.toggle('has-visual-keyboard', keyboard);
  popups.requestReposition();
}

window.visualViewport?.addEventListener('resize', syncViewport);
window.visualViewport?.addEventListener('scroll', syncViewport);
window.addEventListener('resize', syncViewport);
document.addEventListener('focusin', syncViewport);
document.addEventListener('focusout', () => requestAnimationFrame(syncViewport));
const appShell = $('#app-shell');
const topbar = $('[data-topbar]');
let topbarSolid = false;
appShell.addEventListener('scroll', () => {
  const solid = appShell.scrollTop > 1;
  if (solid === topbarSolid) return;
  topbarSolid = solid;
  topbar.classList.toggle('has-glass', solid);
}, { passive: true });
document.addEventListener('visibilitychange', () => { if (document.hidden) stopPolling(); else { syncViewport(); void poll(); } });
window.addEventListener('pagehide', () => { stopPolling(); cancelPending(); });

async function boot() {
  try {
    for (const locale of ['ru', 'en']) {
      const response = await fetch(new URL(`./locales/${locale}.json`, import.meta.url), { cache: 'no-store', credentials: 'same-origin' });
      if (!response.ok) throw new Error();
      dictionary[locale] = await response.json();
    }
    appearance({ language, theme: preferredTheme, darkCharts: true,
      plainHeadings: preferredPlainHeadings });
    const period = storage.get('period') || '24h';
    charts.setPeriod(period);
    $('[data-period]').value = charts.period;
    syncViewport();
    if (!hasHost) {
      $('#pin-input').disabled = true;
      toast(t('error.host_required'), 'error');
    }
  } catch {
    $('#pin-input').disabled = true;
    $('#pin-prompt').textContent = t('auth.loading');
    toast(t('error.locale_unavailable'), 'error');
  }
}

void boot();
