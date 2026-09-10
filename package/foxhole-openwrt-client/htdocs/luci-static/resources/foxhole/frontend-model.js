export class ModelError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ModelError';
    this.code = code;
  }
}

export const countryCodes = Object.freeze(
  'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'.split(' ')
);

export const countryFlagPath = (code) =>
  `./assets/flags/${String(code).toLowerCase()}.svg`;

export function countryCode(value) {
  const code = String(value || '').toUpperCase();
  return countryCodes.includes(code) ? code : '';
}

export function serverCountryCode(server, runtime = {}) {
  return countryCode(server?.country) ||
    (runtime.connected && runtime.activeServerId === server?.id
      ? countryCode(runtime.country) : '');
}

export const defaultSettings = Object.freeze({
  language: 'ru',
  standaloneAccess: true,
  localRules: false,
  localScope: 'all',
  clientRules: false,
  killSwitch: false,
  darkStyle: false,
  darkCharts: true,
  plainHeadings: false,
  hideRouterStatus: false,
  theme: 'dark'
});

let idSequence = 0;

export const clone = (value) => JSON.parse(JSON.stringify(value));

export function randomId(prefix) {
  const bytes = new Uint8Array(6);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    const stamp = (Date.now() + idSequence++).toString(16).slice(-12)
      .padStart(12, '0');
    return `${prefix}-${stamp}`;
  }
  const suffix = [...bytes].map((byte) => byte.toString(16)
    .padStart(2, '0')).join('');
  return `${prefix}-${suffix}`;
}

export function normalizeMac(value) {
  const raw = String(value ?? '').trim().toLowerCase();
  if (!raw) return null;
  const compact = raw.replace(/[-:.]/g, '');
  if (!/^[0-9a-f]{12}$/.test(compact)) return null;
  const multicast = Number.parseInt(compact.slice(0, 2), 16) & 1;
  if (compact === '000000000000' || multicast) return null;
  return compact.match(/../g).join(':');
}

export function clientDeviceType(value) {
  if (value === 'tablet') return 'tablet';
  if (value === 'computer' || value === 'desktop') return 'computer';
  return 'smartphone';
}

export function clientDeviceIcon(value) {
  const type = clientDeviceType(value);
  if (type === 'computer') return 'monitor';
  return type === 'tablet' ? 'tablet' : 'mobile';
}

export function networkDeviceIcon(device) {
  const name = String(device?.name || '').toLowerCase();
  if (/playstation|xbox|nintendo|steam.?deck|game|console|(?:^|-)ps[345](?:-|$)/.test(name))
    return 'gamepad';
  if (/smart.?tv|television|bravia|webos|tizen|chromecast|apple.?tv|fire.?tv|roku|(?:^|-)tv(?:-|$)/.test(name))
    return 'tv';
  if (/ipad|tablet|galaxy.?tab|surface.?go/.test(name)) return 'tablet';
  if (/iphone|android|pixel|galaxy|phone|mobile/.test(name)) return 'mobile';
  if (/macbook|laptop|notebook|thinkpad|chromebook|(?:^|-)air(?:-|$)/.test(name))
    return 'laptop';
  if (/desktop|workstation|imac|windows|(?:^|-)pc(?:-|$)/.test(name))
    return 'monitor';
  if (/camera|doorbell|webcam|(?:^|-)cam(?:-|$)/.test(name))
    return 'camera';
  if (/router|gateway|openwrt|access.?point/.test(name)) return 'router';
  return 'devices';
}

export function normalizeSettings(value = {}) {
  const input = { ...defaultSettings, ...value };
  return {
    language: input.language === 'en' ? 'en' : 'ru',
    standaloneAccess: input.standaloneAccess !== false,
    localScope: input.localScope === 'selected' ? 'selected' : 'all',
    localRules: input.localRules === true,
    clientRules: input.clientRules === true,
    killSwitch: input.killSwitch === true,
    darkStyle: false,
    darkCharts: input.darkCharts === true,
    plainHeadings: input.plainHeadings === true,
    hideRouterStatus: input.hideRouterStatus === true,
    theme: input.theme === 'light' ? 'light' : 'dark'
  };
}

export function normalizeDevice(value) {
  if (!value || typeof value !== 'object') return null;
  const address = String(value.address ?? '').trim();
  const mac = normalizeMac(value.mac);
  if (!address && !mac) return null;
  const bindMac = value.bindMac === true || (!address && Boolean(mac));
  return {
    id: String(value.id || randomId('device')),
    name: String(value.name || '').slice(0, 64),
    address: address || null,
    route: value.route === 'direct' ? 'direct' : 'vpn',
    bindMac,
    mac: bindMac ? mac : null
  };
}

export function normalizeSite(value) {
  if (!value || typeof value !== 'object') return null;
  const pattern = String(value.pattern ?? '').trim();
  if (!pattern) return null;
  return {
    id: String(value.id || randomId('site')),
    pattern,
    route: value.route === 'vpn' ? 'vpn' : 'direct'
  };
}

export function normalizeCountry(value) {
  const legacy = typeof value === 'string';
  const code = String(legacy ? value : value?.code ?? '').toUpperCase();
  if (!countryCodes.includes(code)) return null;
  return {
    code,
    route: !legacy && value?.route === 'vpn' ? 'vpn' : 'direct'
  };
}

export function normalizeRuntime(value = {}) {
  const rawRuntime = value && typeof value === 'object' ? value : {};
  const phase = ['disconnected', 'connecting', 'connected', 'blocked',
    'error'].includes(rawRuntime.phase) ? rawRuntime.phase : 'disconnected';
  const activeServerId = typeof rawRuntime.activeServerId === 'string'
    ? rawRuntime.activeServerId : null;
  const desiredServerId = typeof rawRuntime.desiredServerId === 'string'
    ? rawRuntime.desiredServerId : null;
  const connected = rawRuntime.connected === true && phase === 'connected' &&
    activeServerId !== null;
  return {
    mode: 'runtime', phase, connected,
    enforced: rawRuntime.enforced === true,
    activeServerId: connected ? activeServerId : null,
    desiredServerId,
    interface: connected && typeof rawRuntime.interface === 'string'
      ? rawRuntime.interface : null,
    error: typeof rawRuntime.error === 'string'
      ? rawRuntime.error.slice(0, 48) : null,
    since: Number.isInteger(rawRuntime.since) ? rawRuntime.since : null,
    address: connected && typeof rawRuntime.address === 'string'
      ? rawRuntime.address.slice(0, 64) : '',
    country: connected ? countryCode(rawRuntime.country) : '',
    latency: connected ? finite(rawRuntime.latency) : null
  };
}

export function normalizedState(next) {
  const countries = Array.isArray(next.countries)
    ? next.countries.map(normalizeCountry).filter((item, index, items) =>
      item && items.findIndex((candidate) =>
        candidate?.code === item.code) === index)
    : [];
  const devices = Array.isArray(next.devices)
    ? next.devices.map(normalizeDevice).filter(Boolean) : [];
  const sites = Array.isArray(next.sites)
    ? next.sites.map(normalizeSite).filter(Boolean) : [];
  return {
    ...next,
    settings: normalizeSettings(next.settings),
    countries,
    devices,
    sites,
    servers: Array.isArray(next.servers) ? next.servers : [],
    clients: Array.isArray(next.clients) ? next.clients : [],
    runtime: normalizeRuntime(next.runtime)
  };
}

export function finite(value) {
  if (value == null || value === '' || !Number.isFinite(Number(value)))
    return null;
  return Number(value);
}

export function validIPv4(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) =>
    /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

export function validIPv6(value) {
  let address = value;
  if (address.startsWith('[') && address.endsWith(']'))
    address = address.slice(1, -1);
  if (!address || address.includes('%') || address.includes(':::'))
    return false;
  const sections = address.split('::');
  if (sections.length > 2) return false;
  const count = (part) => {
    if (!part) return 0;
    let total = 0;
    for (const group of part.split(':')) {
      if (group.includes('.')) {
        if (!validIPv4(group)) return -1;
        total += 2;
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(group)) return -1;
        total += 1;
      }
    }
    return total;
  };
  const left = count(sections[0]);
  const right = count(sections[1] ?? '');
  if (left < 0 || right < 0) return false;
  return sections.length === 2 ? left + right < 8 : left === 8;
}

export function validAddress(value) {
  const parts = String(value).trim().split('/');
  if (parts.length > 2 || /[\s%]/.test(value)) return false;
  const address = parts[0].replace(/^\[|\]$/g, '');
  if (!address) return false;
  const max = address.includes(':') ? 128 : 32;
  if (parts[1] != null && (!/^\d{1,3}$/.test(parts[1]) ||
      Number(parts[1]) > max)) return false;
  return max === 32 ? validIPv4(address) : validIPv6(address);
}

export function maskIpv4(value) {
  const raw = String(value).replace(/[^0-9./]/g, '');
  const splitValue = raw.split('/', 2);
  const parts = splitValue[0].split('.').slice(0, 4)
    .map((part) => part.slice(0, 3));
  let address = parts.join('.');
  const last = parts.at(-1) || '';
  if (splitValue[1] == null && parts.length < 4 && last.length === 3 &&
      Number(last) <= 255 && !address.endsWith('.'))
    address += '.';
  const prefix = splitValue[1]?.replace(/\D/g, '').slice(0, 2);
  return prefix != null ? `${address}/${prefix}` : address;
}

export function maskMac(value) {
  const compact = String(value).replace(/[^0-9a-f]/gi, '')
    .slice(0, 12).toLowerCase();
  return compact.match(/.{1,2}/g)?.join(':') || '';
}

function asciiHost(value) {
  if (/^[\x00-\x7f]*$/.test(value)) return value;
  const converted = [];
  for (const label of value.split('.')) {
    if (/^[\x00-\x7f]*$/.test(label)) {
      converted.push(label);
      continue;
    }
    if (/[*?]/.test(label)) return null;
    try {
      const host = new URL(`http://${label}.invalid`).hostname;
      if (!host.endsWith('.invalid')) return null;
      converted.push(host.slice(0, -8));
    } catch {
      return null;
    }
  }
  return converted.join('.');
}

function validHostMask(value) {
  if (!value || value.length > 253 || !value.includes('.') ||
      !/[a-z0-9]/i.test(value) || !/^[a-z0-9?*.-]+$/i.test(value))
    return false;
  return value.split('.').every((label) => {
    if (!label || label.length > 63 || label.startsWith('-') ||
        label.endsWith('-')) return false;
    return /[a-z0-9*?]/i.test(label);
  });
}

export function normalizeSitePattern(value) {
  let raw = String(value ?? '').trim();
  if (!raw || /[\s\u0000-\u001f\u007f]/.test(raw))
    throw new ModelError('invalid_site');
  if (/^https?:\/\//i.test(raw)) {
    let url;
    try {
      url = new URL(raw);
    } catch {
      throw new ModelError('invalid_site');
    }
    if (!url.hostname || url.username || url.password || url.port)
      throw new ModelError('invalid_site');
    if (url.pathname !== '/' && url.pathname !== '/*')
      throw new ModelError('site_path_unsupported');
    if (url.search || url.hash)
      throw new ModelError('site_path_unsupported');
    raw = url.hostname.toLowerCase();
  }
  if (raw.includes('://') || raw.includes('/') || raw.includes('#'))
    throw new ModelError('invalid_site');
  raw = raw.toLowerCase();
  if (raw.startsWith('||')) {
    raw = raw.slice(2);
    if (!raw.endsWith('^')) throw new ModelError('invalid_site');
    raw = raw.slice(0, -1);
  }
  raw = raw.replace(/^\.|\.$/g, '');
  const host = asciiHost(raw);
  if (!host || !validHostMask(host))
    throw new ModelError('invalid_site');
  return host;
}
