const COUNTRIES = split('AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW', ' ');

export function fail(code) {
	die(code);
};

function object(value) {
	return type(value) == 'object';
};

function text(value, limit, code) {
	if (type(value) != 'string' || !length(value) ||
	    length(value) > limit || match(value, /[[:cntrl:]]/))
		fail(code);
	return value;
};

function only(value, fields, code) {
	if (!object(value)) fail(code);
	for (let key in value)
		if (index(fields, key) < 0) fail(code);
};

function decode(value) {
	if (match(replace(value, /%[0-9a-fA-F]{2}/g, ''), /%/))
		fail('invalid_config');
	return replace(value, /%([0-9a-fA-F]{2})/g,
		(all, byte) => chr(int(byte, 16)));
};

function encode(value) {
	let result = '';
	for (let char in split(value, '')) {
		result += match(char, /^[a-zA-Z0-9_.~-]$/) ? char :
			sprintf('%%%02X', ord(char));
	}
	return result;
};

function dns(value) {
	if (type(value) != 'string' || length(value) > 253 ||
	    !match(value, /^[a-zA-Z0-9.-]+$/)) return false;
	for (let label in split(value, '.'))
		if (!length(label) || length(label) > 63 ||
		    !match(label, /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/))
			return false;
	return true;
};

function endpoint(value) {
	text(value, 320, 'invalid_config');
	let parts = match(value, /^\[([0-9a-fA-F:.]+)\](:([0-9,-]+))?$/);
	let host, port;
	if (parts) {
		host = parts[1];
		port = parts[3] || '443';
		if (length(iptoarr(host) || []) != 16) fail('invalid_config');
		host = '[' + arrtoip(iptoarr(host)) + ']';
	} else {
		parts = split(value, ':');
		if (length(parts) > 2 || !dns(parts[0])) fail('invalid_config');
		host = lc(parts[0]);
		port = parts[1] || '443';
	}
	let ranges = split(port, ',');
	if (length(ranges) > 32) fail('invalid_config');
	for (let range in ranges) {
		if (!match(range, /^[0-9]+(-[0-9]+)?$/)) fail('invalid_config');
		let pair = split(range, '-');
		let start = int(pair[0], 10), end = int(pair[1] || pair[0], 10);
		if (start < 1 || end > 65535 || start > end) fail('invalid_config');
	}
	return host + ':' + port;
};

function from_uri(raw) {
	let body = replace(raw, /^(hysteria2|hy2):\/\//, '');
	let hash = split(body, '#');
	if (length(hash) > 2) fail('invalid_config');
	let name = hash[1] ? decode(hash[1]) : null;
	let query = split(hash[0], '?');
	if (length(query) > 2) fail('invalid_config');
	let authority = replace(query[0], /\/$/, '');
	let credentials = split(authority, '@');
	if (length(credentials) != 2) fail('invalid_config');
	let config = { server: endpoint(credentials[1]), auth: decode(credentials[0]) };
	let params = {};
	for (let entry in split(query[1] || '', '&')) {
		if (!entry) continue;
		let pair = split(entry, '=', 2), key = decode(pair[0]);
		if (exists(params, key)) fail('invalid_config');
		params[key] = decode(pair[1] || '');
	}
	only(params, ['sni', 'insecure', 'pinSHA256', 'obfs', 'obfs-password'],
		'unsupported_config');
	if (params.sni || params.insecure || params.pinSHA256) {
		config.tls = {};
		if (params.sni) config.tls.sni = params.sni;
		if (params.insecure) {
			if (index(['0', '1', 'false', 'true'], params.insecure) < 0)
				fail('invalid_config');
			config.tls.insecure = params.insecure == '1' || params.insecure == 'true';
		}
		if (params.pinSHA256) config.tls.pinSHA256 = params.pinSHA256;
	}
	if (params.obfs) {
		config.obfs = { type: params.obfs };
		config.obfs[params.obfs] = { password: params['obfs-password'] };
	} else if (params['obfs-password']) fail('invalid_config');
	return { config, name };
};

function scalar(value) {
	if (substr(value, 0, 1) == '"') {
		try { return json(value); } catch (_) { fail('invalid_config'); }
	}
	if (substr(value, 0, 1) == "'") {
		if (substr(value, -1) != "'") fail('invalid_config');
		return replace(substr(value, 1, length(value) - 2), /''/g, "'");
	}
	value = trim(replace(value, /[ \t]+#.*$/, ''));
	if (value == 'true') return true;
	if (value == 'false') return false;
	if (match(value, /[{}\[\]&*!|>]/)) fail('unsupported_config');
	return value;
};

function from_yaml(raw) {
	let result = {}, stack = [{ indent: -1, value: result }];
	for (let line in split(raw, '\n')) {
		if (!trim(line) || match(line, /^[ ]*#/)) continue;
		if (match(line, /\t/)) fail('invalid_config');
		let parts = match(line, /^([ ]*)([a-zA-Z][a-zA-Z0-9]*):([ ]+.*|[ ]*)$/);
		if (!parts) fail('unsupported_config');
		let indent = length(parts[1]), key = parts[2];
		while (length(stack) > 1 && indent <= stack[-1].indent) pop(stack);
		if (indent > 8 || (length(stack) == 1 && indent != 0))
			fail('invalid_config');
		let target = stack[-1].value, value = trim(parts[3]);
		if (exists(target, key)) fail('invalid_config');
		if (!value || substr(value, 0, 1) == '#') {
			target[key] = {};
			push(stack, { indent, value: target[key] });
		} else target[key] = scalar(value);
	}
	return result;
};

export function parse_config(raw) {
	if (type(raw) != 'string' || length(raw) > 16384 || !length(trim(raw)))
		fail('invalid_config');
	let input = trim(raw), config, name = null;
	if (match(input, /^(hysteria2|hy2):\/\//)) {
		let parsed = from_uri(input);
		config = parsed.config;
		name = parsed.name;
	} else if (substr(input, 0, 1) == '{') {
		try { config = json(input); } catch (_) { fail('invalid_config'); }
	} else config = from_yaml(input);
	only(config, ['server', 'auth', 'tls', 'obfs', 'bandwidth', 'socks5', 'http',
		'congestion', 'fastOpen'],
		'unsupported_config');
	if (config.fastOpen != null && type(config.fastOpen) != 'bool')
		fail('invalid_config');
	if (config.congestion != null) {
		only(config.congestion, ['type', 'bbrProfile'], 'unsupported_config');
		if (config.congestion.type != 'bbr' ||
		    index(['conservative', 'standard', 'aggressive'],
			config.congestion.bbrProfile || 'standard') < 0)
			fail('unsupported_config');
	}
	config.server = endpoint(config.server);
	text(config.auth, 1024, 'invalid_config');
	if (config.tls != null) {
		only(config.tls, ['sni', 'insecure', 'pinSHA256'], 'unsupported_config');
		if (config.tls.sni != null && !dns(config.tls.sni)) fail('invalid_config');
		if (config.tls.insecure != null && type(config.tls.insecure) != 'bool')
			fail('invalid_config');
		if (config.tls.pinSHA256 != null) {
			let pin = replace(config.tls.pinSHA256, /:/g, '');
			if (!match(pin, /^[a-fA-F0-9]{64}$/)) fail('invalid_config');
			config.tls.pinSHA256 = lc(pin);
		}
	}
	if (config.obfs != null) {
		let kind = config.obfs.type;
		if (index(['salamander', 'gecko'], kind) < 0) fail('unsupported_config');
		only(config.obfs, ['type', kind], 'unsupported_config');
		only(config.obfs[kind], ['password'], 'invalid_config');
		text(config.obfs[kind].password, 1024, 'invalid_config');
	}
	if (config.bandwidth != null) {
		only(config.bandwidth, ['up', 'down'], 'unsupported_config');
		for (let key, value in config.bandwidth)
			if (type(value) != 'string' ||
			    !match(value, /^[0-9]+([.][0-9]+)?[ ]*([KMG]?bps)$/))
				fail('invalid_config');
	}
	for (let mode in ['socks5', 'http']) {
		if (config[mode] == null) continue;
		only(config[mode], mode == 'socks5' ?
			['listen', 'username', 'password', 'disableUDP'] :
			['listen', 'username', 'password'], 'unsupported_config');
		if (config[mode].disableUDP != null &&
		    type(config[mode].disableUDP) != 'bool') fail('invalid_config');
		if (!match(config[mode].listen || '', /^127[.]0[.]0[.]1:[0-9]+$/))
			fail('unsupported_config');
		endpoint(config[mode].listen);
		for (let key in ['username', 'password'])
			if (config[mode][key] != null) text(config[mode][key], 1024, 'invalid_config');
	}
	if (name != null) text(name, 64, 'invalid_name');
	return { config, name: name || config.server, endpoint: config.server };
};

export function config_uri(config, name) {
	let query = [];
	if (config.tls?.sni) push(query, 'sni=' + encode(config.tls.sni));
	if (config.tls?.insecure) push(query, 'insecure=1');
	if (config.tls?.pinSHA256) push(query, 'pinSHA256=' + config.tls.pinSHA256);
	if (config.obfs) {
		push(query, 'obfs=' + config.obfs.type);
		push(query, 'obfs-password=' + encode(config.obfs[config.obfs.type].password));
	}
	return 'hysteria2://' + encode(config.auth) + '@' + config.server + '/' +
		(length(query) ? '?' + join('&', query) : '') + '#' + encode(name);
};

export function defaults() {
	return {
		schema: 1, revision: 0, activeServerId: null,
		settings: {
				language: 'ru', standaloneAccess: true,
				localRules: false, localScope: 'all',
				clientRules: false, killSwitch: false,
				darkStyle: false, darkCharts: true,
				plainHeadings: false, hideRouterStatus: false,
				theme: 'dark',
		},
		countries: [], devices: [], sites: [], servers: [], clients: [],
	};
};

export function server_name(value) {
	if (type(value) != 'string' || match(value, /[[:cntrl:]]/))
		die('invalid_name');
	let name = trim(value), count = 0;
	// Count UTF-8 leading bytes, not bytes within a character.
	for (let i = 0; i < length(name); i++)
		if ((ord(name, i) & 0xc0) != 0x80) count++;
	if (!count || count > 13) die('invalid_name');
	return name;
};

export function client_name(value) {
	text(value, 48, 'invalid_name');
	if (index(value, chr(0)) >= 0) fail('invalid_name');
	let name = trim(value);
	if (!length(name)) fail('invalid_name');
	return name;
};

export function client_profile(state, client) {
	let server = null;
	for (let item in state.servers)
		if (item.id == client.serverId) server = item;
	let config = server ? parse_config(server.config).config :
		{ server: 'router.invalid:443', auth: 'inactive' };
	let uri = config_uri(config, client.name);
	return {
		id: client.id, name: client.name, deviceType: client.deviceType,
		serverId: server ? server.id : null, provisioned: false,
		uri, config: uri, inactive: !server,
		warning: server ? null : 'inactive_template'
	};
};

export function public_state(state, runtime) {
	runtime ??= {
		mode: 'runtime', phase: state.activeServerId ?
			'connecting' : 'disconnected',
		connected: false, enforced: false,
		activeServerId: null,
		desiredServerId: state.activeServerId || null,
		error: null
	};
	return {
		schema: state.schema, revision: state.revision,
		settings: state.settings, countries: state.countries,
		devices: state.devices, sites: state.sites,
		servers: map(state.servers, server => ({
			id: server.id, name: server.name,
			endpoint: server.endpoint, state: 'saved',
			protocol: 'hysteria2',
			metrics: {
				received: 0, sent: 0,
				averageLatency: null, ping: null,
			},
		})),
		clients: map(state.clients, client => ({
			id: client.id, name: client.name, deviceType: client.deviceType,
			serverId: client.serverId, provisioned: client.inbound == true,
			allowLan: client.allowLan == true,
			metrics: { received: 0, sent: 0, lastConnected: null },
		})),
		runtime,
	};
};

function address_data(value) {
	if (type(value) != 'string') return null;
	let parts = split(trim(value), '/');
	if (length(parts) > 2 || !length(parts[0])) return null;
	let bytes = iptoarr(parts[0]);
	if (!bytes || (length(bytes) != 4 && length(bytes) != 16))
		return null;
	let width = length(bytes) * 8, prefix = width;
	if (parts[1] != null) {
		if (!match(parts[1], /^[0-9]{1,3}$/)) return null;
		prefix = int(parts[1], 10);
		if (prefix > width) return null;
	}
	return { bytes, width, prefix, explicit: parts[1] != null };
};

function canonical_address(info) {
	let bytes = [...info.bytes];
	for (let i = 0; i < length(bytes); i++) {
		let left = info.prefix - i * 8;
		if (left <= 0) bytes[i] = 0;
		else if (left < 8)
			bytes[i] = bytes[i] & ((0xff << (8 - left)) & 0xff);
	}
	let value = arrtoip(bytes);
	return info.explicit ? value + '/' + info.prefix : value;
};

export function normalize_address(value) {
	let info = address_data(value);
	if (!info) fail('invalid_address');
	let bytes = info.bytes;
	if (info.prefix == info.width && info.width == 32 &&
		(bytes[0] == 0 || bytes[0] == 127 || bytes[0] >= 224))
		fail('invalid_address');
	if (info.prefix == info.width && info.width == 128 &&
	    (bytes[0] == 255 || arrtoip(bytes) == '::' ||
	    arrtoip(bytes) == '::1')) fail('invalid_address');
	return canonical_address(info);
};

export function host_address(value) {
	let info = address_data(value);
	return info && info.prefix == info.width ? arrtoip(info.bytes) : null;
};

export function address_matches(value, rule) {
	let flow = address_data(value), target = address_data(rule);
	if (!flow || !target || flow.width != target.width ||
		flow.prefix < target.prefix) return false;
	let bits = target.prefix;
	for (let i = 0; i < length(target.bytes); i++) {
		if (bits <= 0) break;
		let take = bits >= 8 ? 8 : bits;
		let mask = take == 8 ? 0xff : ((0xff << (8 - take)) & 0xff);
		if ((flow.bytes[i] & mask) != (target.bytes[i] & mask)) return false;
		bits -= take;
	}
	return true;
};

export function normalize_mac(value) {
	if (type(value) != 'string' ||
	    !match(value, /^[a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5}$/) ||
	    (int(substr(value, 0, 2), 16) & 1) ||
	    value == '00:00:00:00:00:00') fail('invalid_mac');
	return lc(value);
};

export function normalize_site(value) {
	if (type(value) != 'string') fail('invalid_site');
	let pattern = lc(trim(value));
	if (match(pattern, /^https?:\/\//)) {
		pattern = replace(pattern, /^https?:\/\//, '');
		let slash = index(pattern, '/');
		if (slash >= 0) {
			if (index(['/', '/*'], substr(pattern, slash)) < 0)
				fail('site_path_unsupported');
			pattern = substr(pattern, 0, slash);
		}
		if (match(pattern, /[?#]/)) fail('site_path_unsupported');
	}
	if (match(pattern, /^\|\|[^|]+\^$/))
		pattern = substr(pattern, 2, length(pattern) - 3);
	pattern = replace(pattern, /^\.|\.$/g, '');
	if (length(pattern) > 253 || index(pattern, '.') < 0 ||
	    !match(pattern, /^[a-z0-9*?_.-]+$/) || match(pattern, /_|[.][.]/) ||
	    !match(pattern, /[a-z0-9]/)) fail('invalid_site');
	for (let label in split(pattern, '.'))
		if (!length(label) || length(label) > 63 || match(label, /^-|[-]$/))
			fail('invalid_site');
	return pattern;
};

export function site_matches(host, pattern) {
	if (type(host) != 'string') return false;
	host = lc(replace(host, /\.$/, ''));
	if (!dns(host)) return false;
	if (match(pattern, /[*?]/)) return wildcard(host, pattern);
	return host == pattern || substr(host, -(length(pattern) + 1)) == '.' + pattern;
};

export function validate_settings(payload, resolve_mac) {
	let defaults_settings = defaults().settings;
	only(payload.settings, keys(defaults_settings), 'invalid_settings');
	let settings = { ...defaults_settings, ...payload.settings };
	payload.countries ??= [];
	payload.devices ??= [];
	payload.sites ??= [];
	if (index(['ru', 'en'], settings.language) < 0 ||
	    index(['all', 'selected'], settings.localScope) < 0 ||
	    index(['dark', 'light'], settings.theme) < 0)
		fail('invalid_settings');
	for (let key in ['standaloneAccess', 'localRules', 'clientRules',
		'killSwitch', 'darkStyle', 'darkCharts', 'plainHeadings',
		'hideRouterStatus'])
		if (type(settings[key]) != 'bool') fail('invalid_settings');
	if (type(payload.countries) != 'array' || length(payload.countries) > 249 ||
	    type(payload.devices) != 'array' || length(payload.devices) > 512 ||
	    type(payload.sites) != 'array' || length(payload.sites) > 2048)
		fail('invalid_settings');
	let countries = [], devices = [], sites = [], ids = {}, identities = {};
	let country_codes = {};
	for (let country in payload.countries) {
		let legacy = type(country) == 'string';
		let code = legacy ? country : country?.code;
		let route = legacy ? 'direct' : country?.route;
		if (index(COUNTRIES, code) < 0 || country_codes[code] ||
		    index(['vpn', 'direct'], route) < 0)
			fail('invalid_settings');
		country_codes[code] = true;
		push(countries, { code, route });
	}
	for (let item in payload.devices) {
		if (!match(item.id || '', /^device-[a-f0-9]{12}$/) || ids[item.id] ||
		    index(['vpn', 'direct'], item.route) < 0 ||
		    type(item.bindMac) != 'bool' ||
		    (item.preventLeak != null && type(item.preventLeak) != 'bool'))
			fail('invalid_settings');
		let name = item.name ?? '';
		if (type(name) != 'string' || length(name) > 64 ||
		    match(name, /[[:cntrl:]]/)) fail('invalid_name');
		name = trim(name);
		let address = item.address ? normalize_address(item.address) : null;
		let mac = null;
		if (!address && !item.bindMac) fail('invalid_address');
		if (item.bindMac) {
			let host = address ? host_address(address) : null;
			mac = item.mac || (host ? resolve_mac(host) : null);
			if (!mac) fail('mac_not_found');
			mac = normalize_mac(mac);
		}
		let identity = item.bindMac ? mac : (host_address(address) || address);
		if (identities[identity]) fail('duplicate_rule');
		identities[identity] = true;
		ids[item.id] = true;
		push(devices, {
			id: item.id, name, address, mac, bindMac: item.bindMac,
			route: item.route,
		});
	}
	for (let item in payload.sites) {
		if (!match(item.id || '', /^site-[a-f0-9]{12}$/) || ids[item.id] ||
		    index(['vpn', 'direct'], item.route) < 0) fail('invalid_site');
		let pattern = normalize_site(item.pattern);
		if (identities['site:' + pattern]) fail('duplicate_rule');
		identities['site:' + pattern] = true;
		ids[item.id] = true;
		push(sites, { id: item.id, pattern, route: item.route });
	}
	return { settings, countries, devices, sites };
};

export function validate_state(state) {
	if (!state || state.schema != 1 || type(state.revision) != 'int' ||
	    state.revision < 0 || !state.settings)
		fail('storage_error');
	let checked = validate_settings({
		settings: state.settings,
		countries: state.countries || [],
		devices: state.devices || [],
		sites: state.sites || []
	}, _ => null);
	state.settings = checked.settings;
	state.countries = checked.countries;
	state.devices = checked.devices;
	state.sites = checked.sites;
	if (type(state.servers) != 'array' || type(state.clients) != 'array')
		fail('storage_error');
	let ids = {};
	for (let server in state.servers) {
		if (!match(server.id || '', /^server-[a-f0-9]{12}$/) ||
		    ids[server.id] || type(server.name) != 'string' ||
		    type(server.endpoint) != 'string' || !server.config)
			fail('storage_error');
		parse_config(server.config);
		ids[server.id] = true;
	}
	if (state.activeServerId != null && !ids[state.activeServerId])
		fail('storage_error');
	for (let client in state.clients) {
		if (!match(client.id || '', /^client-[a-f0-9]{12}$/) ||
		    ids[client.id] || type(client.name) != 'string' ||
		    index(['smartphone', 'tablet', 'computer',
			'mobile', 'desktop'], client.deviceType) < 0 ||
		    (client.serverId != null && !ids[client.serverId]))
			fail('storage_error');
		if (client.inbound == true &&
		    (!match(client.secret || '', /^[a-f0-9]{64}$/) ||
		     type(client.port) != 'int' || client.port < 1 ||
		     client.port > 65535 || type(client.allowLan) != 'bool'))
			fail('storage_error');
		delete client.uri;
		ids[client.id] = true;
	}
	state.activeServerId ??= null;
	return state;
};

export function policy_decision(state, flow) {
	flow.country = type(flow.country) == 'string' ? uc(flow.country) : null;
	if (flow.source == 'client') {
		if (!flow.connected || !state.settings.clientRules) return 'direct';
		for (let country in state.countries) {
			let code = type(country) == 'string' ? country : country.code;
			if (code == flow.country && (type(country) == 'string' ||
			    country.route == 'direct')) return 'direct';
		}
		return 'vpn';
	}
	let device = null;
	if (flow.source == 'lan' && state.settings.localRules) {
		for (let item in state.devices) {
			let matches = item.bindMac ? lc(flow.mac || '') == item.mac :
				address_matches(flow.address, item.address);
			if (matches) { device = item; break; }
		}
	}
	let scope = flow.source == 'client' ? state.settings.clientRules :
		state.settings.localRules && (state.settings.localScope == 'all' || device != null);
	if (device?.route == 'direct') return 'direct';
	if (scope) {
		for (let site in state.sites)
			if (site_matches(flow.host, site.pattern)) {
				if (site.route == 'direct') return 'direct';
				if (!flow.connected && state.settings.killSwitch)
					return 'block';
				return flow.connected ? 'vpn' : 'direct';
			}
		for (let country in state.countries) {
			let legacy = type(country) == 'string';
			let code = legacy ? country : country.code;
			let route = legacy ? 'direct' : country.route;
			if (code != flow.country) continue;
			if (route == 'direct') return 'direct';
			if (!flow.connected && state.settings.killSwitch)
				return 'block';
			return flow.connected ? 'vpn' : 'direct';
		}
	}
	if (!flow.connected && state.settings.killSwitch)
		return 'block';
	return flow.connected ? 'vpn' : 'direct';
};
