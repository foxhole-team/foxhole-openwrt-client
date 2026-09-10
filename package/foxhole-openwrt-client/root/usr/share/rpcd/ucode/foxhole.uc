#!/usr/bin/env ucode

'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as uci from 'uci';
import * as ubus from 'ubus';
import * as model from '/usr/share/foxhole/model.uc';
import * as runtime_model from '/usr/share/foxhole/runtime-model.uc';
import * as probe from '/usr/share/foxhole/probe.uc';
import * as history_store from '/usr/share/foxhole/history.uc';
import * as inbound from '/usr/share/foxhole/inbound.uc';

const STATE_PATH = '/etc/foxhole/state.json';
const AUTH_PATH = '/etc/foxhole/auth.json';
const LOCK_PATH = '/etc/foxhole/state.lock';
const RUNTIME_PATH = '/tmp/foxhole/runtime.json';
const RUNTIME_INIT = '/etc/init.d/foxhole-runtime';
const MAX_STATE = 262144;
const TOKEN_TTL = 1800;
const FAILURE_WINDOW = 60;
const FAILURE_LIMIT = 8;
const HISTORY_LIMIT = 8640;
const RUNTIME_PHASES = [
	'disconnected', 'connecting', 'connected', 'blocked', 'error'
];
const RUNTIME_ERRORS = [
	'storage_error', 'invalid_state', 'server_not_found',
	'client_rules_unsupported', 'site_pattern_unsupported',
	'invalid_interface', 'invalid_dns_uid', 'runtime_missing',
	'resolve_failed', 'country_fetch_failed',
	'country_data_invalid', 'country_data_too_large',
	'dnsmasq_nftset_required', 'policy_invalid',
	'policy_apply_failed', 'route_apply_failed',
	'dnsmasq_apply_failed', 'tunnel_missing',
	'tunnel_start_failed', 'tunnel_exited'
];
const ERRORS = [
	'invalid_pin', 'pin_required', 'pin_unchanged',
	'locked', 'unauthorized', 'revision_conflict',
	'invalid_config', 'unsupported_config', 'invalid_name',
	'invalid_address', 'invalid_mac', 'mac_not_found', 'invalid_site',
	'site_path_unsupported', 'invalid_settings', 'duplicate_rule',
	'not_found', 'storage_error', 'unavailable', 'pin_mismatch', 'client_limit',
	'runtime_unavailable', ...RUNTIME_ERRORS
];

let sessions = {};
let failures = { count: 0, since: 0 };
let history = [];
let last_cpu = null;
let last_sample = 0;
let last_probe_request = 0;

function fail(code) {
	die(index(ERRORS, code) >= 0 ? code : 'storage_error');
};

function error_code(error) {
	let code = type(error) == 'string' ? error : error?.message;
	return index(ERRORS, code) >= 0 ? code : 'storage_error';
};

function safe(fn) {
	try {
		return fn();
	} catch (error) {
		return { _foxhole_error: error_code(error) };
	}
};

function ensure_dir() {
	try { fs.mkdir('/etc/foxhole', 0o700); } catch (_) {}
	try { fs.mkdir('/tmp/foxhole', 0o700); } catch (_) {}
};

function read_json(path, limit) {
	let raw = fs.readfile(path, limit);
	if (raw == null) return null;
	if (!length(raw) || length(raw) > limit) fail('storage_error');
	try { return json(raw); } catch (_) { fail('storage_error'); }
};

function write_json(path, value, mode) {
	ensure_dir();
	let temp = path + '.new';
	let raw = sprintf('%J', value);
	if (length(raw) > MAX_STATE) fail('storage_error');
	if (fs.writefile(temp, raw) != length(raw)) fail('storage_error');
	if (!fs.chmod(temp, mode)) fail('storage_error');
	if (!fs.rename(temp, path)) fail('storage_error');
};

function locked(fn) {
	ensure_dir();
	let handle = null;
	try {
		handle = fs.open(LOCK_PATH, 'a+');
		if (!handle || !handle.lock('x')) fail('storage_error');
		let result = fn();
		handle.lock('u');
		handle.close();
		return result;
	} catch (error) {
		if (handle) {
			try { handle.lock('u'); } catch (_) {}
			try { handle.close(); } catch (_) {}
		}
		die(error_code(error));
	}
};

function random_hex(bytes) {
	let raw = fs.readfile('/dev/urandom', bytes);
	if (raw == null || length(raw) != bytes) fail('storage_error');
	return hexenc(raw);
};

function bootstrap_pin() {
	let cursor = uci.cursor();
	let pin = cursor.get('foxhole', 'panel', 'bootstrap_pin');
	try { cursor.unload(); } catch (_) {}
	if (pin == null) pin = join('', ['1', '2', '3', '4']);
	if (type(pin) != 'string' || !match(pin, /^[0-9]{4}$/))
		fail('storage_error');
	return pin;
};

function pin_hash(salt, pin) {
	let result = digest.sha256(salt + ':' + pin);
	if (!result) fail('storage_error');
	return result;
};

function auth_record() {
	let auth = read_json(AUTH_PATH, 4096);
	if (auth != null) {
		if (type(auth.salt) != 'string' ||
		    !match(auth.salt, /^[a-f0-9]{32}$/) ||
		    type(auth.hash) != 'string' ||
		    !match(auth.hash, /^[a-f0-9]{64}$/)) fail('storage_error');
		return auth;
	}
	let salt = random_hex(16);
	auth = { schema: 1, salt, hash: pin_hash(salt, bootstrap_pin()),
		changed: false };
	write_json(AUTH_PATH, auth, 0o600);
	let cursor = uci.cursor();
	try {
		cursor.delete('foxhole', 'panel', 'bootstrap_pin');
		cursor.commit('foxhole');
	} catch (_) {}
	try { cursor.unload(); } catch (_) {}
	return auth;
};

function equal_secret(left, right) {
	if (type(left) != 'string' || type(right) != 'string' ||
	    length(left) != length(right)) return false;
	let diff = 0;
	for (let i = 0; i < length(left); i++)
		diff |= ord(substr(left, i, 1)) ^ ord(substr(right, i, 1));
	return diff == 0;
};

function check_pin(pin) {
	if (type(pin) != 'string' || !match(pin, /^[0-9]{4}$/))
		fail('invalid_pin');
	let now = time();
	if (now - failures.since >= FAILURE_WINDOW) {
		failures.count = 0;
		failures.since = now;
	}
	if (failures.count >= FAILURE_LIMIT) fail('locked');
	let auth = auth_record();
	let valid = equal_secret(pin_hash(auth.salt, pin), auth.hash);
	if (!valid) {
		failures.count++;
		if (!failures.since) failures.since = now;
		fail('invalid_pin');
	}
	failures.count = 0;
	return true;
};

function user_of(request) {
	return request?.info?.acl?.user || 'unknown';
};

function new_token(user) {
	for (let key, item in sessions)
		if (item.expires < time()) delete sessions[key];
	if (length(keys(sessions)) >= 64) fail('locked');
	let token = random_hex(32);
	sessions[token] = { user, expires: time() + TOKEN_TTL,
		setup: auth_record().changed != true };
	return token;
};

function session(request, allow_setup) {
	let token = request.args?.token;
	if (type(token) != 'string' || !match(token, /^[a-f0-9]{64}$/))
		fail('unauthorized');
	let item = sessions[token];
	if (!item || item.user != user_of(request)) fail('unauthorized');
	if (item.expires < time()) {
		delete sessions[token];
		fail('unauthorized');
	}
	if (item.setup && !allow_setup) fail('pin_required');
	item.expires = time() + TOKEN_TTL;
	return token;
};

function valid_revision(value) {
	if (type(value) != 'int' || value < 0 || value > 0x7fffffff)
		fail('revision_conflict');
	return value;
};

function valid_state_shape(state) {
	return model.validate_state(state);
};

function standalone_setting() {
	let cursor = null, enabled = true;
	try {
		cursor = uci.cursor();
		enabled = cursor.get('foxhole', 'panel', 'standalone') != '0';
	} catch (_) {}
	try { if (cursor) cursor.unload(); } catch (_) {}
	return enabled;
};

function state_record() {
	let state = read_json(STATE_PATH, MAX_STATE);
	if (state == null) {
		state = model.defaults();
		write_json(STATE_PATH, state, 0o600);
	}
	state = valid_state_shape(state);
	state.settings.standaloneAccess = standalone_setting();
	return state;
};

function fallback_runtime(state) {
	return {
		mode: 'runtime',
		phase: state.activeServerId ? 'connecting' : 'disconnected',
		connected: false, enforced: false, activeServerId: null,
		desiredServerId: state.activeServerId || null,
		interface: null, error: null, since: null,
		address: '', country: '', latency: null
	};
};

function runtime_status(state) {
	let fallback = fallback_runtime(state);
	let snapshot = probe.runtime_snapshot();
	let value = snapshot?.value;
	if (!value || value.schema != 1 || value.mode != 'runtime' ||
	    index(RUNTIME_PHASES, value.phase) < 0 ||
	    type(value.connected) != 'bool' ||
	    type(value.enforced) != 'bool' ||
	    value.desiredServerId != fallback.desiredServerId)
		return fallback;
	let desired = fallback.desiredServerId;
	let active = value.activeServerId;
	let tun = runtime_model.constants().tunName;
	let connected = value.connected && desired != null && active == desired &&
		fs.stat('/sys/class/net/' + tun) != null;
	let error = index(RUNTIME_ERRORS, value.error) >= 0 ? value.error : null;
	let phase = value.phase;
	let enforced = value.enforced;
	if (value.connected && !connected) {
		phase = 'error';
		error = 'tunnel_missing';
		enforced = false;
	}
	let sample = connected ? probe.vpn_sample(
		probe.read_json(probe.cache_path), snapshot, time()) : null;
	return {
		mode: 'runtime', phase, connected,
		enforced: enforced == true,
		activeServerId: connected ? desired : null,
		desiredServerId: desired,
		interface: connected ? tun : null,
		error, since: type(value.since) == 'int' ? value.since : null,
		address: sample?.address || '', country: sample?.country || '',
		latency: sample?.latency ?? null
	};
};

function restart_runtime(state) {
	if (system([ RUNTIME_INIT, 'restart' ], 30000) == 0) return true;
	write_json(RUNTIME_PATH, {
		schema: 1, mode: 'runtime', phase: 'error',
		connected: false, enforced: false, activeServerId: null,
		desiredServerId: state.activeServerId || null,
		interface: null, error: 'runtime_missing', since: time()
	}, 0o600);
	return false;
};

function next_id(prefix) {
	return prefix + '-' + random_hex(6);
};

function replace_state(state, expected, checked) {
	if (state.revision != expected) fail('revision_conflict');
	state.settings = checked.settings;
	state.countries = checked.countries;
	state.devices = checked.devices;
	state.sites = checked.sites;
	state.revision++;
	write_json(STATE_PATH, state, 0o600);
	return state;
};

function resolve_mac(address) {
	let arp = fs.readfile('/proc/net/arp', 65536) || '';
	for (let line in split(arp, '\n')) {
		let found = match(line, /^([^ ]+)[ ]+[^ ]+[ ]+[^ ]+[ ]+([0-9a-fA-F:]{17})/);
		if (found && found[1] == address) {
			try { return model.normalize_mac(found[2]); } catch (_) {}
		}
	}
	return null;
};

function interface_name(value) {
	return type(value) == 'string' &&
		match(value, /^[a-zA-Z0-9_.:-]{1,32}$/) ? value : null;
};

function number_file(path) {
	let raw = fs.readfile(path, 128);
	if (raw == null) return null;
	let found = match(trim(raw), /^([0-9]+([.][0-9]+)?)/);
	return found ? +found[1] : null;
};

function decimal(value) {
	return value == null ? null : +sprintf('%.1f', value);
};

function counter(iface, name) {
	iface = interface_name(iface);
	if (!iface) return null;
	return number_file('/sys/class/net/' + iface + '/statistics/' + name);
};

function default_gateway(iface) {
	let routes = fs.readfile('/proc/net/route', 65536) || '';
	for (let line in split(routes, '\n')) {
		let fields = split(trim(line), /[ \t]+/);
		if (length(fields) < 3 || fields[0] != iface ||
		    fields[1] != '00000000' ||
		    !match(fields[2], /^[0-9a-fA-F]{8}$/)) continue;
		let value = int(fields[2], 16);
		return sprintf('%d.%d.%d.%d', value & 255,
			(value >> 8) & 255, (value >> 16) & 255,
			(value >> 24) & 255);
	}
	return null;
};

function interface_names() {
	let wan = null, lan = null;
	try {
		let cursor = uci.cursor();
		wan = interface_name(cursor.get('network', 'wan', 'device'));
		lan = interface_name(cursor.get('network', 'lan', 'device'));
		try { cursor.unload(); } catch (_) {}
	} catch (_) {}
	let routes = fs.readfile('/proc/net/route', 65536) || '';
	for (let line in split(routes, '\n')) {
		let fields = split(trim(line), /[ \t]+/);
		if (length(fields) >= 2 && fields[1] == '00000000') {
			wan = interface_name(fields[0]) || wan;
			break;
		}
	}
	return { wan: wan || 'wan', lan: lan || 'br-lan' };
};

function interface_address(iface) {
	let connection = null;
	try {
		connection = ubus.connect();
		if (!connection) return null;
		let dump = connection.call('network.interface', 'dump', {});
		connection.disconnect();
		for (let item in dump?.interface || []) {
			if (item.l3_device != iface && item.device != iface) continue;
			for (let address in item['ipv4-address'] || [])
				if (address.address) return address.address;
			for (let address in item['ipv6-address'] || [])
				if (address.address) return address.address;
		}
	} catch (_) {
		if (connection) try { connection.disconnect(); } catch (_) {}
	}
	return null;
};

function request_probe() {
	let now = time();
	if (probe.fresh(last_probe_request, now, probe.interval - 1)) return;
	last_probe_request = now;
	ensure_dir();
	// The worker owns the probe lock and exits after one sample.
	system('/usr/libexec/foxhole-probe </dev/null >/dev/null 2>&1 &');
};

function cpu_percent() {
	let raw = fs.readfile('/proc/stat', 4096) || '';
	let line = split(raw, '\n')[0] || '';
	let fields = split(trim(line), /[ \t]+/);
	if (length(fields) < 5 || fields[0] != 'cpu') return null;
	let total = 0;
	for (let i = 1; i < length(fields); i++) total += +fields[i];
	let idle = +fields[4] + +(fields[5] || 0);
	let current = { total, idle };
	let result = history_store.cpu_percent(last_cpu, current);
	last_cpu = current;
	return result;
};

function memory_stats() {
	let raw = fs.readfile('/proc/meminfo', 8192) || '';
	let total = null, available = null;
	for (let line in split(raw, '\n')) {
		let found = match(line, /^(MemTotal|MemAvailable):[ ]+([0-9]+)/);
		if (!found) continue;
		if (found[1] == 'MemTotal') total = +found[2] * 1024;
		else available = +found[2] * 1024;
	}
	let ram = total && available != null ?
		decimal(100 * (total - available) / total) : null;
	return { total, available, ram };
};

function telemetry_sample(state) {
	request_probe();
	let runtime = runtime_status(state);
	let names = interface_names();
	let memory = memory_stats();
	let load = number_file('/proc/loadavg');
	let uptime = number_file('/proc/uptime');
	let now = time();
	let network = probe.wan_sample(probe.read_json(probe.cache_path),
		names.wan, default_gateway(names.wan) || null, now);
	let sample = {
		time: now * 1000,
		uptime,
		load,
		cpu: cpu_percent(),
		ram: memory.ram,
		memory: { total: memory.total, available: memory.available },
		wan: {
			device: names.wan, address: interface_address(names.wan),
			country: network.country,
			rx: counter(names.wan, 'rx_bytes'), tx: counter(names.wan, 'tx_bytes')
		},
		lan: {
			device: names.lan, address: interface_address(names.lan),
			rx: counter(names.lan, 'rx_bytes'), tx: counter(names.lan, 'tx_bytes')
		},
		vpn: {
			device: runtime.interface,
			address: runtime.address,
			country: runtime.country,
			rx: counter(runtime.interface, 'rx_bytes'),
			tx: counter(runtime.interface, 'tx_bytes')
		},
		latency: {
			wan: network.latency,
			vpn: runtime.latency,
			serverId: runtime.activeServerId
		},
	};
	return { sample, runtime };
};

function telemetry() {
	let state = state_record();
	let current = telemetry_sample(state);
	let sample = current.sample;
	let stamp = sample.time;
	history = history_store.read();
	if (!last_sample || stamp - last_sample >= 300000) {
		push(history, {
			t: stamp, measurementVersion: 2, cpu: sample.cpu, ram: sample.ram,
			wanRx: sample.wan?.rx, wanTx: sample.wan?.tx,
			wanCountry: sample.wan?.country,
			lanRx: sample.lan?.rx, lanTx: sample.lan?.tx,
			vpnRx: sample.vpn?.rx, vpnTx: sample.vpn?.tx,
			vpnCountry: sample.vpn?.country,
			wanLatency: sample.latency?.wan,
			vpnLatency: sample.latency?.vpn,
			vpnServerId: sample.latency?.serverId,
		});
		while (length(history) > HISTORY_LIMIT) shift(history);
		last_sample = stamp;
	}
	return { available: sample.load != null || sample.memory.total != null,
		sample, history, runtime: current.runtime };
};

function test_server(raw) {
	let parsed = model.parse_config(raw);
	return {
		valid: true, scope: 'config', connected: false, code: 'validated',
		name: parsed.name, endpoint: parsed.endpoint
	};
};

function public_state(state) {
	let runtime = runtime_status(state);
	let result = model.public_state(state, runtime);
	if (runtime.connected) {
		for (let server in result.servers) {
			if (server.id != runtime.activeServerId) continue;
			server.state = 'connected';
			server.metrics.received = counter(runtime.interface,
				'rx_bytes') || 0;
			server.metrics.sent = counter(runtime.interface,
				'tx_bytes') || 0;
			server.metrics.averageLatency = runtime.latency;
			server.metrics.ping = runtime.latency;
		}
	}
	return result;
};

function settings_call(request) {
	session(request);
	let args = request.args;
	let expected = valid_revision(args.revision);
	let result = locked(() => {
		session(request);
		let state = state_record();
		if (state.revision != expected) fail('revision_conflict');
		let before = runtime_model.runtime_fingerprint(state);
		let checked = model.validate_settings({
			settings: args.settings,
			countries: args.countries || [],
			devices: args.devices || [],
			sites: args.sites || []
		}, address => resolve_mac(address));
		checked.settings.standaloneAccess =
			state.settings.standaloneAccess;
		replace_state(state, expected, checked);
		return {
			state,
			restart: before != runtime_model.runtime_fingerprint(state)
		};
	});
	if (result.restart) restart_runtime(result.state);
	return public_state(result.state);
};

function save_server(request) {
	session(request);
	let args = request.args, expected = valid_revision(args.revision);
	let parsed = model.parse_config(args.config);
	let id = args.id || next_id('server');
	if (!match(id, /^server-[a-f0-9]{12}$/)) fail('not_found');
	let name = model.server_name(args.name || 'VPN SERVER 01');
	let result = locked(() => {
		session(request);
		let state = state_record(), found = false;
		if (state.revision != expected) fail('revision_conflict');
		for (let server in state.servers) {
			if (server.id != id) continue;
			server.name = name;
			server.endpoint = parsed.endpoint;
			server.config = trim(args.config);
			found = true;
		}
		if (!found && args.id) fail('not_found');
		if (!found) push(state.servers, {
			id, name, endpoint: parsed.endpoint,
			config: trim(args.config)
		});
		state.revision++;
		write_json(STATE_PATH, state, 0o600);
		return { state, restart: state.activeServerId == id };
	});
	if (result.restart) restart_runtime(result.state);
	return public_state(result.state);
};

function get_server(request) {
	session(request);
	let id = request.args.id;
	let state = state_record();
	for (let server in state.servers)
		if (server.id == id)
			return { id: server.id, name: server.name, endpoint: server.endpoint,
				config: server.config };
	fail('not_found');
};

function delete_server(request) {
	let expected = valid_revision(request.args.revision), id = request.args.id;
	let result = locked(() => {
		session(request);
		let state = state_record();
		if (state.revision != expected) fail('revision_conflict');
		let found = false;
		for (let i = 0; i < length(state.servers); i++) {
			if (state.servers[i].id != id) continue;
			splice(state.servers, i, 1);
			found = true;
			break;
		}
		if (!found) fail('not_found');
		let restart = state.activeServerId == id;
		if (restart) state.activeServerId = null;
		for (let client in state.clients)
			if (client.serverId == id) client.serverId = null;
		state.revision++;
		write_json(STATE_PATH, state, 0o600);
		return { state, restart };
	});
	if (result.restart) restart_runtime(result.state);
	return public_state(result.state);
};

function start_server(request) {
	session(request);
	let expected = valid_revision(request.args.revision);
	let id = request.args.id;
	let result = locked(() => {
		session(request);
		let state = state_record(), found = false;
		if (state.revision != expected) fail('revision_conflict');
		for (let server in state.servers)
			if (server.id == id) found = true;
		if (!found) fail('not_found');
		let changed = state.activeServerId != id;
		state.activeServerId = id;
		runtime_model.hysteria_config(state, null);
		if (changed) {
			state.revision++;
			write_json(STATE_PATH, state, 0o600);
		}
		return state;
	});
	restart_runtime(result);
	return public_state(result);
};

function stop_server(request) {
	session(request);
	let expected = valid_revision(request.args.revision);
	let result = locked(() => {
		session(request);
		let state = state_record();
		if (state.revision != expected) fail('revision_conflict');
		if (state.activeServerId != null) {
			state.activeServerId = null;
			state.revision++;
			write_json(STATE_PATH, state, 0o600);
		}
		return state;
	});
	restart_runtime(result);
	return public_state(result);
};

function qr_svg(uri) {
	ensure_dir();
	let directory = '/tmp/foxhole/qr-' + random_hex(6);
	if (!fs.mkdir(directory, 0o700)) return null;
	let input = directory + '/input', output = directory + '/code.svg';
	let markup = null;
	try {
		if (fs.writefile(input, uri) != length(uri) ||
		    !fs.chmod(input, 0o600)) die('unavailable');
		let status = system([
			'qrencode', '-r', input, '-t', 'SVG', '-o', output,
			'--rle', '--inline', '-m', '4', '-l', 'M'
		], 5000);
		if (status != 0) die('unavailable');
		markup = fs.readfile(output, 500000);
		let start = type(markup) == 'string' ? index(markup, '<svg') : -1;
		if (start < 0) markup = null;
		else {
			markup = substr(markup, start);
			markup = replace(markup,
				/style="stroke:#([0-9a-fA-F]{6})"/g,
				'stroke="#$1" stroke-width="1"');
		}
	} catch (_) {}
	try { fs.unlink(input); } catch (_) {}
	try { fs.unlink(output); } catch (_) {}
	try { fs.rmdir(directory); } catch (_) {}
	if (markup == null) return null;
	return markup;
};

function client_export(state, client) {
	let profile = client.inbound == true ? inbound.profile(
		read_json('/etc/foxhole/inbound.json', 65536), client) :
		model.client_profile(state, client);
	profile.qrSvg = qr_svg(profile.uri);
	return profile;
};

function save_client(request) {
	session(request);
	let args = request.args, expected = valid_revision(args.revision);
	let name = model.client_name(args.name);
	if (index(['smartphone', 'tablet', 'computer',
		'mobile', 'desktop'], args.deviceType) < 0) fail('invalid_name');
	return locked(() => {
		session(request);
		let state = state_record();
		if (state.revision != expected) fail('revision_conflict');
		let server = null;
		if (args.serverId) {
			for (let item in state.servers)
				if (item.id == args.serverId) server = item;
			if (!server) fail('not_found');
		} else if (length(state.servers)) server = state.servers[0];
		let id = next_id('client');
		let client = {
			id, name, deviceType: args.deviceType,
			serverId: server ? server.id : null, provisioned: false
		};
		let base = read_json('/etc/foxhole/inbound.json', 65536);
		if (base) {
			let used = map(filter(state.clients, c => c.inbound), c => c.port);
			if (length(used) >= inbound.limit(base)) fail('client_limit');
			let port = inbound.shared(base) ? 443 : (base.firstPort || 14443);
			if (!inbound.shared(base)) while (index(used, port) >= 0) port++;
			client.inbound = true;
			client.port = port;
			client.secret = random_hex(32);
			client.allowLan = false;
			client.serverId = null;
		}
		push(state.clients, client);
		state.revision++;
		write_json(STATE_PATH, state, 0o600);
		return { state: public_state(state), client: client_export(state, client) };
	});
};

function update_client(request) {
	session(request);
	let args = request.args, expected = valid_revision(args.revision);
	let name = model.client_name(args.name);
	return locked(() => {
		session(request);
		let state = state_record();
		if (state.revision != expected) fail('revision_conflict');
		for (let client in state.clients) {
			if (client.id != args.id) continue;
			client.name = name;
			state.revision++;
			write_json(STATE_PATH, state, 0o600);
			return { state: public_state(state), client: client_export(state, client) };
		}
		fail('not_found');
	});
};

function get_client(request) {
	session(request);
	let state = state_record();
	for (let client in state.clients)
		if (client.id == request.args.id)
			return { export: client_export(state, client) };
	fail('not_found');
};

function client_access(request) {
	session(request);
	if (inbound.shared(read_json('/etc/foxhole/inbound.json', 65536) || {}))
		fail('client_rules_unsupported');
	let args = request.args, expected = valid_revision(args.revision);
	if (type(args.allowLan) != 'bool') fail('invalid_settings');
	return locked(() => {
		session(request);
		let state = state_record();
		if (state.revision != expected) fail('revision_conflict');
		for (let client in state.clients) {
			if (client.id != args.id || !client.inbound) continue;
			client.allowLan = args.allowLan;
			state.revision++;
			write_json(STATE_PATH, state, 0o600);
			return { state: public_state(state), client: client_export(state, client) };
		}
		fail('not_found');
	});
};

function delete_client(request) {
	let expected = valid_revision(request.args.revision), id = request.args.id;
	return locked(() => {
		session(request);
		let state = state_record();
		if (state.revision != expected) fail('revision_conflict');
		let found = false;
		for (let i = 0; i < length(state.clients); i++) {
			if (state.clients[i].id != id) continue;
			splice(state.clients, i, 1);
			found = true;
			break;
		}
		if (!found) fail('not_found');
		state.revision++;
		write_json(STATE_PATH, state, 0o600);
		return public_state(state);
	});
};

function store_pin(pin) {
	if (type(pin) != 'string' || !match(pin, /^[0-9]{4}$/))
		fail('pin_mismatch');
	let previous = auth_record();
	if (!previous.changed &&
	    equal_secret(previous.hash, pin_hash(previous.salt, pin)))
		fail('pin_unchanged');
	let auth = { schema: 1, salt: random_hex(16), changed: true };
	auth.hash = pin_hash(auth.salt, pin);
	write_json(AUTH_PATH, auth, 0o600);
	for (let item in sessions) delete sessions[item];
};

function admin_pin(request) {
	let sid = request.args.ubus_rpc_session;
	if (type(sid) != 'string' || !match(sid, /^[a-f0-9]{32}$/) ||
	    sid == '00000000000000000000000000000000')
		fail('unauthorized');
	let connection = ubus.connect();
	if (!connection) fail('unavailable');
	// Session methods share rpcd's loop; defer nested calls.
	return connection.defer('session', 'access', {
		ubus_rpc_session: sid, scope: 'ubus',
		object: 'foxhole.admin', function: 'set_pin'
	}, (code, access) => {
		let result = safe(() => {
			if (code != 0 || access?.access != true)
				fail('unauthorized');
			return locked(() => {
				store_pin(request.args.newPin);
				return { changed: true };
			});
		});
		request.reply(result);
		connection.disconnect();
	});
};

function change_pin(request) {
	session(request, true);
	let pin = request.args.newPin;
	if (type(pin) != 'string' || !match(pin, /^[0-9]{4}$/)) fail('pin_mismatch');
	return locked(() => {
		session(request, true);
		store_pin(pin);
		let token = new_token(user_of(request));
		return { token };
	});
};

function resolve_device(request) {
	session(request);
	let address = model.normalize_address(request.args.address);
	let host = model.host_address(address);
	return { address, mac: host ? resolve_mac(host) : null };
};

function list_devices(request) {
	session(request);
	let raw = fs.readfile('/tmp/dhcp.leases', 262144) || '';
	let devices = [], seen = {};
	for (let line in split(raw, '\n')) {
		let fields = split(trim(line), /[ \t]+/);
		if (length(fields) < 4) continue;
		let mac, address;
		try {
			mac = model.normalize_mac(fields[1]);
			address = model.normalize_address(fields[2]);
		} catch (_) { continue; }
		if (!model.host_address(address) || seen[mac]) continue;
		let name = fields[3];
		if (name == '*' || !length(name) ||
		    match(name, /[[:cntrl:]]/)) name = address;
		name = substr(name, 0, 64);
		seen[mac] = true;
		push(devices, { name, address, mac });
		if (length(devices) >= 256) break;
	}
	return { devices };
};

function unlock(request) {
	let pin = request.args.pin;
	check_pin(pin);
	let token = new_token(user_of(request));
	return { token, state: public_state(state_record()),
		pinChangeRequired: sessions[token].setup };
};

function lock(request) {
	let token = session(request, true);
	delete sessions[token];
	return {};
};

function state_call(request) {
	session(request);
	return public_state(state_record());
};

function call(name, request, fn) {
	return safe(() => fn(request));
};

const methods = {
	unlock: { args: { pin: '' }, call: request => call('unlock', request, unlock) },
	lock: { args: { token: '' }, call: request => call('lock', request, lock) },
	state: { args: { token: '' }, call: request => call('state', request, state_call) },
	telemetry: { args: { token: '' }, call: request => call('telemetry', request,
		request => { session(request); return telemetry(); }) },
	settings: { args: { token: '', revision: 0, settings: {}, countries: [],
		devices: [], sites: [] }, call: request => call('settings', request, settings_call) },
	'server.test': { args: { token: '', config: '' }, call: request =>
		call('server.test', request, request => { session(request); return test_server(request.args.config); }) },
	'server.save': { args: { token: '', revision: 0, config: '', id: '', name: '' },
		call: request => call('server.save', request, save_server) },
	'server.get': { args: { token: '', id: '' }, call: request =>
		call('server.get', request, get_server) },
	'server.start': { args: { token: '', revision: 0, id: '' },
		call: request => call('server.start', request, start_server) },
	'server.stop': { args: { token: '', revision: 0 },
		call: request => call('server.stop', request, stop_server) },
	'server.delete': { args: { token: '', revision: 0, id: '' }, call: request =>
		call('server.delete', request, delete_server) },
	'client.save': { args: { token: '', revision: 0, name: '', deviceType: '', serverId: '' },
		call: request => call('client.save', request, save_client) },
	'client.update': { args: { token: '', revision: 0, id: '', name: '' },
		call: request => call('client.update', request, update_client) },
	'client.access': { args: { token: '', revision: 0, id: '', allowLan: false },
		call: request => call('client.access', request, client_access) },
	'client.get': { args: { token: '', id: '' }, call: request =>
		call('client.get', request, get_client) },
	'client.delete': { args: { token: '', revision: 0, id: '' }, call: request =>
		call('client.delete', request, delete_client) },
	'pin.change': { args: { token: '', newPin: '' }, call: request =>
		call('pin.change', request, change_pin) },
	'device.resolve': { args: { token: '', address: '' }, call: request =>
		call('device.resolve', request, resolve_device) },
	'device.list': { args: { token: '' }, call: request =>
		call('device.list', request, list_devices) }
};

return { foxhole: methods, 'foxhole.admin': {
	set_pin: { args: { newPin: '' },
		call: request => safe(() => admin_pin(request)) }
} };
