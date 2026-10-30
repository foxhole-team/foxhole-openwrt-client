#!/usr/bin/env ucode

'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as socket from 'socket';
import * as uci from 'uci';
import * as ubus from 'ubus';
import * as model from '/usr/share/foxhole/model.uc';
import * as runtime_model from '/usr/share/foxhole/runtime-model.uc';
import * as probe from '/usr/share/foxhole/probe.uc';
import * as history_store from '/usr/share/foxhole/history.uc';
import * as inbound from '/usr/share/foxhole/inbound.uc';
import * as pairing from '/usr/share/foxhole/pairing.uc';
import * as mobile from '/usr/share/foxhole/mobile.uc';
import * as core_adapter from '/usr/share/foxhole/core-adapter.uc';
import * as store from '/usr/share/foxhole/private-store.uc';
import * as core_model from '/usr/share/foxhole/core-model.uc';
import * as handoff from '/usr/share/foxhole/handoff.uc';
import * as remote from '/usr/share/foxhole/remote.uc';
import * as handoff_adapter from '/usr/share/foxhole/handoff-adapter.uc';
import * as device_model from '/usr/share/foxhole/device-model.uc';
import * as observation from '/usr/share/foxhole/client-observation.uc';
import * as engine_service from '/usr/share/foxhole/engine-service.uc';
import * as update_service from '/usr/share/foxhole/update-service.uc';
import * as update_model from '/usr/share/foxhole/update-model.uc';

const STATE_PATH = '/etc/foxhole/state.json';
const AUTH_PATH = '/etc/foxhole/auth.json';
const PAIRING_PATH = '/etc/foxhole/pairing.json';
const MOBILE_PATH = '/etc/foxhole/mobile.json';
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
	...map(update_model.reasons, code => 'update_' + lc(code)),
	'engine_unknown_protocol', 'engine_not_released', 'engine_unsupported_target', 'engine_unsupported_profile_graph', 'engine_stale_plan', 'engine_stale_session', 'engine_router_unavailable', 'engine_busy', 'engine_no_space', 'engine_authentication_failed', 'engine_download_failed', 'engine_package_verification_failed', 'engine_candidate_check_failed', 'engine_reconnect_failed', 'engine_recovery_required', 'engine_invalid_request', 'engine_in_use',
	'invalid_pin', 'pin_required', 'pin_unchanged', 'pin_setup_required', 'license_required',
	'locked', 'unauthorized', 'revision_conflict',
	'invalid_config', 'unsupported_config', 'invalid_name',
	'invalid_address', 'invalid_mac', 'mac_not_found', 'invalid_site',
	'site_path_unsupported', 'invalid_settings', 'duplicate_rule',
	'not_found', 'storage_error', 'unavailable', 'pin_mismatch', 'client_limit',
	'runtime_unavailable', 'invalid_pairing', 'pairing_conflict',
	'pairing_limit', 'inbound_required', 'invalid_handoff', 'handoff_conflict', 'public_address_required', 'client_revoked', ...RUNTIME_ERRORS
];

let sessions = {};
let failures = { count: 0, since: 0 };
let history = [];
let last_cpu = null;
let last_sample = 0;
let last_probe_request = 0;
let last_core_probe_request = 0;
let provider_resolutions = {};

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
	store.directory('/etc/foxhole');
	store.directory('/tmp/foxhole');
};

function read_json(path, limit) {
	let raw = fs.readfile(path, limit);
	if (raw == null) return null;
	if (!length(raw) || length(raw) > limit) fail('storage_error');
	try { return json(raw); } catch (_) { fail('storage_error'); }
};

function write_json(path, value, mode) {
	ensure_dir();
	let raw = sprintf('%J', value);
	if (length(raw) > MAX_STATE) fail('storage_error');
	if (mode != 0o600) fail('storage_error');
	store.write(path, raw);
};

function locked(fn) {
	ensure_dir();
	let handle = null;
	try {
		store.target(LOCK_PATH);
		handle = fs.open(LOCK_PATH, 'a+', 0o600);
		if (!handle || !handle.lock('x') ||
		    !store.file_metadata(fs.lstat(LOCK_PATH))) fail('storage_error');
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

function pin_hash(salt, pin) {
	let result = digest.sha256(salt + ':' + pin);
	if (!result) fail('storage_error');
	return result;
};

function auth_record(allow_missing) {
	let auth = read_json(AUTH_PATH, 4096);
	if (auth == null) {
		if (allow_missing) return null;
		fail('pin_setup_required');
	}
	if (auth.schema != 1 || type(auth.changed) != 'bool' ||
	    !match(auth.salt || '', /^[a-f0-9]{32}$/) ||
	    !match(auth.hash || '', /^[a-f0-9]{64}$/)) fail('storage_error');
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
	if (auth.changed != true) {
		let uptime = fs.readfile('/proc/uptime', 256);
		let boot = trim(fs.readfile('/proc/sys/kernel/random/boot_id', 128) || '');
		if (!pairing.bootstrap_valid(auth, uptime, boot))
			fail('invalid_pin');
	}
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

function pairing_record() {
	let record = read_json(PAIRING_PATH, 32768) || pairing.defaults();
	pairing.public_devices(record);
	return record;
};

function new_token(user, paired) {
	for (let key, item in sessions)
		if (item.expires < time()) delete sessions[key];
	if (length(keys(sessions)) >= 64) fail('locked');
	let token = random_hex(32);
	if (paired) token = 'p1.' + token;
	sessions[token] = { user, expires: time() + TOKEN_TTL,
		setup: auth_record().changed != true, pairing: paired || null };
	return token;
};

function session(request, allow_setup) {
	let token = request.args?.token;
	if (type(token) != 'string' || !match(token, /^(p1\.)?[a-f0-9]{64}$/))
		fail('unauthorized');
	let item = sessions[token];
	if (!item || item.user != user_of(request)) fail('unauthorized');
	if (item.expires < time()) {
		delete sessions[token];
		fail('unauthorized');
	}
	if (item.setup && !allow_setup) fail('pin_required');
	if (item.pairing &&
	    !pairing.session_current(pairing_record(), item.pairing)) {
		delete sessions[token];
		fail('unauthorized');
	}
	if (!item.reset) item.expires = time() + TOKEN_TTL;
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

function admit_server(raw, engine) {
	if (!engine || engine == 'hysteria') return model.parse_config(raw);
	if (engine != 'core') fail('unsupported_config');
	return core_adapter.admit(raw);
};

function test_server(raw, engine) {
	let parsed = admit_server(raw, engine);
	return {
		valid: true, scope: 'config', connected: false, code: 'validated',
		name: parsed.name, endpoint: parsed.endpoint,
		protocol: parsed.protocol || 'hysteria2',
		configSha256: digest.sha256(engine == 'core' ? parsed.raw : trim(raw))
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
	engine_service.guard_mutation();
	session(request);
	let args = request.args;
	let expected = valid_revision(args.revision);
	let result = locked(() => {
		session(request);
		engine_service.guard_mutation();
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
	engine_service.guard_mutation();
	session(request);
	let args = request.args, expected = valid_revision(args.revision);
	let parsed = admit_server(args.config, args.engine);
	let subscription = core_model.subscription(args.subscription);
	if (subscription && subscription.selectedProtocol !=
	    (parsed.protocol || 'hysteria2')) fail('invalid_config');
	let id = args.id || next_id('server');
	if (!match(id, /^server-[a-f0-9]{12}$/)) fail('not_found');
	let name = model.server_name(args.name || 'VPN SERVER 01');
	let result = locked(() => {
		session(request);
		engine_service.guard_mutation();
		let state = state_record(), found = false;
		if (state.revision != expected) fail('revision_conflict');
		for (let server in state.servers) {
			if (server.id != id) continue;
			let preserve_portable = args.engine == 'core' &&
				trim(args.config) == trim(server.config) && server.portableProfile != null;
			server.name = name;
			server.endpoint = parsed.endpoint;
			server.config = args.engine == 'core' ? parsed.raw : trim(args.config);
			if (args.engine == 'core') {
				server.engine = 'core'; server.protocol = parsed.protocol;
				if (!preserve_portable) server.portableProfile = parsed.portableProfile;
			} else {
				delete server.engine; delete server.protocol; delete server.portableProfile;
			}
			if (subscription) server.subscription = subscription;
			else delete server.subscription;
			found = true;
		}
		if (!found && args.id) fail('not_found');
		if (!found) push(state.servers, {
			id, name, endpoint: parsed.endpoint,
			config: args.engine == 'core' ? parsed.raw : trim(args.config),
			...(args.engine == 'core' ?
				{ engine: 'core', protocol: parsed.protocol,
					portableProfile: parsed.portableProfile } : {}),
			...(subscription ? { subscription } : {})
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
				config: server.config,
				configSha256: digest.sha256(server.config),
				...(server.subscription ? { subscription: server.subscription } : {}),
				...(server.engine == 'core' ? { engine: 'core',
					portableProfile: core_model.portable(server.portableProfile, server.config) } : {}) };
	fail('not_found');
};

function delete_server(request) {
	engine_service.guard_mutation();
	let expected = valid_revision(request.args.revision), id = request.args.id;
	let result = locked(() => {
		session(request);
		engine_service.guard_mutation();
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
	engine_service.guard_mutation();
	session(request);
	let expected = valid_revision(request.args.revision);
	let id = request.args.id;
	let result = locked(() => {
		session(request);
		engine_service.guard_mutation();
		let state = state_record(), found = false;
		if (state.revision != expected) fail('revision_conflict');
		for (let server in state.servers)
			if (server.id == id) found = true;
		if (!found) fail('not_found');
		let changed = state.activeServerId != id;
		state.activeServerId = id;
		let selected = runtime_model.active_server(state);
		if (selected.engine != 'core')
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
		engine_service.stop_intent();
		if (state.activeServerId != null) {
			state.activeServerId = null;
			state.revision++;
			write_json(STATE_PATH, state, 0o600);
		}
		return state;
	});
	if (!engine_service.defer_stop_for_update()) restart_runtime(result);
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

function profile_app_metadata(paired, client_id, uri) {
	if (type(paired) != 'object' || type(paired.id) != 'string' ||
	    length(paired.id) != 37 ||
	    !match(paired.id, /^pair-[a-f0-9]{32}$/) ||
	    type(client_id) != 'string' || length(client_id) != 19 ||
	    !match(client_id, /^client-[a-f0-9]{12}$/) ||
	    type(uri) != 'string' || !length(uri) || length(uri) > 16384)
		return null;
	for (let i = 0; i < length(uri); i++) {
		let byte = ord(uri, i);
		if (byte < 0x20 || byte == 0x7f) return null;
	}
	return { schema: 1, kind: 'foxhole-openwrt-client',
		pairingId: paired.id, clientId: client_id,
		uriSha256: digest.sha256(uri) };
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
	for (let client in state.clients) {
		if (client.id != request.args.id) continue;
		let profile = client_export(state, client);
		let sid = session(request), paired = sessions[sid].pairing;
		if (paired && client.inbound == true) {
			let metadata = profile_app_metadata(paired, client.id, profile.uri);
			if (metadata) profile.appMetadata = metadata;
		}
		return { export: profile };
	}
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
		let found = false, revoked = false;
		for (let i = 0; i < length(state.clients); i++) {
			if (state.clients[i].id != id) continue;
			if (state.clients[i].inbound == true && system([
				'/usr/libexec/foxhole-inbound-revoke', id
			], 2500) != 0) fail('runtime_unavailable');
			if (state.clients[i].inbound == true) {
				revoked = true;
				let phones = mobile.journal(read_json(MOBILE_PATH, 65536)), changed = false;
				for (let phone in phones.phones) if (phone.remoteClientId == id) {
					phone.remoteRevoked = true; changed = true;
				}
				if (changed) write_json(MOBILE_PATH, phones, 0o600);
			}
			splice(state.clients, i, 1);
			found = true;
			break;
		}
		if (!found) fail('not_found');
		state.revision++;
		write_json(STATE_PATH, state, 0o600);
		return { ...public_state(state), clientRevocation: { id,
			applied: true, targetRevoked: revoked } };
	});
};

function handoff_record() {
	let raw = store.read(handoff.path, 65536);
	return handoff.journal(raw ? json(raw) : null);
};

function handoff_apply(record, pairs) {
	let connection = ubus.connect(), listener;
	if (!connection) fail('unavailable');
	try { listener = mobile.lan_listener(connection.call(
		'network.interface.lan', 'status', {})); }
	catch (_) { connection.disconnect(); fail('unavailable'); }
	connection.disconnect();
	handoff_adapter.apply(record, pairs, listener.device);
	write_json(handoff.path, record, 0o600);
};

function revoke_handoff(id) {
	if (!store.read(handoff.path, 65536)) return;
	let record = handoff_record();
	record.leases = filter(record.leases, lease => id && lease.pairId != id);
	record.revision++;
	handoff_apply(record, pairing_record());
};

const LICENSE_VERSION = 1;
const LICENSE_RECORD_PATH = '/etc/foxhole/license.json';

function license_record() {
 let record = read_json(LICENSE_RECORD_PATH, 4096);
 if (record == null) return false;
 if (record.schema != 1 || type(record.licenseAccepted) != 'bool' ||
     type(record.licenseVersion) != 'int' || record.licenseVersion != LICENSE_VERSION) fail('storage_error');
 return record.licenseAccepted == true;
};

function license_required(auth) {
 return auth?.changed != true && !(type(auth?.licenseAccepted) == 'bool' && auth.licenseAccepted == true &&
  type(auth?.licenseVersion) == 'int' && auth.licenseVersion == LICENSE_VERSION) && !license_record();
};

function license_choice(auth, acceptance) {
 let recorded = license_record();
 let accepted = type(acceptance?.licenseAccepted) == 'bool' && acceptance.licenseAccepted == true &&
  type(acceptance?.licenseVersion) == 'int' && acceptance.licenseVersion == LICENSE_VERSION;
 if (license_required(auth) && !accepted) fail('license_required');
 return recorded || accepted || (type(auth?.licenseAccepted) == 'bool' && auth.licenseAccepted == true &&
  type(auth?.licenseVersion) == 'int' && auth.licenseVersion == LICENSE_VERSION);
};

function store_pin(pin, acceptance) {
	if (type(pin) != 'string' || !match(pin, /^[0-9]{4}$/))
		fail('pin_mismatch');
	let previous = auth_record(true), accepted = license_choice(previous, acceptance);
	let auth = { schema: 1, salt: random_hex(16), changed: true };
	if (accepted) { auth.licenseAccepted = true; auth.licenseVersion = LICENSE_VERSION; }
	auth.hash = pin_hash(auth.salt, pin);
	revoke_handoff(null);
	write_json(PAIRING_PATH, pairing.defaults(), 0o600);
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
				store_pin(request.args.newPin, request.args);
				return { changed: true };
			});
		});
		request.reply(result);
		connection.disconnect();
	});
};

function change_pin(request) {
	let sid = session(request, true);
	if (sessions[sid].pairing) fail('unauthorized');
	let pin = request.args.newPin;
	if (type(pin) != 'string' || !match(pin, /^[0-9]{4}$/)) fail('pin_mismatch');
	return locked(() => {
		session(request, true);
		store_pin(pin, request.args);
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

function neighbor_observation() {
	let directory = '/tmp/foxhole/neighbors-' + random_hex(6);
	let output = directory + '/output', raw = null;
	try {
		if (!fs.mkdir(directory, 0o700)) return [];
		store.directory(directory);
		let code = system([ '/bin/sh', '-c', 'umask 077; ' +
			'/sbin/ip neigh show 2>/dev/null | head -c 262145 >' + output ], 2000);
		if (code == 0) raw = store.read(output, 262144);
	} catch (_) { raw = null; }
	try { fs.unlink(output); } catch (_) {}
	try { fs.rmdir(directory); } catch (_) {}
	return device_model.parse_neighbors(raw);
};

function list_devices(request) {
	session(request);
	let raw = fs.readfile('/tmp/dhcp.leases', 262144) || '';
	let devices = [], seen = {}, neighbors = neighbor_observation();
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
		push(devices, { name, address, mac,
			online: device_model.online(neighbors, address, mac) });
		if (length(devices) >= 256) break;
	}
	return { devices };
};

function unlock(request) {
	return locked(() => {
		let pin = request.args.pin;
		check_pin(pin);
		let token = new_token(user_of(request));
		let auth = auth_record();
		if (auth.changed != true && auth.bootstrapExpiresUptimeMs != null) {
			auth.bootstrapConsumed = true;
			write_json(AUTH_PATH, auth, 0o600);
		}
		return { token, state: public_state(state_record()),
			pinChangeRequired: sessions[token].setup, licenseRequired: license_required(auth),
			licenseVersion: LICENSE_VERSION };
	});
};

function lock(request) {
	let token = session(request, true);
	delete sessions[token];
	return {};
};

function pair_create(request) {
	let sid = session(request);
	if (sessions[sid].pairing) fail('unauthorized');
	return locked(() => {
		session(request);
		let args = request.args;
		let record = pairing.register(pairing_record(), args.id,
			args.credential, args.name, time());
		write_json(PAIRING_PATH, record, 0o600);
		return { id: args.id };
	});
};

function pair_unlock(request) {
	let now = time();
	if (now - failures.since >= FAILURE_WINDOW) {
		failures.count = 0;
		failures.since = now;
	}
	if (failures.count >= FAILURE_LIMIT) fail('locked');
	if (auth_record().changed != true) fail('pin_required');
	let paired;
	try {
		paired = pairing.authenticate(pairing_record(),
			request.args.id, request.args.credential);
	} catch (error) {
		if (error_code(error) != 'unauthorized') die(error_code(error));
		failures.count++;
		if (!failures.since) failures.since = now;
		fail('unauthorized');
	}
	let token = new_token(user_of(request), paired);
	return { token, state: public_state(state_record()) };
};

function pair_revoke(request) {
	let sid = session(request), id = request.args.id;
	if (sessions[sid].pairing && sessions[sid].pairing.id != id)
		fail('unauthorized');
	return locked(() => {
		session(request);
		let record = pairing.revoke(pairing_record(), id);
		revoke_handoff(id);
		write_json(PAIRING_PATH, record, 0o600);
		for (let token, item in sessions)
			if (item.pairing?.id == id) delete sessions[token];
		return {};
	});
};

function phone_session(request) {
	let token = session(request);
	let paired = sessions[token].pairing;
	if (!paired) fail('unauthorized');
	return paired;
};

function remote_wan_address() {
	let connection = ubus.connect(), address = null;
	if (!connection) fail('public_address_required');
	try { address = remote.wan_address(connection.call('network.interface.wan', 'status', {})); }
	catch (_) {}
	try { connection.disconnect(); } catch (_) {}
	if (!address) fail('public_address_required');
	return address;
};

function phone_capabilities(request) {
	phone_session(request);
	let native = core_adapter.receipt('capabilities');
	let protocols = [];
	if (native?.schema_version == 1 && native.router_contract_version == 1 &&
	    native.platform == 'linux' && type(native.protocols) == 'array' &&
	    length(native.protocols) <= 12)
		for (let name in native.protocols) {
			if (type(name) != 'string' || !core_model.supported_protocol(name) ||
			    index(protocols, name) >= 0) { protocols = []; break; }
			push(protocols, name);
		}
	let legacy = fs.stat('/usr/bin/hysteria') != null;
	let incoming = legacy && read_json('/etc/foxhole/inbound.json', 65536) != null;
	if (legacy && !incoming) try { incoming = remote_wan_address() != null; } catch (_) {}
	return { schema: 1, coreProtocols: protocols,
		legacyProtocols: legacy ? ['hysteria2'] : [],
		inboundProtocols: incoming ? ['hysteria2'] : [],
		subscriptionSelection: true, phoneRegistration: true,
		independentPhoneChoices: true, packageUpdates: true,
		phoneRemoteProvisioning: incoming, homeProof: false, phoneHandoff: false,
		providerResolve: false };
};

function phone_address(request) {
	let address = model.normalize_address(request.args.address);
	if (address != request.args._peerAddress ||
	    model.host_address(address) != address ||
	    length(iptoarr(address) || []) != 4) fail('invalid_address');
	return address;
};

function phone_provision(request) {
	phone_session(request);
	let address = phone_address(request), mac = resolve_mac(address);
	if (!mac) fail('mac_not_found');
	let result = locked(() => {
		let paired = phone_session(request), state = state_record();
		let base = read_json('/etc/foxhole/inbound.json', 65536);
		if (request.args.createRemote == true && !base)
			base = remote.prepare(remote_wan_address());
		let record = mobile.prune(read_json(MOBILE_PATH, 65536),
			pairing_record());
		let prepared = mobile.prepare(state, record,
			paired, { name: request.args.name, address, mac,
				registerPhone: request.args.registerPhone,
				createRemote: request.args.createRemote }, base, random_hex);
		let applied = mobile.apply(state, prepared.phone);
		let profile = null;
		if (prepared.phone.remoteClientId) {
			for (let client in applied.state.clients)
				if (client.id == prepared.phone.remoteClientId)
					profile = inbound.profile(base, client).uri;
		}
		// Persist intent first; retries must not duplicate clients.
		write_json(MOBILE_PATH, prepared.record, 0o600);
		if (applied.changed) write_json(STATE_PATH, applied.state, 0o600);
		return { state: applied.state, changed: applied.changed,
			phone: prepared.phone, profile };
	});
	if (!restart_runtime(result.state))
		fail('runtime_unavailable');
	if (result.phone.remoteClientId && system([
		'/usr/libexec/foxhole-inbound', 'force'
	], 30000) != 0) fail('unavailable');
	let paired = phone_session(request);
	let response = {
		revision: result.state.revision,
		lanDeviceId: result.phone.lanDeviceId,
		remoteClientId: result.phone.remoteClientId,
		profileUri: result.profile, remoteReady: false
	};
	let metadata = profile_app_metadata(paired,
		result.phone.remoteClientId, result.profile);
	if (metadata) response.appMetadata = metadata;
	return response;
};

function phone_status(request) {
	let paired = phone_session(request), address = phone_address(request);
	let state = state_record(), device = null;
	let record = mobile.journal(read_json(MOBILE_PATH, 65536));
	for (let phone in record.phones)
		if (phone.pairId == paired.id && phone.verifier == paired.verifier &&
		    phone.mac == resolve_mac(address))
			for (let item in state.devices)
				if (item.id == phone.lanDeviceId) device = item;
	let result = { schema: 1, pairingId: paired.id,
		lanDeviceId: device?.id || null,
		serverId: state.activeServerId, generation: null,
		validated: false, vpnBound: false, checkedAgeMs: null,
		routed: false, failClosed: false, address,
		lossConfirmed: false,
		observedUptimeMs: core_adapter.clock_ms(), handoff: null };
	try { result.handoff = handoff_adapter.observe(handoff_record(),
		pairing_record(), paired); } catch (_) { delete result.handoff; }
	let selected = runtime_model.active_server(state);
	if (!selected && !fs.stat('/sys/class/net/foxhole0') &&
	    core_adapter.receipt('capabilities')?.router_contract_version == 1) {
		result.lossConfirmed = true;
		return result;
	}
	if (selected?.engine != 'core') return result;
	let current = runtime_status(state);
	let owner = core_adapter.receipt('owner');
	let key = core_adapter.generation(owner);
	if (owner?.owned != true || !key || !current.connected ||
	    !current.enforced) {
		result.lossConfirmed = current.phase != 'connecting' &&
			!fs.stat('/sys/class/net/foxhole0');
		return result;
	}
	let policy = read_json(core_adapter.policy_path, 4096);
	if (policy?.generation_key != key ||
	    policy.serverId != state.activeServerId ||
	    policy.stateIdentity != core_adapter.policy_identity(state)) return result;
	let kernel = core_adapter.kernel_policy(key, policy.stateIdentity);
	if (policy.kernelIdentity != kernel) {
		result.lossConfirmed = true;
		result.observedUptimeMs = core_adapter.clock_ms();
		return result;
	}
	let after = core_adapter.receipt('owner');
	if (after?.owned != true || core_adapter.generation(after) != key) {
		result.lossConfirmed = !fs.stat('/sys/class/net/foxhole0');
		return result;
	}
	result.generation = key;
	if (!device || device.route != 'vpn' || device.bindMac != true) {
		result.lossConfirmed = device?.route == 'direct';
		return result;
	}
	result.routed = true;
	result.failClosed = selected.engine == 'core';
	result.lossConfirmed = !result.failClosed;
	let proof = read_json(core_adapter.proof_path, 4096);
	let now = core_adapter.clock_ms();
	let checked = proof?.checkedUptimeMs;
	if (core_model.proof_identity(proof, { ...selected, id: state.activeServerId }, after, now)) {
		result.checkedAgeMs = now - checked + 10;
		result.validated = core_model.proof_valid(proof, { ...selected, id: state.activeServerId }, after, now);
		result.vpnBound = result.validated;
	}
	if (!result.validated && type(now) == 'int' &&
	    now - last_core_probe_request >= 5000) {
		last_core_probe_request = now;
		system('/usr/libexec/foxhole-runtime probe ' +
			'</dev/null >/dev/null 2>&1 &');
	}
	return result;
};

function registered_phone(request) {
	let paired = phone_session(request), address = phone_address(request);
	let mac = resolve_mac(address), state = state_record();
	for (let phone in mobile.journal(read_json(MOBILE_PATH, 65536)).phones)
		if (phone.pairId == paired.id && phone.verifier == paired.verifier && phone.mac == mac)
			for (let device in state.devices)
				if (device.id == phone.lanDeviceId && device.mac == mac &&
				    device.bindMac == true && device.route == 'vpn')
					return { ...phone, address };
	fail('unauthorized');
};

function phone_resolve(request) {
	let paired = phone_session(request), phone = registered_phone(request);
	let host = handoff.hostname(request.args.host), now = core_adapter.clock_ms();
	let bucket = provider_resolutions[paired.id];
	if (bucket?.verifier != paired.verifier || now < bucket.windowUptimeMs)
		bucket = { verifier: paired.verifier, windowUptimeMs: now, requests: 0, hosts: {} };
	let previous = bucket.hosts[host];
	if (previous && now >= previous.checkedUptimeMs &&
	    now - previous.checkedUptimeMs < previous.ttlMs)
		return { ...previous, ttlMs: previous.ttlMs - (now - previous.checkedUptimeMs) };
	if (now - bucket.windowUptimeMs >= 5000) {
		bucket.windowUptimeMs = now; bucket.requests = 0;
	}
	if (bucket.requests >= 8) fail('unavailable');
	for (let name, value in bucket.hosts)
		if (now - value.checkedUptimeMs >= value.ttlMs) delete bucket.hosts[name];
	if (length(keys(bucket.hosts)) >= 8 && !bucket.hosts[host]) fail('unavailable');
	if (length(keys(provider_resolutions)) >= 16 && !provider_resolutions[paired.id])
		provider_resolutions = {};
	bucket.requests++;
	provider_resolutions[paired.id] = bucket;
	let directory = '/tmp/foxhole/resolve-' + random_hex(12);
	if (!fs.mkdir(directory, 0o700)) fail('storage_error');
	let output = directory + '/output', result = null;
	try {
		store.directory(directory);
		if (system(['/usr/libexec/foxhole-provider-resolve', host, output], 4500) != 0)
			fail('unavailable');
		let raw = store.read(output, 8192);
		result = handoff.dns_answer(json(raw), host);
	} catch (_) {}
	try { fs.unlink(output); fs.rmdir(directory); } catch (_) {}
	// Recheck pair and DHCP ownership after the WAN operation.
	registered_phone(request); phone_session(request);
	let checked = core_adapter.clock_ms();
	bucket.hosts[host] = { schema: 1, pairingId: paired.id,
		host, addresses: result?.addresses || [],
		ttlMs: result?.ttlMs || 0, checkedUptimeMs: checked };
	if (!result) fail('unavailable');
	return { ...bucket.hosts[host] };
};

function phone_handoff(request) {
	return locked(() => {
		let paired = phone_session(request), phone = registered_phone(request);
		let now = core_adapter.clock_ms(), pairs = pairing_record();
		if (type(request.args._receivedUptimeMs) != 'int' ||
		    request.args._receivedUptimeMs > now ||
		    now - request.args._receivedUptimeMs > 5000) fail('invalid_handoff');
		let record = handoff_record();
		let before = phone_status(request);
		now = core_adapter.clock_ms();
		if (now - request.args._receivedUptimeMs > 5000) fail('invalid_handoff');
		if (request.args.mode == 'router_vpn' &&
		    (!before.validated || !before.vpnBound || !before.routed || !before.failClosed ||
		     before.serverId != request.args.expectedServerId ||
		     before.generation != request.args.expectedGeneration)) fail('unavailable');
		let next = handoff.request(record, pairs, paired, phone, request.args,
			now, handoff_adapter.boot_id());
		handoff_apply(next, pairs);
		let observed = handoff_adapter.observe(next, pairs, paired);
		if (request.args.mode == 'phone_vpn' && !observed) fail('unavailable');
		let after = phone_status(request);
		if (request.args.mode == 'router_vpn' &&
		    (!after.validated || !after.vpnBound || !after.routed || !after.failClosed ||
		     after.serverId != request.args.expectedServerId ||
		     after.generation != request.args.expectedGeneration)) fail('unavailable');
		return { schema: 1, claimId: request.args.claimId,
			mode: request.args.mode, phase: observed ? 'active' : 'released',
			remainingMs: observed?.remainingMs || 0,
			observedUptimeMs: core_adapter.clock_ms(),
			serverId: after.serverId, generation: after.generation,
			policyRevision: next.revision };
	});
};

function online_ready(connection, flags, deadline) {
	let now = core_adapter.clock_ms();
	if (now == null || now >= deadline) return false;
	let ready = socket.poll(deadline - now, [connection, flags]);
	return length(ready || []) == 1 && (ready[0][1] & flags) != 0;
};

function read_online(listener, ids) {
	let connection = null;
	let read = () => {
		let port = match(listener.listen || '', /^127\.0\.0\.1:90([1-5])$/);
		if (!port || type(listener.secret) != 'string' ||
		    !match(listener.secret, /^[a-f0-9]{64}$/)) return null;
		let now = core_adapter.clock_ms();
		if (now == null) return null;
		let deadline = now + 2000;
		connection = socket.connect({ family: socket.AF_INET,
			address: '127.0.0.1', port: 900 + int(port[1]) }, null, null, 500);
		if (!connection) return null;
		let request = 'GET /online HTTP/1.0\r\nHost: ' + listener.listen +
			'\r\nConnection: close\r\nAuthorization: ' + listener.secret + '\r\n\r\n';
		let offset = 0;
		while (offset < length(request)) {
			if (!online_ready(connection, socket.POLLOUT, deadline)) return null;
			let sent = connection.send(substr(request, offset), socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL);
			if (sent == null || sent <= 0) return null;
			offset += sent;
		}
		let raw = '';
		while (true) {
			if (!online_ready(connection, socket.POLLIN | socket.POLLHUP, deadline)) return null;
			let part = connection.recv(10241 - length(raw), socket.MSG_DONTWAIT);
			if (part == null) return null;
			if (!length(part)) break;
			raw += part;
			if (length(raw) > 10240) return null;
		}
		return observation.online_map(observation.http_body(raw), ids);
	};
	let result = null;
	try { result = read(); } catch (_) {}
	if (connection) try { connection.close(); } catch (_) {}
	return result;
};

function client_status(request) {
	session(request);
	return locked(() => {
		session(request);
		let state = state_record();
		let rows = map(state.clients, item => ({ id: item.id, online: null }));
		let unknown = () => ({ schema: 1, revision: state.revision,
			clients: map(state.clients, item => ({ id: item.id, online: null })) });
		let directory = '/tmp/foxhole/inbound', record;
		try { record = json(store.read(directory + '/observations.json', 8192) || 'null'); }
		catch (_) { return unknown(); }
		if (record?.schema != 1 || record.revision != state.revision ||
		    type(record.listeners) != 'array' || length(record.listeners) > 4 ||
		    type(record.generation) != 'string' || !match(record.generation, /^[a-f0-9]{64}$/))
			return unknown();
		let generation;
		try { generation = store.read(directory + '/generation', 128); }
		catch (_) { return unknown(); }
		if (generation != record.generation) return unknown();
		let ids = map(filter(state.clients, item => item.inbound == true), item => item.id);
		let shared = length(record.listeners) == 1 && record.listeners[0]?.id == 'shared';
		if ((!shared && length(record.listeners) != length(ids)) ||
		    (shared && !length(ids))) return unknown();
		let seen = {};
		for (let listener in record.listeners) {
			let id = listener?.id;
			if (type(id) != 'string' || (id != 'shared' && index(ids, id) < 0) || seen[id]) return unknown();
			seen[id] = true;
			let config;
			try { config = json(store.read(directory + '/' + id + '.json', 65536)); }
			catch (_) { return unknown(); }
			if (config?.trafficStats?.listen != listener.listen || config.trafficStats.secret != listener.secret ||
			    config.auth?.type != 'userpass' || type(config.auth.userpass) != 'object') return unknown();
			let users = keys(config.auth.userpass);
			if ((shared && length(users) != length(ids)) ||
			    (!shared && (length(users) != 1 || users[0] != id))) return unknown();
			for (let user in users) {
				let client = filter(state.clients, item => item.id == user && item.inbound == true)[0];
				if (!client || config.auth.userpass[user] != client.secret) return unknown();
			}
			let values = read_online(listener, users);
			for (let row in rows)
				if (index(users, row.id) >= 0) row.online = observation.online(values, row.id);
		}
		try { if (store.read(directory + '/generation', 128) != generation) return unknown(); }
		catch (_) { return unknown(); }
		return { schema: 1, revision: state.revision, clients: rows };
	});
};

function engine_principal(request) {
	let item = sessions[session(request)];
	if (item.pairing) return { kind: 'pair', id: item.pairing.id, verifier: item.pairing.verifier };
	return { kind: 'admin', user: item.user, verifier: digest.sha256(auth_record().hash) };
};
function update_request(request, action) {
	let principal = engine_principal(request), args = request.args;
	try {
	if (action == 'status') return update_service.status(principal);
	if (action == 'job') return update_service.job(args.jobId, principal);
	if (action == 'check') return update_service.check({ expectedRevision: args.expectedRevision }, principal);
	if (action == 'plan') return update_service.plan({ expectedRevision: args.expectedRevision }, principal);
	if (action == 'settings') return update_service.settings({ expectedRevision: args.expectedRevision, autoUpdateEnabled: args.autoUpdateEnabled }, principal);
	return update_service.apply({ planId: args.planId, planSha256: args.planSha256, expectedRevision: args.expectedRevision, confirmed: args.confirmed }, principal);
	} catch (error) {
		let code = type(error) == 'string' ? error : error?.message;
		if (substr(code || '', 0, 7) == 'engine_' && index(update_model.reasons, uc(substr(code, 7))) >= 0)
			die('update_' + substr(code, 7));
		die(error);
	}
};
function engines_status(request) { return engine_service.status(engine_principal(request)); };
function engines_plan(request) {
	let owner = engine_principal(request);
	return engine_service.plan({ operation: request.args.operation, engineIds: request.args.engineIds,
		storage: request.args.storage, expectedRevision: request.args.expectedRevision,
		catalogSha256: request.args.catalogSha256 }, owner);
};
function engines_apply(request) {
	let owner = engine_principal(request);
	return engine_service.apply({ planId: request.args.planId, planSha256: request.args.planSha256,
		expectedRevision: request.args.expectedRevision, confirmed: request.args.confirmed }, owner);
};
function engines_job(request) { return engine_service.job(request.args.jobId, engine_principal(request)); };

function package_status(request) {
	let auth = auth_record(true);
	return { schema: 1, product: 'foxhole', installed: true,
		pinConfigured: auth?.changed == true, resetSupported: true, packageUpdates: true,
		licenseRequired: license_required(auth), licenseVersion: LICENSE_VERSION };
};

function setup_reset(request) {
	let sid = session(request);
	if (sessions[sid].pairing) fail('unauthorized');
	if (type(request.args.confirm) != 'bool' || request.args.confirm != true) fail('unauthorized');
	let expected = valid_revision(request.args.revision);
	return locked(() => {
		let sid = session(request);
		if (sessions[sid].pairing) fail('unauthorized');
		let previous = auth_record(), state = state_record();
		if (previous.changed != true) fail('pin_required');
		if (state.revision != expected || state.revision >= 0x7fffffff)
			fail('revision_conflict');
		revoke_handoff(null);
		if (system([ RUNTIME_INIT, 'stop' ], 10000) != 0 ||
		    system([ '/etc/init.d/foxhole-inbound', 'stop' ], 10000) != 0)
			fail('unavailable');
		let inbound_path = '/etc/foxhole/inbound.json';
		store.target(inbound_path);
		if (fs.lstat(inbound_path) && !fs.unlink(inbound_path)) fail('storage_error');
		let cleared = model.defaults();
		cleared.revision = state.revision + 1;
		for (let item in sessions) delete sessions[item];
		write_json(STATE_PATH, cleared, 0o600);
		let pairs = pairing.defaults(), phones = { schema: 1, phones: [] };
		let auth = { schema: 1, salt: previous.salt,
			hash: previous.hash, changed: false, resetPending: true };
		write_json(PAIRING_PATH, pairs, 0o600);
		write_json(MOBILE_PATH, phones, 0o600);
		write_json(AUTH_PATH, auth, 0o600);
		for (let path, expected in { [STATE_PATH]: cleared,
			[PAIRING_PATH]: pairs, [MOBILE_PATH]: phones, [AUTH_PATH]: auth })
			if (sprintf('%J', read_json(path, MAX_STATE)) != sprintf('%J', expected))
				fail('storage_error');
		let token = new_token(user_of(request));
		sessions[token].expires = time() + 300;
		sessions[token].reset = true;
		return { schema: 1, scope: 'foxhole', reset: true,
			revision: cleared.revision, token, pinChangeRequired: true };
	});
};

function state_call(request) {
	session(request);
	return public_state(state_record());
};

function call(name, request, fn) {
	return safe(() => fn(request));
};

const methods = {
	'updates.status': { args: { token: '' }, call: request => call('updates.status', request, request => update_request(request, 'status')) },
	'updates.check': { args: { token: '', expectedRevision: 0 }, call: request => call('updates.check', request, request => update_request(request, 'check')) },
	'updates.plan': { args: { token: '', expectedRevision: 0 }, call: request => call('updates.plan', request, request => update_request(request, 'plan')) },
	'updates.apply': { args: { token: '', planId: '', planSha256: '', expectedRevision: 0, confirmed: false }, call: request => call('updates.apply', request, request => update_request(request, 'apply')) },
	'updates.job': { args: { token: '', jobId: '' }, call: request => call('updates.job', request, request => update_request(request, 'job')) },
	'updates.settings': { args: { token: '', expectedRevision: 0, autoUpdateEnabled: false }, call: request => call('updates.settings', request, request => update_request(request, 'settings')) },
	'engines.status': { args: { token: '' }, call: request => call('engines.status', request, engines_status) },
	'engines.plan': { args: { token: '', operation: '', engineIds: [], storage: 'AUTO', expectedRevision: 0, catalogSha256: '' },
		call: request => call('engines.plan', request, engines_plan) },
	'engines.apply': { args: { token: '', planId: '', planSha256: '', expectedRevision: 0, confirmed: false },
		call: request => call('engines.apply', request, engines_apply) },
	'engines.job': { args: { token: '', jobId: '' }, call: request => call('engines.job', request, engines_job) },
	'client.status': { args: { token: '' }, call: request => call('client.status', request, client_status) },
	'package.status': { args: {}, call: request => call('package.status', request, package_status) },
	'setup.reset': { args: { token: '', revision: 0, confirm: false }, call: request => call('setup.reset', request, setup_reset) },
	'phone.resolve': { args: { token: '', address: '', _peerAddress: '', host: '' },
		call: request => call('phone.resolve', request, phone_resolve) },
	'phone.handoff': { args: { token: '', address: '', _peerAddress: '',
		claimId: '', mode: '', leaseMs: 60000, upstreamTargets: [],
		requestUptimeMs: 0, _receivedUptimeMs: 0,
		expectedServerId: '', expectedGeneration: '' }, call: request =>
		call('phone.handoff', request, phone_handoff) },
	'phone.capabilities': { args: { token: '' }, call: request =>
		call('phone.capabilities', request, phone_capabilities) },
	'phone.provision': { args: { token: '', name: '', address: '',
		_peerAddress: '', registerPhone: true, createRemote: false },
		call: request => call('phone.provision', request, phone_provision) },
	'phone.status': { args: { token: '', address: '', _peerAddress: '' },
		call: request => call('phone.status', request, phone_status) },
	unlock: { args: { pin: '' }, call: request => call('unlock', request, unlock) },
	lock: { args: { token: '' }, call: request => call('lock', request, lock) },
	'pair.create': { args: { token: '', id: '', credential: '', name: '' },
		call: request => call('pair.create', request, pair_create) },
	'pair.unlock': { args: { id: '', credential: '' },
		call: request => call('pair.unlock', request, pair_unlock) },
	'pair.list': { args: { token: '' }, call: request =>
		call('pair.list', request, request => {
			session(request);
			return { devices: pairing.public_devices(pairing_record()) };
		}) },
	'pair.revoke': { args: { token: '', id: '' },
		call: request => call('pair.revoke', request, pair_revoke) },
	state: { args: { token: '' }, call: request => call('state', request, state_call) },
	telemetry: { args: { token: '' }, call: request => call('telemetry', request,
		request => { session(request); return telemetry(); }) },
	settings: { args: { token: '', revision: 0, settings: {}, countries: [],
		devices: [], sites: [] }, call: request => call('settings', request, settings_call) },
	'server.test': { args: { token: '', config: '', engine: '' }, call: request =>
		call('server.test', request, request => {
			session(request);
			return test_server(request.args.config, request.args.engine);
		}) },
	'server.save': { args: { token: '', revision: 0, config: '', id: '', name: '', engine: '', subscription: {} },
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
	'pin.change': { args: { token: '', newPin: '', licenseAccepted: false, licenseVersion: 0 }, call: request =>
		call('pin.change', request, change_pin) },
	'device.resolve': { args: { token: '', address: '' }, call: request =>
		call('device.resolve', request, resolve_device) },
	'device.list': { args: { token: '' }, call: request =>
		call('device.list', request, list_devices) }
};

return { foxhole: methods, 'foxhole.admin': {
	set_pin: { args: { newPin: '', licenseAccepted: false, licenseVersion: 0 },
		call: request => safe(() => admin_pin(request)) }
} };
