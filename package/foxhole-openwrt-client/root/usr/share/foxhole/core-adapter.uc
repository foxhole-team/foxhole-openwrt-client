'use strict';

import * as fs from 'fs';
import * as core from './core-model.uc';
import * as digest from 'digest';
import * as store from './private-store.uc';
import * as engine_registry from './engine-registry.uc';

export const binary = '/usr/bin/foxcore-cli';
export const config_path = '/tmp/foxhole/core.json';
export const state_path = '/tmp/foxhole/core-state.json';
export const auth_path = '/tmp/foxhole/bridge-auth.json';
export const proof_path = '/tmp/foxhole/core-proof.json';
export const policy_path = '/tmp/foxhole/core-policy.json';
let kernel_cache = null;
let owner_cache = null;

function erase(path) { try { fs.unlink(path); } catch (_) {} };

export function binary_for(raw) {
	return engine_registry.select(raw)?.path || binary;
};

export function admit(raw) {
	let selected_binary = binary_for(raw);
	if (!fs.stat(selected_binary) || type(raw) != 'string' ||
	    length(raw) > 262144 || length(raw) < 2)
		die('unsupported_config');
	store.directory('/tmp/foxhole');
	let entropy = fs.readfile('/dev/urandom', 12);
	if (length(entropy || '') != 12) die('storage_error');
	let directory = '/tmp/foxhole/admit-' + hexenc(entropy);
	if (!fs.mkdir(directory, 0o700)) die('storage_error');
	store.directory(directory);
	let input = directory + '/input', output = directory + '/config';
	let result = null, error = null;
	try {
		store.write(input, raw);
		if (system([ selected_binary, 'import', '--profile', input,
			'--out', output ], 30000) != 0) die('unsupported_config');
		let imported = store.read(output, 262144);
		if (!imported || length(imported) > 262144)
			die('unsupported_config');
		let parsed = core.describe(imported);
		result = { ...parsed, raw: imported,
			portableProfile: { content: raw, sha256: digest.sha256(raw),
				configSha256: digest.sha256(imported) } };
	} catch (caught) {
		error = type(caught) == 'string' ? caught : caught.message;
	}
	erase(input); erase(output);
	try { fs.rmdir(directory); } catch (_) {}
	if (error) die(error == 'storage_error' ? error : 'unsupported_config');
	return result;
};

export function check() {
	let selected_binary = engine_registry.current_binary();
	return fs.stat(selected_binary) && system([
		selected_binary, 'check', '--config', config_path
	], 30000) == 0;
};

export function clock_ms() {
	let raw = fs.readfile('/proc/uptime', 128);
	if (!raw || !match(raw, /^[0-9]+\.[0-9]+ /)) return null;
	return int(+split(raw, ' ')[0] * 1000);
};

function runtime_identity(raw) {
	let value, generation;
	try { value = raw ? json(raw) : null; } catch (_) { return null; }
	generation = raw ? match(raw, /"generation":([0-9]{1,20})/) : null;
	if (value?.phase != 'running' || !generation) return null;
	return sprintf('%s:%s:%s:%s:%s', value.pid, value.process_start,
		value.ifindex, value.tun_fd, generation[1]);
};

export function receipt(action) {
	// Authentication requires fresh owner and kernel observations.
	if (action == 'probe') { owner_cache = null; kernel_cache = null; }
	let selected_binary = engine_registry.current_binary();
	if (index(['owner', 'probe', 'capabilities'], action) < 0 ||
	    !fs.stat(selected_binary)) return null;
	store.directory('/tmp/foxhole');
	let cache_key = null, cache_stamp = clock_ms();
	if (action == 'owner') {
		let status = store.read(state_path, 8192);
		let index = fs.readfile('/sys/class/net/foxhole0/ifindex', 32);
		let value = null;
		try { value = status ? json(status) : null; } catch (_) {}
		let process = type(value?.pid) == 'int' ?
			fs.stat('/proc/' + value.pid + '/exe') : null;
		if (runtime_identity(status) && index && process)
			cache_key = sprintf('%s:%s:%s:%s:%s', runtime_identity(status),
				index, process.dev.major, process.dev.minor, process.inode);
		if (cache_key && owner_cache?.key == cache_key &&
		    cache_stamp >= owner_cache.stamp &&
		    cache_stamp - owner_cache.stamp <= 250)
			return owner_cache.value;
		owner_cache = null;
	}
	let random = fs.readfile('/dev/urandom', 12);
	if (length(random || '') != 12) return null;
	let output = '/tmp/foxhole/receipt-' + hexenc(random);
	let command = selected_binary + ' ' + action;
	if (action != 'capabilities')
		command += ' --state ' + state_path + ' --interface foxhole0';
	let code = system([ '/bin/sh', '-c', 'umask 077; ' +
		command + ' >' + output + ' 2>/dev/null' ],
		action == 'probe' ? 43000 : 3000);
	let raw = code == 0 ? store.read(output, 8192) : null;
	erase(output);
	if (!raw || length(raw) > 8192) return null;
	try {
		let result = json(raw);
		if (action == 'owner' && result?.owned == true && cache_key)
			owner_cache = { key: cache_key, stamp: clock_ms(), value: result };
		return result;
	} catch (_) { return null; }
};

export function generation(value) {
	return type(value?.generation_key) == 'string' &&
		match(value.generation_key, /^[a-f0-9]{16}$/) ?
		value.generation_key : null;
};

function kernel_json(command) {
	store.directory('/tmp/foxhole');
	let random = fs.readfile('/dev/urandom', 12);
	if (length(random || '') != 12) return null;
	let path = '/tmp/foxhole/kernel-' + hexenc(random);
	let code = system([ '/bin/sh', '-c', 'umask 077; ' + command +
		' >' + path + ' 2>/dev/null' ], 3000);
	let raw = code == 0 ? store.read(path, 262144) : null;
	erase(path);
	if (!raw || length(raw) > 262144) return null;
	try { return json(raw); } catch (_) { return null; }
};

export function policy_identity(state) {
	let selected = filter(state.servers,
		s => s.id == state.activeServerId)[0];
	return digest.sha256(sprintf('%J', {
		active: state.activeServerId,
		config: selected?.config,
		localRules: state.settings.localRules,
		localScope: state.settings.localScope,
		killSwitch: state.settings.killSwitch,
		devices: state.devices, sites: state.sites,
		countries: state.countries
	}));
};

function normalized(value, depth, budget) {
	if (++budget.count > 65536 || depth > 32) die('unavailable');
	if (type(value) == 'array')
		return map(value, item => normalized(item, depth + 1, budget));
	if (type(value) != 'object') return value;
	let result = {};
	for (let key, item in value) {
		if (key == 'counter') result[key] = {};
		else result[key] = normalized(item, depth + 1, budget);
	}
	return result;
};

export function kernel_policy(key, state_identity) {
	let raw = store.read(state_path, 8192), running = null;
	try { running = raw ? json(raw) : null; } catch (_) {}
	let status = runtime_identity(raw);
	let index = fs.readfile('/sys/class/net/foxhole0/ifindex', 32);
	let process = type(running?.pid) == 'int' ?
		fs.stat('/proc/' + running.pid + '/exe') : null;
	let stamp = clock_ms();
	if (!status || !index || !process ||
	    stamp == null) { kernel_cache = null; return null; }
	let identity = sprintf('%s:%s:%s:%s:%s:%s:%s',
		key, state_identity, status, index,
		process.dev.major, process.dev.minor, process.inode);
	if (kernel_cache?.identity == identity && stamp >= kernel_cache.stamp &&
	    stamp - kernel_cache.stamp <= 1000) return kernel_cache.value;
	kernel_cache = null;
	let route = kernel_json('/usr/libexec/ip-full -j -4 route get ' +
		'1.1.1.1 mark 0x40000000');
	if (type(route) != 'array' || length(route) != 1 ||
	    route[0]?.dev != 'foxhole0' ||
	    (route[0]?.type != null && route[0].type != 'unicast'))
		return null;
	let route6 = kernel_json('/usr/libexec/ip-full -j -6 route get ' +
		'2606:4700:4700::1111 mark 0x40000000');
	let table6 = null, rules6 = null;
	if (!route6 || !length(route6)) {
		table6 = kernel_json('/usr/libexec/ip-full -j -6 route show table 201');
		rules6 = kernel_json('/usr/libexec/ip-full -j -6 rule show');
	}
	if (!core.ipv6_policy(route6, table6, rules6)) return null;
	let chains = [];
	for (let name in [ 'classify', 'mark_vpn', 'selected_rules',
		'scoped_rules', 'guard_egress' ]) {
		let current = kernel_json('/usr/sbin/nft -j list chain inet ' +
			'foxhole ' + name);
		if (type(current?.nftables) != 'array') return null;
		try { push(chains, normalized(current, 0, { count: 0 })); }
		catch (_) { return null; }
	}
	let after = runtime_identity(store.read(state_path, 8192));
	if (after != status ||
	    fs.readfile('/sys/class/net/foxhole0/ifindex', 32) != index)
		return null;
	let value = digest.sha256(sprintf('%J', chains));
	kernel_cache = { identity, value, stamp: clock_ms() };
	return value;
};
