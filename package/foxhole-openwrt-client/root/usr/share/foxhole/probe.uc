'use strict';

import * as fs from 'fs';

export const interval = 15;
export const sample_ttl = 45;
export const country_ttl = 21600;
export const country_retry = 300;
export const cache_path = '/tmp/foxhole/probe.json';
export const runtime_path = '/tmp/foxhole/runtime.json';

export function read_json(path, limit) {
	if (limit == null) limit = 8192;
	try {
		let raw = fs.readfile(path, limit + 1);
		return raw && length(raw) <= limit ? json(raw) : null;
	} catch (_) { return null; }
};

export function runtime_snapshot() {
	let before = fs.stat(runtime_path);
	let value = read_json(runtime_path);
	let after = fs.stat(runtime_path);
	if (!before || !after || !value || before.inode != after.inode)
		return null;
	return {
		value,
		generation: sprintf('%s:%s:%s:%s', after.dev, after.inode,
			after.mtime, value.since)
	};
};

export function fresh(stamp, now, ttl) {
	return type(stamp) == 'int' && stamp > 0 &&
		stamp <= now && now - stamp <= ttl;
};

function latency(value) {
	return (type(value) == 'int' || type(value) == 'double') &&
		value >= 0 && value <= 60000 ? value : null;
};

function country(value) {
	return type(value) == 'string' && match(value, /^[A-Z]{2}$/)
		? value : null;
};

export function vpn_sample(cache, runtime, now) {
	let sample = cache?.vpn;
	let current = runtime?.value;
	if (cache?.schema != 1 || !current?.connected ||
	    !current.activeServerId ||
	    current.desiredServerId != current.activeServerId ||
	    sample?.serverId != current.activeServerId ||
	    sample.generation != runtime.generation ||
	    !fresh(sample.sampledAt, now, sample_ttl)) return null;
	let bytes = type(sample.address) == 'string'
		? iptoarr(sample.address) : null;
	if (length(bytes || []) != 4 && length(bytes || []) != 16)
		return null;
	let code = country(sample.country), delay = latency(sample.latency);
	if (!code || delay == null) return null;
	return { address: arrtoip(bytes), country: code, latency: delay };
};

export function wan_sample(cache, iface, gateway, now) {
	let sample = cache?.wan;
	if (cache?.schema != 1 || sample?.device != iface ||
	    sample.gateway != gateway)
		return { latency: null, country: null };
	return {
		latency: fresh(sample.sampledAt, now, sample_ttl)
			? latency(sample.latency) : null,
		country: fresh(sample.countryAt, now, country_ttl)
			? country(sample.country) : null
	};
};
