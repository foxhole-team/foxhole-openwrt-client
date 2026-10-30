'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as store from './private-store.uc';
import * as handoff from './handoff.uc';
import * as core from './core-adapter.uc';
import * as pairing from './pairing.uc';

const receipt_path = '/tmp/foxhole/handoff-policy.json';
let cached = null;

export function boot_id() {
	let value = trim(fs.readfile('/proc/sys/kernel/random/boot_id', 128) || '');
	if (!match(value, /^[a-f0-9-]{36}$/)) die('unavailable');
	return value;
};

function query_command(tables) {
	store.directory('/tmp/foxhole');
	let entropy = fs.readfile('/dev/urandom', 12);
	if (length(entropy || '') != 12) die('storage_error');
	let output = '/tmp/foxhole/handoff-query-' + hexenc(entropy);
	let raw = null;
	try {
		let code = system(['/bin/sh', '-c', 'umask 077; /usr/sbin/nft -j list ' + (tables ? 'tables ' : 'table ') +
			(tables ? '' : 'inet foxhole_handoff ') + '>' + output + ' 2>/dev/null'], 1000);
		if (code == 0) raw = store.read(output, 262144);
	} catch (_) {}
	try { fs.unlink(output); } catch (_) {}
	if (!raw) return null;
	try { return json(raw); } catch (_) { return null; }
};

function query() {
	let current = query_command(false);
	if (current != null) return current;
	let tables = query_command(true);
	if (type(tables?.nftables) != 'array') return null;
	for (let item in tables.nftables)
		if (item.table?.family == 'inet' && item.table.name == 'foxhole_handoff')
			return null;
	return { nftables: [], absent: true };
};

export function residual(actual, mac) {
	for (let item in actual?.nftables || [])
		for (let element in item.set?.elem || []) {
			let value = element.elem;
			if (value?.val?.concat?.[0] == mac &&
			    (type(value.expires) != 'int' || value.expires > 0)) return true;
		}
	return false;
};

function normalized(value, depth) {
	if (depth > 32) die('unavailable');
	if (type(value) == 'array') return map(value, item => normalized(item, depth + 1));
	if (type(value) != 'object') return value;
	let result = {};
	for (let key, item in value) {
		if (index(['handle', 'elem', 'counter', 'metainfo'], key) >= 0) continue;
		result[key] = normalized(item, depth + 1);
	}
	return result;
};

export function structural_identity(value) {
	if (type(value?.nftables) != 'array' || length(value.nftables) > 16)
		die('unavailable');
	return digest.sha256(sprintf('%J', filter(map(value.nftables,
		item => normalized(item, 0)), item => length(keys(item)) > 0)));
};

export function journal_matches(actual, receipt, record, boot) {
	if (actual?.absent == true) return true;
	return actual != null && receipt?.bootId == boot &&
		receipt.revision == record.revision &&
		structural_identity(actual) == receipt.identity;
};

function pairing_current(pairs, lease) {
	return pairing.session_current(pairs, { id: lease.pairId, verifier: lease.verifier });
};

export function elements_match(actual, record, pairs, boot) {
	let allowed = {}, seen = {}, count = 0;
	for (let lease in handoff.journal(record).leases) {
		if (lease.bootId != boot || !pairing_current(pairs, lease)) continue;
		for (let target in lease.targets)
			allowed[sprintf('%J', [lease.mac, target.address, target.transport, target.port])] = true;
	}
	for (let item in actual?.nftables || []) {
		let set = item.set;
		if (!set) continue;
		if (set.family != 'inet' || set.table != 'foxhole_handoff' ||
		    index(['upstream4', 'upstream6'], set.name) < 0) return false;
		for (let element in set.elem || []) {
			if (++count > 128) return false;
			let value = element.elem, tuple = value?.val?.concat;
			if (type(tuple) != 'array' || length(tuple) != 4 ||
			    type(value.timeout) != 'int' || value.timeout < 1 || value.timeout > 60000 ||
			    type(value.expires) != 'int' || value.expires < 0 || value.expires > 60000)
				return false;
			let key = sprintf('%J', tuple);
			if (!allowed[key] || seen[key]) return false;
			seen[key] = true;
		}
	}
	return true;
};

export function remaining(value, lease) {
	let remaining = 60000;
	for (let target in lease.targets) {
		let family = length(iptoarr(target.address)) == 4 ? '4' : '6';
		let expected = [lease.mac, target.address, target.transport, target.port];
		let found = false;
		for (let item in value?.nftables || []) {
			let set = item.set;
			if (set?.family != 'inet' || set.table != 'foxhole_handoff' ||
			    set.name != 'upstream' + family) continue;
			for (let element in set.elem || []) {
				let val = element.elem;
				if (sprintf('%J', val?.val?.concat) != sprintf('%J', expected)) continue;
				if (type(val.expires) != 'int' || val.expires <= 0 ||
				    val.expires > 60000 || type(val.timeout) != 'int' ||
				    val.timeout > 60000) die('unavailable');
				remaining = min(remaining, val.expires);
				found = true;
			}
		}
		if (!found) return 0;
	}
	return remaining;
};

export function apply(record, pairs, device) {
	let before = query(), raw = store.read(receipt_path, 4096), previous = null;
	try { previous = raw ? json(raw) : null; } catch (_) {}
	if (!before) die('unavailable');
	let old = store.read(handoff.path, 65536);
	let old_record = handoff.journal(old ? json(old) : null);
	if (!before.absent && !elements_match(before, old_record, pairs, boot_id())) die('unavailable');
	if (!before.absent && (!previous || previous.bootId != boot_id() ||
	    structural_identity(before) != previous.identity)) die('unavailable');
	let now = core.clock_ms();
	let input = '/tmp/foxhole/handoff.nft';
	store.write(input, handoff.nft(record, pairs, now, device, boot_id()));
	if (system(['/usr/sbin/nft', '-f', input], 1000) != 0) die('unavailable');
	let after = query();
	if (!after || after.absent || !elements_match(after, record, pairs, boot_id())) die('unavailable');
	let receipt = { schema: 1, bootId: boot_id(), revision: record.revision,
		identity: structural_identity(after) };
	store.write(receipt_path, sprintf('%J', receipt));
	cached = null;
	return receipt;
};

export function observe(record, pairs, paired) {
	let now = core.clock_ms(), boot = boot_id(), lease = null;
	for (let item in handoff.active(record, pairs, now, boot))
		if (item.pairId == paired.id && item.verifier == paired.verifier) lease = item;
	let raw = store.read(receipt_path, 4096), receipt = null;
	try { receipt = raw ? json(raw) : null; } catch (_) {}
	let actual = cached?.revision == record.revision && now >= cached.stamp &&
		now - cached.stamp <= 250 ? cached.value : query();
	if (!journal_matches(actual, receipt, record, boot) ||
	    !elements_match(actual, record, pairs, boot)) die('unavailable');
	if (actual.absent) return null;
	if (!lease) {
		for (let prior in record.leases)
			if (prior.pairId == paired.id && residual(actual, prior.mac)) die('unavailable');
		return null;
	}
	let left = min(remaining(actual, lease), lease.expiresUptimeMs - now);
	if (left <= 0) {
		if (residual(actual, lease.mac)) die('unavailable');
		return null;
	}
	cached = { revision: record.revision, stamp: now, value: actual };
	return { claimId: lease.claimId, mode: 'phone_vpn', phase: 'active',
		remainingMs: left, policyRevision: record.revision };
};
