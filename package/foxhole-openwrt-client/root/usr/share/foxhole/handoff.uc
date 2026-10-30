'use strict';

import * as model from './model.uc';
import * as pairing from './pairing.uc';

export const path = '/tmp/foxhole/phone-handoff.json';
export const mark = '0x08000000';
const MAX_LEASE = 60000;

function reject() { die('invalid_handoff'); };

export function public_address(address) {
	if (type(address) != 'string' || model.host_address(address) != address)
		return false;
	let value = iptoarr(address);
	if (length(value || []) == 4) {
		let a = value[0], b = value[1], c = value[2];
		return a > 0 && a < 224 && a != 10 && a != 127 &&
			!(a == 100 && b >= 64 && b <= 127) &&
			!(a == 169 && b == 254) && !(a == 172 && b >= 16 && b <= 31) &&
			!(a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2)))) &&
			!(a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100))) &&
			!(a == 203 && b == 0 && c == 113);
	}
	return length(value || []) == 16 && value[0] >= 0x20 && value[0] <= 0x3f &&
		!(value[0] == 0x20 && value[1] == 1 &&
		  ((value[2] == 0 && value[3] <= 0x2f) ||
		   (value[2] == 0x0d && value[3] == 0xb8))) &&
		!(value[0] == 0x20 && value[1] == 2);
};

export function hostname(value) {
	if (type(value) != 'string' || length(value) < 3 || length(value) > 253 ||
	    !match(value, /^[A-Za-z0-9.-]+$/) || index(value, '.') < 0) reject();
	value = lc(value);
	for (let label in split(value, '.'))
		if (!match(label, /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/)) reject();
	if (match(value, /\.(local|localhost|lan|onion|invalid)$/)) reject();
	return value;
};

function dns_name(value) {
	if (type(value) != 'string') reject();
	if (substr(value, -1) == '.') value = substr(value, 0, length(value)-1);
	return hostname(value);
};

export function dns_answer(value, host) {
	host = hostname(host);
	if (value?.Status != 0 || type(value.Status) != 'int' || value.TC == true ||
	    type(value.Question) != 'array' || length(value.Question) != 1 ||
	    type(value.Question[0].type) != 'int' || value.Question[0].type != 1 ||
	    dns_name(value.Question[0].name) != host ||
	    type(value.Answer) != 'array' || length(value.Answer) > 32) reject();
	let related = {}, ttl = 60; related[host] = true;
	for (let step = 0; step < 8; step++)
		for (let answer in value.Answer)
			if (answer.type == 5 && related[dns_name(answer.name)]) {
				if (type(answer.type) != 'int' || type(answer.TTL) != 'int' ||
				    answer.TTL < 0 || answer.TTL > 86400) reject();
				ttl = min(ttl, answer.TTL);
				related[dns_name(answer.data)] = true;
			}
	let addresses = [];
	for (let answer in value.Answer) {
		if (answer.type != 1 || !related[dns_name(answer.name)]) continue;
		if (type(answer.type) != 'int' || !public_address(answer.data) || length(iptoarr(answer.data)) != 4 ||
		    type(answer.TTL) != 'int' || answer.TTL < 0 || answer.TTL > 86400) reject();
		let address = arrtoip(iptoarr(answer.data));
		if (index(addresses, address) < 0) push(addresses, address);
		ttl = min(ttl, answer.TTL);
	}
	if (!length(addresses) || length(addresses) > 8) reject();
	return { addresses: sort(addresses), ttlMs: ttl * 1000 };
};

export function targets(value) {
	if (type(value) != 'array' || !length(value) || length(value) > 8) reject();
	let found = {}, result = [];
	for (let item in value) {
		if (type(item) != 'object' || length(keys(item)) != 3 ||
		    !public_address(item.address) || type(item.port) != 'int' ||
		    item.port < 1 || item.port > 65535 ||
		    index(['tcp', 'udp'], item.transport) < 0) reject();
		let address = arrtoip(iptoarr(item.address));
		let key = address + ':' + item.port + ':' + item.transport;
		if (found[key]) reject();
		found[key] = true;
		push(result, { address, port: item.port, transport: item.transport });
	}
	return sort(result, (a, b) => {
		let first = sprintf('%J', a), second = sprintf('%J', b);
		return first < second ? -1 : first > second ? 1 : 0;
	});
};

export function journal(value) {
	value ??= { schema: 1, revision: 0, leases: [], retired: [] };
	value.retired ??= [];
	if (type(value.schema) != 'int' || value.schema != 1 || type(value.revision) != 'int' ||
	    value.revision < 0 || value.revision >= 2147483647 ||
	    type(value.leases) != 'array' || length(value.leases) > 16 ||
	    type(value.retired) != 'array' || length(value.retired) > 96) reject();
	for (let entry in value.retired)
		if (!match(entry?.pairId || '', /^pair-[a-f0-9]{32}$/) ||
		    !match(entry.verifier || '', /^[a-f0-9]{64}$/) ||
		    !match(entry.claimId || '', /^[a-f0-9]{32}$/) ||
		    !match(entry.bootId || '', /^[a-f0-9-]{36}$/) ||
		    type(entry.expiresUptimeMs) != 'int' || entry.expiresUptimeMs < 0) reject();
	let pairs = {};
	for (let lease in value.leases) {
		if (!match(lease?.pairId || '', /^pair-[a-f0-9]{32}$/) || pairs[lease.pairId] ||
		    !match(lease.verifier || '', /^[a-f0-9]{64}$/) ||
		    !match(lease.claimId || '', /^[a-f0-9]{32}$/) ||
		    !match(lease.bootId || '', /^[a-f0-9-]{36}$/) ||
		    model.normalize_mac(lease.mac) != lease.mac ||
		    model.host_address(lease.address) != lease.address ||
		    type(lease.expiresUptimeMs) != 'int' || lease.expiresUptimeMs < 0 ||
		    type(lease.updatedUptimeMs) != 'int' || lease.updatedUptimeMs < 0 ||
		    lease.expiresUptimeMs - lease.updatedUptimeMs > MAX_LEASE ||
		    lease.expiresUptimeMs < lease.updatedUptimeMs) reject();
		if (type(lease.previousClaims) != 'array' || length(lease.previousClaims) > 32)
			reject();
		let claims = {};
		for (let claim in lease.previousClaims) {
			if (!match(claim || '', /^[a-f0-9]{32}$/) || claims[claim] ||
			    claim == lease.claimId) reject();
			claims[claim] = true;
		}
		targets(lease.targets);
		pairs[lease.pairId] = true;
	}
	return json(sprintf('%J', value));
};

export function active(value, pairs, now, boot) {
	if (type(now) != 'int' || now < 0) reject();
	return filter(journal(value).leases, lease =>
		lease.bootId == boot &&
		lease.updatedUptimeMs <= now && lease.expiresUptimeMs > now &&
		pairing.session_current(pairs, { id: lease.pairId, verifier: lease.verifier }));
};

export function request(value, current_pairs, paired, phone, args, now, boot) {
	if (!match(boot || '', /^[a-f0-9-]{36}$/)) reject();
	if (type(args.requestUptimeMs) != 'int' || args.requestUptimeMs < 0 ||
	    args.requestUptimeMs > now + 1000 || now - args.requestUptimeMs > 5000)
		reject();
	let record = journal(value), live = active(record, current_pairs, now, boot);
	let retired = filter(record.retired, entry => entry.bootId == boot &&
		entry.expiresUptimeMs > now && pairing.session_current(current_pairs,
			{ id: entry.pairId, verifier: entry.verifier }));
	if (!pairing.session_current(current_pairs, paired) || phone?.pairId != paired.id ||
	    phone.verifier != paired.verifier || phone.lanDeviceId == null ||
	    phone.address != args.address || !match(args.claimId || '', /^[a-f0-9]{32}$/) ||
	    index(['phone_vpn', 'router_vpn'], args.mode) < 0) reject();
	let found = null;
	for (let lease in live) if (lease.pairId == paired.id) found = lease;
	for (let entry in retired)
		if (entry.pairId == paired.id && entry.claimId == args.claimId &&
		    args.mode == 'phone_vpn') die('handoff_conflict');
	if (found && index(found.previousClaims, args.claimId) >= 0)
		die('handoff_conflict');
	if (args.mode == 'router_vpn') {
		if (found && found.claimId != args.claimId) die('handoff_conflict');
		if (!match(args.expectedGeneration || '', /^[a-f0-9]{16}$/) ||
		    !match(args.expectedServerId || '', /^server-[a-f0-9]{12}$/)) reject();
		if (found) for (let claim in [...found.previousClaims, found.claimId]) {
			if (length(retired) >= 96) die('handoff_conflict');
			push(retired, { pairId: paired.id, verifier: paired.verifier,
				claimId: claim, bootId: boot, expiresUptimeMs: now + MAX_LEASE });
		}
		live = filter(live, lease => lease.pairId != paired.id);
	} else {
		if (type(args.leaseMs) != 'int' || args.leaseMs < 1000 || args.leaseMs > MAX_LEASE) reject();
		let selected = targets(args.upstreamTargets);
		if (found?.claimId == args.claimId &&
		    sprintf('%J', selected) != sprintf('%J', found.targets))
			die('handoff_conflict');
		let previousClaims = found?.previousClaims || [];
		if (found && found.claimId != args.claimId) {
			if (length(previousClaims) >= 32) die('handoff_conflict');
			push(previousClaims, found.claimId);
		}
		let lease = { pairId: paired.id, verifier: paired.verifier, claimId: args.claimId,
			mac: phone.mac, address: phone.address, targets: selected, bootId: boot,
			previousClaims,
			updatedUptimeMs: now, expiresUptimeMs: now + args.leaseMs };
		live = filter(live, item => item.pairId != paired.id);
		push(live, lease);
	}
	return journal({ schema: 1, revision: record.revision + 1, leases: live, retired });
};

export function nft(value, pairs, now, device, boot) {
	if (!match(device || '', /^[A-Za-z0-9_.:-]{1,32}$/)) reject();
	let leases = active(value, pairs, now, boot), values = { '4': [], '6': [] };
	for (let lease in leases) for (let target in lease.targets) {
		let family = length(iptoarr(target.address)) == 4 ? '4' : '6';
		push(values[family], lease.mac + ' . ' + target.address + ' . ' +
			target.transport + ' . ' + target.port + ' timeout ' +
			(lease.expiresUptimeMs - now) + 'ms');
	}
	let lines = ['add table inet foxhole_handoff', 'delete table inet foxhole_handoff',
		'table inet foxhole_handoff {'];
	for (let family in ['4', '6']) {
		push(lines, ' set upstream' + family + ' { type ether_addr . ipv' + family +
			'_addr . inet_proto . inet_service; flags timeout; timeout 60s;');
		if (length(values[family])) push(lines, ' elements = { ' + join(', ', values[family]) + ' };');
		push(lines, ' }');
	}
	push(lines, ' chain ingress { type filter hook prerouting priority mangle - 6; policy accept;');
	push(lines, ' meta mark set meta mark & 0xf7ffffff');
	for (let family in ['4', '6'])
		push(lines, ' iifname "' + device + '" ether saddr . ip' +
			(family == '6' ? '6' : '') + ' daddr . meta l4proto . th dport @upstream' +
			family + ' meta mark set meta mark | ' + mark + ' counter accept');
	push(lines, ' }', '}');
	return join('\n', lines) + '\n';
};
