'use strict';

export function parse_neighbors(raw) {
	if (type(raw) != 'string' || length(raw) > 262144) return [];
	let records = [];
	for (let line in split(raw, '\n')) {
		let fields = split(trim(line), /[ \t]+/);
		if (length(fields) < 4) continue;
		let bytes = iptoarr(fields[0]);
		if (length(bytes || []) != 4 && length(bytes || []) != 16) continue;
		let state = fields[length(fields) - 1];
		if (index(['REACHABLE', 'FAILED', 'INCOMPLETE', 'STALE', 'DELAY', 'PROBE'], state) < 0) continue;
		let at = index(fields, 'lladdr'), mac = null;
		if (at >= 0) {
			mac = lc(fields[at + 1] || '');
			if (!match(mac, /^[a-f0-9]{2}(:[a-f0-9]{2}){5}$/)) continue;
		}
		push(records, { address: arrtoip(bytes), mac, state });
		if (length(records) > 512) return [];
	}
	return records;
};

export function online(records, address, mac) {
	let bytes = iptoarr(address);
	if (!bytes) return null;
	let canonical = arrtoip(bytes), found = null;
	for (let row in records) {
		if (row.address != canonical || (row.mac && row.mac != lc(mac))) continue;
		if (found != null) return null;
		found = row;
	}
	if (found?.state == 'REACHABLE' && found.mac == lc(mac)) return true;
	if (found?.state == 'FAILED' || found?.state == 'INCOMPLETE') return false;
	return null;
};
