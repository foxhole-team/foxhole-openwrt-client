'use strict';

import * as fs from 'fs';
import * as socket from 'socket';
import * as store from './private-store.uc';
import * as handoff from './handoff.uc';

export function endpoint(value) {
	if (type(value) != 'string' || length(value) > 320)
		die('invalid_config');
	let parts = match(value, /^\[([0-9a-fA-F:.]+)\]:([0-9]+)([-,][0-9,-]+)?$/);
	if (!parts) parts = match(value, /^([A-Za-z0-9.-]+):([0-9]+)([-,][0-9,-]+)?$/);
	if (!parts) die('invalid_config');
	let port = int(parts[2], 10);
	if (port < 1 || port > 65535) die('invalid_config');
	return { host: parts[1], port };
};

export function resolve_public(host) {
	store.directory('/tmp/foxhole');
	let bytes = fs.readfile('/dev/urandom', 12);
	if (length(bytes || '') != 12) die('storage_error');
	let directory = '/tmp/foxhole/resolve-' + hexenc(bytes);
	if (!fs.mkdir(directory, 0o700)) die('storage_error');
	let output = directory + '/output', result = null;
	try {
		store.directory(directory);
		if (system(['/usr/libexec/foxhole-provider-resolve', host, output], 4500) == 0)
			result = handoff.dns_answer(json(store.read(output, 8192)), host);
	} catch (_) {}
	try { fs.unlink(output); fs.rmdir(directory); } catch (_) {}
	return result?.addresses || [];
};

export function check(parsed, resolver) {
	let target = endpoint(parsed.endpoint), addresses = null;
	let udp = index(['hysteria2', 'tuic', 'wireguard'], parsed.protocol || 'hysteria2') >= 0;
	let scope = udp ? 'host' : 'tcp';
	let result = code => ({ scope, code, reachable: code == 'reachable' });
	let literal = iptoarr(target.host);
	if (length(literal || []) == 4 || length(literal || []) == 16) {
		let address = arrtoip(literal);
		if (!handoff.public_address(address)) return result('blocked_address');
		addresses = [address];
	} else {
		try { handoff.hostname(target.host); } catch (_) { return result('blocked_address'); }
		try { addresses = (resolver || resolve_public)(target.host); } catch (_) {}
		if (type(addresses) != 'array' || !length(addresses) || length(addresses) > 8)
			return result('resolve_failed');
		for (let address in addresses)
			if (!handoff.public_address(address)) return result('blocked_address');
	}
	// A connected UDP socket does not prove server reachability.
	for (let i = 0; i < min(length(addresses), 2); i++) {
		let address = addresses[i];
		if (udp) {
			let args = [length(iptoarr(address)) == 16 ? '-6' : '-4',
				'-n', '-c', '1', '-W', '1', address];
			if (system(['/bin/sh', '-c', 'exec /bin/ping "$@" >/dev/null 2>&1',
				'foxhole-server-check', ...args], 1500) == 0) return result('reachable');
		} else {
			let connection = null;
			try {
				connection = socket.connect({ address, port: target.port,
					family: length(iptoarr(address)) == 16 ? socket.AF_INET6 : socket.AF_INET },
					null, null, 1500);
			} catch (_) {}
			if (connection) {
				try { connection.close(); } catch (_) {}
				return result('reachable');
			}
		}
	}
	return result('not_confirmed');
};
