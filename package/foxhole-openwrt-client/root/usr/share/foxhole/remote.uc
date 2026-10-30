'use strict';

import * as fs from 'fs';
import * as store from './private-store.uc';
import * as handoff from './handoff.uc';

export function wan_address(status) {
	if (status?.up == true)
		for (let item in status['ipv4-address'] || [])
			if (handoff.public_address(item.address) && length(iptoarr(item.address)) == 4)
				return item.address;
	die('public_address_required');
};

export function template(address, pin) {
	if (!handoff.public_address(address) || length(iptoarr(address) || []) != 4 ||
	    !match(pin || '', /^[a-f0-9]{64}$/)) die('invalid_config');
	return { schema: 1, listenerMode: 'per-client', firstPort: 14443,
		endpointHost: address, allowedLan: [],
		template: { tls: { cert: '/etc/foxhole/remote-identity/cert.pem',
			key: '/etc/foxhole/remote-identity/key.pem' } },
		public: { tls: { insecure: false, pinSHA256: pin } } };
};

export function prepare(address) {
	let raw = store.read('/etc/foxhole/inbound.json', 65536);
	if (raw) return json(raw);
	if (!fs.stat('/usr/bin/hysteria')) die('inbound_required');
	wan_address({ up: true, 'ipv4-address': [{ address }] });
	store.directory('/etc/foxhole'); store.directory('/tmp/foxhole');
	let bytes = fs.readfile('/dev/urandom', 12);
	if (length(bytes || '') != 12) die('storage_error');
	let output = '/tmp/foxhole/remote-identity-' + hexenc(bytes), identity = null;
	try {
		let status = system(['/bin/sh', '-c', 'umask 077; ' +
			'/usr/libexec/foxhole-remote-identity >' + output + ' 2>/dev/null'], 5000);
		if (status == 0) identity = json(store.read(output, 512));
	} catch (_) {}
	try { fs.unlink(output); } catch (_) {}
	if (identity?.schema != 1) die('unavailable');
	let base = template(address, identity.certificateSha256);
	store.write('/etc/foxhole/inbound.json', sprintf('%J', base));
	return base;
};
