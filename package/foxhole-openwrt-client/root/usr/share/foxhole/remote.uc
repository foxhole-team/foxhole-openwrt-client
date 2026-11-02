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

export function uplink(statuses) {
	if (type(statuses) != 'array' || length(statuses) > 64) die('network_unavailable');
	let best = null, addresses = [];
	for (let status in statuses) {
		if (status?.up != true) continue;
		if (index(['dhcp','static','pppoe','ppp','3g','qmi','mbim','ncm','wwan','modemmanager'], status.proto) < 0) continue;
		let device = status.l3_device || status.device || '';
		if (type(device) != 'string' || !match(device, /^[A-Za-z0-9_.:-]{1,32}$/) ||
		    match(device, /^(tun|tap|wg|ipsec|gre|sit|tailscale|zerotier)/)) continue;
		let routes = status.route || [];
		if (type(routes) != 'array' || length(routes) > 128) die('network_unavailable');
		let metric = null;
		for (let route in routes) {
			if (route.target != '0.0.0.0' || route.mask != 0 ||
			    route.table != null && index([0,254,'main'], route.table) < 0) continue;
			let value = route.metric ?? status.metric ?? 0;
			if (type(value) != 'int' || value < 0 || value > 0xffffffff) die('network_unavailable');
			if (metric == null || value < metric) metric = value;
		}
		if (metric == null) continue;
		let address = null;
		try { address = wan_address(status); } catch (_) {}
		if (best == null || metric < best) { best = metric; addresses = []; }
		if (metric == best && index(addresses, address) < 0) push(addresses, address);
	}
	// Equal-priority uplinks with different addresses do not establish one direct endpoint.
	if (length(addresses) > 1) return { publicIpv4Available: null, address: null };
	let address = length(addresses) == 1 ? addresses[0] : null;
	return { publicIpv4Available: address != null, address };
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
