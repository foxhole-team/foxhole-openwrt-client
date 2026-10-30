'use strict';

import * as digest from 'digest';
import * as model from './model.uc';
import * as inbound from './inbound.uc';
import * as pairing from './pairing.uc';

export const port = 8443;

export function lan_listener(status) {
	if (status?.up != true ||
	    !match(status.l3_device || '', /^[a-zA-Z0-9_.:-]{1,32}$/))
		die('lan_unavailable');
	for (let item in status['ipv4-address'] || []) {
		let bytes = type(item.address) == 'string' ?
			iptoarr(item.address) : null;
		if (length(bytes || []) != 4) continue;
		if (bytes[0] == 10 ||
		    (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
		    (bytes[0] == 192 && bytes[1] == 168))
			return { address: arrtoip(bytes), device: status.l3_device,
				port };
	}
	die('lan_unavailable');
};

export function journal(value) {
	value ??= { schema: 1, phones: [] };
	if (value.schema != 1 || type(value.phones) != 'array' ||
	    length(value.phones) > 16) die('storage_error');
	let seen = {};
	for (let phone in value.phones) {
		if (!match(phone?.pairId || '', /^pair-[a-f0-9]{32}$/) ||
		    seen[phone.pairId] ||
		    !match(phone.verifier || '', /^[a-f0-9]{64}$/) ||
		    !match(phone.intent || '', /^[a-f0-9]{64}$/) ||
		    (phone.lanDeviceId != null &&
		     !match(phone.lanDeviceId, /^device-[a-f0-9]{12}$/)) ||
		    type(phone.name) != 'string' ||
		    length(phone.name) < 1 || length(phone.name) > 48 ||
		    model.host_address(phone.address) != phone.address ||
		    model.normalize_mac(phone.mac) != phone.mac)
			die('storage_error');
		seen[phone.pairId] = true;
		if (phone.remoteRevoked != null && type(phone.remoteRevoked) != 'bool')
			die('storage_error');
		if (phone.lanDeviceId != null) {
			if (seen[phone.lanDeviceId]) die('storage_error');
			seen[phone.lanDeviceId] = true;
		}
		if (phone.remoteClientId != null &&
		    (!match(phone.remoteClientId, /^client-[a-f0-9]{12}$/) ||
		     !match(phone.remoteSecret || '', /^[a-f0-9]{64}$/) ||
		     type(phone.remotePort) != 'int' ||
		     phone.remotePort < 1 || phone.remotePort > 65535))
			die('storage_error');
		if (phone.remoteClientId != null) {
			if (seen[phone.remoteClientId]) die('storage_error');
			seen[phone.remoteClientId] = true;
		}
	}
	return json(sprintf('%J', value));
};

export function prune(stored, current_pairs) {
	let record = journal(stored);
	record.phones = filter(record.phones, phone =>
		pairing.session_current(current_pairs,
			{ id: phone.pairId, verifier: phone.verifier }));
	return record;
};

export function prepare(state, stored, paired, args, base, random_hex) {
	let record = journal(stored);
	if (!match(paired?.id || '', /^pair-[a-f0-9]{32}$/) ||
	    !match(paired.verifier || '', /^[a-f0-9]{64}$/))
		die('unauthorized');
	let name = model.client_name(args.name);
	let address = model.normalize_address(args.address);
	if (model.host_address(address) != address ||
	    length(iptoarr(address) || []) != 4)
		die('invalid_address');
	let mac = model.normalize_mac(args.mac);
	let register = args.registerPhone ?? true;
	if (type(args.createRemote) != 'bool' || type(register) != 'bool')
		die('invalid_settings');
	let intent = digest.sha256(sprintf('%J', {
		name, mac, registerPhone: register, createRemote: args.createRemote
	}));
	for (let phone in record.phones) {
		if (phone.pairId != paired.id) continue;
		if (phone.verifier != paired.verifier || phone.intent != intent)
			die('pairing_conflict');
		if (args.createRemote && phone.remoteRevoked == true) die('client_revoked');
		return { record, phone };
	}
	if (length(record.phones) >= 16) die('pairing_limit');
	let phone = {
		pairId: paired.id, verifier: paired.verifier, intent,
		name, address, mac,
		lanDeviceId: register ? 'device-' + random_hex(6) : null,
		remoteClientId: null, remoteSecret: null, remotePort: null
	};
	if (args.createRemote) {
		if (!base) die('inbound_required');
		let used = map(filter(state.clients, c => c.inbound), c => c.port);
		if (length(used) >= inbound.limit(base)) die('client_limit');
		phone.remotePort = inbound.shared(base) ? 443 :
			(base.firstPort || 14443);
		if (!inbound.shared(base))
			while (index(used, phone.remotePort) >= 0) phone.remotePort++;
		if (phone.remotePort > 65535) die('client_limit');
		phone.remoteClientId = 'client-' + random_hex(6);
		phone.remoteSecret = random_hex(32);
	}
	push(record.phones, phone);
	return { record: journal(record), phone };
};

export function apply(state, phone) {
	state = model.validate_state(json(sprintf('%J', state)));
	let found = false, changed = false;
	for (let device in state.devices) {
		if (device.id != phone.lanDeviceId) continue;
		if (device.mac != phone.mac || device.address != phone.address ||
		    device.route != 'vpn' || device.bindMac != true)
			die('pairing_conflict');
		found = true;
	}
	if (phone.lanDeviceId != null && !found) {
		push(state.devices, { id: phone.lanDeviceId,
			name: phone.name, address: phone.address, mac: phone.mac,
			bindMac: true, route: 'vpn' });
		changed = true;
	}
	if (phone.remoteClientId != null) {
		found = false;
		for (let client in state.clients) {
			if (client.id != phone.remoteClientId) continue;
			if (client.inbound != true || client.secret != phone.remoteSecret ||
			    client.port != phone.remotePort) die('pairing_conflict');
			found = true;
		}
		if (!found) {
			push(state.clients, { id: phone.remoteClientId,
				name: phone.name, deviceType: 'smartphone',
				serverId: null, provisioned: true, inbound: true,
				port: phone.remotePort, secret: phone.remoteSecret,
				allowLan: false });
			changed = true;
		}
	}
	if (changed) state.revision++;
	return { state: model.validate_state(state), changed };
};
