'use strict';

import * as digest from 'digest';

const MAX_DEVICES = 10;
const LEGACY_MAX_DEVICES = 16;

export function bootstrap_valid(auth, uptime, boot) {
	return auth?.bootstrapConsumed == false &&
		type(auth.bootstrapExpiresUptimeMs) == 'int' &&
		match(uptime || '', /^[0-9]+\.[0-9]+ /) != null &&
		boot == auth.bootstrapBootId &&
		int(+split(uptime, ' ')[0] * 1000) <= auth.bootstrapExpiresUptimeMs;
};

function valid_id(id) {
	return type(id) == 'string' &&
		match(id, /^pair-[a-f0-9]{32}$/) != null;
};

function valid_name(name) {
	return type(name) == 'string' && length(name) > 0 &&
		length(name) <= 128 && !match(name, /[[:cntrl:]]/);
};

function client_metadata(client, version) {
 let result = {};
 if (client == 'guard' || client == 'vpn') result.client = client;
 if (result.client && type(version) == 'string' && length(version) <= 64 &&
     match(version, /^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?(\+[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$/))
  result.clientVersion = version;
 return result;
};

function verifier(credential) {
	if (type(credential) != 'string' ||
	    !match(credential, /^[a-f0-9]{64}$/)) die('invalid_pairing');
	let hash = digest.sha256(credential);
	if (!hash) die('storage_error');
	return hash;
};

function equal_secret(left, right) {
	if (type(left) != 'string' || type(right) != 'string' ||
	    length(left) != length(right)) return false;
	let diff = 0;
	for (let i = 0; i < length(left); i++)
		diff |= ord(substr(left, i, 1)) ^ ord(substr(right, i, 1));
	return diff == 0;
};

function checked(record) {
	if (type(record) != 'object' || record.schema != 1 ||
	    type(record.devices) != 'array' ||
	    length(record.devices) > LEGACY_MAX_DEVICES) die('storage_error');
	for (let key in keys(record))
		if (index(['schema', 'devices'], key) < 0)
			die('storage_error');
	let seen = {};
	for (let device in record.devices) {
		if (type(device) != 'object' || !valid_id(device.id) ||
		    !valid_name(device.name) || type(device.hash) != 'string' ||
		    !match(device.hash, /^[a-f0-9]{64}$/) ||
		    type(device.created) != 'int' || device.created < 0 ||
		    seen[device.id]) die('storage_error');
		for (let key in keys(device))
			if (index(['id', 'hash', 'name', 'created', 'client', 'clientVersion'], key) < 0)
				die('storage_error');
		seen[device.id] = true;
	}
	let result = json(sprintf('%J', record));
	for (let device in result.devices) {
		let metadata = client_metadata(device.client, device.clientVersion);
		delete device.client; delete device.clientVersion;
		for (let key, value in metadata) device[key] = value;
	}
	return result;
};

export function defaults() { return { schema: 1, devices: [] }; };
export function requires_tls(action, token) {
	return (type(action) == 'string' && match(action, /^(pair|phone)\./)) ||
		(type(token) == 'string' && match(token, /^p1\./)) ? true : false;
};
export function update_metadata(record, id, client, clientVersion) {
 let result = checked(record), metadata = client_metadata(client, clientVersion);
 for (let device in result.devices) {
  if (device.id != id) continue;
  for (let key, value in metadata) device[key] = value;
 }
 return result;
};
export function register(record, id, credential, name, created, client, clientVersion) {
	let result = checked(record), hash = verifier(credential);
	if (!valid_id(id) || !valid_name(name) ||
	    type(created) != 'int' || created < 0) die('invalid_pairing');
	for (let device in result.devices) {
		if (device.id != id) continue;
		if (!equal_secret(device.hash, hash)) die('pairing_conflict');
		return update_metadata(result, id, client, clientVersion);
	}
	if (length(result.devices) >= MAX_DEVICES) die('pairing_limit');
	push(result.devices, { id, hash, name, created, ...client_metadata(client, clientVersion) });
	return result;
};
export function authenticate(record, id, credential) {
	let result = checked(record);
	if (!valid_id(id)) die('unauthorized');
	let hash;
	try { hash = verifier(credential); }
	catch (_) { die('unauthorized'); }
	for (let device in result.devices)
		if (device.id == id && equal_secret(device.hash, hash))
			return { id, verifier: hash };
	die('unauthorized');
};
export function session_current(record, session) {
	let result = checked(record);
	if (type(session) != 'object') return false;
	for (let device in result.devices)
		if (device.id == session.id &&
		    equal_secret(device.hash, session.verifier)) return true;
	return false;
};
export function revoke(record, id) {
	let result = checked(record);
	if (!valid_id(id)) die('invalid_pairing');
	for (let i = 0; i < length(result.devices); i++)
		if (result.devices[i].id == id) {
			splice(result.devices, i, 1);
			break;
		}
	return result;
};
export function public_devices(record) {
	let result = [];
	for (let device in checked(record).devices)
		push(result, { id: device.id, name: device.name,
			created: device.created, ...client_metadata(device.client, device.clientVersion) });
	return result;
};
