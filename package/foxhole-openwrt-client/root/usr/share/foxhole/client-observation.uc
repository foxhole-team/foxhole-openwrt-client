'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as store from './private-store.uc';

// The generator admits up to 200000 normalized IP prefixes plus
// a 64 KiB template.
const MAX_CONFIG_BYTES = 16 * 1024 * 1024;

function file_identity(info) {
	if (!store.file_metadata(info) || info.size < 1 || info.size > MAX_CONFIG_BYTES) return null;
	return sprintf('%J', [info.dev, info.inode, info.uid, info.gid, info.mode, info.nlink, info.size, info.mtime, info.ctime]);
};

export function config_hash(id) {
	if (id != 'shared' && !match(id || '', /^client-[a-f0-9]{12}$/)) return null;
	let path = '/tmp/foxhole/inbound/' + id + '.json';
	store.target(path);
	let before = file_identity(fs.lstat(path));
	if (!before) return null;
	let handle = fs.open(path, 're');
	if (!handle) return null;
	let hash = null;
	try {
		let fd = '/proc/self/fd/' + handle.fileno();
		if (file_identity(fs.stat(fd)) == before) {
			hash = digest.sha256_file(fd);
			if (file_identity(fs.stat(fd)) != before || file_identity(fs.lstat(path)) != before) hash = null;
		}
	} catch (_) {}
	handle.close();
	return hash;
};

export function witness(id, hash, stats, users) {
	if (type(hash) != 'string' || !match(hash, /^[a-f0-9]{64}$/)) return null;
	let credentials = map(sort(keys(users)), user => [user, users[user]]);
	return digest.sha256(sprintf('%J', [id, hash, stats.listen, stats.secret, credentials]));
};

export function stats_config(index, secret) {
	if (type(index) != 'int' || index < 0 || index > 4 ||
	    type(secret) != 'string' || !match(secret, /^[a-f0-9]{64}$/))
		die('invalid_config');
	return { listen: '127.0.0.1:' + (901 + index), secret };
};

export function online_map(raw, ids, legacy) {
	if (type(raw) != 'string' || !length(raw) || length(raw) > 8192 ||
	    type(ids) != 'array' || length(ids) > 32) return null;
	let value;
	try { value = json(raw); } catch (_) { return null; }
	if (type(value) != 'object' || length(keys(value)) > length(ids) + length(keys(legacy || {}))) return null;
	let result = {};
	for (let id, count in value) {
		if (type(count) != 'int' || count < 0 || count > 0x7fffffff) return null;
		if (index(ids, id) >= 0) result[id] = count;
		else if (!exists(legacy || {}, id)) return null;
	}
	return result;
};

export function online(value, id) {
	if (type(value) != 'object') return null;
	return (value[id] || 0) > 0;
};

export function http_body(raw) {
	if (type(raw) != 'string' || length(raw) > 10240) return null;
	let end = index(raw, '\r\n\r\n');
	if (end < 0 || end > 2048) return null;
	let lines = split(substr(raw, 0, end), '\r\n');
	if (!match(lines[0] || '', /^HTTP\/1\.[01] 200( |$)/)) return null;
	let size = null, mime = false, seen = {};
	for (let i = 1; i < length(lines); i++) {
		let header = match(lines[i], /^([a-zA-Z0-9-]+):[ \t]*(.*)$/);
		if (!header) return null;
		let key = lc(header[1]), value = trim(header[2]);
		if (seen[key]) return null;
		seen[key] = true;
		if (key == 'transfer-encoding') return null;
		if (key == 'content-length') {
			if (!match(value, /^[0-9]{1,4}$/)) return null;
			size = int(value, 10);
			if (size > 8192) return null;
		}
		if (key == 'content-type') {
			if (!match(value, /^application\/json([ \t]*;.*)?$/i)) return null;
			mime = true;
		}
	}
	let body = substr(raw, end + 4);
	if (!mime || length(body) > 8192 || (size != null && size != length(body))) return null;
	return body;
};
