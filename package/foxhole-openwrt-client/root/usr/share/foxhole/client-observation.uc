'use strict';

export function stats_config(index, secret) {
	if (type(index) != 'int' || index < 0 || index > 4 ||
	    type(secret) != 'string' || !match(secret, /^[a-f0-9]{64}$/))
		die('invalid_config');
	return { listen: '127.0.0.1:' + (901 + index), secret };
};

export function online_map(raw, ids) {
	if (type(raw) != 'string' || !length(raw) || length(raw) > 8192 ||
	    type(ids) != 'array' || length(ids) > 32) return null;
	let value;
	try { value = json(raw); } catch (_) { return null; }
	if (type(value) != 'object' || length(keys(value)) > 32) return null;
	for (let id, count in value)
		if (index(ids, id) < 0 || type(count) != 'int' || count < 0 ||
		    count > 0x7fffffff) return null;
	return value;
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
