import * as fs from 'fs';

export const path = '/tmp/foxhole/history.json';
export const archive = '/etc/foxhole/history.json.gz';
const MAX = 6000000;
const MONTH = 2592000000;

export function cpu_percent(previous, current) {
	if (!previous || current.total <= previous.total ||
	    current.idle < previous.idle) return null;
	let busy = 100.0 * (1.0 - (current.idle - previous.idle) * 1.0 /
		(current.total - previous.total));
	return +sprintf('%.1f', min(100.0, max(0.0, busy)));
};

export function compact(points, now) {
	let coarse = {}, recent = [], output = [];
	for (let point in points || []) {
		if (type(point?.t) != 'int' || point.t < now - MONTH ||
		    point.t > now + 60000) continue;
		if (point.measurementVersion != 2) point.cpu = null;
		if (point.t >= now - 900000) push(recent, point);
		else coarse['' + int(point.t / 300000)] = point;
	}
	for (let key, value in coarse) push(output, value);
	output = sort([...output, ...recent], (a, b) => a.t - b.t);
	return slice(output, max(0, length(output) - 9000));
};

export function read() {
	let raw = fs.readfile(path, MAX + 1), source = null;
	if (!raw && fs.stat(archive)) {
		try {
			source = fs.popen('gzip -dc ' + archive, 'r');
			raw = source?.read(MAX + 1);
		} catch (_) {}
		try { source?.close(); } catch (_) {}
	}
	if (!raw || length(raw) > MAX) return [];
	try {
		let data = json(raw);
		return type(data) == 'array' ? compact(data, time() * 1000) : [];
	} catch (_) { return []; }
};

export function write(points) {
	let raw = sprintf('%J', compact(points, time() * 1000));
	if (length(raw) > MAX) die('history_too_large');
	if (fs.writefile(path + '.new', raw) != length(raw) ||
	    !fs.chmod(path + '.new', 0o600) ||
	    !fs.rename(path + '.new', path)) die('history_write_failed');
};
