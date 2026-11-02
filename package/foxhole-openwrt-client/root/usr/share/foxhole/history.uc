import * as fs from 'fs';
import * as store from './private-store.uc';

export const path = '/tmp/foxhole/history.json';
export const archive = '/etc/foxhole/history.json.gz';
export const preview_path = '/tmp/foxhole/history-preview.json';
export const preview_max_bytes = 240000;
export const preview_max_points = 512;
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
	let compacted = compact(points, time() * 1000);
	let raw = sprintf('%J', compacted);
	if (length(raw) > MAX) die('history_too_large');
	if (fs.writefile(path + '.new', raw) != length(raw) ||
	    !fs.chmod(path + '.new', 0o600) ||
	    !fs.rename(path + '.new', path)) die('history_write_failed');
	return compacted;
};

export function preview_json(points) {
	if (type(points) != 'array') die('history_preview_invalid');
	let count = min(preview_max_points, length(points));
	while (count > 0) {
		let parts = [], bytes = 2;
		for (let i = 0; i < count; i++) {
			let offset = count == 1 ? 0 : int(i * (length(points) - 1) / (count - 1));
			let part = sprintf('%J', points[offset]);
			bytes += length(part) + (i > 0 ? 1 : 0);
			if (bytes > preview_max_bytes) break;
			push(parts, part);
		}
		if (length(parts) == count) return '[' + join(',', parts) + ']';
		if (count <= 2) break;
		count = max(2, int(count / 2));
	}
	// An unrepresentable endpoint never truncates or replaces the full owner history.
	return '[]';
};

export function write_preview(points) {
	store.write(preview_path, preview_json(points));
};

export function read_preview() {
	try {
		let raw = store.read(preview_path, preview_max_bytes);
		if (!raw) return [];
		let points = json(raw);
		if (type(points) != 'array' || length(points) > preview_max_points) return [];
		let previous = -1;
		for (let point in points) {
			if (type(point) != 'object' || type(point.t) != 'int' || point.t < previous) return [];
			previous = point.t;
		}
		return points;
	} catch (_) { return []; }
};
