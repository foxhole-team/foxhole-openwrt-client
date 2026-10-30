'use strict';

import * as fs from 'fs';

export function directory_metadata(info) {
	return info?.type == 'directory' && info.uid == 0 &&
		(info.mode & 0o077) == 0 && info.inode > 0;
};

export function file_metadata(info) {
	return info?.type == 'file' && info.uid == 0 && info.nlink == 1 &&
		(info.mode & 0o077) == 0 && info.inode > 0;
};

function allowed(path) {
	return type(path) == 'string' &&
		match(path, /^\/(tmp|etc)\/foxhole(\/[a-zA-Z0-9_.-]+)*$/) &&
		!match(path, /\/(\.|\.\.)(\/|$)/);
};

export function directory(path) {
	if (!allowed(path)) die('storage_error');
	if (path != '/tmp/foxhole' && path != '/etc/foxhole')
		directory(fs.dirname(path));
	let info = fs.lstat(path);
	if (!info) {
		if (!fs.mkdir(path, 0o700)) die('storage_error');
		info = fs.lstat(path);
	}
	if (!directory_metadata(info)) die('storage_error');
	return info;
};

export function target(path) {
	if (!allowed(path)) die('storage_error');
	directory(fs.dirname(path));
	let info = fs.lstat(path);
	if (info && !file_metadata(info)) die('storage_error');
};

export function read(path, limit) {
	target(path);
	let before = fs.lstat(path);
	if (!before) return null;
	if (before.size > limit) die('storage_error');
	let raw = fs.readfile(path, limit + 1);
	let after = fs.lstat(path);
	if (!file_metadata(after) || before.inode != after.inode ||
	    raw == null || length(raw) != after.size || length(raw) > limit)
		die('storage_error');
	return raw;
};

export function write(path, raw) {
	if (type(raw) != 'string') die('storage_error');
	target(path);
	let random = fs.readfile('/dev/urandom', 12);
	if (length(random || '') != 12) die('storage_error');
	let temporary = path + '.new-' + hexenc(random);
	let file = fs.open(temporary, 'wxe', 0o600);
	if (!file) die('storage_error');
	let result = false;
	try {
		if (file.write(raw) != length(raw) || !file.flush())
			die('storage_error');
		file.close(); file = null;
		target(path);
		if (!fs.rename(temporary, path)) die('storage_error');
		result = true;
	} catch (_) {
		if (file) try { file.close(); } catch (_) {}
	}
	if (!result) {
		try { fs.unlink(temporary); } catch (_) {}
		die('storage_error');
	}
};
