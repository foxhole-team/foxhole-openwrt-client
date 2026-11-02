'use strict';

import * as fs from 'fs';
import * as engines from './engine-model.uc';
import * as registry from './engine-registry.uc';
import * as store from './private-store.uc';

function fail(reason) { die('engine_' + lc(reason)); };
export function asset(url, expected, maximum) {
	store.directory('/tmp/foxhole/engine-assets');
	let path = '/tmp/foxhole/engine-assets/' + expected;
	store.target(path);
	if (!fs.lstat(path) && system(['/usr/libexec/foxhole-engine-fetch', url, path, '' + maximum], 130000) != 0)
		fail('DOWNLOAD_FAILED');
	let info = fs.lstat(path);
	if (!store.file_metadata(info) || info.size <= 0 || info.size > maximum || registry.hash_file(path) != expected)
		fail('PACKAGE_VERIFICATION_FAILED');
	return path;
};
export function apk(argv, timeout) { return registry.capture(['/usr/bin/apk', ...argv], 8388608, timeout || 30000); };
export function decode(raw) { try { return json(raw); } catch (_) { fail('PACKAGE_VERIFICATION_FAILED'); } };
export function installed(tolerate) {
	let rows = decode(apk(['--no-network', '--repositories-file', '/dev/null', 'query', '--from', 'installed', '--all-matches', '--format', 'json', '--fields', 'name,version,arch,status', '*']));
	if (type(rows) != 'array' || length(rows) > 4096) fail('PACKAGE_VERIFICATION_FAILED');
	let result = {};
	for (let row in rows) {
		if (type(row.name) != 'string' || result[row.name] ||
		    (sprintf('%J', row.status) != sprintf('%J', ['installed']) && index(tolerate || [], row.name) < 0)) fail('PACKAGE_VERIFICATION_FAILED');
		result[row.name] = { name: row.name, version: row.version, arch: row.arch };
	}
	return result;
};

export function candidate(value, directory, keys) {
	let package = asset(value.packageUrl, value.packageSha256, value.archiveBytes);
	if (fs.lstat(package).size != value.archiveBytes) fail('PACKAGE_VERIFICATION_FAILED');
	let index = asset(value.indexUrl, value.indexSha256, value.indexBytes);
	if (fs.lstat(index).size != value.indexBytes) fail('PACKAGE_VERIFICATION_FAILED');
	apk(['--keys-dir', keys, 'verify', package, index]);
	let document = decode(apk(['adbdump', '--format', 'json', package]));
	engines.package_layout(document, value);
	let entries = decode(apk(['adbdump', '--format', 'json', index])).packages;
	let matching = type(entries) == 'array' ? filter(entries, row => row.name == value.packageName) : [];
	if (length(matching) != 1 || matching[0].version != value.packageVersion ||
	    matching[0].arch != value.architecture || matching[0]['file-size'] != value.archiveBytes ||
	    !match(matching[0].hashes || '', /^[a-f0-9]{64}$/))
		fail('PACKAGE_VERIFICATION_FAILED');
	let target = directory + '/' + value.packageName + '-' + value.packageVersion + '.apk';
	if (system(['/bin/cp', package, target], 10000) != 0) fail('PACKAGE_VERIFICATION_FAILED');
	let repository = directory + '/fetch-' + value.id;
	store.directory(repository); store.directory(repository + '/root'); store.directory(repository + '/output');
	if (system(['/bin/cp', index, repository + '/packages.adb'], 10000) != 0 ||
	    system(['/bin/cp', package, repository + '/' + value.packageName + '-' + value.packageVersion + '.apk'], 10000) != 0)
		fail('PACKAGE_VERIFICATION_FAILED');
	store.write(repository + '/repositories', repository + '/packages.adb\n');
	let common = ['--root', repository + '/root', '--arch', value.architecture, '--no-network', '--no-cache',
		'--repositories-file', repository + '/repositories', '--keys-dir', keys];
	apk([...common, 'add', '--initdb']);
	apk([...common, 'fetch', '--output', repository + '/output', value.packageName]);
	if (registry.hash_file(repository + '/output/' + value.packageName + '-' + value.packageVersion + '.apk') != value.packageSha256)
		fail('PACKAGE_VERIFICATION_FAILED');
	return { package: target, index, value, nativeId:matching[0].hashes, payload:document };
};
export function world() {
	let raw = fs.readfile('/etc/apk/world', 65536);
	if (type(raw) != 'string' || length(raw) > 65536) fail('PACKAGE_VERIFICATION_FAILED');
	let rows = filter(map(split(raw, '\n'), item => trim(item)), item => length(item));
	let seen = {};
	for (let row in rows) {
		if (length(row) > 512 || seen[row]) fail('PACKAGE_VERIFICATION_FAILED');
		seen[row] = true;
	}
	return rows;
};
