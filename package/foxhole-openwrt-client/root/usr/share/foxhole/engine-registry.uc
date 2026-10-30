'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as store from './private-store.uc';
import * as engines from './engine-model.uc';

const REGISTRY = '/etc/foxhole/engines.json';
const CATALOG = '/usr/share/foxhole/engine-catalog.json';
const ROOT = '/usr/libexec/foxhole/engines/';
let hashes = {};
let command_generation = null;
function fail() { die('engine_package_verification_failed'); };
function public_file(path, limit) {
	let info = fs.lstat(path);
	if (info?.type != 'file' || info.uid != 0 || info.nlink != 1 || (info.mode & 0o022) || info.size > limit) fail();
	let part = fs.dirname(path);
	while (part != '/') {
		let directory = fs.lstat(part);
		if (directory?.type != 'directory' || directory.uid != 0 || (directory.mode & 0o022)) fail();
		part = fs.dirname(part);
	}
	let raw = fs.readfile(path, limit + 1), after = fs.lstat(path);
	if (raw == null || length(raw) != info.size || length(raw) > limit ||
	    after?.inode != info.inode || after.size != info.size || after.mtime != info.mtime) fail();
	return raw;
};
function router_certificate() {
	let canonical = '/etc/foxhole/mobile-identity/cert.pem', alias = '/etc/foxhole/mobile.crt';
	let current = fs.lstat(canonical);
	if (!current || current.nlink == 1) return public_file(current ? canonical : alias, 16384);
	function identity(info, leaf) {
		if (type(info?.dev?.major) != 'int' || type(info?.dev?.minor) != 'int' ||
		    info.dev.major < 0 || info.dev.minor < 0 || type(info.inode) != 'int' || info.inode <= 0) fail();
		let value = [info.type, info.uid, info.gid, info.mode, info.dev.major, info.dev.minor, info.inode];
		if (leaf) {
			if (type(info.mtime) != 'int' || type(info.ctime) != 'int') fail();
			push(value, info.nlink, info.size, info.mtime, info.ctime);
		}
		return sprintf('%J', value);
	};
	function certificate(path) {
		let info = fs.lstat(path);
		if (info?.type != 'file' || info.uid != 0 || info.gid != 0 || info.nlink != 2 ||
		    (info.mode & 0o7777) != 0o644 || type(info.size) != 'int' || info.size <= 0 || info.size > 16384) fail();
		identity(info, true);
		return info;
	};
	let parents = {}, paths = ['/', '/etc', '/etc/foxhole', '/etc/foxhole/mobile-identity'];
	function parent(path) {
		let info = fs.lstat(path);
		if (info?.type != 'directory' || info.uid != 0 || info.gid != 0 || (info.mode & 0o022) ||
		    ((path == '/etc/foxhole' || path == '/etc/foxhole/mobile-identity') &&
		     (info.mode & 0o7777) != 0o700)) fail();
		return identity(info, false);
	};
	for (let path in paths) parents[path] = parent(path);
	let first = certificate(canonical), second = certificate(alias);
	if (identity(first, true) != identity(second, true)) fail();
	let raw = fs.readfile(canonical, 16385), other = fs.readfile(alias, 16385);
	if (raw == null || other == null || length(raw) != first.size || length(other) != second.size || raw != other) fail();
	if (identity(certificate(canonical), true) != identity(first, true) ||
	    identity(certificate(alias), true) != identity(second, true)) fail();
	for (let path in paths) if (parent(path) != parents[path]) fail();
	return raw;
};
export function capture(argv, maximum, timeout) {
	if (type(maximum) != 'int' || maximum < 1 || maximum > 8388608 ||
	    type(timeout) != 'int' || timeout < 1000 || timeout > 130000) fail();
	// Keep helper generation across BASE replacement and rollback.
	if (!command_generation) command_generation = {
		helper: public_file('/usr/libexec/foxhole-engine-command-v2', 16384),
		utility: public_file('/usr/share/foxhole/engine-capture.uc', 32768)
	};
	store.directory('/tmp/foxhole');
	let random = fs.readfile('/dev/urandom', 12);
	if (length(random || '') != 12) die('engine_package_verification_failed');
	let path = '/tmp/foxhole/engine-command-' + hexenc(random);
	let stage = path + '.io';
	if (fs.lstat(stage)) fail();
	store.directory(stage);
	store.write(stage + '/helper', command_generation.helper);
	store.write(stage + '/utility.uc', command_generation.utility);
	let code = system(['/bin/sh', stage + '/helper', path, '' + maximum, '' + timeout, ...argv], timeout + 5000);
	let cleaned = !fs.lstat(stage + '/owner.json') && !fs.lstat(stage + '/stdout') && !fs.lstat(stage + '/stderr');
	if (cleaned) {
		for (let name in ['helper', 'utility.uc']) if (!fs.unlink(stage + '/' + name)) cleaned = false;
		if (!fs.rmdir(stage)) cleaned = false;
	}
	let raw = null, error = null;
	try { raw = store.read(path, maximum); error = store.read(path + '.err', maximum); }
	catch (_) {}
	for (let name in [path, path + '.err']) try { fs.unlink(name); } catch (_) {}
	if (!cleaned || code != 0 || raw == null || match(raw, /(^|\n)ERROR:/) || match(error || '', /(^|\n)ERROR:/))
		die('engine_package_verification_failed');
	return raw;
};
export function hash_file(path) {
	let info = fs.lstat(path);
	if (info?.type != 'file' || info.uid != 0 || info.nlink != 1 || (info.mode & 0o022) || info.size > 134217728) fail();
	let key = sprintf('%J', [info.dev?.major, info.dev?.minor, info.inode, info.size, info.mtime, info.ctime, info.mode]);
	if (hashes[path]?.key == key) return hashes[path].value;
	let raw = trim(capture(['/usr/bin/sha256sum', path], 4096, 15000));
	let found = match(raw, /^([a-f0-9]{64})  /);
	if (!found) fail();
	let after = fs.lstat(path);
	if (sprintf('%J', [after?.dev?.major, after?.dev?.minor, after?.inode, after?.size, after?.mtime, after?.ctime, after?.mode]) != key) fail();
	hashes[path] = { key, value: found[1] };
	return found[1];
};
export function catalog() {
	let raw = public_file(CATALOG, 262144);
	return { value: engines.catalog(json(raw)), sha256: digest.sha256(raw) };
};
export function read() {
	let raw = store.read(REGISTRY, 262144);
	return raw ? engines.registry(json(raw)) : engines.defaults();
};
export function write(value) {
	let checked = engines.registry(value), raw = sprintf('%J', checked);
	if (length(raw) > 262144) fail();
	store.write(REGISTRY, raw);
	if (store.read(REGISTRY, 262144) != raw) fail();
};
export function manifest(value) {
	return { schema: 1, id: value.id, storage: value.storage, version: value.version,
		architecture: value.architecture, binarySha256: value.binarySha256,
		executableSha256: value.executableSha256, producerSha256: value.producerSha256, capabilitiesSha256: value.capabilitiesSha256,
		legalProvenanceSha256: value.legalProvenanceSha256,
		sourceCommit: value.sourceCommit, binaryBytes: value.binaryBytes,
		runtimeMemoryBytes: value.runtimeMemoryBytes, reserveBytes: value.reserveBytes };
};
export function executable(value) {
	return ROOT + value.id + '/' + value.manifestSha256 + '/foxcore-cli';
};
export function verify_slot(value) {
	let path = executable(value), folder = fs.dirname(path);
	let raw = public_file(folder + '/slot.json', 32768);
	if (digest.sha256(raw) != value.manifestSha256 ||
	    sprintf('%J', json(raw)) != sprintf('%J', manifest(value)) ||
	    hash_file(path) != value.executableSha256) fail();
	let producer = public_file(folder + '/core-producer.json', 131072);
	if (digest.sha256(producer) != value.producerSha256) fail();
	let parsed = json(producer);
	if (parsed.exitCode != 0 || parsed.sourceCommit != value.sourceCommit ||
	    parsed.binarySha256 != value.binarySha256 || sprintf('%J', parsed.protocols) != sprintf('%J', [value.id])) fail();
	let caps = public_file(folder + '/capabilities.json', 131072);
	if (digest.sha256(caps) != value.capabilitiesSha256) fail();
	let capability = json(caps);
	if (capability.platform != 'linux' || capability.router_contract_version != 1 ||
	    capability.core_version != value.version || sprintf('%J', capability.protocols) != sprintf('%J', [value.id])) fail();
	let notices = '/usr/share/licenses/' + value.packageName;
	let legal_raw = public_file(notices + '/LEGAL-PROVENANCE.json', 131072);
	if (digest.sha256(legal_raw) != value.legalProvenanceSha256) fail();
	let legal = json(legal_raw);
	if (legal.schema == 2) {
		let fields = ['schema', 'coreCommit', 'sourceContentSha256',
			'sourceManifestSha256', 'sourceAuthority', 'target', 'protocols',
			'producerSha256', 'binarySha256', 'originalCoreNotices',
			'files', 'authorities'];
		if (length(keys(legal)) != length(fields)) fail();
		for (let name in keys(legal)) if (index(fields, name) < 0) fail();
		let authority = legal.sourceAuthority;
		let names = ['commit', 'tree', 'signatureReceiptSha256',
			'sourceBankReceiptSha256'];
		if (type(legal.schema) != 'int' || type(authority) != 'object' ||
		    length(keys(authority)) != length(names)) fail();
		for (let name in keys(authority)) if (index(names, name) < 0) fail();
		if (legal.coreCommit != parsed.sourceCommit ||
		    legal.sourceContentSha256 != parsed.sourceSha256 ||
		    authority.commit != parsed.sourceCommit ||
		    !match(authority.commit || '', /^[a-f0-9]{40}$/) ||
		    !match(authority.tree || '', /^[a-f0-9]{40}$/)) fail();
		for (let pin in [legal.sourceContentSha256,
		     legal.sourceManifestSha256, authority.signatureReceiptSha256,
		     authority.sourceBankReceiptSha256])
			if (type(pin) != 'string' || !match(pin, /^[a-f0-9]{64}$/)) fail();
		let texts = ['DEPENDENCY-LICENSES.txt', 'RUNTIME-NOTICES.txt'];
		if (type(legal.files) != 'object' ||
		    length(keys(legal.files)) != length(texts)) fail();
		for (let name in keys(legal.files))
			if (index(texts, name) < 0) fail();
		let proofs = ['producerStageReceiptSha256',
			'producerSummaryReceiptSha256', 'cargoCaptureSha256',
			'selectedCargoSbomSha256', 'cargoOriginalNoticesReportSha256',
			'runtimeOriginalNoticesReportSha256'];
		if (type(legal.authorities) != 'object' ||
		    length(keys(legal.authorities)) != length(proofs)) fail();
		for (let name in keys(legal.authorities))
			if (index(proofs, name) < 0 ||
			    type(legal.authorities[name]) != 'string' ||
			    !match(legal.authorities[name], /^[a-f0-9]{64}$/)) fail();
	} else if (legal.schema != 1 || legal.coreCommit != parsed.sourceCommit ||
	           legal.sourceArchiveSha256 != parsed.sourceSha256) fail();
	if (legal.target != parsed.target || sprintf('%J', legal.protocols) != sprintf('%J', [value.id]) ||
	    legal.producerSha256 != value.producerSha256 || legal.binarySha256 != value.binarySha256 ||
	    sprintf('%J', legal.originalCoreNotices) != sprintf('%J', parsed.filesSha256)) fail();
	for (let name in ['LICENSE', 'THIRD_PARTY_NOTICES.md'])
		if (hash_file(notices + '/' + name) != parsed.filesSha256[name]) fail();
	if (type(legal.files) != 'object' || length(keys(legal.files)) != 2) fail();
	let total = 0;
	for (let name in ['DEPENDENCY-LICENSES.txt', 'RUNTIME-NOTICES.txt']) {
		let row = legal.files[name], info = fs.lstat(notices + '/' + name);
		if (legal.schema == 2 && (type(row) != 'object' ||
		    length(keys(row)) != 2 || type(row.sha256) != 'string' ||
		    !match(row.sha256, /^[a-f0-9]{64}$/))) fail();
		if (type(row?.bytes) != 'int' || row.bytes < 1 || row.bytes > 33554432 || info?.size != row.bytes ||
		    hash_file(notices + '/' + name) != row.sha256) fail();
		total += row.bytes;
	}
	if (total > 67108864) fail();
	return path;
};
export function profile_protocol(raw) {
	if (type(raw) != 'string' || length(raw) < 2 || length(raw) > 262144) return null;
	let trimmed = trim(raw);
	if (substr(trimmed, 0, 1) == '{') {
		let parsed = null;
		try { parsed = json(trimmed); } catch (_) { return null; }
		if (parsed.schema_version != null) {
			if (parsed.schema_version != 1 || !engines.protocols() ||
			    index(engines.protocols(), parsed.outbound?.type) < 0 ||
			    (parsed.outbounds != null && length(parsed.outbounds)))
				die('engine_unsupported_profile_graph');
			return parsed.outbound.type;
		}
		return null;
	}
	if (substr(trimmed, 0, 11) == '[Interface]') return 'wireguard';
	let scheme = match(trimmed, /^([a-zA-Z0-9]+):\/\//);
	if (!scheme) return null;
	let name = lc(scheme[1]);
	let aliases = { hy2: 'hysteria2', ss: 'shadowsocks', socks5: 'socks', wg: 'wireguard' };
	name = aliases[name] || name;
	return index(engines.protocols(), name) >= 0 ? name : null;
};
export function select_protocol(id) {
	let value = engines.selected(read(), id);
	return value ? { id: value.id, slotId: engines.slot_id(value), path: verify_slot(value),
		manifestSha256: value.manifestSha256, binarySha256: value.binarySha256 } : null;
};
export function select(raw) {
	let id = profile_protocol(raw);
	return id ? select_protocol(id) : null;
};
export function legacy_protocols() {
	try {
		let raw = public_file('/usr/share/foxhole/core-producer.json', 131072), value = json(raw);
		if (value.exitCode != 0 || type(value.protocols) != 'array' ||
		    hash_file('/usr/bin/foxcore-cli') != value.binarySha256) return [];
		return filter(value.protocols, id => index(engines.protocols(), id) >= 0);
	} catch (_) { return []; }
};
export function current_binary() {
	let raw = store.read('/tmp/foxhole/core.json', 262144);
	if (!raw) return '/usr/bin/foxcore-cli';
	let selected = select(raw);
	return selected?.path || '/usr/bin/foxcore-cli';
};
export function architecture() {
	let raw = trim(public_file('/etc/apk/arch', 128));
	if (index(['x86_64', 'aarch64_generic', 'aarch64_cortex-a53'], raw) < 0)
		die('engine_unsupported_target');
	return raw;
};
export function snapshot_context(state) {
	let current = catalog(), active = filter(state.servers, row => row.id == state.activeServerId)[0];
	let intent_raw = store.read('/etc/foxhole/engine-intent.json', 4096);
	let intent = intent_raw ? json(intent_raw) : { schema: 1, revision: 0 };
	if (intent.schema != 1 || type(intent.revision) != 'int' || intent.revision < 0 || intent.revision > 0x7fffffff) fail();
	let memory = fs.readfile('/proc/meminfo', 65536), found = match(memory || '', /\n?MemAvailable:[ \t]+([0-9]+) kB/);
	let df = trim(capture(['/bin/df', '-Pk', '/'], 16384, 3000)), lines = split(df, '\n');
	let fields = split(trim(lines[length(lines) - 1]), /[ \t]+/);
	if (!found || length(fields) < 6 || !match(fields[3], /^[0-9]+$/)) die('engine_no_space');
	let boot = trim(fs.readfile('/proc/sys/kernel/random/boot_id', 128) || '');
	let world = public_file('/etc/apk/world', 65536);
	let certificate = router_certificate();
	let generation = store.read('/tmp/foxhole/core-state.json', 8192);
	let running = null, generation_number = generation ? match(generation, /"generation":([0-9]{1,20})/) : null;
	try { running = generation ? json(generation) : null; } catch (_) {}
	return { routerId: digest.sha256(certificate), architecture: architecture(), bootId: boot,
		worldSha256: digest.sha256(world), catalogSha256: current.sha256,
		stopIntent: intent.revision, activeConfigSha256: active ? digest.sha256(active.config) : null,
		activeGeneration: active ? digest.sha256(sprintf('%J', [active.id, active.config,
			running?.phase == 'running' ? (generation_number ? generation_number[1] : null) : null])) : null,
		activeEngineId: active?.engine == 'core' ? active.protocol : null, legacyProtocols: legacy_protocols(),
		activeProfileId: state.activeServerId, flashAvailableBytes: +fields[3] * 1024,
		ramAvailableBytes: +found[1] * 1024 };
};
