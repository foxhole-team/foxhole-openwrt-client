'use strict';

import * as digest from 'digest';
import * as package_format from './engine-package-layout.uc';

const IDS = ['vless', 'vmess', 'hysteria2', 'tuic', 'trojan', 'shadowsocks',
	'wireguard', 'naive', 'anytls', 'shadowtls', 'socks', 'http'];
const ARCHES = ['x86_64', 'aarch64_generic', 'aarch64_cortex-a53'];
const BASE = 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/';
const ENTRY_FIELDS = ['id', 'storage', 'version', 'architecture', 'binarySha256',
	'executableSha256', 'producerSha256', 'capabilitiesSha256', 'legalProvenanceSha256', 'manifestSha256', 'sourceCommit',
	'binaryBytes', 'archiveBytes', 'indexBytes', 'installedBytes', 'runtimeMemoryBytes', 'reserveBytes',
	'packageName', 'packageVersion', 'packageSha256', 'indexSha256', 'packageUrl', 'indexUrl'];

function reject(code) { die('engine_' + code); };
function copy(value) { return json(sprintf('%J', value)); };
function number(value, maximum) { return type(value) == 'int' && value >= 0 && value <= maximum; };
function sha(value) { return type(value) == 'string' && match(value, /^[a-f0-9]{64}$/); };
function exact(value, fields, code) {
	if (type(value) != 'object') reject(code);
	for (let key in keys(value)) if (index(fields, key) < 0) reject(code);
};
function ids(value) {
	if (type(value) != 'array' || !length(value) || length(value) > 12) reject('unknown_protocol');
	let seen = {};
	for (let id in value) {
		if (type(id) != 'string' || index(IDS, id) < 0 || seen[id]) reject('unknown_protocol');
		seen[id] = true;
	}
	return sort(copy(value));
};
function entry(value) {
	exact(value, ENTRY_FIELDS, 'package_verification_failed');
	if (index(IDS, value.id) < 0 || index(['FLASH', 'RAM'], value.storage) < 0 ||
	    index(ARCHES, value.architecture) < 0 ||
	    type(value.version) != 'string' || !match(value.version, /^[0-9]+\.[0-9]+\.[0-9]+([+-][a-zA-Z0-9.-]+)?$/) ||
	    type(value.packageVersion) != 'string' || !match(value.packageVersion, /^[a-zA-Z0-9][a-zA-Z0-9_.~+-]{0,159}$/) ||
	    type(value.sourceCommit) != 'string' || !match(value.sourceCommit, /^[a-f0-9]{40}$/))
		reject('package_verification_failed');
	for (let key in ['binarySha256', 'executableSha256', 'producerSha256', 'capabilitiesSha256', 'legalProvenanceSha256', 'manifestSha256',
		'packageSha256', 'indexSha256']) if (!sha(value[key])) reject('package_verification_failed');
	for (let key in ['binaryBytes', 'archiveBytes', 'indexBytes', 'installedBytes', 'runtimeMemoryBytes', 'reserveBytes'])
		if (!number(value[key], 2147483648) || value[key] == 0) reject('package_verification_failed');
	if (value.binaryBytes > 67108864 || value.archiveBytes > 134217728 ||
	    value.indexBytes > 8388608 || value.installedBytes > 536870912 || value.reserveBytes < 16777216)
		reject('package_verification_failed');
	let package = 'foxcore-engine-' + value.id + '-' + lc(value.storage) + '-' + value.manifestSha256;
	let base = BASE + 'v' + value.version + '/';
	if (value.packageName != package || value.packageUrl != base + package + '-' + value.packageVersion + '.apk' ||
	    value.indexUrl != base + 'engines.adb' ||
	    (value.storage == 'FLASH' && value.executableSha256 != value.binarySha256))
		reject('package_verification_failed');
	return copy(value);
};
export function protocols() { return copy(IDS); };
export function slot_id(value) { return value.id + '-' + lc(value.storage) + '-' + value.manifestSha256; };
export function defaults() { return { schema: 1, revision: 0, slots: [], selected: [] }; };
export function catalog(value) {
	exact(value, ['schema', 'entries'], 'package_verification_failed');
	if (type(value.schema) != 'int' || value.schema != 1 || type(value.entries) != 'array' || length(value.entries) > 72)
		reject('package_verification_failed');
	let result = [], seen = {};
	for (let raw in value.entries) {
		let item = entry(raw), key = item.id + ':' + item.storage + ':' + item.architecture;
		if (seen[key]) reject('package_verification_failed');
		seen[key] = true; push(result, item);
	}
	return { schema: 1, entries: result };
};
export function registry(value) {
	exact(value, ['schema', 'revision', 'slots', 'selected'], 'package_verification_failed');
	if (type(value.schema) != 'int' || value.schema != 1 || !number(value.revision, 0x7fffffff) ||
	    type(value.slots) != 'array' || length(value.slots) > 48 ||
	    type(value.selected) != 'array' || length(value.selected) > 12)
		reject('package_verification_failed');
	let slots = [], selected = [], seen = {}, names = {};
	for (let raw in value.slots) {
		let item = entry(raw), key = slot_id(item);
		if (seen[key]) reject('package_verification_failed');
		seen[key] = item; push(slots, item);
	}
	for (let item in value.selected) {
		exact(item, ['id', 'slotId'], 'package_verification_failed');
		if (index(IDS, item.id) < 0 || names[item.id] || seen[item.slotId]?.id != item.id)
			reject('package_verification_failed');
		names[item.id] = true; push(selected, copy(item));
	}
	return { schema: 1, revision: value.revision, slots, selected };
};
export function selected(value, id) {
	let checked = registry(value);
	let key = filter(checked.selected, row => row.id == id)[0]?.slotId;
	return filter(checked.slots, row => slot_id(row) == key)[0] || null;
};
export function status(raw_catalog, raw_registry, context) {
	let available = catalog(raw_catalog), installed = registry(raw_registry), rows = [];
	for (let id in IDS) {
		let same = filter(available.entries, row => row.id == id);
		let matching = filter(same, row => row.architecture == context.architecture);
		let current = selected(installed, id), candidate = filter(matching, row => row.storage == current?.storage)[0] || matching[0];
		push(rows, { id, displayName: id, availability: length(matching) ? 'AVAILABLE' :
			length(same) ? 'UNSUPPORTED_TARGET' : 'NOT_RELEASED', installed: current != null,
			storage: current?.storage, version: current?.version, binarySha256: current?.binarySha256,
			active: context.activeEngineId == id, updateAvailable: current != null && candidate != null &&
				(current.binarySha256 != candidate.binarySha256 || current.packageVersion != candidate.packageVersion),
			archiveBytes: candidate?.archiveBytes, installedBytes: candidate?.installedBytes });
	}
	return { schema: 1, routerId: context.routerId, revision: installed.revision,
		catalogSha256: context.catalogSha256, activeEngineId: context.activeEngineId,
		activeProfileId: context.activeProfileId, entries: rows };
};
function binding(context) {
	return { routerId: context.routerId, bootId: context.bootId, worldSha256: context.worldSha256,
		catalogSha256: context.catalogSha256, activeGeneration: context.activeGeneration,
		activeConfigSha256: context.activeConfigSha256, stopIntent: context.stopIntent,
		activeEngineId: context.activeEngineId, activeProfileId: context.activeProfileId };
};
function fingerprint(value) {
	let cloned = copy(value); delete cloned.planSha256;
	return digest.sha256(sprintf('%J', cloned));
};
function resources(budget, context) {
	if (!number(context.flashAvailableBytes, 9007199254740991) ||
	    !number(context.ramAvailableBytes, 9007199254740991) ||
	    context.flashAvailableBytes < budget.flashRequiredBytes || context.ramAvailableBytes < budget.ramRequiredBytes)
		reject('no_space');
};
export function plan(request, raw_catalog, raw_registry, context, owner, nonce, now) {
	exact(request, ['operation', 'engineIds', 'storage', 'expectedRevision', 'catalogSha256'], 'invalid_request');
	if (index(['ADD', 'UPDATE', 'REMOVE'], request.operation) < 0 ||
	    index(['AUTO', 'FLASH', 'RAM'], request.storage) < 0 ||
	    !number(request.expectedRevision, 0x7ffffffe) || !sha(owner) || !sha(nonce) || !number(now, 9007198954740991))
		reject('invalid_request');
	let wanted = ids(request.engineIds), available = catalog(raw_catalog), installed = registry(raw_registry);
	if (installed.revision != request.expectedRevision || request.catalogSha256 != context.catalogSha256)
		reject('stale_plan');
	let changes = [], artifacts = [], removals = [], impact = 'KEEP_ACTIVE', warnings = [];
	let download = 0, staging = 0, flash = 0, ram = 0, volatile = 0, reserve = 16777216;
	for (let id in wanted) {
		let old = selected(installed, id), next = null;
		if (request.operation == 'REMOVE') {
			if (!old) reject('invalid_request');
			if (context.activeEngineId == id) reject('in_use');
			push(removals, id);
		} else {
			if (request.operation == 'ADD' && old || request.operation == 'UPDATE' && !old && index(context.legacyProtocols || [], id) < 0) reject('invalid_request');
			let same = filter(available.entries, row => row.id == id);
			if (!length(same)) reject('not_released');
			let matching = filter(same, row => row.architecture == context.architecture);
			if (!length(matching)) reject('unsupported_target');
			if (request.storage != 'AUTO') next = filter(matching, row => row.storage == request.storage)[0];
			else {
				let fixed = filter(matching, row => row.storage == 'FLASH')[0];
				next = fixed && context.flashAvailableBytes >= flash + fixed.installedBytes + reserve ?
					fixed : filter(matching, row => row.storage == 'RAM')[0];
			}
			if (!next) reject('unsupported_target');
			if (old && old.binarySha256 == next.binarySha256 && old.storage == next.storage && old.packageVersion == next.packageVersion)
				reject('invalid_request');
			push(artifacts, next); download += next.archiveBytes + next.indexBytes;
			staging += next.archiveBytes * 3 + next.indexBytes * 3; flash += next.installedBytes;
			ram = max(ram, next.runtimeMemoryBytes);
			volatile += next.storage == 'RAM' ? next.binaryBytes : 0;
			reserve = max(reserve, next.reserveBytes);
			if (next.storage == 'RAM' && index(warnings, 'RAM_DOWNLOAD_REQUIRED') < 0) push(warnings, 'RAM_DOWNLOAD_REQUIRED');
			if ((old || index(context.legacyProtocols || [], id) >= 0) && index(warnings, 'OLD_SLOT_RETAINED') < 0) push(warnings, 'OLD_SLOT_RETAINED');
			if (context.activeEngineId == id) impact = 'RECONNECT_REQUIRED';
		}
		push(changes, { id, fromVersion: old?.version, toVersion: next?.version,
			storage: next?.storage || old?.storage, archiveBytes: next?.archiveBytes || 0,
			installedBytes: next?.installedBytes || 0 });
	}
	if (impact == 'RECONNECT_REQUIRED') push(warnings, 'RECONNECT_REQUIRED');
	let budget = { downloadBytes: download, stagingBytes: staging, flashRequiredBytes: flash + reserve,
		ramRequiredBytes: ram + volatile + staging + reserve, flashAvailableBytes: context.flashAvailableBytes,
		ramAvailableBytes: context.ramAvailableBytes, reservedBytes: reserve };
	resources(budget, context);
	let value = { schema: 1, routerId: context.routerId, planId: 'engine-plan-' + substr(nonce, 0, 32),
		revision: installed.revision, expiresAtEpochMs: null, bootId: context.bootId,
		createdAtUptimeMs: now, expiresAtUptimeMs: now + 300000, operation: request.operation,
		engineIds: wanted, changes, budget, impact, confirmationRequired: true, warnings,
		owner, binding: binding(context), artifacts, removals };
	value.planSha256 = fingerprint(value);
	return value;
};
export function public_plan(value) {
	let result = copy(value);
	for (let key in ['owner', 'binding', 'artifacts', 'removals', 'createdAtUptimeMs']) delete result[key];
	return result;
};
export function admit_apply(value, request, raw_registry, context, owner, now) {
	exact(request, ['planId', 'planSha256', 'expectedRevision', 'confirmed'], 'invalid_request');
	if (request.confirmed != true || type(request.confirmed) != 'bool') reject('invalid_request');
	if (owner != value.owner) reject('authentication_failed');
	let installed = registry(raw_registry);
	if (value.planSha256 != fingerprint(value) || request.planId != value.planId ||
	    request.planSha256 != value.planSha256 || request.expectedRevision != installed.revision ||
	    value.revision != installed.revision || sprintf('%J', value.binding) != sprintf('%J', binding(context)) ||
	    !number(now, 9007199254740991) || now < value.createdAtUptimeMs || now > value.expiresAtUptimeMs)
		reject('stale_plan');
	resources(value.budget, context);
	return true;
};
export function add_only_delta(delta, artifacts) {
	if (type(delta) != 'array' || length(delta) != length(artifacts)) return false;
	let wanted = {}, seen = {};
	for (let value in artifacts) wanted[value.packageName] = true;
	for (let item in delta) {
		if (item.action != 'install' || !wanted[item.name] || seen[item.name]) return false;
		seen[item.name] = true;
	}
	return true;
};
export function commit(raw_registry, additions, removals, expected) {
	let result = registry(raw_registry);
	if (result.revision != expected || expected >= 0x7fffffff) reject('stale_plan');
	for (let id in removals) {
		result.selected = filter(result.selected, row => row.id != id);
		result.slots = filter(result.slots, row => row.id != id);
	}
	for (let raw in additions) {
		let item = entry(raw), key = slot_id(item);
		if (!length(filter(result.slots, row => slot_id(row) == key))) push(result.slots, item);
		result.selected = filter(result.selected, row => row.id != item.id);
		push(result.selected, { id: item.id, slotId: key });
	}
	result.revision++;
	return registry(result);
};

export function restart_allowed(bound, context) {
	return bound.routerId == context.routerId && bound.bootId == context.bootId &&
		bound.activeProfileId == context.activeProfileId && bound.activeConfigSha256 == context.activeConfigSha256 &&
		bound.stopIntent == context.stopIntent;
};

export function package_layout(document, raw) {
	return package_format.layout(document, entry(raw));
};
export function purge_only(raw, names, installed) {
	if (type(raw) != 'string' || length(raw) > 8388608 || type(names) != 'array' || !length(names)) return false;
	let seen = {}, count = 0;
	for (let line in split(raw, '\n')) {
		if (!length(trim(line))) continue;
		if (substr(trim(line), 0, 1) != '(') continue;
		let item = match(trim(line), /^\([ ]*([0-9]+)\/([0-9]+)\) Purging ([a-zA-Z0-9][a-zA-Z0-9_.+-]*) \(([^()]+)\)$/);
		if (!item || +item[1] != count + 1 || +item[2] != length(names) ||
		    index(names, item[3]) < 0 || seen[item[3]] || installed[item[3]]?.version != item[4]) return false;
		seen[item[3]] = true; count++;
	}
	return count == length(names);
};
export function worker_current(worker, process, boot) {
	return type(worker) == 'object' && type(process) == 'object' && worker.bootId == boot &&
		worker.pid == process.pid && worker.start == process.start && worker.commandSha256 == process.commandSha256 &&
		process.root == true && process.zombie == false;
};

export function world_pins(before, after, additions, removals) {
	if (type(before) != 'array' || type(after) != 'array' || length(before) > 4096 || length(after) > 4096) return false;
	let expected = [];
	for (let pin in before) {
		let named = type(pin) == 'string' ? match(pin, /^([a-zA-Z0-9][a-zA-Z0-9_.+-]*)([<>=~@].*)?$/) : null;
		if (!named) return false;
		if (index(removals, named[1]) < 0) push(expected, pin);
	}
	for (let name in additions) if (index(expected, name) < 0) push(expected, name);
	return sprintf('%J', sort(expected)) == sprintf('%J', sort(copy(after)));
};
