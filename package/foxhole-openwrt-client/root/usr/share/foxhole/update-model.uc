'use strict';

export const reasons = ['UNSUPPORTED_TARGET', 'NOT_CHECKED', 'RELEASE_UNAVAILABLE',
	'AUTHENTICATION_FAILED', 'STALE_PLAN', 'STALE_SESSION', 'BUSY', 'NO_SPACE',
	'DOWNLOAD_FAILED', 'PACKAGE_VERIFICATION_FAILED', 'DOWNGRADE_REJECTED',
	'VERSION_IDENTITY_CONFLICT', 'ROLLBACK_UNAVAILABLE', 'RAM_STAGE_UNAVAILABLE',
	'ROUTER_UNAVAILABLE', 'RECOVERY_REQUIRED', 'INVALID_REQUEST', 'LEGACY_CONNECTION_ACTIVE'];
export function fail(reason) { die('update_' + lc(reason)); };
function safe_int(value) { return type(value) == 'int' && value >= 0 && value <= 9007199254740991; };
function same(a, b) { return sprintf('%J', a) == sprintf('%J', b); };
export function policy(value) {
	if (value == null) return { schema:1, revision:0, enabled:false, lastAttemptAtUnixMs:null };
	if (value.schema != 1 || !safe_int(value.revision) || value.revision >= 0x7fffffff ||
	    type(value.enabled) != 'bool' || value.lastAttemptAtUnixMs != null && !safe_int(value.lastAttemptAtUnixMs))
		fail('RECOVERY_REQUIRED');
	return value;
};
export function due(value, now, busy) {
	return value.enabled && !busy && safe_int(now) && now >= 1577836800000 &&
		(value.lastAttemptAtUnixMs == null || now >= value.lastAttemptAtUnixMs + 86400000);
};
export function auto_authorized(job, value) {
	return job.automatic == true && value.enabled == true && value.revision == job.policyRevision;
};
export function release_tag(value) {
	if (value?.draft != false || value.prerelease != false || type(value.tag_name) != 'string' ||
	    !match(value.tag_name, /^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$/)) fail('RELEASE_UNAVAILABLE');
	return value.tag_name;
};
export function version_admit(comparison, previous_hash, candidate_hash) {
	if (comparison == '>') fail('DOWNGRADE_REJECTED');
	if (comparison == '=') {
		if (previous_hash != candidate_hash) fail('VERSION_IDENTITY_CONFLICT');
		return false;
	}
	if (comparison != '<') fail('PACKAGE_VERIFICATION_FAILED');
	return true;
};
export function package_delta(before, after, allowed) {
	if (type(before) != 'object' || type(after) != 'object' || type(allowed) != 'array') fail('PACKAGE_VERIFICATION_FAILED');
	let wanted = {};
	for (let row in allowed) {
		if (type(row?.name) != 'string' || wanted[row.name] ||
		    before[row.name] && row.name != 'foxhole-openwrt-client') fail('PACKAGE_VERIFICATION_FAILED');
		wanted[row.name] = row;
	}
	for (let name, row in before)
		if (!same(after[name], wanted[name] || row)) fail('PACKAGE_VERIFICATION_FAILED');
	for (let name, row in after)
		if (!before[name] && !same(row, wanted[name])) fail('PACKAGE_VERIFICATION_FAILED');
	for (let name, row in wanted) if (!same(after[name], row)) fail('PACKAGE_VERIFICATION_FAILED');
	return true;
};
export function simulation(raw, before, allowed) {
	let wanted = {}, seen = {}, count = 0;
	for (let row in allowed) wanted[row.name] = row;
	for (let line in split(raw, '\n')) {
		if (!match(trim(line), /^\(/)) continue;
		let found = match(trim(line), /^\([ ]*([0-9]+)\/([0-9]+)\) (Installing|Upgrading) ([a-zA-Z0-9][a-zA-Z0-9_.+-]*) \(([^()]+)\)$/);
		if (!found || seen[found[4]] || !wanted[found[4]] || +found[1] != count + 1 || +found[2] != length(allowed)) fail('PACKAGE_VERIFICATION_FAILED');
		let name = found[4], row = wanted[name];
		if (before[name] ? name != 'foxhole-openwrt-client' || found[3] != 'Upgrading' || found[5] != before[name].version + ' -> ' + row.version :
		    found[3] != 'Installing' || found[5] != row.version) fail('PACKAGE_VERIFICATION_FAILED');
		seen[name] = true; count++;
	}
	if (count != length(allowed)) fail('PACKAGE_VERIFICATION_FAILED');
	return true;
};
export function base_path(path) {
	if (type(path) != 'string' || length(path) > 256 ||
	    !match(path, /^[a-zA-Z0-9_+./-]+$/) || match(path, /(^|\/)\.\.?($|\/)/)) return false;
	if (index(['etc/config/foxhole','etc/uci-defaults/99-foxhole-openwrt-client',
		'etc/nftables.d/31-foxhole-inbound.nft','www/foxhole.html',
		'www/cgi-bin/foxhole','www/foxhole-mobile/cgi-bin/foxhole',
		'usr/share/rpcd/ucode/foxhole.uc','usr/share/rpcd/acl.d/luci-app-foxhole.json',
		'usr/share/luci/menu.d/luci-app-foxhole.json','lib/apk/packages/foxhole-openwrt-client.list',
		'lib/apk/packages/foxhole-openwrt-client.conffiles',
		'lib/apk/packages/foxhole-openwrt-client.conffiles_static',
		'lib/upgrade/keep.d/foxhole-openwrt-client',
		'usr/libexec/foxhole-engine-command-v2','usr/libexec/foxhole-transaction-stage-v1',
		'usr/libexec/foxhole-transaction-command-v1','usr/share/foxhole/transaction-x86_64.gz',
		'usr/share/foxhole/transaction-aarch64_cortex-a53.gz'], path) >= 0) return true;
	return match(path, /^etc\/init.d\/foxhole-[a-z-]+$/) != null ||
		match(path, /^usr\/libexec\/foxhole-[a-z-]+$/) != null ||
		match(path, /^usr\/share\/foxhole\/[a-zA-Z0-9_.-]+\.(uc|json|pem)$/) != null ||
		match(path, /^usr\/share\/nftables.d\/chain-pre\/(input|forward)\/3[01]-foxhole(-inbound)?\.nft$/) != null ||
		match(path, /^usr\/share\/licenses\/foxhole-openwrt-client\/[a-zA-Z0-9_.-]+$/) != null ||
		match(path, /^www\/luci-static\/resources\/(foxhole\/[a-zA-Z0-9_+./-]+|view\/foxhole\/[a-z-]+\.js)$/) != null;
};
function acl(value, modes) {
	let mode = type(value?.mode) == 'int' ? value.mode : -1;
	return index(modes, mode) >= 0 && index(['root','0'], value.user) >= 0 &&
		index(['root','0'], value.group) >= 0 && !length(value.xattrs || []);
};
export function base_layout(document, version) {
	let info = document?.info;
	if (info?.name != 'foxhole-openwrt-client' || info.version != version || info.arch != 'noarch' ||
	    !safe_int(info['installed-size']) || info['installed-size'] > 33554432 ||
	    type(document.paths) != 'array' || length(document.paths) > 192 ||
	    length(document.triggers || []) || type(document.scripts || {}) != 'object') fail('PACKAGE_VERIFICATION_FAILED');
	for (let key in keys(document.scripts || {}))
		if (index(['pre-install','post-install','pre-deinstall','post-deinstall','pre-upgrade','post-upgrade'], key) < 0)
			fail('PACKAGE_VERIFICATION_FAILED');
	if (info.provides != null && (type(info.provides) != 'array' ||
	    length(info.provides) && !same(info.provides, ['foxhole-openwrt-client-any'])))
		fail('PACKAGE_VERIFICATION_FAILED');
	for (let key in ['replaces','install-if','recommends'])
		if (length(info[key] || [])) fail('PACKAGE_VERIFICATION_FAILED');
	let seen = {}, directories = {}, count = 0, total = 0;
	for (let folder in document.paths) {
		let name = folder.name || '';
		if (directories[name] || !acl(folder.acl,[0o755]) || type(folder.files || []) != 'array' ||
		    name && (!match(name,/^[a-zA-Z0-9_+./-]+$/) || match(name,/(^|\/)\.\.?($|\/)/))) fail('PACKAGE_VERIFICATION_FAILED');
		directories[name] = true;
		for (let file in folder.files || []) {
			let path = name + '/' + file.name;
			if (!base_path(path) || seen[path] || file.target != null || !acl(file.acl,path=='etc/config/foxhole'?[0o600,0o644,0o755]:[0o644,0o755]) ||
			    !safe_int(file.size) || file.size > 8388608 || !match(file.hash || '', /^[a-f0-9]{64}$/)) fail('PACKAGE_VERIFICATION_FAILED');
			seen[path] = true; count++; total += file.size;
		}
	}
	if (count < 8 || count > 768 || total > 33554432) fail('PACKAGE_VERIFICATION_FAILED');
	for (let name in keys(directories)) if (name && !length(filter(keys(seen), path => substr(path,0,length(name)+1) == name + '/')))
		fail('PACKAGE_VERIFICATION_FAILED');
	for (let path in ['usr/share/foxhole/update-policy.json','usr/share/foxhole/engine-catalog.json',
		'usr/share/foxhole/update-service.uc','usr/libexec/foxhole-update-job','www/foxhole.html',
		'usr/share/rpcd/ucode/foxhole.uc','etc/config/foxhole','lib/apk/packages/foxhole-openwrt-client.list'])
		if (!seen[path]) fail('PACKAGE_VERIFICATION_FAILED');
	return seen;
};
