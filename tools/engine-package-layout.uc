'use strict';

function reject(code) { die('engine_' + code); };
function acl(value, wanted) {
	if (type(value) != 'object' || index(['root', '0'], value.user) < 0 || index(['root', '0'], value.group) < 0 ||
	    (value.xattrs != null && (type(value.xattrs) != 'array' || length(value.xattrs))))
		return false;
	let mode = type(value.mode) == 'int' ? value.mode :
		type(value.mode) == 'string' && match(value.mode, /^0?[0-7]{3,4}$/) ? int(value.mode, 8) : -1;
	return mode == wanted;
};
export function layout(document, value) {
	let info = document?.info;
	if (info?.name != value.packageName || info.version != value.packageVersion || info.arch != value.architecture ||
	    info['installed-size'] != value.installedBytes ||
	    (document.scripts != null && (type(document.scripts) != 'object' || length(keys(document.scripts)))) ||
	    (document.triggers != null && (type(document.triggers) != 'array' || length(document.triggers))))
		reject('package_verification_failed');
	for (let field in ['provides', 'replaces', 'install-if', 'recommends'])
		if (info[field] != null && (type(info[field]) != 'array' || length(info[field]))) reject('package_verification_failed');
	let folder = 'usr/libexec/foxhole/engines/' + value.id + '/' + value.manifestSha256;
	let notices = 'usr/share/licenses/' + value.packageName, allowed = {}, directories = {};
	for (let name in ['foxcore-cli', 'slot.json', 'core-producer.json', 'capabilities.json']) allowed[folder + '/' + name] = true;
	for (let name in ['LICENSE', 'THIRD_PARTY_NOTICES.md', 'DEPENDENCY-LICENSES.txt', 'RUNTIME-NOTICES.txt', 'LEGAL-PROVENANCE.json']) allowed[notices + '/' + name] = true;
	allowed['lib/apk/packages/' + value.packageName + '.list'] = true;
	let seen = {}, seen_dirs = {}, native_root_seen = false;
	for (let name in keys(allowed)) {
		let parts = split(name, '/'); pop(parts);
		while (length(parts)) { directories[join('/', parts)] = true; pop(parts); }
	}
	if (type(document.paths) != 'array' || length(document.paths) > 24) reject('package_verification_failed');
	for (let directory in document.paths) {
		if (type(directory) != 'object') reject('package_verification_failed');
		let native_root = index(keys(directory), 'name') < 0 ||
			(type(directory.name) == 'string' && directory.name == '');
		if (native_root) {
			if (native_root_seen || type(directory.acl) != 'object' ||
			    length(keys(directory.acl)) != 3 || type(directory.acl.mode) != 'int' ||
			    directory.acl.mode != 0o755 || directory.acl.user != 'root' || directory.acl.group != 'root' ||
			    (index(keys(directory), 'files') >= 0 &&
			     (type(directory.files) != 'array' || length(directory.files)))) reject('package_verification_failed');
			for (let key in keys(directory))
				if (index(['name', 'acl', 'files'], key) < 0) reject('package_verification_failed');
			native_root_seen = true;
			continue;
		}
		if (!directories[directory.name] || seen_dirs[directory.name] || !acl(directory.acl, 0o755) ||
		    type(directory.files || []) != 'array') reject('package_verification_failed');
		seen_dirs[directory.name] = true;
		for (let file in directory.files || []) {
			let name = directory.name + '/' + file.name;
			if (!allowed[name] || seen[name] || file.target != null ||
			    !acl(file.acl, file.name == 'foxcore-cli' ? 0o755 : 0o644)) reject('package_verification_failed');
			seen[name] = true;
		}
	}
	if (length(keys(seen)) != length(keys(allowed))) reject('package_verification_failed');
	return true;
};
