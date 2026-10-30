import * as engines from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/engine-model.uc';

let passed = 0, failed = 0;
function copy(value) { return json(sprintf('%J', value)); };
function equal(value, wanted) { if (sprintf('%J', value) != sprintf('%J', wanted)) die('assertion_failed'); };
function rejects(fn, expected) {
	let caught = null;
	try { fn(); } catch (error) { caught = type(error) == 'string' ? error : error.message; }
	equal(caught, expected);
};
function test(name, fn) {
	try { fn(); passed++; print('ok ', name, '\n'); }
	catch (error) { failed++; print('not ok ', name, ': ', type(error) == 'string' ? error : error.message, '\n'); }
};
const H = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const C = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
function artifact(id, storage, binary) {
	binary = binary || H;
	let manifest = binary == H ? C : binary;
	let package = 'foxcore-engine-' + id + '-' + lc(storage) + '-' + manifest;
	return { id, storage, version: '1.0.0', architecture: 'x86_64', binarySha256: binary,
		executableSha256: binary, producerSha256: B, capabilitiesSha256: C, legalProvenanceSha256: C, manifestSha256: manifest, sourceCommit: substr(H, 0, 40),
		binaryBytes: 1024, archiveBytes: 2048, indexBytes: 1024, installedBytes: 4096,
		runtimeMemoryBytes: 8192, reserveBytes: 16777216, packageName: package,
		packageVersion: '1.0.0-r1', packageSha256: B, indexSha256: C,
		packageUrl: 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.0/' + package + '-1.0.0-r1.apk',
		indexUrl: 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.0/engines.adb' };
};
function catalog() { return { schema: 1, entries: [artifact('vless', 'FLASH'), artifact('vless', 'RAM')] }; };
function context() {
	return { routerId: H, architecture: 'x86_64', bootId: 'synthetic-boot', worldSha256: B,
		catalogSha256: C, activeGeneration: 'generation-1', activeEngineId: 'hysteria2',
		activeProfileId: 'server-synthetic', flashAvailableBytes: 1073741824,
		ramAvailableBytes: 1073741824 };
};
function request() { return { operation: 'ADD', engineIds: ['vless'], storage: 'AUTO',
	expectedRevision: 0, catalogSha256: C }; };
function plan() { return engines.plan(request(), catalog(), engines.defaults(), context(), H, B, 1000); };
function apply_request(value) { return { planId: value.planId, planSha256: value.planSha256,
	expectedRevision: 0, confirmed: true }; };

test('all twelve ids are recognized but absent signed artifacts stay unavailable', () => {
	equal(length(engines.protocols()), 12);
	let rows = engines.status({ schema: 1, entries: [] }, engines.defaults(), context());
	equal(length(rows.entries), 12);
	for (let row in rows.entries) { equal(row.availability, 'NOT_RELEASED'); equal(row.installed, false); }
	rejects(() => engines.plan(request(), { schema: 1, entries: [] }, engines.defaults(), context(), H, B, 1000), 'engine_not_released');
});
test('plan is read-only and a new unused engine retains the active route', () => {
	let registry = engines.defaults(), previous = sprintf('%J', registry);
	let value = engines.plan(request(), catalog(), registry, context(), H, B, 1000);
	equal(value.impact, 'KEEP_ACTIVE'); equal(value.engineIds, ['vless']);
	equal(sprintf('%J', registry), previous); equal(value.expiresAtUptimeMs, 301000);
	equal(engines.public_plan(value).binding, null); equal(engines.public_plan(value).owner, null);
});
test('normal memory movement does not invalidate an otherwise sufficient plan', () => {
	let value = plan(), ctx = context(); ctx.ramAvailableBytes--;
	equal(engines.admit_apply(value, apply_request(value), engines.defaults(), ctx, H, 2000), true);
});
test('apply rechecks resource sufficiency rather than old available-byte equality', () => {
	let value = plan(), ctx = context(); ctx.flashAvailableBytes = 1;
	rejects(() => engines.admit_apply(value, apply_request(value), engines.defaults(), ctx, H, 2000), 'engine_no_space');
});
for (let field in ['routerId', 'worldSha256', 'catalogSha256', 'activeGeneration', 'bootId']) {
	test('changed ' + field + ' cannot reuse a confirmed plan', () => {
		let value = plan(), ctx = context(); ctx[field] = 'changed';
		rejects(() => engines.admit_apply(value, apply_request(value), engines.defaults(), ctx, H, 2000), 'engine_stale_plan');
	});
}
test('expired monotonic plan and a clock moving backwards fail closed', () => {
	let value = plan();
	for (let now in [999, 301001])
		rejects(() => engines.admit_apply(value, apply_request(value), engines.defaults(), context(), H, now), 'engine_stale_plan');
});
test('another pairing and an unconfirmed request cannot apply a plan', () => {
	let value = plan();
	rejects(() => engines.admit_apply(value, apply_request(value), engines.defaults(), context(), B, 2000), 'engine_authentication_failed');
	let request = apply_request(value); request.confirmed = false;
	rejects(() => engines.admit_apply(value, request, engines.defaults(), context(), H, 2000), 'engine_invalid_request');
});
test('unknown ids, duplicate ids and caller-supplied paths never become a plan', () => {
	for (let ids in [['all'], ['vless', 'vless'], ['../../bin/sh']]) {
		let value = request(); value.engineIds = ids;
		rejects(() => engines.plan(value, catalog(), engines.defaults(), context(), H, B, 1000), 'engine_unknown_protocol');
	}
	let value = request(); value.executable = '/bin/sh';
	rejects(() => engines.plan(value, catalog(), engines.defaults(), context(), H, B, 1000), 'engine_invalid_request');
});
test('a catalog name cannot confer canonical authority through a broad prefix', () => {
	for (let field in ['packageName', 'packageUrl', 'indexUrl']) {
		let value = catalog(); value.entries[0][field] = field == 'packageName' ? 'foxcore-engine-foreign' : 'https://foreign.invalid/payload';
		rejects(() => engines.catalog(value), 'engine_package_verification_failed');
	}
});
test('wrong-target artifacts cannot be silently replaced by all or another ABI', () => {
	let ctx = context(); ctx.architecture = 'aarch64_generic';
	rejects(() => engines.plan(request(), catalog(), engines.defaults(), ctx, H, B, 1000), 'engine_unsupported_target');
});
test('active removal is refused before any package or runtime operation', () => {
	let reg = engines.defaults(), entry = artifact('vless', 'FLASH');
	reg.slots = [entry]; reg.selected = [{ id: 'vless', slotId: engines.slot_id(entry) }];
	let ctx = context(); ctx.activeEngineId = 'vless';
	let req = request(); req.operation = 'REMOVE';
	rejects(() => engines.plan(req, catalog(), reg, ctx, H, B, 1000), 'engine_in_use');
});
test('retained versions stay installed while registry selects a new immutable slot', () => {
	let reg = engines.defaults(), old = artifact('vless', 'FLASH', B);
	reg.slots = [old]; reg.selected = [{ id: 'vless', slotId: engines.slot_id(old) }];
	let next = engines.commit(reg, [artifact('vless', 'FLASH')], [], 0);
	equal(length(next.slots), 2); equal(next.revision, 1);
	equal(next.selected[0].slotId, engines.slot_id(artifact('vless', 'FLASH')));
	equal(reg.revision, 0);
});
test('same-name package upgrade or common dependency changes cannot be an add-unused delta', () => {
	let value = artifact('vless', 'FLASH');
	equal(engines.add_only_delta([{ name: value.packageName, action: 'install' }], [value]), true);
	for (let action in ['upgrade', 'remove', 'reinstall'])
		equal(engines.add_only_delta([{ name: 'libc', action }], [value]), false);
	equal(engines.add_only_delta([{ name: value.packageName, action: 'install' }, { name: 'libc', action: 'install' }], [value]), false);
});
function layout(value) {
	let folder = 'usr/libexec/foxhole/engines/' + value.id + '/' + value.manifestSha256;
	let notices = 'usr/share/licenses/' + value.packageName;
	let dirs = ['usr', 'usr/libexec', 'usr/libexec/foxhole', 'usr/libexec/foxhole/engines',
		'usr/libexec/foxhole/engines/' + value.id, folder, 'usr/share', 'usr/share/licenses', notices, 'lib', 'lib/apk', 'lib/apk/packages'];
	return { info: { name: value.packageName, version: value.packageVersion,
		arch: value.architecture, 'installed-size': value.installedBytes },
		paths: map(dirs, name => ({ name, acl: { user: 'root', group: 'root', mode: '0755' },
			files: name == folder ? map(['foxcore-cli', 'slot.json', 'core-producer.json', 'capabilities.json'],
				file => ({ name: file, acl: { user: 'root', group: 'root', mode: file == 'foxcore-cli' ? '0755' : '0644' } })) :
				name == notices ? map(['LICENSE', 'THIRD_PARTY_NOTICES.md', 'DEPENDENCY-LICENSES.txt', 'RUNTIME-NOTICES.txt', 'LEGAL-PROVENANCE.json'],
				file => ({ name: file, acl: { user: 'root', group: 'root', mode: '0644' } })) :
				name == 'lib/apk/packages' ? [{ name: value.packageName + '.list', acl: { user: 'root', group: 'root', mode: '0644' } }] : [] })) };
};
test('engine APK layout permits only exact slot and license ancestors', () => {
	let value = artifact('vless', 'FLASH'); equal(engines.package_layout(layout(value), value), true);
});
for (let kind in ['foreign-empty', 'duplicate', 'foreign-owner', 'writable-dir', 'setuid-file', 'writable-file', 'link', 'foreign-list', 'second-list', 'writable-list', 'foreign-list-owner', 'hooks', 'triggers']) {
	test('engine APK refuses ' + kind + ' before native install', () => {
		let value = artifact('vless', 'FLASH'), doc = layout(value);
		if (kind == 'foreign-empty') push(doc.paths, { name: 'etc/init.d', acl: { user: 'root', group: 'root', mode: '0755' }, files: [] });
		if (kind == 'duplicate') push(doc.paths, copy(doc.paths[0]));
		if (kind == 'foreign-owner') doc.paths[0].acl.user = 'nobody';
		if (kind == 'writable-dir') doc.paths[0].acl.mode = '0777';
		if (kind == 'setuid-file') doc.paths[5].files[0].acl.mode = '04755';
		if (kind == 'writable-file') doc.paths[5].files[0].acl.mode = '0775';
		if (kind == 'link') doc.paths[5].files[0].target = '2f62696e2f7368';
		if (kind == 'foreign-list') doc.paths[11].files[0].name = 'foreign.list';
		if (kind == 'second-list') push(doc.paths[11].files, { name: 'another.list', acl: { user: 'root', group: 'root', mode: '0644' } });
		if (kind == 'writable-list') doc.paths[11].files[0].acl.mode = '0666';
		if (kind == 'foreign-list-owner') doc.paths[11].files[0].acl.user = 'nobody';
		if (kind == 'hooks') doc.scripts = { 'post-install': 'echo forbidden' };
		if (kind == 'triggers') doc.triggers = ['etc/config/*'];
		rejects(() => engines.package_layout(doc, value), 'engine_package_verification_failed');
	});
}
test('remove dry-run permits only exact expected healthy package purges', () => {
	let before = { 'engine-a': { version: '1.0.0-r1' }, libc: { version: '1.2.5-r5' } };
	equal(engines.purge_only('(1/1) Purging engine-a (1.0.0-r1)\nOK: 1 MiB in 2 packages\n', ['engine-a'], before), true);
	for (let raw in ['(1/1) Purging libc (1.2.5-r5)\n', '(1/1) Upgrading engine-a (1 -> 2)\n',
		'(1/1) Reinstalling engine-a (1.0.0-r1)\n', '(1/2) Purging engine-a (1.0.0-r1)\n',
		'(1/1) Purging engine-a (wrong)\n', '(1/1) Purging engine-a (1.0.0-r1)\n(1/1) Purging engine-a (1.0.0-r1)\n'])
		equal(engines.purge_only(raw, ['engine-a'], before), false);
});
test('worker identity refuses a reused PID, zombie or another boot', () => {
	let worker = { pid: 42, start: '1234', commandSha256: H, bootId: 'boot-a' };
	let process = { pid: 42, start: '1234', commandSha256: H, root: true, zombie: false };
	equal(engines.worker_current(worker, process, 'boot-a'), true);
	for (let changed in [{ ...process, start: '1235' }, { ...process, zombie: true },
		{ ...process, commandSha256: B }, { ...process, root: false }])
		equal(engines.worker_current(worker, changed, 'boot-a'), false);
	equal(engines.worker_current(worker, process, 'boot-b'), false);
	equal(engines.worker_current(worker, null, 'boot-a'), false);
});
test('user STOP invalidates reconnect even if the selected profile id stays the same', () => {
	let before = context(); before.activeConfigSha256 = H; before.stopIntent = 7;
	let later = copy(before); later.stopIntent++;
	equal(engines.restart_allowed(before, later), false);
	later = copy(before); later.activeConfigSha256 = B;
	equal(engines.restart_allowed(before, later), false);
	equal(engines.restart_allowed(before, copy(before)), true);
});
test('legacy provider migration selects an actual modular artifact without removing the old provider', () => {
	let req = request(); req.operation = 'UPDATE';
	let ctx = context(); ctx.legacyProtocols = ['vless'];
	let value = engines.plan(req, catalog(), engines.defaults(), ctx, H, B, 1000);
	equal(value.operation, 'UPDATE'); equal(value.engineIds, ['vless']);
	equal(value.removals, []); equal(index(value.warnings, 'OLD_SLOT_RETAINED') >= 0, true);
});
test('world readback retains exact kernel/checksum and foreign version pins', () => {
	let before = ['kernel><X17157abc', 'libc=1.2.5-r5', 'foreign>=2-r1'];
	equal(engines.world_pins(before, [...before, 'engine-new'], ['engine-new'], []), true);
	equal(engines.world_pins(before, ['kernel', 'libc=1.2.5-r5', 'foreign>=2-r1', 'engine-new'], ['engine-new'], []), false);
	equal(engines.world_pins(before, ['kernel><X17157abc', 'libc=1.2.6-r1', 'foreign>=2-r1', 'engine-new'], ['engine-new'], []), false);
	equal(engines.world_pins([...before, 'engine-old=1-r1', 'engine-old-other=2'], [...before, 'engine-old-other=2'], [], ['engine-old']), true);
});
print('1..', passed + failed, '\n# Engine model tests: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
