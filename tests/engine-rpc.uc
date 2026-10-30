import * as engines from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/engine-model.uc';

let context, commands, principal_allowed, locked, writes;
let fs = {
	open: (path, mode, permission) => ({ lock: mode => mode == 'u' ? true : !locked, close: () => {} }),
	lstat: path => ({ type: 'file', uid: 0, nlink: 1, mode: 0o600, inode: 1 })
};
let store = { target: path => {}, file_metadata: info => true };
let registry = { snapshot_context: value => context };
function state() { return {}; };
function principal_current(value) { return principal_allowed; };
function fail(code) { die(code); };
function read(path, limit) { return { schema: 1, revision: context.stopIntent }; };
function write(path, value) {
	if (path != '/etc/foxhole/engine-intent.json') die('unexpected_write');
	context.stopIntent = value.revision; writes++;
};
function system(argv, timeout) { push(commands, argv); return 0; };
// Actual stop-intent and restart guard are injected here.
let passed = 0, failed = 0;
function equal(a, b) { if (sprintf('%J', a) != sprintf('%J', b)) die('assertion'); };
function test(name, fn) {
	context = { routerId: 'router-a', bootId: 'boot-a', activeProfileId: 'server-same',
		activeConfigSha256: 'config-a', stopIntent: 7 };
	commands = []; writes = 0; principal_allowed = true; locked = false;
	let job = { principal: {}, plan: { binding: json(sprintf('%J', context)) } };
	try { fn(job); passed++; print('ok ', name, '\n'); }
	catch (error) { failed++; print('not ok ', name, ': ', sprintf('%J', error), '\n'); }
};
test('accepted user STOP prevents a background start even with the same profile id', job => {
	stop_intent();
	equal(context.activeProfileId, 'server-same'); equal(writes, 1);
	equal(start_if_allowed(job, 'start'), false); equal(commands, []);
});
test('changed profile configuration prevents background reconnect', job => {
	context.activeConfigSha256 = 'config-b';
	equal(start_if_allowed(job, 'restart'), false); equal(commands, []);
});
test('another state mutation holding the lock prevents deferred start', job => {
	locked = true;
	equal(start_if_allowed(job, 'start'), false); equal(commands, []);
});
test('revoked controlling principal cannot restart VPN', job => {
	principal_allowed = false;
	equal(start_if_allowed(job, 'restart'), false); equal(commands, []);
});
test('unchanged confirmed router intent starts exactly the owned service', job => {
	equal(start_if_allowed(job, 'start'), true);
	equal(commands, [['/etc/init.d/foxhole-runtime', 'start']]);
});
print('1..', passed + failed, '\n# Engine STOP/restart RPC tests: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
