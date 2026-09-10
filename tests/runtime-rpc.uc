import * as model from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/model.uc';
import * as runtime_model from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/runtime-model.uc';

const STATE_PATH = '/in-memory/state';
let state, writes, restarts, session_calls, reject_second_session;

function clone(value) {
	return json(sprintf('%J', value));
};

function fail(code) {
	die(code);
};

function session(request) {
	session_calls++;
	if (request.args.token != 'fixture-token' ||
	    (reject_second_session && session_calls > 1))
		fail('unauthorized');
};

function valid_revision(value) {
	if (type(value) != 'int' || value < 0) fail('revision_conflict');
	return value;
};

function state_record() {
	return clone(state);
};

function locked(fn) {
	return fn();
};

function write_json(path, value, mode) {
	if (path != STATE_PATH || mode != 0o600) die('unexpected_write');
	writes++;
	state = clone(value);
};

function restart_runtime(value) {
	restarts++;
	if (sprintf('%J', value) != sprintf('%J', state))
		die('unexpected_restart_state');
	return true;
};

function public_state(value) {
	return model.public_state(value);
};

function next_id(kind) {
	return kind + '-000000000002';
};

// Runtime RPC implementations are injected without services.

function reset() {
	state = model.defaults();
	state.revision = 5;
	state.servers = [{
		id: 'server-000000000001', name: 'Example',
		endpoint: 'example.com:443',
		config: 'hy2://fixture@example.com:443/#Example'
	}];
	writes = 0;
	restarts = 0;
	session_calls = 0;
	reject_second_session = false;
};

function request(extra) {
	return { args: {
		token: 'fixture-token', revision: 5,
		id: 'server-000000000001', ...extra
	} };
};

function equal(actual, expected) {
	if (sprintf('%J', actual) != sprintf('%J', expected))
		die('assertion_failed');
};

function rejects(fn, code) {
	let caught = null;
	try { fn(); } catch (error) {
		caught = type(error) == 'string' ? error : error.message;
	}
	equal(caught, code);
};

let passed = 0, failed = 0;

function test(name, fn) {
	reset();
	try {
		fn();
		passed++;
		print('ok ', passed + failed, ' - ', name, '\n');
	} catch (error) {
		failed++;
		print('not ok ', passed + failed, ' - ', name, '\n');
		print('# ', sprintf('%J', error), '\n');
	}
};

test('server name survives save and Unicode overflow cannot write', () => {
	reset();
	let config = 'hy2://fixture@example.com:443/#Imported';
	let result = save_server(request({ name: 'АБВГДЕЖЗИКЛМН', config }));
	equal(result.servers[0].name, 'АБВГДЕЖЗИКЛМН');
	equal(state.servers[0].name, 'АБВГДЕЖЗИКЛМН');
	equal(writes, 1);
	rejects(() => save_server(request({ revision: 6,
		name: 'АБВГДЕЖЗИКЛМНО', config })), 'invalid_name');
	equal(writes, 1);
});

test('new server uses default name without leaking config fragment', () => {
	reset();
	let config = 'hy2://fixture@example.com:443/#Imported';
	let result = save_server(request({ id: '', config }));
	equal(result.servers[1].name, 'VPN SERVER 01');
});

test('start stores one desired server before restarting runtime', () => {
	let result = start_server(request({}));
	equal(state.activeServerId, 'server-000000000001');
	equal(state.revision, 6);
	equal(result.revision, 6);
	equal(result.runtime.desiredServerId, 'server-000000000001');
	equal(writes, 1);
	equal(restarts, 1);
	equal(session_calls, 2);
});

test('restarting an already desired server is idempotent', () => {
	state.activeServerId = 'server-000000000001';
	let result = start_server(request({}));
	equal(result.revision, 5);
	equal(writes, 0);
	equal(restarts, 1);
});

test('stop clears desired server and restarts policy', () => {
	state.activeServerId = 'server-000000000001';
	let result = stop_server(request({}));
	equal(state.activeServerId, null);
	equal(result.revision, 6);
	equal(writes, 1);
	equal(restarts, 1);
});

test('stale revision cannot start or restart runtime', () => {
	rejects(() => start_server(request({ revision: 4 })),
		'revision_conflict');
	equal(writes, 0);
	equal(restarts, 0);
});

test('missing server cannot mutate desired state', () => {
	rejects(() => start_server(request({
		id: 'server-000000000002'
	})), 'not_found');
	equal(writes, 0);
	equal(restarts, 0);
});

test('inbound client routing permits the upstream tunnel', () => {
	state.settings.clientRules = true;
	start_server(request({}));
	equal(writes, 1);
	equal(restarts, 1);
});

test('session is revalidated while runtime state is locked', () => {
	reject_second_session = true;
	rejects(() => start_server(request({})), 'unauthorized');
	equal(writes, 0);
	equal(restarts, 0);
});

print('1..', passed + failed, '\n');
print('# runtime RPC tests: ', passed, ' passed, ', failed,
	' failed\n');
exit(failed ? 1 : 0);
