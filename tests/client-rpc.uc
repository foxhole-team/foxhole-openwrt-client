import * as model from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/model.uc';

const STATE_PATH = '/in-memory/state';
let state, writes = 0, session_calls = 0, reject_second_session = false;

function clone(value) {
	return json(sprintf('%J', value));
};

function fail(code) {
	die(code);
};

function session(request) {
	session_calls++;
	if (request.args.token != 'fixture-token' ||
		(reject_second_session && session_calls > 1)) fail('unauthorized');
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

function public_state(value) {
	return model.public_state(value);
};

function qr_svg(_) {
	return 'in-memory-fixture';
};

// RPC implementations are injected without loading system state.

function reset() {
	state = model.defaults();
	state.revision = 3;
	state.servers = [{ id: 'server-000000000001', name: 'Example',
		endpoint: 'example.com:443',
		config: 'hy2://fixture@example.com:443/#Example' }];
	state.clients = [{ id: 'client-000000000001', name: 'Phone',
		deviceType: 'smartphone', serverId: state.servers[0].id,
		provisioned: false }];
	writes = 0;
	session_calls = 0;
	reject_second_session = false;
};

function request(extra) {
	return { args: { token: 'fixture-token', revision: 3,
		id: 'client-000000000001', name: '  Travel phone  ', ...extra } };
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
	} catch (_) {
		failed++;
		print('not ok ', passed + failed, ' - ', name, '\n');
	}
};

test('rename preserves client identity and current upstream export', () => {
	let original = clone(state);
	let result = update_client(request({
		deviceType: 'computer', serverId: null
	}));
	equal(result.state.revision, 4);
	equal(writes, 1);
	equal(session_calls, 2);
	equal(length(state.clients), 1);
	equal(state.clients[0].name, 'Travel phone');
	for (let key in ['id', 'deviceType', 'serverId', 'provisioned'])
		equal(state.clients[0][key], original.clients[0][key]);
	equal(state.servers, original.servers);
	equal(result.client.name, 'Travel phone');
	equal(result.client.qrSvg, 'in-memory-fixture');
	equal(model.parse_config(result.client.uri).name, 'Travel phone');
	equal(model.parse_config(result.client.uri).config,
		model.parse_config(original.servers[0].config).config);
});

test('stale revisions reject without writes', () => {
	let original = clone(state);
	rejects(() => update_client(request({ revision: 2 })), 'revision_conflict');
	equal(writes, 0);
	equal(state, original);
});

test('revision conflict prevents a second competing rename', () => {
	update_client(request({ name: 'First name' }));
	rejects(() => update_client(request({ name: 'Second name' })),
		'revision_conflict');
	equal(writes, 1);
	equal(state.clients[0].name, 'First name');
});

test('missing client rejects without writes', () => {
	let original = clone(state);
	rejects(() => update_client(request({ id: 'client-000000000002' })),
		'not_found');
	equal(writes, 0);
	equal(state, original);
});

test('invalid names cannot mutate the state', () => {
	let original = clone(state);
	for (let name in ['', '  ', 'Phone\nname', 'Phone' + chr(0),
		'1234567812345678123456781234567812345678123456789'])
		rejects(() => update_client(request({ name })), 'invalid_name');
	equal(writes, 0);
	equal(state, original);
});

test('missing authentication rejects without writes', () => {
	rejects(() => update_client(request({ token: '' })), 'unauthorized');
	equal(writes, 0);
});

test('session is revalidated inside the state lock', () => {
	reject_second_session = true;
	rejects(() => update_client(request({})), 'unauthorized');
	equal(writes, 0);
});

test('inactive profiles remain inactive after a rename', () => {
	state.servers = [];
	state.clients[0].serverId = null;
	let result = update_client(request({}));
	equal(result.client.inactive, true);
	equal(result.client.serverId, null);
	equal(result.client.name, 'Travel phone');
});

print('1..', passed + failed, '\n');
print('# client RPC tests: ', passed, ' passed, ', failed, ' failed\n');
if (failed) exit(1);
