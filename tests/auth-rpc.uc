let sessions = {}, setup = true, stored = null, locked_depth = 0;
const TOKEN_TTL = 1800;
function fail(code) { die(code); };
function user_of(request) { return request.user || 'root'; };
function random_hex(bytes) { return substr('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 0, bytes * 2); };
function auth_record() { return { changed: !setup }; };
function locked(fn) {
	locked_depth++;
	try {
		let value = fn();
		locked_depth--;
		return value;
	} catch (error) { locked_depth--; die(error); }
};
function store_pin(pin) {
	if (!locked_depth) die('write_without_lock');
	stored = pin;
	setup = false;
	sessions = {};
};
function safe(fn) {
	try { return fn(); } catch (error) { return { _foxhole_error: error }; }
};
let deferred, permitted = false;
let ubus = { connect: () => ({
	defer: (object, method, args, callback) => {
		deferred = () => callback(0, { access: permitted });
		return 'pending';
	},
	disconnect: () => {}
}) };
// Authentication uses isolated sessions and storage.
function equal(value, expected) {
	if (sprintf('%J', value) != sprintf('%J', expected)) die('assertion');
};
function rejects(fn, expected) {
	let caught = null;
	try { fn(); } catch (error) { caught = error; }
	equal(caught, expected);
};
let passed = 0, failed = 0;
function test(name, fn) {
	sessions = {}; setup = true; stored = null;
	try { fn(); passed++; print('ok ', passed + failed, ' - ', name, '\n'); }
	catch (error) { failed++; print('not ok ', passed + failed, ' - ', name, ': ', error, '\n'); }
};
test('bootstrap token cannot authorize ordinary operations', () => {
	let token = new_token('root'), request = { args: { token } };
	rejects(() => session(request), 'pin_required');
	equal(session(request, true), token);
});
test('PIN setup replaces the restricted session inside the state lock', () => {
	let token = new_token('root');
	let result = change_pin({ args: { token, newPin: '5678' } });
	equal(stored, '5678');
	equal(sessions[result.token].setup, false);
	equal(session({ args: { token: result.token } }), result.token);
});
test('foreign and expired sessions cannot set PIN', () => {
	let token = new_token('root');
	rejects(() => session({ user: 'guest', args: { token } }, true),
		'unauthorized');
	sessions[token].expires = time() - 1;
	rejects(() => session({ args: { token } }, true), 'unauthorized');
});
test('LuCI recovery waits for deferred access before acquiring the lock', () => {
	let reply;
	let request = { args: { ubus_rpc_session: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', newPin: '5678' },
		reply: value => { reply = value; } };
	permitted = false;
	equal(admin_pin(request), 'pending');
	equal(stored, null);
	equal(locked_depth, 0);
	deferred();
	equal(reply._foxhole_error, 'unauthorized');
	equal(stored, null);
	permitted = true;
	equal(admin_pin(request), 'pending');
	deferred();
	equal(reply.changed, true);
	equal(stored, '5678');
});
print('1..', passed + failed, '\n');
print('# authentication tests: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
