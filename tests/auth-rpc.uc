import * as pairing from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/pairing.uc';
import * as digest from 'digest';

let sessions = {}, setup = true, stored = null, locked_depth = 0;
let bootstrap = null;
let paired_record = pairing.defaults(), token_number = 0;
let failures = { count: 0, since: 0 };
const TOKEN_TTL = 1800;
const LICENSE_VERSION = 1;
const LICENSE_RECORD_PATH = '/etc/foxhole/license.json';
const FAILURE_WINDOW = 60, FAILURE_LIMIT = 8;
const PAIRING_PATH = '/etc/foxhole/pairing.json';
const AUTH_PATH = '/etc/foxhole/auth.json';
const PAIR_ID = 'pair-0123456789abcdef0123456789abcdef';
const PAIR_KEY = digest.sha256('synthetic pairing fixture');
function fail(code) { die(code); };
function error_code(error) {
	return type(error) == 'string' ? error : error.message;
};
function user_of(request) { return request.user || 'root'; };
function random_hex(bytes) { return sprintf('%064x', ++token_number); };
function auth_record() { return { ...(bootstrap || {}), changed: !setup }; };
function check_pin(pin) {
	if (pin != '5678' || bootstrap?.bootstrapConsumed == true)
		fail('invalid_pin');
};
function pairing_record() { return paired_record; };
function state_record() { return {}; };
function public_state(state) { return state; };
function read_json(path, maximum) {
	if (path != LICENSE_RECORD_PATH || maximum != 4096)
		die('unexpected_license_read');
	return null;
};
function write_json(path, value, mode) {
	if (locked_depth && path == AUTH_PATH && mode == 0o600) {
		bootstrap = value;
		return;
	}
	if (!locked_depth || path != PAIRING_PATH || mode != 0o600)
		die('invalid_pairing_write');
	paired_record = value;
};
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
	paired_record = pairing.defaults();
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
function revoke_handoff(id) {};
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
	bootstrap = null;
	paired_record = pairing.defaults(); failures = { count: 0, since: 0 };
	try { fn(); passed++; print('ok ', passed + failed, ' - ', name, '\n'); }
	catch (error) { failed++; print('not ok ', passed + failed, ' - ', name, ': ', error, '\n'); }
};
test('fresh bootstrap is consumed while retaining mandatory PIN setup', () => {
	bootstrap = { bootstrapExpiresUptimeMs: 10000, bootstrapConsumed: false };
	let result = unlock({ args: { pin: '5678' } });
	equal(result.pinChangeRequired, true);
	equal(result.licenseRequired, true);
	equal(result.licenseVersion, LICENSE_VERSION);
	equal(bootstrap.bootstrapConsumed, true);
	rejects(() => unlock({ args: { pin: '5678' } }), 'invalid_pin');
	rejects(() => session({ args: { token: result.token } }), 'pin_required');
	change_pin({ args: { token: result.token, newPin: '6789',
		licenseAccepted: true, licenseVersion: LICENSE_VERSION } });
	equal(stored, '6789');
});
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
test('pairing requires a changed PIN and never accepts short PIN credentials', () => {
	let token = new_token('root');
	let request = { args: { token, id: PAIR_ID,
		credential: PAIR_KEY, name: 'Phone' } };
	rejects(() => pair_create(request), 'pin_required');
	setup = false; sessions[token].setup = false;
	request.args.credential = '1234';
	rejects(() => pair_create(request), 'invalid_pairing');
	request.args.credential = PAIR_KEY;
	equal(pair_create(request), { id: PAIR_ID });
	equal(pair_create(request), { id: PAIR_ID });
	equal(length(paired_record.devices), 1);
});
test('paired sessions cannot delegate or change PIN and revoke immediately', () => {
	setup = false;
	paired_record = pairing.register(paired_record, PAIR_ID, PAIR_KEY,
		'Phone', 10);
	let reply = pair_unlock({ args: { id: PAIR_ID,
		credential: PAIR_KEY } });
	equal(substr(reply.token, 0, 3), 'p1.');
	let request = { args: { token: reply.token, id: PAIR_ID,
		credential: PAIR_KEY, name: 'Phone', newPin: '5678' } };
	rejects(() => pair_create(request), 'unauthorized');
	rejects(() => change_pin(request), 'unauthorized');
	equal(pair_revoke(request), {});
	rejects(() => session(request), 'unauthorized');
	rejects(() => pair_unlock({ args: { id: PAIR_ID,
		credential: PAIR_KEY } }), 'unauthorized');
});
test('key login shares the bounded failure window and rejects unknown devices', () => {
	setup = false;
	for (let i = 0; i < FAILURE_LIMIT; i++)
		rejects(() => pair_unlock({ args: { id: PAIR_ID,
			credential: PAIR_KEY } }), 'unauthorized');
	rejects(() => pair_unlock({ args: { id: PAIR_ID,
		credential: PAIR_KEY } }), 'locked');
});
print('1..', passed + failed, '\n');
print('# authentication tests: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
