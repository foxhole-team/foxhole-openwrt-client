import * as model from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/model.uc';
import * as pairing from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/pairing.uc';
import * as digest from 'digest';

const STATE_PATH = '/etc/foxhole/state.json';
const AUTH_PATH = '/etc/foxhole/auth.json';
const PAIRING_PATH = '/etc/foxhole/pairing.json';
const MOBILE_PATH = '/etc/foxhole/mobile.json';
const MAX_STATE = 262144, TOKEN_TTL = 1800;
const LICENSE_VERSION = 1;
const LICENSE_RECORD_PATH = '/etc/foxhole/license.json';
const FAILURE_WINDOW = 60, FAILURE_LIMIT = 8;
const RUNTIME_INIT = '/etc/init.d/foxhole-runtime';
const OLD_PIN = '5678', PAIR_ID = 'pair-0123456789abcdef0123456789abcdef';
const PAIR_KEY = digest.sha256('synthetic setup-pair fixture');
let records, sessions, failures, writes, commands, handoffs, sequence;
let locked_depth, stop_failed, corrupt_write, inbound_present;
let permitted = false, deferred;
function fail(code) { die(code); };
function copy(value) { return value == null ? null : json(sprintf('%J', value)); };
function user_of(request) { return request.user || 'root'; };
function random_hex(bytes) { return substr(sprintf('%064x', ++sequence), 0, bytes * 2); };
function read_json(path, limit) { return copy(records[path]); };
function write_json(path, value, mode) {
	if (!locked_depth || mode != 0o600 || index([
		STATE_PATH, AUTH_PATH, PAIRING_PATH, MOBILE_PATH], path) < 0)
		die('unexpected_write');
	push(writes, path);
	if (path != corrupt_write) records[path] = copy(value);
};
function locked(fn) {
	locked_depth++;
	try { let result = fn(); locked_depth--; return result; }
	catch (error) { locked_depth--; die(error); }
};
function state_record() { return copy(records[STATE_PATH]); };
function pairing_record() { return copy(records[PAIRING_PATH]); };
function revoke_handoff(id) { if (!locked_depth) die('unlocked_handoff'); handoffs++; };
function system(argv, timeout) {
	if (!locked_depth || timeout != 10000 || argv[1] != 'stop' ||
	    index([RUNTIME_INIT, '/etc/init.d/foxhole-inbound'], argv[0]) < 0)
		die('unexpected_command');
	push(commands, copy(argv));
	return stop_failed ? 1 : 0;
};
let fs = {
	readfile: (path, limit) => path == '/proc/uptime' ? '1.00 0.00' : 'synthetic-boot',
	lstat: path => {
		if (path != '/etc/foxhole/inbound.json') die('unexpected_stat');
		return inbound_present ? { type: 'file' } : null;
	},
	unlink: path => {
		if (path != '/etc/foxhole/inbound.json') die('unexpected_delete');
		inbound_present = false; return true;
	}
};
let store = { target: path => {
	if (path != '/etc/foxhole/inbound.json') die('unexpected_target');
} };
function safe(fn) { try { return fn(); } catch (error) { return { _foxhole_error: error }; } };
let ubus = { connect: () => ({
	defer: (object, method, args, callback) => {
		if (object != 'session' || method != 'access' || args.scope != 'ubus' ||
		    args.object != 'foxhole.admin' || args.function != 'set_pin') die('unexpected_acl');
		deferred = () => callback(0, { access: permitted }); return 'pending';
	}, disconnect: () => {}
}) };
// Setup RPC implementations use isolated storage and services.
function equal(actual, expected, label) {
	if (sprintf('%J', actual) != sprintf('%J', expected)) die(label || 'assertion');
};
function rejects(fn, expected) {
	let caught = null;
	try { fn(); } catch (error) { caught = error; }
	equal(caught, expected, 'wrong_refusal');
};
function reset_request(token) { return { args: { token, revision: 7, confirm: true } }; };
let passed = 0, failed = 0;
function test(name, fn) {
	records = { [STATE_PATH]: { ...model.defaults(), revision: 7,
		servers: [{ id: 'server-old', config: 'synthetic' }], clients: [{ id: 'client-old' }] },
		[AUTH_PATH]: { schema: 1, salt: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
			hash: digest.sha256('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:' + OLD_PIN), changed: true },
		[PAIRING_PATH]: pairing.register(pairing.defaults(), PAIR_ID, PAIR_KEY, 'Phone', 10),
		[MOBILE_PATH]: { schema: 1, phones: [{ pairId: PAIR_ID }] },
		'/etc/foxhole/mobile-tls.key': 'synthetic TLS identity',
		'/etc/config/network': 'synthetic OS network', '/etc/shadow': 'synthetic root password' };
	sessions = {}; failures = { count: 0, since: 0 }; writes = []; commands = [];
	handoffs = 0; sequence = 0; locked_depth = 0; stop_failed = false;
	corrupt_write = null; inbound_present = true; permitted = false;
	try { fn(); passed++; print('ok ', passed + failed, ' - ', name, '\n'); }
	catch (error) { failed++; print('not ok ', passed + failed, ' - ', name, ': ', error, '\n'); }
};
test('missing auth has no default PIN and metadata performs no writes', () => {
	delete records[AUTH_PATH];
	equal(package_status({}), { schema: 1, product: 'foxhole', installed: true,
		pinConfigured: false, resetSupported: true, packageUpdates: true, licenseRequired: true, licenseVersion: 1 });
	rejects(() => check_pin('1234'), 'pin_setup_required');
	equal(writes, []); equal(length(keys(sessions)), 0);
});
test('legacy unconfigured default auth cannot grant a PIN session', () => {
	records[AUTH_PATH].changed = false;
	records[AUTH_PATH].hash = pin_hash(records[AUTH_PATH].salt, '1234');
	rejects(() => check_pin('1234'), 'invalid_pin');
	equal(writes, []);
});
test('direct-install first PIN requires a genuine deferred LuCI owner ACL', () => {
	delete records[AUTH_PATH]; let response;
	let request = { args: { ubus_rpc_session: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', newPin: '6789', licenseAccepted: true, licenseVersion: 1 },
		reply: value => { response = value; } };
	rejects(() => admin_pin({ args: { ubus_rpc_session: '00000000000000000000000000000000', newPin: '6789' } }), 'unauthorized');
	equal(admin_pin(request), 'pending'); deferred();
	equal(response._foxhole_error, 'unauthorized'); equal(writes, []);
	permitted = true; equal(admin_pin(request), 'pending'); deferred();
	equal(response.changed, true); equal(auth_record().changed, true);
	equal(check_pin('6789'), true); equal(package_status({}).pinConfigured, true);
});
test('reset requires old-PIN admin session, explicit consent and exact revision', () => {
	rejects(() => setup_reset(reset_request('f')), 'unauthorized');
	let paired = new_token('root', { id: PAIR_ID, verifier: records[PAIRING_PATH].devices[0].hash });
	rejects(() => setup_reset(reset_request(paired)), 'unauthorized');
	let token = new_token('root'), request = reset_request(token);
	for (let consent in [false, null, 'true', 1]) {
		request.args.confirm = consent;
		rejects(() => setup_reset(request), 'unauthorized');
	}
	request.args.confirm = true; request.args.revision = 6;
	rejects(() => setup_reset(request), 'revision_conflict');
	equal(commands, []); equal(writes, []); equal(handoffs, 0);
});
test('reset clears owned data, preserves TLS and OS identity and restricts new PIN session', () => {
	let preserved = [records['/etc/foxhole/mobile-tls.key'], records['/etc/config/network'], records['/etc/shadow']];
	let token = new_token('root'), request = reset_request(token);
	let result = setup_reset(request);
	equal(result.schema, 1); equal(result.scope, 'foxhole'); equal(result.reset, true);
	equal(result.revision, 8); equal(result.pinChangeRequired, true);
	equal(commands, [[RUNTIME_INIT, 'stop'], ['/etc/init.d/foxhole-inbound', 'stop']]);
	equal(records[STATE_PATH], { ...model.defaults(), revision: 8 });
	equal(records[PAIRING_PATH], pairing.defaults()); equal(records[MOBILE_PATH].phones, []);
	equal(inbound_present, false);
	equal([records['/etc/foxhole/mobile-tls.key'], records['/etc/config/network'], records['/etc/shadow']], preserved);
	rejects(() => session(request), 'unauthorized');
	rejects(() => check_pin(OLD_PIN), 'invalid_pin');
	let restricted = { args: { token: result.token, newPin: '7890', licenseAccepted: true, licenseVersion: 1 } };
	rejects(() => session(restricted), 'pin_required');
	let deadline = sessions[result.token].expires;
	equal(session(restricted, true), result.token);
	equal(sessions[result.token].expires, deadline, 'setup_deadline_extended');
	if (sessions[result.token].expires < time() + 299 || sessions[result.token].expires > time() + 300)
		die('reset_session_not_bounded');
	let ready = change_pin(restricted);
	equal(check_pin('7890'), true); equal(sessions[ready.token].setup, false);
	equal(pair_create({ args: { token: ready.token, id: PAIR_ID, credential: PAIR_KEY, name: 'Phone' } }), { id: PAIR_ID });
});
test('failed owned runtime stop never acknowledges or clears configuration', () => {
	let before = copy(records); stop_failed = true;
	rejects(() => setup_reset(reset_request(new_token('root'))), 'unavailable');
	equal(records, before); equal(writes, []); equal(inbound_present, true);
});
test('failed readback cannot issue a reset acknowledgment or setup token', () => {
	let token = new_token('root'); corrupt_write = MOBILE_PATH;
	rejects(() => setup_reset(reset_request(token)), 'storage_error');
	equal(length(keys(sessions)), 0);
	rejects(() => session({ args: { token } }), 'unauthorized');
});
test('restricted reset session expires and cannot reset again', () => {
	let result = setup_reset(reset_request(new_token('root')));
	rejects(() => setup_reset(reset_request(result.token)), 'pin_required');
	sessions[result.token].expires = time() - 1;
	rejects(() => change_pin({ args: { token: result.token, newPin: '7890' } }), 'unauthorized');
});
print('1..', passed + failed, '\n');
print('# setup tests: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
