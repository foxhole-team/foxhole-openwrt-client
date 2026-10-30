import * as pairing from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/pairing.uc';
import * as digest from 'digest';

let passed = 0, failed = 0;
const ID = 'pair-0123456789abcdef0123456789abcdef';
const KEY = digest.sha256('synthetic pairing fixture');
const WRONG_KEY = (substr(KEY, 0, 1) == '0' ? '1' : '0') + substr(KEY, 1);
function equal(actual, expected) {
	if (sprintf('%J', actual) != sprintf('%J', expected))
		die('assertion_failed');
};
function rejects(fn, expected) {
	let caught = null;
	try { fn(); } catch (error) {
		caught = type(error) == 'string' ? error : error.message;
	}
	equal(caught, expected);
};
function test(name, fn) {
	try { fn(); passed++; print('ok ', name, '\n'); }
	catch (_) { failed++; print('not ok ', name, '\n'); }
};
test('bootstrap requires current boot, monotonic deadline and unused credential', () => {
	let auth = { bootstrapConsumed: false, bootstrapExpiresUptimeMs: 20000,
		bootstrapBootId: 'synthetic-boot' };
	equal(pairing.bootstrap_valid(auth, '10.00 100.00', 'synthetic-boot'), true);
	equal(pairing.bootstrap_valid(auth, '21.00 100.00', 'synthetic-boot'), false);
	equal(pairing.bootstrap_valid(auth, '10.00 100.00', 'other-boot'), false);
	equal(pairing.bootstrap_valid(auth, null, 'synthetic-boot'), false);
	auth.bootstrapConsumed = true;
	equal(pairing.bootstrap_valid(auth, '10.00 100.00', 'synthetic-boot'), false);
});
test('pairing saves only a verifier and authenticates its own device', () => {
	let result = pairing.register(pairing.defaults(), ID, KEY, 'Phone', 10);
	equal(length(result.devices), 1);
	equal(index(sprintf('%J', result), KEY), -1);
	equal(pairing.authenticate(result, ID, KEY).id, ID);
	equal(pairing.public_devices(result), [{ id: ID, name: 'Phone', created: 10 }]);
	rejects(() => pairing.authenticate(result, ID, WRONG_KEY),
		'unauthorized');
});
test('retry is idempotent and cannot overwrite another device key', () => {
	let result = pairing.register(pairing.defaults(), ID, KEY, 'Phone', 10);
	equal(pairing.register(result, ID, KEY, 'Phone', 20), result);
	rejects(() => pairing.register(result, ID, WRONG_KEY,
		'Other', 20), 'pairing_conflict');
});
test('revocation invalidates the credential without changing other devices', () => {
	let result = pairing.register(pairing.defaults(), ID, KEY, 'Phone', 10);
	let removed = pairing.revoke(result, ID);
	equal(pairing.public_devices(removed), []);
	rejects(() => pairing.authenticate(removed, ID, KEY), 'unauthorized');
	equal(length(result.devices), 1);
});
test('short PINs are refused as pairing credentials and data stays bounded', () => {
	for (let credential in ['1234', '', KEY + 'f'])
		rejects(() => pairing.register(pairing.defaults(), ID, credential,
			'Phone', 10), 'invalid_pairing');
	for (let name in ['', 'bad\nname', sprintf('%0129d', 0)])
		rejects(() => pairing.register(pairing.defaults(), ID, KEY, name, 10),
			'invalid_pairing');
	rejects(() => pairing.public_devices({ schema: 2, devices: [] }),
		'storage_error');
});
test('revocation also fences short sessions after a device ID is reused', () => {
	let result = pairing.register(pairing.defaults(), ID, KEY, 'Phone', 10);
	let session = pairing.authenticate(result, ID, KEY);
	equal(pairing.session_current(result, session), true);
	let replaced = pairing.register(pairing.revoke(result, ID), ID,
		WRONG_KEY, 'Phone', 20);
	equal(pairing.session_current(replaced, session), false);
});
test('storage refuses duplicate devices and registration has a hard limit', () => {
	let record = pairing.defaults();
	for (let i = 0; i < 16; i++)
		record = pairing.register(record, sprintf('pair-%032x', i), KEY,
			'Phone', 10);
	rejects(() => pairing.register(record, ID, KEY, 'Phone', 10),
		'pairing_limit');
	let corrupt = pairing.defaults();
	corrupt.devices = [record.devices[0], record.devices[0]];
	rejects(() => pairing.public_devices(corrupt), 'storage_error');
});
test('every paired session action requires TLS as well as pairing login', () => {
	for (let action in ['pair.create', 'pair.unlock', 'pair.list', 'pair.revoke'])
		equal(pairing.requires_tls(action, null), true);
	for (let action in ['state', 'settings', 'server.save', 'client.get', 'lock'])
		equal(pairing.requires_tls(action, 'p1.' + KEY), true);
	equal(pairing.requires_tls('state', KEY), false);
	equal(pairing.requires_tls('state', null), false);
});
print('# pairing tests: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
