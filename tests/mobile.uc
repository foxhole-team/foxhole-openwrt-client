import * as mobile from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/mobile.uc';
import * as remote from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/remote.uc';
import * as inbound from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/inbound.uc';
import * as model from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/model.uc';
import * as digest from 'digest';

let passed = 0, failed = 0, sequence = 0;
const paired = { id: 'pair-0123456789abcdef0123456789abcdef',
	verifier: digest.sha256('synthetic verifier') };
const args = { name: 'Phone', address: '192.168.1.101',
	mac: '02:01:02:03:04:05', createRemote: false };
function random_hex(bytes) {
	return substr(sprintf('%064x', ++sequence), 64 - bytes * 2);
};
function equal(actual, expected) {
	if (sprintf('%J', actual) != sprintf('%J', expected)) die('assertion');
};
function rejects(fn, expected) {
	let result = null;
	try { fn(); } catch (error) {
		result = type(error) == 'string' ? error : error.message;
	}
	equal(result, expected);
};
function test(name, fn) {
	try { fn(); passed++; print('ok ', name, '\n'); }
	catch (error) { failed++; print('not ok ', name, ': ',
		type(error) == 'string' ? error : error.message, '\n'); }
};
test('automatic remote setup requires public WAN and pinned separate TLS identity', () => {
	let address = remote.wan_address({ up: true, 'ipv4-address': [{ address: '1.1.1.1' }] });
	let base = remote.template(address, digest.sha256('synthetic remote certificate'));
	let uri = inbound.profile(base, { id: 'client-0123456789ab', name: 'Phone',
		secret: sprintf('%064x', 7), port: 14443, allowLan: false }).uri;
	equal(index(uri, 'pinSHA256=') >= 0, true);
	equal(index(uri, 'insecure=1'), -1);
	for (let value in ['192.168.1.1', '100.64.0.1', '203.0.113.1'])
		rejects(() => remote.wan_address({ up: true, 'ipv4-address': [{ address: value }] }),
			'public_address_required');
});
test('mobile listener binds only a live private LAN address', () => {
	let status = { up: true, l3_device: 'br-lan',
		'ipv4-address': [{ address: '192.168.1.1' }] };
	equal(mobile.lan_listener(status), {
		address: '192.168.1.1', device: 'br-lan', port: 8443 });
	for (let address in ['203.0.113.1', '127.0.0.1', '169.254.1.1']) {
		status['ipv4-address'][0].address = address;
		rejects(() => mobile.lan_listener(status), 'lan_unavailable');
	}
	status.up = false;
	rejects(() => mobile.lan_listener(status), 'lan_unavailable');
});
test('a lost phone provision reply cannot create a second LAN device', () => {
	let first = mobile.prepare(model.defaults(), null, paired, args,
		null, random_hex);
	let applied = mobile.apply(model.defaults(), first.phone);
	let retry = mobile.prepare(applied.state, first.record, paired,
		args, null, random_hex);
	equal(retry.phone, first.phone);
	equal(mobile.apply(applied.state, retry.phone), {
		state: applied.state, changed: false });
	equal(length(applied.state.devices), 1);
});
test('a reused pairing ID cannot receive the old phone credentials', () => {
	let first = mobile.prepare(model.defaults(), null, paired, args,
		null, random_hex);
	let replaced = { ...paired, verifier: digest.sha256('other verifier') };
	rejects(() => mobile.prepare(model.defaults(), first.record,
		replaced, args, null, random_hex), 'pairing_conflict');
	rejects(() => mobile.prepare(model.defaults(), first.record, paired,
		{ ...args, mac: '02:01:02:03:04:06' }, null, random_hex),
		'pairing_conflict');
});
test('a DHCP address change preserves the same MAC-owned phone', () => {
	let first = mobile.prepare(model.defaults(), null, paired, args,
		null, random_hex);
	let retry = mobile.prepare(model.defaults(), first.record, paired,
		{ ...args, address: '192.168.1.102' }, null, random_hex);
	equal(retry.phone.lanDeviceId, first.phone.lanDeviceId);
});
test('PIN-reset or revoked pairings do not exhaust the journal forever', () => {
	let first = mobile.prepare(model.defaults(), null, paired, args,
		null, random_hex);
	equal(mobile.prune(first.record, { schema: 1, devices: [] }),
		{ schema: 1, phones: [] });
});
test('remote registration can be selected independently from a LAN rule', () => {
	let first = mobile.prepare(model.defaults(), null, paired,
		{ ...args, registerPhone: false, createRemote: true },
		{ listenerMode: 'per-client', firstPort: 14443 }, random_hex);
	let applied = mobile.apply(model.defaults(), first.phone);
	equal(length(applied.state.devices), 0);
	equal(length(applied.state.clients), 1);
});
test('remote profile requires a configured inbound instead of upstream secrets', () => {
	rejects(() => mobile.prepare(model.defaults(), null, paired,
		{ ...args, createRemote: true }, null, random_hex),
		'inbound_required');
});
test('prepared remote credentials and ports remain stable after a retry', () => {
	let base = { listenerMode: 'per-client', firstPort: 14443 };
	let first = mobile.prepare(model.defaults(), null, paired,
		{ ...args, createRemote: true }, base, random_hex);
	let applied = mobile.apply(model.defaults(), first.phone);
	let retry = mobile.prepare(applied.state, first.record, paired,
		{ ...args, createRemote: true }, base, random_hex);
	equal(first.phone, retry.phone);
	equal(length(mobile.apply(applied.state, retry.phone).state.clients), 1);
	equal(first.phone.remotePort, 14443);
	equal(length(first.phone.remoteSecret), 64);
});
test('registration refuses a conflicting existing LAN device', () => {
	let first = mobile.prepare(model.defaults(), null, paired, args,
		null, random_hex);
	let applied = mobile.apply(model.defaults(), first.phone);
	applied.state.devices[0].route = 'direct';
	rejects(() => mobile.apply(applied.state, first.phone),
		'pairing_conflict');
});
test('an old provision retry cannot restore deliberately revoked remote access', () => {
	let base = { listenerMode: 'per-client', firstPort: 14443 };
	let first = mobile.prepare(model.defaults(), null, paired,
		{ ...args, createRemote: true }, base, random_hex);
	first.record.phones[0].remoteRevoked = true;
	rejects(() => mobile.prepare(model.defaults(), first.record, paired,
		{ ...args, createRemote: true }, base, random_hex), 'client_revoked');
});
print('# mobile tests: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
