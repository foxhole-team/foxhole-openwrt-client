import * as devices from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/device-model.uc';

let passed = 0, failed = 0, checkpoint = 'start';
function test(name, fn) {
	checkpoint = 'start';
	try { fn(); passed++; print('ok ', name, '\n'); }
	catch (_) { failed++; print('not ok ', name, ' [', checkpoint, ']\n'); }
};
function equal(actual, expected) {
	if (sprintf('%J', actual) != sprintf('%J', expected)) die('assertion');
};
const MAC = '02:01:02:03:04:05';
function row(state, mac) {
	return '192.168.1.20 dev br-lan' + (mac ? ' lladdr ' + mac : '') + ' ' + state;
};
test('online requires a reachable matching kernel neighbor', () => {
	let record = devices.parse_neighbors(row('REACHABLE', MAC));
	equal(devices.online(record, '192.168.1.20', MAC), true);
	equal(devices.online(record, '192.168.1.20', '02:01:02:03:04:06'), null);
});
test('failed or incomplete resolution is explicit offline evidence', () => {
	for (let state in ['FAILED', 'INCOMPLETE'])
		equal(devices.online(devices.parse_neighbors(row(state)), '192.168.1.20', MAC), false);
});
test('a lease or stale delay probe neighbor never proves online', () => {
	for (let state in ['STALE', 'DELAY', 'PROBE'])
		equal(devices.online(devices.parse_neighbors(row(state, MAC)), '192.168.1.20', MAC), null);
	equal(devices.online([], '192.168.1.20', MAC), null);
});
test('duplicates malformed input and oversized output do not invent state', () => {
	let duplicate = devices.parse_neighbors(row('REACHABLE', MAC) + '\n' + row('REACHABLE', MAC));
	checkpoint = 'duplicate-neighbor';
	equal(devices.online(duplicate, '192.168.1.20', MAC), null);
	checkpoint = 'malformed-line';
	equal(devices.parse_neighbors('garbage REACHABLE'), []);
	checkpoint = 'malformed-mac';
	equal(devices.parse_neighbors(row('REACHABLE', 'invalid')), []);
	checkpoint = 'bounded-fixture-build';
	let padding = ' ';
	for (let i = 0; i < 18; i++) padding += padding;
	let permitted = substr(row('REACHABLE', MAC) + '\n' + padding, 0, 262144);
	let oversized = permitted + ' ';
	checkpoint = 'exact-fixture-byte-bounds';
	equal(length(permitted), 262144);
	equal(length(oversized), 262145);
	checkpoint = 'allowed-output-boundary';
	equal(devices.online(devices.parse_neighbors(permitted), '192.168.1.20', MAC), true);
	checkpoint = 'oversized-output-refused';
	equal(devices.parse_neighbors(oversized), []);
});
print('device-model: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
