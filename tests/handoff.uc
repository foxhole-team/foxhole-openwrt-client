import * as handoff from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/handoff.uc';
import * as adapter from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/handoff-adapter.uc';
import * as pairing from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/pairing.uc';

let passed = 0, failed = 0;
const id = 'pair-0123456789abcdef0123456789abcdef';
const credential = sprintf('%064x', 42);
const pairs = pairing.register(pairing.defaults(), id, credential, 'Phone', 1);
const paired = pairing.authenticate(pairs, id, credential);
const boot = '01234567-89ab-cdef-0123-456789abcdef';
const phone = { pairId: id, verifier: paired.verifier, lanDeviceId: 'device-0123456789ab',
	address: '192.168.1.101', mac: '02:01:02:03:04:05' };
const args = { address: phone.address, claimId: '0123456789abcdef0123456789abcdef',
	mode: 'phone_vpn', leaseMs: 60000,
	upstreamTargets: [{ address: '1.1.1.1', port: 443, transport: 'tcp' }] };
function equal(a, b) { if (sprintf('%J', a) != sprintf('%J', b)) die('assertion'); };
function rejects(fn, code) {
	let found = null;
	try { fn(); } catch (error) { found = type(error) == 'string' ? error : error.message; }
	equal(found, code);
};
function test(name, fn) {
	try { fn(); passed++; print('ok ', name, '\n'); }
	catch (error) { failed++; print('not ok ', name, ': ', error, '\n'); }
};
function request(value, pairs, paired, phone, args, now, boot) {
	return handoff.request(value, pairs, paired, phone,
		{ ...args, requestUptimeMs: args.requestUptimeMs ?? now }, now, boot);
};
test('same claim renews without widening targets', () => {
	let first = request(null, pairs, paired, phone, args, 1000, boot);
	let renewed = request(first, pairs, paired, phone, args, 21000, boot);
	equal(length(renewed.leases), 1);
	equal(renewed.leases[0].expiresUptimeMs, 81000);
	rejects(() => request(first, pairs, paired, phone,
		{ ...args, upstreamTargets: [{ address: '8.8.8.8', port: 443, transport: 'tcp' }] },
		2000, boot), 'handoff_conflict');
	let replacement = request(first, pairs, paired, phone,
		{ ...args, claimId: '1123456789abcdef0123456789abcdef' }, 2000, boot);
	rejects(() => request(replacement, pairs, paired, phone, args,
		3000, boot), 'handoff_conflict');
});
test('delayed renewal cannot resurrect an expired newer claim', () => {
	let first = request(null, pairs, paired, phone, args, 1000, boot);
	let replacement = request(first, pairs, paired, phone,
		{ ...args, claimId: '1123456789abcdef0123456789abcdef' }, 2000, boot);
	rejects(() => request(replacement, pairs, paired, phone,
		{ ...args, requestUptimeMs: 1000 }, 62000, boot), 'invalid_handoff');
	rejects(() => request(null, pairs, paired, phone,
		{ ...args, requestUptimeMs: 72000 }, 62000, boot), 'invalid_handoff');
});
test('expiry, reboot and revocation fence a lease', () => {
	let first = request(null, pairs, paired, phone, args, 1000, boot);
	equal(length(handoff.active(first, pairs, 61000, boot)), 0);
	equal(length(handoff.active(first, pairs, 2000, '11234567-89ab-cdef-0123-456789abcdef')), 0);
	equal(length(handoff.active(first, pairing.revoke(pairs, id), 2000, boot)), 0);
});
test('pairing and registered phone ownership are mandatory', () => {
	for (let invalid in [{ ...phone, pairId: 'pair-1123456789abcdef0123456789abcdef' },
		{ ...phone, lanDeviceId: null }, { ...phone, address: '192.168.1.102' }])
		rejects(() => request(null, pairs, paired, invalid, args, 1000, boot), 'invalid_handoff');
});
test('private, transition and duplicate provider targets are refused', () => {
	for (let address in ['127.0.0.1', '192.168.1.1', '100.64.0.1', '203.0.113.1',
		'2001:db8::1', '2001::1', '2002:101:101::1'])
		rejects(() => handoff.targets([{ address, port: 443, transport: 'tcp' }]), 'invalid_handoff');
	rejects(() => handoff.targets([...args.upstreamTargets, ...args.upstreamTargets]), 'invalid_handoff');
});
test('router release requires exact generation and removes only the own lease', () => {
	let first = request(null, pairs, paired, phone, args, 1000, boot);
	rejects(() => request(first, pairs, paired, phone,
		{ ...args, mode: 'router_vpn' }, 2000, boot), 'invalid_handoff');
	let released = request(first, pairs, paired, phone,
		{ ...args, mode: 'router_vpn', expectedServerId: 'server-0123456789ab',
			expectedGeneration: 'ffffffffffffffff' }, 2000, boot);
	equal(length(released.leases), 0);
	rejects(() => request(released, pairs, paired, phone, args,
		3000, boot), 'handoff_conflict');
});
test('NFT marks only exact MAC/provider transport/port and expires in kernel', () => {
	let first = request(null, pairs, paired, phone, args, 1000, boot);
	let text = handoff.nft(first, pairs, 2000, 'br-lan', boot);
	equal(index(text, '02:01:02:03:04:05 . 1.1.1.1 . tcp . 443 timeout 59000ms') >= 0, true);
	equal(index(text, 'meta mark set meta mark & 0xf7ffffff') >= 0, true);
	rejects(() => handoff.nft(first, pairs, 2000, 'br-lan"; flush ruleset', boot), 'invalid_handoff');
});
test('readback requires actual expiring tuple rather than desired journal', () => {
	let first = request(null, pairs, paired, phone, args, 1000, boot);
	let actual = { nftables: [{ set: { family: 'inet', table: 'foxhole_handoff', name: 'upstream4',
		elem: [{ elem: { val: { concat: [phone.mac, '1.1.1.1', 'tcp', 443] }, timeout: 60000, expires: 50000 } }] } }] };
	equal(adapter.remaining(actual, first.leases[0]), 50000);
	actual.nftables[0].set.elem[0].elem.val.concat[3] = 444;
	equal(adapter.remaining(actual, first.leases[0]), 0);
});
test('unknown or permanent kernel elements cannot retain ownership', () => {
	let first = request(null, pairs, paired, phone, args, 1000, boot);
	let actual = { nftables: [{ set: { family: 'inet', table: 'foxhole_handoff', name: 'upstream4',
		elem: [{ elem: { val: { concat: [phone.mac, '1.1.1.1', 'tcp', 443] }, timeout: 60000, expires: 50000 } }] } }] };
	equal(adapter.elements_match(actual, first, pairs, boot), true);
	push(actual.nftables[0].set.elem, { elem: { val: { concat: [phone.mac, '8.8.8.8', 'tcp', 443] },
		timeout: 60000, expires: 50000 } });
	equal(adapter.elements_match(actual, first, pairs, boot), false);
	actual.nftables[0].set.elem = [actual.nftables[0].set.elem[0]];
	delete actual.nftables[0].set.elem[0].elem.expires;
	equal(adapter.elements_match(actual, first, pairs, boot), false);
});
test('failed journal persistence is unknown rather than confirmed absent', () => {
	let actual = { nftables: [{ table: { family: 'inet', name: 'foxhole_handoff' } }] };
	let record = { revision: 1 };
	let receipt = { bootId: boot, revision: 2, identity: adapter.structural_identity(actual) };
	equal(adapter.journal_matches(actual, receipt, record, boot), false);
	equal(adapter.journal_matches(null, receipt, record, boot), false);
	equal(adapter.journal_matches({ absent: true, nftables: [] }, receipt, record, boot), true);
});
test('bounded DNS answers cannot redirect provider bootstrap to local addresses', () => {
	let value = { Status: 0, TC: false, Question: [{ name: 'example.com', type: 1 }],
		Answer: [{ name: 'example.com', type: 1, TTL: 120, data: '1.1.1.1' }] };
	equal(handoff.dns_answer(value, 'example.com'), { addresses: ['1.1.1.1'], ttlMs: 60000 });
	value.Answer = [{ name: 'example.com', type: 5, TTL: 10, data: 'node.example.com' },
		{ name: 'node.example.com', type: 1, TTL: 120, data: '1.1.1.1' }];
	equal(handoff.dns_answer(value, 'example.com').ttlMs, 10000);
	value.Answer = [{ name: 'example.com', type: 1, TTL: 120, data: '1.1.1.1' }];
	value.Answer[0].data = '192.168.1.1';
	rejects(() => handoff.dns_answer(value, 'example.com'), 'invalid_handoff');
	rejects(() => handoff.hostname('example.com&name=localhost'), 'invalid_handoff');
});
print(passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
