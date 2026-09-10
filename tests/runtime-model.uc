import * as model from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/model.uc';
import * as runtime from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/runtime-model.uc';

let passed = 0, failed = 0;

function equal(actual, expected) {
	if (sprintf('%J', actual) != sprintf('%J', expected))
		die('assertion_failed');
};

function truth(value) {
	if (!value) die('assertion_failed');
};

function rejects(fn, code) {
	let caught = null;
	try { fn(); } catch (error) {
		caught = type(error) == 'string' ? error : error.message;
	}
	if (caught != code) die('unexpected_error_code');
};

function test(name, fn) {
	try {
		fn();
		passed++;
		print('ok ', passed + failed, ' - ', name, '\n');
	} catch (_) {
		failed++;
		print('not ok ', passed + failed, ' - ', name, '\n');
	}
};

function state() {
	let value = model.defaults();
	value.servers = [{
		id: 'server-000000000001', name: 'Example',
		endpoint: 'vpn.example.com:443',
		config: 'hy2://sample@vpn.example.com:443/#Example'
	}];
	value.activeServerId = value.servers[0].id;
	return value;
};

function offset(text, part) {
	let value = index(text, part);
	if (value < 0) die('assertion_failed');
	return value;
};

test('Hysteria plan uses one route-free upstream TUN', () => {
	let current = state();
	let plan = runtime.hysteria_config(current, {
		server: '203.0.113.8:443', sni: 'vpn.example.com'
	});
	equal(plan.server.id, current.activeServerId);
	equal(plan.config.server, '203.0.113.8:443');
	equal(plan.config.tls.sni, 'vpn.example.com');
	equal(plan.config.tun.name, 'foxhole0');
	equal(plan.config.tun.address.ipv4, '198.18.0.1/30');
	equal(plan.config.tun.address.ipv6, 'fdfe:dcba:9876::1/126');
	truth(plan.config.tun.route == null);
	equal(plan.config.http.listen, '127.0.0.1:17890');
});

test('VPN-client policy does not change the LAN TUN plan', () => {
	let current = state();
	let before = runtime.hysteria_config(current, null);
	current.settings.clientRules = true;
	equal(runtime.hysteria_config(current, null), before);
});

test('explicit migration preserves loopback SOCKS and bounded MTU', () => {
	let current = state();
	current.servers[0].config = sprintf('%J', {
		server: 'vpn.example.com:443', auth: 'sample',
		socks5: { listen: '127.0.0.1:1080', disableUDP: false },
		congestion: { type: 'bbr', bbrProfile: 'standard' },
		fastOpen: true
	});
	let plan = runtime.hysteria_config(current, null,
		{ preserveSocks: true, mtu: 1400 });
	equal(plan.config.socks5.listen, '127.0.0.1:1080');
	equal(plan.config.tun.mtu, 1400);
	equal(plan.config.congestion.bbrProfile, 'standard');
	truth(plan.config.fastOpen);
	equal(runtime.hysteria_config(current, null).config.socks5.listen,
		'127.0.0.1:17891');
	rejects(() => runtime.hysteria_config(current, null,
		{ mtu: 9000 }), 'invalid_interface');
});

test('nft plan preserves bypass and direct-device precedence', () => {
	let current = state();
	current.settings.localRules = true;
	current.devices = [
		{ id: 'device-000000000001', name: 'Direct',
			address: null, mac: '02:00:00:00:00:01',
			bindMac: true, route: 'direct' },
		{ id: 'device-000000000002', name: 'VPN',
			address: '192.168.1.20', mac: null,
			bindMac: false, route: 'vpn' }
	];
	let nft = runtime.nft_config(current, {
		interfaces: ['br-lan'], dnsUid: 453,
		country4: ['198.51.100.0/24'], country6: []
	});
	truth(index(nft, 'table inet foxhole') >= 0);
	truth(index(nft, '02:00:00:00:00:01') >= 0);
	truth(index(nft, '192.168.1.20') >= 0);
	truth(index(nft, '198.51.100.0/24') >= 0);
	let classify = split(nft, 'chain classify {')[1];
	truth(offset(classify, 'ether saddr 02:00:00:00:00:01 goto mark_direct') <
		offset(classify, 'ip saddr 192.168.1.20 goto selected_rules'));
	truth(offset(nft, 'ip daddr @site_vpn4 jump mark_vpn') <
		offset(nft, 'ip daddr @country_direct4 jump mark_direct'));
	truth(index(nft, 'meta mark set meta mark | 0x40000000') >= 0);
	truth(index(nft, 'meta skuid 453') >= 0);
});

test('selected scope limits exceptions without limiting VPN', () => {
	let current = state();
	current.settings.localRules = true;
	current.settings.localScope = 'selected';
	current.devices = [{
		id: 'device-000000000001', name: 'Selected',
		address: '192.168.1.20', mac: null,
		bindMac: false, route: 'vpn'
	}];
	let nft = runtime.nft_config(current, {
		interfaces: ['br-lan'], dnsUid: 453
	});
	let classify = split(nft, 'chain classify {')[1];
	truth(offset(classify, 'ip saddr 192.168.1.20 goto selected_rules') <
		offset(classify, 'jump mark_vpn'));
});

test('ISP DNS migration may retain router DNS routing', () => {
	let current = state();
	let nft = runtime.nft_config(current, {
		interfaces: ['br-lan'], dnsUid: 453, dnsViaTunnel: false
	});
	truth(index(nft, 'meta skuid 453') < 0);
	truth(index(nft, 'jump mark_vpn') >= 0);
});

test('dnsmasq rules target separate VPN and direct sets', () => {
	let config = runtime.dnsmasq_config([
		{ pattern: 'example.com', route: 'direct' },
		{ pattern: '*.vpn.example.com', route: 'vpn' }
	]);
	truth(index(config, 'site_direct4') >= 0);
	truth(index(config, 'site_direct6') >= 0);
	truth(index(config, 'site_vpn4') >= 0);
	truth(index(config, 'site_vpn6') >= 0);
	rejects(() => runtime.dnsmasq_config([
		{ pattern: 'cdn?.example.com', route: 'direct' }
	]), 'site_pattern_unsupported');
});

test('policy routes are marked for TUN or prohibit', () => {
	let connected = runtime.route_commands(true);
	let blocked = runtime.route_commands(false);
	equal(connected.route4,
		['-4', 'route', 'replace', 'default', 'dev', 'foxhole0',
			'table', '201']);
	equal(blocked.route6,
		['-6', 'route', 'replace', 'prohibit', 'default',
			'table', '201']);
	truth(index(connected.rule4, '0x40000000/0x40000000') >= 0);
	truth(index(connected.delete4, '0x40000000/0x40000000') >= 0);
});

print('1..', passed + failed, '\n');
print('# runtime model tests: ', passed, ' passed, ', failed,
	' failed\n');
exit(failed ? 1 : 0);
