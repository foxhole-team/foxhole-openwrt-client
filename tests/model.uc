import * as model from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/model.uc';

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

function device(address, route, extra) {
	let item = {
		id: 'device-000000000001', address, route,
		bindMac: false
	};
	for (let key, value in extra || {}) item[key] = value;
	return item;
};

function flow(extra) {
	let item = {
		source: 'lan', address: '192.0.2.42',
		host: 'service.example.com', country: 'DE', connected: false
	};
	for (let key, value in extra || {}) item[key] = value;
	return item;
};

test('server names use thirteen Unicode characters', () => {
	equal(model.server_name('  VPN SERVER 01  '), 'VPN SERVER 01');
	equal(model.server_name('АБВГДЕЖЗИКЛМН'), 'АБВГДЕЖЗИКЛМН');
	equal(model.server_name('VPN 🚀'), 'VPN 🚀');
	rejects(() => model.server_name('АБВГДЕЖЗИКЛМНО'), 'invalid_name');
	rejects(() => model.server_name('VPN SERVER 012'), 'invalid_name');
	rejects(() => model.server_name(''), 'invalid_name');
	rejects(() => model.server_name('line\nbreak'), 'invalid_name');
});

test('defaults remain empty and inactive', () => {
	let state = model.defaults();
	equal(state.revision, 0);
	equal(state.settings.language, 'ru');
	equal(state.settings.standaloneAccess, true);
	equal(state.settings.killSwitch, false);
	equal(state.settings.theme, 'dark');
	equal(state.settings.darkCharts, true);
	equal(state.settings.plainHeadings, false);
	equal(state.settings.hideRouterStatus, false);
	equal(state.activeServerId, null);
	for (let key in ['servers', 'clients', 'countries', 'devices', 'sites'])
		equal(state[key], []);
	equal(model.public_state(state).runtime,
		{ mode: 'runtime', phase: 'disconnected', connected: false,
			enforced: false, activeServerId: null,
			desiredServerId: null, error: null });
});

test('router visibility defaults safely and accepts only booleans', () => {
	let state = model.defaults();
	delete state.settings.hideRouterStatus;
	equal(model.validate_settings(state, _ => null).settings.hideRouterStatus,
		false);
	for (let value in [true, false]) {
		state.settings.hideRouterStatus = value;
		let checked = model.validate_settings(state, _ => null);
		equal(checked.settings.hideRouterStatus, value);
		equal(model.public_state({ ...state, settings: checked.settings })
			.settings.hideRouterStatus, value);
	}
	for (let value in [null, 0, 1, '', 'true', [], {}]) {
		state.settings.hideRouterStatus = value;
		rejects(() => model.validate_settings(state, _ => null),
			'invalid_settings');
	}
});

test('client names share strict save and rename validation', () => {
	equal(model.client_name('  Phone one  '), 'Phone one');
	let longest = join('', map([1, 2, 3, 4, 5, 6], _ => '12345678'));
	equal(model.client_name(longest), longest);
	for (let name in [null, 1, true, [], {}, '', '   ',
		'Phone\nname', 'Phone\tname', 'Phone' + chr(0), longest + '9'])
		rejects(() => model.client_name(name), 'invalid_name');
});

test('Hysteria URI supports escaped data and normalized endpoint', () => {
	let parsed = model.parse_config('hy2://sample%3Avalue@EXAMPLE.com/' +
		'?sni=example.com&insecure=false#Phone%20one');
	equal(parsed.endpoint, 'example.com:443');
	equal(parsed.name, 'Phone one');
	equal(parsed.config.auth, 'sample:value');
	equal(parsed.config.tls.insecure, false);
	let again = model.parse_config(model.config_uri(parsed.config, parsed.name));
	equal(again.config.auth, parsed.config.auth);
	equal(again.name, parsed.name);
});

test('Hysteria URI retains obfuscation and TLS options', () => {
	let parsed = model.parse_config('hysteria2://sample@example.com:443/' +
		'?obfs=salamander&obfs-password=example%20value&insecure=1#Example');
	equal(parsed.config.obfs.salamander.password, 'example value');
	equal(parsed.config.tls.insecure, true);
	equal(model.parse_config(model.config_uri(parsed.config, parsed.name)).config,
		parsed.config);
});

test('JSON and supported YAML parse as configuration data', () => {
	let structured = model.parse_config('{"server":"example.com:443",' +
		'"auth":"sample","tls":{"sni":"example.com"}}');
	let yaml = model.parse_config('server: example.com:443\nauth: sample\n' +
		'tls:\n  sni: example.com\n');
	equal(yaml.config, structured.config);
});

test('IPv6 endpoints and port ranges are supported', () => {
	equal(model.parse_config('hy2://sample@[2001:db8::1]:443-444,8443/').endpoint,
		'[2001:db8::1]:443-444,8443');
	for (let port in ['0', '65536', '444-443', '443,,444'])
		rejects(() => model.parse_config('hy2://sample@example.com:' + port),
			'invalid_config');
});

test('unsupported config and malformed URI options fail closed', () => {
	rejects(() => model.parse_config('hy2://sample@example.com/?unknown=1'),
		'unsupported_config');
	rejects(() => model.parse_config('hy2://sample@example.com/?sni=a&sni=b'),
		'invalid_config');
	rejects(() => model.parse_config('hy2://bad%GG@example.com/'), 'invalid_config');
	rejects(() => model.parse_config('server: example.com\nauth: sample\n' +
		'tun:\n  name: sample\n'), 'unsupported_config');
	rejects(() => model.parse_config('server: example.com\nauth: sample\nauth: other'),
		'invalid_config');
});

test('public state projects metadata instead of secret profiles', () => {
	let state = model.defaults();
	state.auth = 'private-fixture';
	state.servers = [{ id: 'server-000000000001', name: 'Example',
		endpoint: 'router.invalid:443', config: 'private-fixture' }];
	state.clients = [{ id: 'client-000000000001', name: 'Phone',
		deviceType: 'smartphone', serverId: null, uri: 'private-fixture' }];
	let output = model.public_state(state);
	truth(index(sprintf('%J', output), 'private-fixture') < 0);
	equal(sort(keys(output.servers[0])),
		sort(['id', 'name', 'endpoint', 'state', 'protocol', 'metrics']));
	equal(output.servers[0].protocol, 'hysteria2');
	equal(output.servers[0].metrics,
		{ received: 0, sent: 0, averageLatency: null, ping: null });
	equal(sort(keys(output.clients[0])),
		sort(['id', 'name', 'deviceType', 'serverId', 'provisioned',
			'metrics', 'allowLan']));
	equal(output.clients[0].metrics,
		{ received: 0, sent: 0, lastConnected: null });
});

test('client export follows the current server profile', () => {
	let state = model.defaults();
	state.servers = [{ id: 'server-000000000001', name: 'Example',
		endpoint: 'example.com:443',
		config: 'hy2://first@example.com:443/#Example' }];
	let client = { id: 'client-000000000001', name: 'Phone',
		deviceType: 'smartphone', serverId: state.servers[0].id };
	let first = model.client_profile(state, client);
	equal(model.parse_config(first.uri).config.auth, 'first');
	state.servers[0].config = 'hy2://second@example.com:443/#Example';
	equal(model.parse_config(model.client_profile(state, client).uri).config.auth,
		'second');
	state.servers = [];
	let inactive = model.client_profile(state, client);
	equal(inactive.serverId, null);
	equal(inactive.inactive, true);
	equal(model.parse_config(inactive.uri).endpoint, 'router.invalid:443');
});

test('renamed client exports retain identity and upstream configuration', () => {
	let state = model.defaults();
	state.servers = [{ id: 'server-000000000001', name: 'Example',
		endpoint: 'example.com:443',
		config: 'hy2://sample@example.com:443/#Example' }];
	let client = { id: 'client-000000000001', name: 'Phone',
		deviceType: 'smartphone', serverId: state.servers[0].id };
	let before = model.client_profile(state, client);
	client.name = model.client_name('  Travel phone  ');
	let after = model.client_profile(state, client);
	equal(after.name, 'Travel phone');
	equal(model.parse_config(after.uri).name, 'Travel phone');
	equal(model.parse_config(after.uri).config,
		model.parse_config(before.uri).config);
	for (let key in ['id', 'deviceType', 'serverId', 'provisioned',
		'inactive', 'warning']) equal(after[key], before[key]);
});

test('IPv4 and IPv6 rules canonicalize host bits', () => {
	equal(model.normalize_address('192.0.2.42/24'), '192.0.2.0/24');
	equal(model.normalize_address('2001:db8:1::42/48'), '2001:db8:1::/48');
	equal(model.normalize_address('192.0.2.42/32'), '192.0.2.42/32');
	equal(model.normalize_address('2001:db8::42/128'), '2001:db8::42/128');
	equal(model.normalize_address('192.0.2.42'), '192.0.2.42');
});

test('default CIDR routes round-trip in canonical form', () => {
	for (let address in ['192.0.2.42/0', '2001:db8::42/0']) {
		let canonical = model.normalize_address(address);
		equal(model.normalize_address(canonical), canonical);
	}
});

test('CIDR matching checks network membership and family', () => {
	truth(model.address_matches('192.0.2.42', '192.0.2.0/24'));
	truth(!model.address_matches('203.0.113.42', '192.0.2.0/24'));
	truth(model.address_matches('2001:db8:1::42', '2001:db8:1::/48'));
	truth(!model.address_matches('2001:db8:2::42', '2001:db8:1::/48'));
	truth(!model.address_matches('192.0.2.42', '2001:db8::/32'));
	truth(!model.address_matches('bad', '192.0.2.0/24'));
});

test('invalid and unsafe host addresses are rejected', () => {
	for (let address in ['bad', '192.0.2.256', '192.0.2.1/33',
		'2001:db8::1/129', '192.0.2.1/-1', '127.0.0.1', '::1',
		'224.0.0.1', 'ff02::1', '192.0.2.1/24/1'])
		rejects(() => model.normalize_address(address), 'invalid_address');
});

test('MAC rules normalize unicast addresses and reject invalid ones', () => {
	equal(model.normalize_mac('02:AA:BB:CC:DD:EE'), '02:aa:bb:cc:dd:ee');
	for (let address in ['00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff',
		'01:00:5e:00:00:01', '02:aa:bb:cc:dd', 'bad'])
		rejects(() => model.normalize_mac(address), 'invalid_mac');
});

test('MAC resolution strips a host prefix before lookup', () => {
	let seen = [];
	let state = model.defaults();
	state.devices = [device('192.0.2.42/32', 'vpn', { bindMac: true })];
	let checked = model.validate_settings(state, address => {
		push(seen, address);
		return '02:aa:bb:cc:dd:ee';
	});
	equal(seen, ['192.0.2.42']);
	equal(checked.devices[0].mac, '02:aa:bb:cc:dd:ee');
	state.devices[0].address = '192.0.2.42/24';
	rejects(() => model.validate_settings(state, _ => die('unexpected_lookup')),
		'mac_not_found');
});

test('manual MAC-only rules do not require an IP address', () => {
	let state = model.defaults();
	state.devices = [device(null, 'vpn', {
		name: 'Tablet', bindMac: true, mac: '02:aa:bb:cc:dd:ee'
	})];
	let checked = model.validate_settings(state, _ => null);
	equal(checked.devices[0].name, 'Tablet');
	equal(checked.devices[0].address, null);
	equal(checked.devices[0].mac, '02:aa:bb:cc:dd:ee');
});

test('host prefixes are interpreted by address family', () => {
	equal(model.host_address('192.0.2.42'), '192.0.2.42');
	equal(model.host_address('192.0.2.42/32'), '192.0.2.42');
	equal(model.host_address('2001:db8::42'), '2001:db8::42');
	equal(model.host_address('2001:db8::42/128'), '2001:db8::42');
	for (let address in ['192.0.2.42/24', '2001:db8::42/32',
		'2001:db8::42/64', '0.0.0.0/0', '::/0', 'bad'])
		equal(model.host_address(address), null);
});

test('IPv6 slash-32 is a subnet and never invokes MAC lookup', () => {
	let state = model.defaults(), lookups = 0;
	state.devices = [device('2001:db8::42/32', 'vpn', { bindMac: true })];
	rejects(() => model.validate_settings(state, _ => {
		lookups++;
		return '02:aa:bb:cc:dd:ee';
	}), 'mac_not_found');
	equal(lookups, 0);
});

test('host addresses and full-length CIDRs share one identity', () => {
	for (let pair in [['192.0.2.42', '192.0.2.42/32'],
		['2001:db8::42', '2001:db8::42/128']]) {
		let state = model.defaults();
		state.devices = [device(pair[0], 'vpn'),
			device(pair[1], 'direct', { id: 'device-000000000002' })];
		rejects(() => model.validate_settings(state, _ => null), 'duplicate_rule');
	}
});

test('device identities and country choices are validated', () => {
	let state = model.defaults();
	state.countries = ['RU', 'US'];
	state.devices = [device('192.0.2.42/24', 'vpn')];
	let checked = model.validate_settings(state, _ => null);
	equal(checked.countries[0].code, 'RU');
	equal(checked.countries[0].route, 'direct');
	equal(checked.devices[0].address, '192.0.2.0/24');
	state.countries = [{ code: 'DE', route: 'vpn' }];
	checked = model.validate_settings(state, _ => null);
	equal(checked.countries[0].code, 'DE');
	equal(checked.countries[0].route, 'vpn');
	state.devices = [device('192.0.2.42/24', 'vpn'),
		device('192.0.2.99/24', 'direct', { id: 'device-000000000002' })];
	rejects(() => model.validate_settings(state, _ => null), 'duplicate_rule');
	state.devices = [];
	for (let countries in [['RU', 'RU'], ['ZZ'], ['ru'],
		[{ code: 'DE', route: 'other' }],
		[{ code: 'DE', route: 'vpn' }, { code: 'DE', route: 'direct' }]]) {
		state.countries = countries;
		rejects(() => model.validate_settings(state, _ => null), 'invalid_settings');
	}
});

test('site rules normalize supported URL and mask forms', () => {
	for (let value in ['Example.COM', 'https://example.com/',
		'https://example.com/*', '||example.com^', '.example.com.'])
		equal(model.normalize_site(value), 'example.com');
	equal(model.normalize_site('*.Example.COM'), '*.example.com');
	equal(model.normalize_site('cdn?.example.com'), 'cdn?.example.com');
	for (let value in ['https://example.com/private',
		'https://example.com/?query=1', 'https://example.com/#fragment'])
		rejects(() => model.normalize_site(value), 'site_path_unsupported');
	for (let value in ['localhost', 'bad..example.com', 'bad_name.example.com',
		'-bad.example.com', 'example.com:443'])
		rejects(() => model.normalize_site(value), 'invalid_site');
	let state = model.defaults();
	state.sites = [{
		id: 'site-000000000001', pattern: 'example.com', route: 'vpn'
	}];
	equal(model.validate_settings(state, _ => null).sites[0].route, 'vpn');
});

test('plain domains include subdomains but wildcard roots do not', () => {
	truth(model.site_matches('example.com', 'example.com'));
	truth(model.site_matches('cdn.example.com', 'example.com'));
	truth(!model.site_matches('otherexample.com', 'example.com'));
	truth(!model.site_matches('example.com', '*.example.com'));
	truth(model.site_matches('cdn.example.com', '*.example.com'));
	truth(model.site_matches('cdn1.example.com', 'cdn?.example.com'));
	truth(!model.site_matches('cdn12.example.com', 'cdn?.example.com'));
});

test('kill switch is independent from exclusion toggles', () => {
	let state = model.defaults();
	state.settings.killSwitch = true;
	state.countries = ['DE'];
	equal(model.policy_decision(state, flow()), 'block');
	equal(model.policy_decision(state, flow({ connected: true })), 'vpn');
	state.settings.localRules = true;
	equal(model.policy_decision(state, flow()), 'direct');
	equal(model.policy_decision(state, flow({ country: 'US' })), 'block');
});

test('explicit direct devices bypass failure protection', () => {
	let state = model.defaults();
	state.settings.localRules = true;
	state.settings.killSwitch = true;
	state.devices = [device('192.0.2.0/24', 'direct')];
	equal(model.policy_decision(state, flow()), 'direct');
	equal(model.policy_decision(state, flow({ address: '203.0.113.42' })), 'block');
});

test('only the global kill switch protects VPN device routes', () => {
	let state = model.defaults();
	state.settings.localRules = true;
	state.devices = [device('192.0.2.42', 'vpn', { preventLeak: true })];
	equal(model.policy_decision(state, flow()), 'direct');
	state.settings.killSwitch = true;
	equal(model.policy_decision(state, flow()), 'block');
	equal(model.policy_decision(state, flow({ connected: true })), 'vpn');
	equal(model.policy_decision(state, flow({ address: '192.0.2.43' })), 'block');
});

test('selected-device country exclusions do not affect other hosts', () => {
	let state = model.defaults();
	state.settings.localRules = true;
	state.settings.localScope = 'selected';
	state.settings.killSwitch = true;
	state.countries = ['DE'];
	state.devices = [device('192.0.2.42', 'vpn')];
	equal(model.policy_decision(state, flow()), 'direct');
	equal(model.policy_decision(state, flow({ address: '192.0.2.43' })), 'block');
});

test('VPN client exclusions have an independent source scope', () => {
	let state = model.defaults();
	state.settings.killSwitch = true;
	state.settings.clientRules = true;
	state.sites = [{ pattern: 'example.com', route: 'direct' }];
	equal(model.policy_decision(state, flow({ source: 'client' })), 'direct');
	equal(model.policy_decision(state, flow()), 'block');
	equal(model.policy_decision(state, flow({ source: 'client', host: 'other.invalid' })),
		'direct');
	equal(model.policy_decision(state, flow({ source: 'client', connected: true })), 'vpn');
});

test('site routing can force VPN ahead of a country bypass', () => {
	let state = model.defaults();
	state.settings.localRules = true;
	state.settings.killSwitch = true;
	state.countries = ['DE'];
	state.sites = [{ pattern: 'example.com', route: 'vpn' }];
	equal(model.policy_decision(state, flow()), 'block');
	equal(model.policy_decision(state, flow({ connected: true })), 'vpn');
	equal(model.policy_decision(state,
		flow({ host: 'other.invalid' })), 'direct');
});

test('MAC identity survives a changed device address', () => {
	let state = model.defaults();
	state.settings.localRules = true;
	state.settings.killSwitch = true;
	state.devices = [device('192.0.2.42', 'direct', {
		bindMac: true, mac: '02:aa:bb:cc:dd:ee'
	})];
	equal(model.policy_decision(state, flow({ address: '203.0.113.42',
		mac: '02:AA:BB:CC:DD:EE' })), 'direct');
	equal(model.policy_decision(state, flow()), 'block');
});

print('1..', passed + failed, '\n');
print('# model tests: ', passed, ' passed, ', failed, ' failed\n');
if (failed) exit(1);
