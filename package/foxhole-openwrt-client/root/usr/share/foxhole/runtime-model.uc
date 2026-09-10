import * as model from './model.uc';

const TUN_NAME = 'foxhole0';
const ROUTE_TABLE = 201;
const RULE_PRIORITY = 10000;
const MARK = '0x40000000';
const MARK_MASK = '0x40000000';
const PROXY_LISTEN = '127.0.0.1:17890';

const BYPASS4 = [
	'0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10',
	'127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
	'192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16',
	'198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
	'224.0.0.0/4', '240.0.0.0/4'
];

const BYPASS6 = [
	'::/128', '::1/128', '100::/64', '2001:db8::/32',
	'fc00::/7', 'fe80::/10', 'ff00::/8'
];

function fail(code) {
	die(code);
};

function unique(values) {
	let result = [], seen = {};
	for (let value in values || []) {
		if (type(value) != 'string' || seen[value]) continue;
		seen[value] = true;
		push(result, value);
	}
	return result;
};

function quote(value) {
	if (type(value) != 'string' ||
	    !match(value, /^[a-zA-Z0-9_.:-]{1,32}$/))
		fail('invalid_interface');
	return '"' + value + '"';
};

function set_text(name, kind, values, dynamic) {
	let lines = [
		'\tset ' + name + ' {',
		'\t\ttype ' + kind,
		'\t\tflags interval',
		'\t\tauto-merge'
	];
	if (length(values || []))
		push(lines, '\t\telements = { ' + join(', ', values) + ' }');
	if (dynamic) push(lines, '\t\tcomment "FoxHole DNS set"');
	push(lines, '\t}');
	return join('\n', lines);
};

function rule(lines, value) {
	push(lines, '\t\t' + value);
};

export function constants() {
	return { tunName: TUN_NAME, routeTable: ROUTE_TABLE,
		rulePriority: RULE_PRIORITY, mark: MARK, markMask: MARK_MASK,
		proxyListen: PROXY_LISTEN };
};

export function runtime_fingerprint(state) {
	return sprintf('%J', {
		activeServerId: state.activeServerId || null,
		settings: {
			localRules: state.settings.localRules,
			localScope: state.settings.localScope,
			killSwitch: state.settings.killSwitch
		},
		countries: state.countries,
		devices: state.devices,
		sites: state.sites,
		servers: state.servers
	});
};

export function active_server(state) {
	let id = state.activeServerId || null;
	if (!id) return null;
	for (let server in state.servers)
		if (server.id == id) return server;
	return null;
};

export function hysteria_config(state, resolved, options) {
	let server = active_server(state);
	if (!server) fail('server_not_found');
	let parsed = model.parse_config(server.config);
	let config = json(sprintf('%J', parsed.config));
	if (!options?.preserveSocks || !config.socks5)
		config.socks5 = { listen: '127.0.0.1:17891' };
	delete config.http;
	if (resolved?.server) config.server = resolved.server;
	if (resolved?.sni) {
		config.tls ??= {};
		config.tls.sni ??= resolved.sni;
	}
	config.tun = {
		name: TUN_NAME,
		mtu: options?.mtu ?? 1500,
		timeout: '5m',
		address: {
			ipv4: '198.18.0.1/30',
			ipv6: 'fdfe:dcba:9876::1/126'
		}
	};
	config.http = { listen: PROXY_LISTEN };
	if (type(config.tun.mtu) != 'int' || config.tun.mtu < 1280 ||
	    config.tun.mtu > 1500) fail('invalid_interface');
	return { server, config };
};

export function dnsmasq_config(sites) {
	let lines = [ '# Managed by FoxHole.' ];
	for (let item in sites || []) {
		let pattern = item.pattern;
		if (match(pattern, /[?]/) ||
		    (index(pattern, '*') >= 0 && !match(pattern, /^\*\.[^*]+$/)))
			fail('site_pattern_unsupported');
		let name = item.route == 'vpn' ? 'site_vpn' : 'site_direct';
		push(lines, 'nftset=/' + pattern + '/4#inet#foxhole#' +
			name + '4,6#inet#foxhole#' + name + '6');
	}
	return join('\n', lines) + '\n';
};

export function nft_config(state, options) {
	let interfaces = unique(options.interfaces || []);
	if (!length(interfaces)) fail('invalid_interface');
	let country4 = unique(options.country4 || []);
	let country6 = unique(options.country6 || []);
	let dnsUid = options.dnsUid;
	if (type(dnsUid) != 'int' || dnsUid < 1 || dnsUid > 65535)
		fail('invalid_dns_uid');
	let lines = [
		'add table inet foxhole',
		'delete table inet foxhole',
		'table inet foxhole {'
	];
	push(lines, set_text('bypass4', 'ipv4_addr', BYPASS4));
	push(lines, set_text('bypass6', 'ipv6_addr', BYPASS6));
	push(lines, set_text('country_direct4', 'ipv4_addr', country4));
	push(lines, set_text('country_direct6', 'ipv6_addr', country6));
	for (let name in ['site_direct4', 'site_vpn4'])
		push(lines, set_text(name, 'ipv4_addr', [], true));
	for (let name in ['site_direct6', 'site_vpn6'])
		push(lines, set_text(name, 'ipv6_addr', [], true));

	push(lines, '\tchain mark_vpn {');
	rule(lines, 'meta mark set meta mark | ' + MARK);
	rule(lines, 'accept');
	push(lines, '\t}');

	push(lines, '\tchain mark_direct {');
	rule(lines, 'meta mark set meta mark | 0x20000000');
	rule(lines, 'counter accept');
	push(lines, '\t}');

	push(lines, '\tchain scoped_rules {');
	rule(lines, 'ip daddr @site_vpn4 jump mark_vpn');
	rule(lines, 'ip6 daddr @site_vpn6 jump mark_vpn');
	rule(lines, 'ip daddr @site_direct4 jump mark_direct');
	rule(lines, 'ip6 daddr @site_direct6 jump mark_direct');
	rule(lines, 'ip daddr @country_direct4 jump mark_direct');
	rule(lines, 'ip6 daddr @country_direct6 jump mark_direct');
	rule(lines, 'return');
	push(lines, '\t}');

	push(lines, '\tchain selected_rules {');
	rule(lines, 'jump scoped_rules');
	rule(lines, 'jump mark_vpn');
	push(lines, '\t}');

	push(lines, '\tchain classify {');
	rule(lines, 'ip daddr @bypass4 accept');
	rule(lines, 'ip6 daddr @bypass6 accept');
	if (state.settings.localRules) {
		for (let item in state.devices) {
			let identity = item.bindMac ? 'ether saddr ' + item.mac :
				(length(iptoarr(split(item.address, '/')[0])) == 4 ?
					'ip saddr ' : 'ip6 saddr ') + item.address;
			rule(lines, identity + (item.route == 'direct' ?
				' goto mark_direct' : ' goto selected_rules'));
		}
		if (state.settings.localScope == 'all')
			rule(lines, 'jump scoped_rules');
	}
	rule(lines, 'jump mark_vpn');
	push(lines, '\t}');

	push(lines, '\tchain prerouting {');
	rule(lines, 'type filter hook prerouting priority mangle - 5; ' +
		'policy accept;');
	rule(lines, 'iifname { ' + join(', ', map(interfaces, quote)) +
		' } jump classify');
	push(lines, '\t}');

	push(lines, '\tchain output {');
	rule(lines, 'type route hook output priority mangle - 5; policy accept;');
	if (!options.bootstrap && options.dnsViaTunnel != false)
		rule(lines, 'meta skuid ' + dnsUid + ' meta l4proto { tcp, udp } ' +
			'th dport 53 jump mark_vpn');
	push(lines, '\t}');
	if (options.bootstrap) {
		push(lines, '\tchain bootstrap_dns {');
		rule(lines, 'type filter hook input priority filter - 5; ' +
			'policy accept;');
		rule(lines, 'iifname { ' + join(', ', map(interfaces, quote)) +
			' } meta l4proto { tcp, udp } th dport 53 counter drop');
		push(lines, '\t}');
	}
	// Output rerouting finishes after the local output hook.
	push(lines, '\tchain guard_egress {');
	rule(lines, 'type filter hook postrouting priority filter - 5; ' +
		'policy accept;');
	rule(lines, 'meta mark & ' + MARK + ' != 0 oifname != "' +
		TUN_NAME + '" counter drop');
	push(lines, '\t}');
	push(lines, '}');
	return join('\n', lines) + '\n';
};

export function route_commands(connected) {
	let route = connected ? [ 'default', 'dev', TUN_NAME ] :
		[ 'prohibit', 'default' ];
	let selector = [ 'pref', '' + RULE_PRIORITY,
		'fwmark', MARK + '/' + MARK_MASK,
		'lookup', '' + ROUTE_TABLE ];
	return {
		delete4: [ '-4', 'rule', 'del', ...selector ],
		delete6: [ '-6', 'rule', 'del', ...selector ],
		flush4: [ '-4', 'route', 'flush', 'table', '' + ROUTE_TABLE ],
		flush6: [ '-6', 'route', 'flush', 'table', '' + ROUTE_TABLE ],
		route4: [ '-4', 'route', 'replace', ...route,
			'table', '' + ROUTE_TABLE ],
		route6: [ '-6', 'route', 'replace', ...route,
			'table', '' + ROUTE_TABLE ],
		rule4: [ '-4', 'rule', 'add', ...selector ],
		rule6: [ '-6', 'rule', 'add', ...selector ]
	};
};
