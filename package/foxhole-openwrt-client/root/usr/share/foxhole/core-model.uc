'use strict';

import * as digest from 'digest';

const PROTOCOLS = [ 'vless', 'vmess', 'hysteria2', 'tuic', 'trojan',
	'shadowsocks', 'wireguard', 'naive', 'anytls', 'shadowtls', 'socks', 'http' ];

export function supported_protocol(value) { return index(PROTOCOLS, value) >= 0; };

export function describe(raw) {
	if (type(raw) != 'string' || length(raw) < 2 ||
	    length(raw) > 262144) die('invalid_config');
	let config;
	try { config = json(raw); } catch (_) { die('invalid_config'); }
	let outbound = config?.outbound;
	if (config.schema_version != 1 ||
	    index(PROTOCOLS, outbound?.type) < 0 ||
	    type(outbound.server) != 'string' ||
	    length(outbound.server) < 1 || length(outbound.server) > 253 ||
	    match(outbound.server, /[[:cntrl:] \/]/) ||
	    type(outbound.port) != 'int' ||
	    outbound.port < 1 || outbound.port > 65535)
		die('invalid_config');
	let host = index(outbound.server, ':') >= 0 ?
		'[' + outbound.server + ']' : outbound.server;
	return { protocol: outbound.type, endpoint: host + ':' + outbound.port,
		config };
};

export function server(value) {
	if (value?.engine != 'core') die('invalid_config');
	let parsed = describe(value.config);
	if (value.protocol != parsed.protocol ||
	    value.endpoint != parsed.endpoint) die('invalid_config');
	return parsed;
};

export function subscription(value) {
	if (value == null || (type(value) == 'object' && !length(keys(value))))
		return null;
	let fields = { sourceUrl: 4096, selectedProtocol: 32,
		selectedNodeName: 512, selectedOptionId: 128, phoneProfileId: 128 };
	if (type(value) != 'object' || length(keys(value)) != 5)
		die('invalid_config');
	for (let key in keys(value))
		if (fields[key] == null) die('invalid_config');
	for (let key, maximum in fields)
		if (type(value[key]) != 'string' || length(value[key]) < 1 ||
		    length(value[key]) > maximum || match(value[key], /[[:cntrl:]]/))
			die('invalid_config');
	if (index(PROTOCOLS, value.selectedProtocol) < 0 ||
	    !match(value.sourceUrl, /^(https|ssconf):\/\//) ||
	    match(value.sourceUrl, /^(https|ssconf):\/\/[^\/]*@/))
		die('invalid_config');
	return json(sprintf('%J', value));
};

export function portable(value, config) {
	if (value == null) return null;
	if (type(value) != 'object' || length(keys(value)) != 3 ||
	    type(value.content) != 'string' || length(value.content) < 2 ||
	    length(value.content) > 262144 ||
	    type(value.sha256) != 'string' ||
	    type(value.configSha256) != 'string' ||
	    value.sha256 != digest.sha256(value.content) ||
	    value.configSha256 != digest.sha256(config)) die('invalid_config');
	return { content: value.content, sha256: value.sha256 };
};

export function proof_routes(connected) {
	let selector = [ 'pref', '9900', 'fwmark',
		'0x10000000/0x10000000', 'lookup', '202' ];
	let route = connected ? [ 'default', 'dev', 'foxhole0' ] :
		[ 'prohibit', 'default' ];
	return {
		delete4: [ '-4', 'rule', 'del', ...selector ],
		delete6: [ '-6', 'rule', 'del', ...selector ],
		flush4: [ '-4', 'route', 'flush', 'table', '202' ],
		flush6: [ '-6', 'route', 'flush', 'table', '202' ],
		route4: [ '-4', 'route', 'replace', ...route, 'table', '202' ],
		route6: [ '-6', 'route', 'replace', ...route, 'table', '202' ],
		rule4: [ '-4', 'rule', 'add', ...selector ],
		rule6: [ '-6', 'rule', 'add', ...selector ]
	};
};

export function ipv6_policy(route, table, rules) {
	if (type(route) == 'array' && length(route))
		return length(route) == 1 && route[0]?.dev == 'foxhole0' &&
			(route[0].type == null || route[0].type == 'unicast');
	if (type(table) != 'array' || type(rules) != 'array') return false;
	let prohibited = false, selected = false;
	for (let entry in table)
		if (entry.dst == 'default' && entry.type == 'prohibit')
			prohibited = true;
	for (let rule in rules)
		if ((rule.table == 201 || rule.table == '201') &&
		    rule.fwmark == '0x40000000' &&
		    rule.fwmask == '0x40000000') selected = true;
	return prohibited && selected;
};

export function proof_identity(proof, server, owner, stamp, boot, minimum) {
	let key = owner?.generation_key;
	return owner?.owned == true && type(key) == 'string' && match(key, /^[a-f0-9]{16}$/) &&
		proof?.generation_key == key && proof.serverId == server?.id &&
		proof.configIdentity == digest.sha256(server?.config || '') && proof.validated == true &&
		type(stamp) == 'int' && type(proof.checkedUptimeMs) == 'int' &&
		proof.checkedUptimeMs <= stamp &&
		(minimum == null || proof.checkedUptimeMs >= minimum) &&
		(boot == null || proof.bootId == boot);
};

export function proof_valid(proof, server, owner, stamp, boot, minimum) {
	return proof_identity(proof, server, owner, stamp, boot, minimum) && stamp - proof.checkedUptimeMs <= 4990;
};
