import * as model from './model.uc';

const PRIVATE = [
	'0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
	'169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
	'198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4',
	'::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8'
];

export function shared(base) { return base.listenerMode != 'per-client'; };

export function limit(base) { return shared(base) ? 32 : 4; };

export function config(base, state, client, connected, prefixes) {
	if (client.inbound != true ||
	    !match(client.secret || '', /^[a-f0-9]{64}$/) ||
	    type(client.port) != 'int' || client.port < 1 || client.port > 65535)
		die('invalid_config');
	let rules = [];
	if (client.allowLan == true) {
		for (let address in base.allowedLan || [])
			push(rules, 'direct(' + model.normalize_address(address) + ')');
	}
	for (let address in PRIVATE) push(rules, 'reject(' + address + ')');
	if (connected && state.settings.clientRules) {
		for (let address in prefixes || [])
			push(rules, 'direct(' + model.normalize_address(address) + ')');
		push(rules, 'upstream(all)');
	} else push(rules, 'direct(all)');
	let result = json(sprintf('%J', base.template));
	result.listen = '0.0.0.0:' + client.port;
	result.auth = { type: 'userpass', userpass: { [client.id]: client.secret } };
	result.acl = { inline: rules };
	result.outbounds = [{ name: 'direct', type: 'direct', direct: { mode: '4' } }];
	if (connected && state.settings.clientRules) {
		let server = null;
		for (let item in state.servers)
			if (item.id == state.activeServerId) server = item;
		if (!server) die('server_not_found');
		let socks = base.preserveSocks ?
			model.parse_config(server.config).config.socks5 : null;
		socks ??= { listen: '127.0.0.1:17891' };
		push(result.outbounds, {
			name: 'upstream', type: 'socks5',
			socks5: { addr: socks.listen,
				username: socks.username, password: socks.password }
		});
	}
	delete result.trafficStats;
	return result;
};

export function profile(base, client) {
	let config = json(sprintf('%J', base.public));
	config.server = base.endpointHost + ':' + (shared(base) ? 443 : client.port);
	config.auth = client.id + ':' + client.secret;
	model.parse_config(sprintf('%J', config));
	let uri = model.config_uri(config, client.name);
	return { id: client.id, name: client.name, deviceType: client.deviceType,
		serverId: null, provisioned: true,
		lanAccessConfigurable: !shared(base),
		allowLan: shared(base) ? base.sharedAllowLan == true : client.allowLan == true,
		uri, config: uri, inactive: false, warning: null };
};

export function shared_config(base, state, clients, connected, prefixes) {
	if (!length(clients) || length(clients) > limit(base)) die('invalid_config');
	let seed = { ...clients[0], port: 443, allowLan: base.sharedAllowLan == true };
	let result = config(base, state, seed, connected, prefixes);
	let users = { ...(base.legacyUsers || {}) };
	for (let client in clients) users[client.id] = client.secret;
	result.auth.userpass = users;
	return result;
};
