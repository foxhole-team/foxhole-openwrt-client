import * as core from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/core-model.uc';
import * as digest from 'digest';
import * as model from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/model.uc';

let passed = 0, failed = 0;
function equal(actual, expected) {
	if (sprintf('%J', actual) != sprintf('%J', expected)) die('assertion');
};
function rejects(fn) {
	let caught = false;
	try { fn(); } catch (_) { caught = true; }
	if (!caught) die('assertion');
};
function test(name, fn) {
	try { fn(); passed++; print('ok ', name, '\n'); }
	catch (error) { failed++; print('not ok ', name, ': ',
		type(error) == 'string' ? error : error.message, '\n'); }
};
function configuration(kind, host) {
	return sprintf('%J', { schema_version: 1,
		outbound: { type: kind, server: host || 'edge.example', port: 443,
			password: 'synthetic fixture' } });
};
test('Core metadata retains the admitted protocol and IPv6 endpoint', () => {
	equal(core.describe(configuration('hysteria2')).protocol, 'hysteria2');
	equal(core.describe(configuration('wireguard', '2001:db8::1')).endpoint,
		'[2001:db8::1]:443');
	for (let kind in ['direct', 'tor', 'i2p', 'selector', 'unknown'])
		rejects(() => core.describe(configuration(kind)));
});
test('saved metadata cannot switch protocol independently from config', () => {
	let value = { engine: 'core', protocol: 'vless',
		endpoint: 'edge.example:443', config: configuration('vless') };
	equal(core.server(value).protocol, 'vless');
	value.protocol = 'hysteria2';
	rejects(() => core.server(value));
});
test('generic Core servers survive state validation without legacy conversion', () => {
	let state = model.defaults();
	state.servers = [{ id: 'server-000000000001', name: 'Example',
		engine: 'core', protocol: 'vless', endpoint: 'edge.example:443',
		config: configuration('vless') }];
	let checked = model.validate_state(state);
	equal(checked.servers[0].config, state.servers[0].config);
	equal(model.public_state(checked).servers[0].protocol, 'vless');
	equal(model.public_state(checked).servers[0].engine, 'core');
});
test('normal traffic remains separate from the isolated proof route', () => {
	let proof = core.proof_routes(true);
	equal(proof.rule4, ['-4', 'rule', 'add', 'pref', '9900', 'fwmark',
		'0x10000000/0x10000000', 'lookup', '202']);
	equal(proof.route4, ['-4', 'route', 'replace', 'default',
		'dev', 'foxhole0', 'table', '202']);
	equal(core.proof_routes(false).route4,
		['-4', 'route', 'replace', 'prohibit', 'default', 'table', '202']);
});
test('lost Core upstream cannot give inbound clients a direct fallback', () => {
	let state = model.defaults();
	state.servers = [{ id: 'server-000000000001', name: 'Example',
		engine: 'core', protocol: 'vless', endpoint: 'edge.example:443',
		config: configuration('vless') }];
	state.activeServerId = state.servers[0].id;
	state.settings.clientRules = true;
	equal(model.policy_decision(state, { source: 'client', connected: false }),
		'block');
	state.activeServerId = null;
	equal(model.policy_decision(state, { source: 'client', connected: false }),
		'direct');
});
test('IPv6 must enter the owned TUN or an explicit selected prohibit route', () => {
	equal(core.ipv6_policy([{ dev: 'foxhole0', type: 'unicast' }], null, null), true);
	equal(core.ipv6_policy([{ dev: 'wan', type: 'unicast' }], null, null), false);
	equal(core.ipv6_policy(null, [{ dst: 'default', type: 'prohibit' }],
		[{ table: 201, fwmark: '0x40000000', fwmask: '0x40000000' }]), true);
	equal(core.ipv6_policy(null, [{ dst: 'default', type: 'prohibit' }],
		[{ table: '201', fwmark: '0x40000000', fwmask: '0x40000000' }]), true);
	equal(core.ipv6_policy(null, [{ dst: 'default', type: 'prohibit' }], []), false);
	equal(core.ipv6_policy(null, [], []), false);
});
test('private subscription selection is retained without entering public state', () => {
	let selection = { sourceUrl: 'https://example.com/synthetic-source',
		selectedProtocol: 'vless', selectedNodeName: 'Example',
		selectedOptionId: 'option-synthetic', phoneProfileId: 'profile-synthetic' };
	equal(sprintf('%J', core.subscription(selection)), sprintf('%J', selection));
	let state = model.defaults();
	state.servers = [{ id: 'server-000000000001', name: 'Example',
		engine: 'core', protocol: 'vless', endpoint: 'edge.example:443',
		config: configuration('vless'), subscription: selection }];
	let public = model.public_state(model.validate_state(state));
	equal(public.servers[0].subscription, null);
	rejects(() => core.subscription({ ...selection, sourceUrl: 'http://example.com' }));
	rejects(() => core.subscription({ ...selection, extra: 'unapplied' }));
});
test('portable Core copy is exact and bound to its admitted normalized config', () => {
	let config = configuration('hysteria2');
	let content = 'hy2://synthetic@edge.example:443#Example';
	let portable = { content, sha256: digest.sha256(content),
		configSha256: digest.sha256(config) };
	equal(core.portable(portable, config), { content, sha256: digest.sha256(content) });
	rejects(() => core.portable({ ...portable, content: content + 'changed' }, config));
	rejects(() => core.portable(portable, configuration('hysteria2', 'other.example')));
	let state = model.defaults();
	state.servers = [{ id: 'server-000000000001', name: 'Example', engine: 'core',
		protocol: 'hysteria2', endpoint: 'edge.example:443', config, portableProfile: portable }];
	equal(model.public_state(model.validate_state(state)).servers[0].portableProfile, null);
});
test('Core proof rejects stale/future/wrong generation/config/boot identities', () => {
	let server = { id: 'server-synthetic', config: configuration('hysteria2') };
	let synthetic_generation_id = '0123456789abcdef';
	let owner = { owned: true, generation_key: synthetic_generation_id };
	let proof = { generation_key: owner.generation_key, serverId: server.id,
		configIdentity: digest.sha256(server.config), validated: true, checkedUptimeMs: 2000, bootId: 'boot-a' };
	equal(core.proof_valid(proof, server, owner, 3000, 'boot-a', 1500), true);
	for (let changed in [{ ...proof, checkedUptimeMs: 3001 }, { ...proof, checkedUptimeMs: 0 },
		{ ...proof, generation_key: '1111111111111111' }, { ...proof, configIdentity: 'wrong' },
		{ ...proof, bootId: 'boot-b' }, { ...proof, validated: false }])
		equal(core.proof_valid(changed, server, owner, 3000, 'boot-a', 1500), false);
	equal(core.proof_valid(proof, server, { ...owner, owned: false }, 3000, 'boot-a', 1500), false);
	equal(core.proof_valid(proof, server, owner, 8000, 'boot-a'), false);
});
print('# Core model tests: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
