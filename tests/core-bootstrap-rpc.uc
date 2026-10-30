let engine_service = { guard_mutation: () => {}, stop_intent: () => {} };
import * as model from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/model.uc';
import * as core_model from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/core-model.uc';
import * as runtime_model from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/runtime-model.uc';
import * as fixture from '/workspace/tests/bootstrap-profile.uc';
import * as digest from 'digest';

const STATE_PATH = '/fixture/state', IP = '/fixture/ip', NFT = '/fixture/nft';
const CORE_CONFIG_PATH = '/fixture/core-config';
let state, writes, prepared, policy_calls, state_writes, admitted;
let adapter = { binary: '/fixture/core', config_path: CORE_CONFIG_PATH,
	auth_path: '/fixture/bridge-auth', proof_path: '/fixture/proof',
	check: () => writes[CORE_CONFIG_PATH] != null };
let restart_runtime;
function clone(value) { return json(sprintf('%J', value)); };
function fail(code) { die(code); };
function session(request) {
	if (request.args.token != 'synthetic-session') die('unauthorized');
};
function valid_revision(value) {
	if (type(value) != 'int' || value < 0) die('revision_conflict');
	return value;
};
function state_record() { return clone(state); };
function locked(fn) { return fn(); };
function next_id(kind) { return kind + '-000000000001'; };
function public_state(value) { return model.public_state(value); };
function write_json(path, value, mode) {
	if (mode != 0o600) die('unexpected_mode');
	if (path == STATE_PATH) {
		state_writes++; state = model.validate_state(clone(value));
	} else if (path != adapter.auth_path) die('unexpected_write');
};
function write_file(path, raw, mode) {
	if (path != adapter.config_path || mode != 0o600) die('unexpected_write');
	writes[path] = raw;
};
function apply_policy(value, connected, emergency) {
	if (connected || !emergency || sprintf('%J', value) != sprintf('%J', state))
		die('unexpected_policy');
	policy_calls++;
};
function unlink(path) {
	if (path != adapter.proof_path) die('unexpected_unlink');
};
function write_status(value, phase, connected, enforced, error) {
	if (phase != 'connecting' || connected || !enforced || error != null)
		die('unexpected_status');
	prepared++;
};
function resolve_endpoint(endpoint) { die('unexpected_legacy_resolver'); };
let uci = { cursor: () => die('unexpected_legacy_settings') };
let core = core_model, runtime = runtime_model;
let fs = {
	stat: path => index(['/dev/net/tun', adapter.binary, IP, NFT], path) >= 0 ? {} : null,
	readfile: (path, size) => {
		if (path != '/dev/urandom' || size != 32) die('unexpected_read');
		return 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
	}
};
let core_adapter = { admit: raw => {
	admitted++;
	let parsed = core_model.describe(raw);
	return { ...parsed, raw,
		portableProfile: { content: raw, sha256: digest.sha256(raw),
			configSha256: digest.sha256(raw) } };
} };
// Saved native profiles run through the real RPC/runtime bodies.

restart_runtime = value => { prepare(); return true; };

let passed = 0, failed = 0;
function equal(actual, expected) {
	if (sprintf('%J', actual) != sprintf('%J', expected)) die('assertion_failed');
};
function rejects(fn, code) {
	let caught = null;
	try { fn(); } catch (error) { caught = type(error) == 'string' ? error : error.message; }
	equal(caught, code);
};
function reset() {
	state = model.defaults(); writes = {}; prepared = 0; policy_calls = 0;
	state_writes = 0; admitted = 0;
};
function request(extra) {
	return { args: { token: 'synthetic-session', revision: state.revision,
		id: 'server-000000000001', ...extra } };
};
function test(name, fn) {
	reset();
	try { fn(); passed++; print('ok ', passed + failed, ' - ', name, '\n'); }
	catch (error) { failed++; print('not ok ', passed + failed, ' - ', name, '\n');
		print('# ', sprintf('%J', error), '\n'); }
};

for (let upstream in fixture.upstreams()) {
	test('native ' + upstream.type + ' bootstrap survives save/get/start/runtime', () => {
		let original = fixture.profile(upstream), raw = sprintf('%J', original);
		let public = save_server(request({ id: '', name: 'Example', engine: 'core', config: raw }));
		equal(admitted, 1); equal(state_writes, 1);
		equal(state.servers[0].config, raw);
		let private = get_server(request({}));
		equal(private.config, raw); equal(private.configSha256, digest.sha256(raw));
		equal(private.portableProfile, { content: raw, sha256: digest.sha256(raw) });
		equal(public.servers[0].config, null); equal(public.servers[0].portableProfile, null);
		start_server(request({}));
		equal(writes[adapter.config_path], raw);
		let launched = json(writes[adapter.config_path]);
		equal(launched.bootstrap_dns, original.bootstrap_dns);
		equal(launched.outbound, original.outbound);
		equal(state.servers[0].endpoint, 'group.example:8443');
		equal(prepared, 1); equal(policy_calls, 1); equal(admitted, 1);
	});
}
test('changing bootstrap invalidates the bound portable profile', () => {
	let raw = sprintf('%J', fixture.profile(fixture.upstreams()[0]));
	save_server(request({ id: '', name: 'Example', engine: 'core', config: raw }));
	let changed = json(state.servers[0].config);
	changed.bootstrap_dns.upstreams[0].address = '192.0.2.54:53';
	let altered = clone(state);
	altered.servers[0].config = sprintf('%J', changed);
	rejects(() => model.validate_state(altered), 'invalid_config');
	equal(get_server(request({})).config, raw);
});
test('legacy Hysteria rejects bootstrap instead of saving an ignored policy', () => {
	let legacy = { server: 'group.example:443', auth: 'synthetic-fixture',
		bootstrap_dns: fixture.profile(fixture.upstreams()[0]).bootstrap_dns };
	rejects(() => save_server(request({ id: '', name: 'Example', engine: 'hysteria',
		config: sprintf('%J', legacy) })), 'unsupported_config');
	equal(admitted, 0); equal(state_writes, 0); equal(prepared, 0);
	delete legacy.bootstrap_dns;
	save_server(request({ id: '', name: 'Example', engine: 'hysteria', config: sprintf('%J', legacy) }));
	equal(state_writes, 1); equal(model.parse_config(state.servers[0].config).endpoint, 'group.example:443');
});
print('1..', passed + failed, '\n');
print('# Core bootstrap RPC/runtime tests: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
