import * as actual from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/probe.uc';

function equal(value, expected) {
	if (sprintf('%J', value) != sprintf('%J', expected))
		die('assertion_failed');
};

let passed = 0, failed = 0;

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

function runtime(generation, server) {
	return { generation, value: {
		connected: true, activeServerId: server, desiredServerId: server
	} };
};

function cache() {
	return { schema: 1, vpn: {
		serverId: 'server-one', generation: 'generation-one',
		sampledAt: 100, address: '203.0.113.8', country: 'US',
		latency: 83.5
	}, wan: {
		device: 'eth0', gateway: '192.0.2.1', sampledAt: 100,
		latency: 1.5, country: 'DE', countryAt: 100
	} };
};

test('fresh VPN cache preserves actual nonzero measurements', () => {
	equal(actual.vpn_sample(cache(),
		runtime('generation-one', 'server-one'), 110), {
		address: '203.0.113.8', country: 'US', latency: 83.5
	});
});

test('a different server cannot inherit VPN metadata', () => {
	equal(actual.vpn_sample(cache(),
		runtime('generation-one', 'server-two'), 110), null);
});

test('restarting the same server invalidates the old generation', () => {
	equal(actual.vpn_sample(cache(),
		runtime('generation-two', 'server-one'), 110), null);
});

test('expired and future VPN samples are unavailable', () => {
	equal(actual.vpn_sample(cache(),
		runtime('generation-one', 'server-one'), 146), null);
	equal(actual.vpn_sample(cache(),
		runtime('generation-one', 'server-one'), 99), null);
});

test('disconnected runtime and failed probes hide VPN metadata', () => {
	let current = runtime('generation-one', 'server-one');
	current.value.connected = false;
	equal(actual.vpn_sample(cache(), current, 110), null);
	current.value.connected = true;
	let result = cache();
	result.vpn.latency = null;
	equal(actual.vpn_sample(result, current, 110), null);
	result.vpn.latency = -1;
	equal(actual.vpn_sample(result, current, 110), null);
});

test('WAN cache is tied to the actual interface and gateway', () => {
	equal(actual.wan_sample(cache(), 'eth1', '192.0.2.1', 110),
		{ latency: null, country: null });
	equal(actual.wan_sample(cache(), 'eth0', '192.0.2.2', 110),
		{ latency: null, country: null });
});

test('WAN country and latency have independent expiry', () => {
	equal(actual.wan_sample(cache(), 'eth0', '192.0.2.1', 146),
		{ latency: null, country: 'DE' });
	equal(actual.wan_sample(cache(), 'eth0', '192.0.2.1', 21701),
		{ latency: null, country: null });
});

let saved, snapshots, traces, commands, writes;
let probe = {
	cache_path: '/fixture/cache', interval: 15,
	country_ttl: 21600, country_retry: 300,
	fresh: actual.fresh,
	read_json: () => saved,
	runtime_snapshot: () => shift(snapshots)
};
let runtime_model = { constants: () => ({ proxyListen: '127.0.0.1:18080' }) };

function wan() {
	return { device: 'eth0', gateway: '192.0.2.1' };
};

function trace(proxy) {
	push(traces, proxy);
	return { address: null, country: null, latency: null };
};

function run(command, timeout) {
	push(commands, { command, timeout });
	return 'time=1.5 ms';
};

function write_cache(value) {
	saved = json(sprintf('%J', value));
	push(writes, saved);
	return true;
};

// The production sampler is injected with deterministic I/O.

function reset() {
	saved = cache();
	saved.wan.countryAt = time();
	snapshots = [ runtime('generation-one', 'server-one'),
		runtime('generation-one', 'server-one') ];
	traces = []; commands = []; writes = [];
};

test('recent attempt prevents additional network commands', () => {
	reset();
	saved.startedAt = time();
	collect();
	equal(length(commands), 0);
	equal(length(traces), 0);
	equal(length(writes), 0);
});

test('failed VPN probe replaces previously successful measurements', () => {
	reset();
	collect();
	equal(length(traces), 1);
	equal(saved.vpn.latency, null);
	equal(saved.vpn.address, null);
	equal(saved.vpn.country, null);
	equal(saved.wan.latency, 1.5);
	equal(length(writes), 2);
});

test('runtime change during network I/O discards VPN result', () => {
	reset();
	snapshots[1] = runtime('generation-two', 'server-one');
	collect();
	equal(saved.vpn, null);
});

test('WAN failure retries only after the retry interval', () => {
	reset();
	saved.wan.country = null;
	saved.wan.countryAt = null;
	saved.wan.countryAttempt = time();
	collect();
	equal(length(traces), 1);
	reset();
	saved.wan.country = null;
	saved.wan.countryAt = null;
	saved.wan.countryAttempt = time() - 301;
	collect();
	equal(length(traces), 2);
});

print('1..', passed + failed, '\n');
print('# probe tests: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
