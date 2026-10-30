import * as observation from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/client-observation.uc';
import * as inbound from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/inbound.uc';

const ID = 'client-000000000001', OTHER = 'client-000000000002';
let passed = 0, failed = 0;
function equal(actual, expected) {
	if (sprintf('%J', actual) != sprintf('%J', expected)) die('assertion');
};
function test(name, fn) {
	try { fn(); passed++; print('ok ', passed + failed, ' - ', name, '\n'); }
	catch (_) { failed++; print('not ok ', passed + failed, ' - ', name, '\n'); }
};
test('only authenticated active-session counts produce online or offline', () => {
	let values = observation.online_map('{"client-000000000001":2}', [ID, OTHER]);
	equal(observation.online(values, ID), true);
	equal(observation.online(values, OTHER), false);
	equal(observation.online(null, ID), null);
	equal(observation.online(observation.online_map('{}', [ID]), ID), false);
});
test('malformed foreign or oversized statistics remain unknown', () => {
	for (let raw in ['', 'broken', '[]', '{"foreign":1}',
	    '{"client-000000000001":true}', '{"client-000000000001":-1}',
	    '{"client-000000000001":"1"}', '{"client-000000000001":2147483648}'])
		equal(observation.online_map(raw, [ID]), null);
	let spaces = ' ';
	for (let i = 0; i < 14; i++) spaces += spaces;
	equal(observation.online_map(spaces, [ID]), null);
});
test('stats listeners require bounded privileged loopback and independent secret', () => {
	for (let i = 0; i <= 4; i++)
		equal(observation.stats_config(i, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
			{ listen: '127.0.0.1:' + (901 + i), secret: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' });
	for (let args in [[-1, 'a'], [5, 'a'], [0, 'bad'], ['0', 'a']]) {
		let rejected = false;
		try { observation.stats_config(args[0], args[1]); } catch (_) { rejected = true; }
		equal(rejected, true);
	}
});
let status_state, records, online_values, read_count, change_generation;
const GEN = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const SECRET = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
function session(request) {
	if (request.args?.token != 'synthetic-session') die('unauthorized');
};
function locked(fn) { return fn(); };
function state_record() { return status_state; };
let store = { read: (path, limit) => records[path] };
function fixture_read_online(listener, users) {
	read_count++;
	if (change_generation) records['/tmp/foxhole/inbound/generation'] = 'changed';
	return online_values;
};
// The authenticated observer implementation is injected here.
function reset() {
	status_state = { revision: 7, clients: [
		{ id: ID, inbound: true, secret: SECRET }, { id: OTHER, inbound: false }] };
	records = {
		'/tmp/foxhole/inbound/generation': GEN,
		'/tmp/foxhole/inbound/observations.json': sprintf('%J', { schema: 1,
			generation: GEN, revision: 7, listeners: [ { id: 'shared',
			listen: '127.0.0.1:901', secret: SECRET } ] }),
		'/tmp/foxhole/inbound/shared.json': sprintf('%J', {
			trafficStats: { listen: '127.0.0.1:901', secret: SECRET },
			auth: { type: 'userpass', userpass: { [ID]: SECRET } } })
	};
	online_values = { [ID]: 1 }; read_count = 0; change_generation = false;
};
function observe() { return client_status({ args: { token: 'synthetic-session' } }); };
test('RPC status requires authentication and current runtime observation', () => {
	reset(); let rejected = false;
	try { client_status({ args: {} }); } catch (_) { rejected = true; }
	equal(rejected, true); equal(read_count, 0);
	equal(observe(), { schema: 1, revision: 7, clients: [
		{ id: ID, online: true }, { id: OTHER, online: null }] });
	online_values = {};
	equal(observe().clients[0].online, false);
	online_values = null;
	equal(observe().clients[0].online, null);
});
test('missing or stale listener revision cannot infer online from configuration', () => {
	reset(); delete records['/tmp/foxhole/inbound/observations.json'];
	equal(observe().clients[0].online, null); equal(read_count, 0);
	reset(); status_state.revision = 8;
	equal(observe().clients[0].online, null); equal(read_count, 0);
});
test('credential mismatch and generation change discard all observations', () => {
	reset(); status_state.clients[0].secret = GEN;
	equal(observe().clients[0].online, null); equal(read_count, 0);
	reset(); change_generation = true;
	equal(observe().clients[0].online, null); equal(read_count, 1);
});
test('a malformed later listener cannot retain a partial online result', () => {
	reset();
	status_state.clients[1].inbound = true;
	status_state.clients[1].secret = SECRET;
	let value = json(records['/tmp/foxhole/inbound/observations.json']);
	value.listeners[0].id = ID;
	records['/tmp/foxhole/inbound/' + ID + '.json'] = records['/tmp/foxhole/inbound/shared.json'];
	push(value.listeners, value.listeners[0]);
	records['/tmp/foxhole/inbound/observations.json'] = sprintf('%J', value);
	equal(observe().clients[0].online, null); equal(read_count, 1);
});
test('per-client observation cannot attribute another valid client session', () => {
	reset(); status_state.clients[1].inbound = true;
	status_state.clients[1].secret = SECRET;
	let listeners = [];
	for (let id in [ID, OTHER]) {
		push(listeners, { id, listen: '127.0.0.1:902', secret: SECRET });
		records['/tmp/foxhole/inbound/' + id + '.json'] = sprintf('%J', {
			trafficStats: { listen: '127.0.0.1:902', secret: SECRET },
			auth: { type: 'userpass', userpass: { [OTHER]: SECRET } } });
	}
	records['/tmp/foxhole/inbound/observations.json'] = sprintf('%J', {
		schema: 1, generation: GEN, revision: 7, listeners });
	equal(observe().clients[0].online, null);
	equal(observe().clients[1].online, null); equal(read_count, 0);
});
test('incomplete shared authentication inventory remains unknown', () => {
	reset(); status_state.clients[1].inbound = true;
	status_state.clients[1].secret = SECRET;
	equal(observe().clients[0].online, null); equal(read_count, 0);
});
test('generated inbound stats never retain externally supplied stats endpoints', () => {
	let state = { settings: { clientRules: false }, servers: [] };
	let client = { id: ID, inbound: true, port: 14443, secret: SECRET };
	let base = { template: { trafficStats: { listen: '0.0.0.0:9999', secret: 'external' } } };
	let stats = observation.stats_config(0, SECRET);
	equal(inbound.config(base, state, client, false, [], stats).trafficStats, stats);
	equal(inbound.config(base, state, client, false, []).trafficStats, null);
	equal(inbound.shared_config(base, state, [client], false, [], stats).trafficStats, stats);
});
test('HTTP body requires successful bounded complete JSON response', () => {
	let valid = 'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}';
	equal(observation.http_body(valid), '{}');
	for (let raw in [replace(valid, '200 OK', '401 Unauthorized'),
	    replace(valid, 'Content-Length: 2', 'Content-Length: 3'),
	    replace(valid, 'Content-Length: 2', 'Content-Length: 2\r\nContent-Length: 2'),
	    replace(valid, 'Content-Length: 2', 'Transfer-Encoding: chunked'),
	    replace(valid, 'application/json', 'text/plain')])
		equal(observation.http_body(raw), null);
});
let clock, chunks, sent, connect_count, close_count, timed_out, recv_error;
let connection = {
	send: (value, flags) => { sent += value; return length(value); },
	recv: (limit, flags) => { if (recv_error) die('socket_error'); return shift(chunks); },
	close: () => { close_count++; }
};
let socket = {
	AF_INET: 2, POLLIN: 1, POLLOUT: 4, POLLHUP: 16, MSG_DONTWAIT: 64, MSG_NOSIGNAL: 16384,
	connect: (address, service, hints, timeout) => {
		equal(address, { family: 2, address: '127.0.0.1', port: 901 });
		equal(timeout, 500); connect_count++; return connection;
	},
	poll: (timeout, item) => {
		if (timeout <= 0 || timeout > 2000) die('invalid_deadline');
		clock += timed_out ? timeout : 1;
		return timed_out ? [] : [item];
	}
};
let core_adapter = { clock_ms: () => clock };
// The loopback socket reader is injected without process calls.
function reset_socket() {
	clock = 1000; sent = ''; connect_count = 0; close_count = 0; timed_out = false;
	recv_error = false;
	chunks = ['HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}', ''];
};
test('socket observer uses only fixed loopback and closes the successful connection', () => {
	reset_socket();
	let values = read_online({ listen: '127.0.0.1:901', secret: SECRET }, [ID]);
	equal(values, {}); equal(close_count, 1); equal(connect_count, 1);
	equal(index(sent, 'GET /online HTTP/1.0'), 0);
	equal(index(sent, 'Authorization: ' + SECRET) >= 0, true);
});
test('socket timeout or incomplete body is unknown and closes exact connection', () => {
	reset_socket(); timed_out = true;
	equal(read_online({ listen: '127.0.0.1:901', secret: SECRET }, [ID]), null);
	equal(clock, 3000); equal(close_count, 1);
	reset_socket(); chunks = ['HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\n{}', ''];
	equal(read_online({ listen: '127.0.0.1:901', secret: SECRET }, [ID]), null);
	equal(close_count, 1);
});
test('socket observer refuses non-loopback and unbounded ports before connecting', () => {
	reset_socket();
	for (let endpoint in ['0.0.0.0:901', '192.168.1.1:901', '127.0.0.1:906'])
		equal(read_online({ listen: endpoint, secret: SECRET }, [ID]), null);
	equal(connect_count, 0); equal(close_count, 0);
});
test('socket exceptions close the already acquired connection', () => {
	reset_socket(); recv_error = true;
	equal(read_online({ listen: '127.0.0.1:901', secret: SECRET }, [ID]), null);
	equal(connect_count, 1); equal(close_count, 1);
});
let metadata_writes = 0, metadata_locks = 0, metadata_unlocks = 0, metadata_closes = 0;
const directory = '/tmp/foxhole/inbound';
let fs = {
	open: () => ({ lock: mode => {
		if (mode == 'x') metadata_locks++; else metadata_unlocks++;
		return true;
	}, close: () => { metadata_closes++; } }),
	lstat: () => ({ type: 'file', uid: 0, nlink: 1, mode: 0o600, inode: 1 })
};
let model = { validate_state: value => value };
store.target = () => {};
store.file_metadata = value => value.uid == 0 && value.nlink == 1;
store.write = (path, raw) => {
	if (path != directory + '/observations.json') die('unexpected_metadata_write');
	metadata_writes++; records[path] = raw;
};
// The unchanged-generation metadata rebind is injected here.
test('metadata-only state revision refreshes observer without restarting listeners', () => {
	reset(); metadata_writes = 0; metadata_locks = 0;
	let before_config = records[directory + '/shared.json'];
	status_state.revision = 8; status_state.devices = [{ route: 'direct' }];
	records['/etc/foxhole/state.json'] = sprintf('%J', status_state);
	equal(rebind_observations(status_state, GEN, {}, [status_state.clients[0]]), true);
	equal(metadata_locks, 1); equal(metadata_writes, 1);
	equal(records[directory + '/generation'], GEN);
	equal(records[directory + '/shared.json'], before_config);
	equal(observe().revision, 8); equal(observe().clients[0].online, true);
});
test('metadata rebind rejects a changed generation or config binding', () => {
	reset(); metadata_writes = 0;
	records['/etc/foxhole/state.json'] = sprintf('%J', status_state);
	equal(rebind_observations(status_state, SECRET, {}, [status_state.clients[0]]), false);
	equal(metadata_writes, 0);
	let config = json(records[directory + '/shared.json']);
	config.trafficStats.secret = GEN;
	records[directory + '/shared.json'] = sprintf('%J', config);
	equal(rebind_observations(status_state, GEN, {}, [status_state.clients[0]]), false);
	equal(metadata_writes, 0);
});
test('metadata rebind cannot preserve a revoked listener credential', () => {
	reset(); metadata_writes = 0;
	records['/etc/foxhole/state.json'] = sprintf('%J', status_state);
	let config = json(records[directory + '/shared.json']);
	config.auth.userpass[ID] = GEN;
	records[directory + '/shared.json'] = sprintf('%J', config);
	equal(rebind_observations(status_state, GEN, {}, [status_state.clients[0]]), false);
	equal(metadata_writes, 0);
});
test('metadata rebind releases its lock after a state change or read exception', () => {
	for (let raw in ['broken', sprintf('%J', { revision: 8 })]) {
		reset(); metadata_writes = 0; metadata_unlocks = 0; metadata_closes = 0;
		records['/etc/foxhole/state.json'] = raw;
		equal(rebind_observations(status_state, GEN, {}, [status_state.clients[0]]), false);
		equal(metadata_writes, 0); equal(metadata_unlocks, 1); equal(metadata_closes, 1);
	}
});
print('1..', passed + failed, '\n');
print('# client observation tests: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
