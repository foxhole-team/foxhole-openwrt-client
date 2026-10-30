import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import net from 'node:net';
import { functionBody, root, rpcPath } from './helpers.mjs';

assert.equal(root, '/workspace/');
assert.equal(process.getuid(), 1000);
const rpc = await readFile(root + rpcPath, 'utf8');
const id = 'client-000000000001', other = 'client-000000000002';
const secret = randomBytes(32).toString('hex');
const generation = randomBytes(32).toString('hex');
const config = { trafficStats: { listen: '127.0.0.1:901', secret },
  auth: { type: 'userpass', userpass: { [id]: secret, [other]: secret } } };
const state = { revision: 7, clients: [id, other].map(value =>
  ({ id: value, inbound: true, secret })) };
const records = {
  '/tmp/foxhole/inbound/generation': generation,
  '/tmp/foxhole/inbound/shared.json': JSON.stringify(config),
  '/tmp/foxhole/inbound/observations.json': JSON.stringify({ schema: 1,
    generation, revision: 7, listeners: [{ id: 'shared', ...config.trafficStats }] })
};
const source = `import * as socket from 'socket';
import * as core_adapter from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/core-adapter.uc';
import * as observation from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/client-observation.uc';
let records = ${JSON.stringify(records)}, state = ${JSON.stringify(state)};
let store = { read: (path, limit) => records[path] };
function session(request) { if (request.args?.token != 'synthetic-session') die('unauthorized'); };
function locked(fn) { return fn(); };
function state_record() { return state; };
${[['online_ready', 'connection, flags, deadline'], ['read_online', 'listener, ids'],
  ['client_status', 'request']].map(([name, args]) =>
  `function ${name}(${args}) ${functionBody(rpc, name)};`).join('\n')}
print(sprintf('%J', client_status({ args: { token: 'synthetic-session' } })), '\\n');
`;

async function readStatus() {
  return new Promise((resolve, reject) => {
    const child = spawn('ucode', ['-'], { stdio: ['pipe', 'pipe', 'pipe'] });
    let output = '', error = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
    child.stdout.on('data', data => {
      output += data;
      if (output.length > 16384) child.kill('SIGKILL');
    });
    child.stderr.on('data', data => {
      error += data;
      if (error.length > 16384) child.kill('SIGKILL');
    });
    child.on('error', failure => { clearTimeout(timer); reject(failure); });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      if (code !== 0 || signal || error) reject(new Error('actual ucode socket reader failed'));
      else { try { resolve(JSON.parse(output)); } catch (failure) { reject(failure); } }
    });
    child.stdin.end(source);
  });
}

let caseName, requestCount = 0;
const sockets = new Set();
const server = net.createServer(connection => {
  sockets.add(connection);
  connection.setTimeout(5000, () => connection.destroy());
  connection.on('close', () => sockets.delete(connection));
  connection.on('error', () => {});
  let raw = '';
  connection.on('data', data => {
    raw += data;
    if (raw.length > 2048) { connection.destroy(); return; }
    if (!raw.includes('\r\n\r\n')) return;
    connection.removeAllListeners('data');
    requestCount++;
    assert.equal(connection.remoteAddress, '127.0.0.1');
    assert.ok(raw.startsWith('GET /online HTTP/1.0\r\n'));
    assert.ok(raw.includes('\r\nAuthorization: ' + secret + '\r\n'));
    if (caseName === 'timeout') return;
    let status = '200 OK', body = JSON.stringify({ [id]: 1, [other]: 0 });
    if (caseName === 'empty') body = '{}';
    if (caseName === 'unauthorized') { status = '401 Unauthorized'; body = '{}'; }
    if (caseName === 'malformed') body = JSON.stringify({ [id]: true });
    if (caseName === 'oversized') body = ' '.repeat(8193);
    if (caseName === 'truncated') body = '{}';
    const length = caseName === 'truncated' ? body.length + 1 : body.length;
    const response = `HTTP/1.0 ${status}\r\nContent-Type: application/json\r\nContent-Length: ${length}\r\n\r\n${body}`;
    if (caseName === 'fragmented') {
      connection.write(response.slice(0, 23));
      setTimeout(() => connection.end(response.slice(23)), 20);
    } else connection.end(response);
  });
});
await new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(901, '127.0.0.1', resolve);
});
let passed = 0;
try {
  for (caseName of ['active', 'empty', 'fragmented', 'unauthorized', 'malformed',
    'oversized', 'truncated', 'timeout']) {
    const before = requestCount, start = performance.now();
    const result = await readStatus();
    const values = caseName === 'active' || caseName === 'fragmented' ? [true, false]
      : caseName === 'empty' ? [false, false] : [null, null];
    assert.deepEqual(result, { schema: 1, revision: 7,
      clients: [id, other].map((value, index) => ({ id: value, online: values[index] })) });
    assert.equal(requestCount - before, 1);
    if (caseName === 'timeout') {
      assert.ok(performance.now() - start >= 1800);
      assert.ok(performance.now() - start < 3500);
    }
    passed++;
    process.stdout.write(`ok ${passed} - actual ucode loopback ${caseName}\n`);
  }
  process.stdout.write(`1..${passed}\n# real socket tests: ${passed} passed, 0 failed\n`);
} finally {
  for (const connection of sockets) connection.destroy();
  await new Promise(resolve => server.close(resolve));
}
