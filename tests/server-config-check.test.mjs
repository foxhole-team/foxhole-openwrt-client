import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { functionBody, plain, read, rpcPath, panelRoot } from './helpers.mjs';

const path = 'package/foxhole-openwrt-client/root/usr/share/foxhole/server-check.uc';
const source = readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
function harness({ resolved = ['1.1.1.1'], connected = true, ping = 0 } = {}) {
  const calls = [];
  const builtins = { type: x => x == null ? 'null' : Array.isArray(x) ? 'array' : typeof x,
    length: x => x?.length ?? 0, match: (x,r) => x.match(r), split: (x,d) => x.split(d),
    index: (x,v) => x.indexOf(v), int: x => parseInt(x,10), min: Math.min,
    iptoarr: x => /^\d+\.\d+\.\d+\.\d+$/.test(x) ? x.split('.').map(Number) : null,
    arrtoip: x => x.join('.'), die: x => { throw Error(x); } };
  const body = source.replace(/^import .*;\n/gm,'').replace(/^export /gm,'')
    .replace(/for \(let (\w+) in /g,'for (let $1 of ');
  const socket = { AF_INET: 2, AF_INET6: 10,
    connect: (...args) => { calls.push(args); return connected ? {close(){calls.push('close');}} : null; } };
  const fs = { readfile: () => '100.000 200.00' };
  const handoff = { public_address: x => ['1.1.1.1','8.8.8.8'].includes(x),
    hostname: x => { if(!/^[A-Za-z0-9.-]+\.[A-Za-z]+$/.test(x)) throw Error('invalid_handoff'); return x; } };
  const api = new Function(...Object.keys(builtins), 'fs','socket','handoff','system','mock_resolver',
    `${body}; return {endpoint, check: parsed => check(parsed, mock_resolver)};`)(...Object.values(builtins), fs, socket, handoff,
      args => {calls.push(args); return ping;}, host => {calls.push(['resolve',host]); return resolved;});
  return {...api, calls};
}
const config = (endpoint='example.com:443', protocol='trojan') => ({endpoint,protocol});

test('TCP availability pins a bounded public DNS result and closes the connection', () => {
  const h = harness();
  const result = h.check(config());
  assert.deepEqual(plain(result), {scope:'tcp',code:'reachable',reachable:true});
  assert.deepEqual(h.calls[0], ['resolve','example.com']);
  assert.equal(h.calls[1][0].address, '1.1.1.1');
  assert.equal(h.calls[1][0].port, 443);
  assert.equal(h.calls.at(-1), 'close');
});

test('UDP host response never claims a verified VPN or UDP service', () => {
  const h = harness();
  assert.deepEqual(plain(h.check(config('1.1.1.1:443','hysteria2'))),
    {scope:'host',code:'reachable',reachable:true});
  assert.equal(h.calls[0][0], '/bin/sh');
  assert.match(h.calls[0][2], /^exec \/bin\/ping/);
  assert.ok(h.calls[0].includes('1.1.1.1'));
  assert.ok(!h.calls.some(x => Array.isArray(x) && typeof x[0]==='object'));
});

test('blocked/private DNS answers cannot initiate a socket or ping', () => {
  for (const address of ['127.0.0.1','192.168.8.1','169.254.169.254']) {
    const h = harness({resolved:[address]});
    assert.equal(h.check(config()).code,'blocked_address');
    assert.deepEqual(h.calls,[['resolve','example.com']]);
    const literal = harness();
    assert.equal(literal.check(config(`${address}:443`)).code,'blocked_address');
    assert.equal(literal.calls.length,0);
  }
});

test('failed TCP and blocked ICMP remain unconfirmed rather than proving an invalid config', () => {
  assert.deepEqual(plain(harness({connected:false}).check(config('1.1.1.1:443'))),
    {scope:'tcp',code:'not_confirmed',reachable:false});
  assert.deepEqual(plain(harness({ping:1}).check(config('1.1.1.1:443','wireguard'))),
    {scope:'host',code:'not_confirmed',reachable:false});
});

test('endpoint ranges use one bounded port and reject malformed hosts', () => {
  const h = harness();
  assert.equal(h.endpoint('example.com:443-445,9000').port,443);
  for(const value of ['example.com:0','example.com:65536','example.com:443;id','example.com:443/'])
    assert.throws(()=>h.endpoint(value));
});

test('server.test preserves default config admission and only probes explicitly requested valid config', async () => {
  const rpc = await read(rpcPath);
  const calls=[];
  const server = new Function('admit_server','digest','server_check','trim',
    `return function(raw,engine,reachability) ${functionBody(rpc,'test_server')}`)(
      raw=>{calls.push('admit');if(raw==='bad')throw Error('invalid_config');return {...config(),name:'test'};},
      {sha256:()=> 'a'.repeat(64)}, {check:parsed=>{calls.push('check');return {scope:'tcp',code:'reachable',reachable:true};}}, x=>x.trim());
  assert.equal(server('x','',false).scope,'config');
  assert.deepEqual(calls,['admit']);
  const checked=server('x','',true);
  assert.equal(checked.connected,false);
  assert.equal(checked.reachability.scope,'tcp');
  assert.deepEqual(calls,['admit','admit','check']);
  assert.throws(()=>server('bad','',true),/invalid_config/);
  assert.equal(calls.at(-1),'admit');
});

test('web requests the network check and distinguishes TCP from UDP host evidence', async () => {
  const app = await read(`${panelRoot}/app.js`);
  assert.match(functionBody(app,'testServer'),/reachability:\s*true/);
  const notice = new Function(`return function(result) ${functionBody(app,'serverTestNotice')}`)();
  assert.equal(notice({valid:true,reachability:{scope:'tcp',code:'reachable',reachable:true}}).key,'server.test_tcp');
  assert.equal(notice({valid:true,reachability:{scope:'host',code:'reachable',reachable:true}}).key,'server.test_host');
  assert.equal(notice({valid:true}).key,'server.test_unconfirmed');
  assert.equal(notice({valid:false}).key,'server.test_invalid');
});
