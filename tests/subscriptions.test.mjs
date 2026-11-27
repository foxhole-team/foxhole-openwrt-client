import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { functionBody, panelRoot, read } from './helpers.mjs';
const root = new URL('../package/foxhole-openwrt-client/root/', import.meta.url);
const source = () => readFileSync(new URL('usr/share/foxhole/subscriptions.uc', root), 'utf8');
function fixture(environment = {}) {
  const bindings = { length: value => typeof value === 'string' ? Buffer.byteLength(value) : value?.length ?? 0,
    match: (value, pattern) => value.match(pattern), split: (value, separator) => value.split(separator),
    substr: (value, start, count) => value.substr(start, count), trim: value => value.trim(),
    index: (value, item) => value.indexOf(item), lc: value => value.toLowerCase(),
    filter: (values, fn) => values.filter(fn), push: (values, value) => values.push(value),
    b64dec: value => Buffer.from(value, 'base64').toString('utf8'),
    replace: (value, pattern, target) => value.replace(pattern, target), int: (value, radix) => parseInt(value, radix),
    chr: String.fromCharCode, iptoarr: host => /^[0-9.]+$/.test(host) ? host.split('.').map(Number) : null,
    arrtoip: bytes => bytes.join('.'),
    registry: { profile_protocol: uri => ({ hy2: 'hysteria2', wg: 'wireguard' })[uri.split('://')[0]] || uri.split('://')[0],
      select_protocol: protocol => environment.installed?.includes(protocol), legacy_protocols: () => [] },
    server_check: { endpoint: value => ({ host: value.replace(/:[0-9]+$/, '') }) },
    core: { clock_ms: () => environment.now ?? 0,
      admit: (uri, timeout) => { assert.ok(timeout > 0 && timeout <= 1000); return environment.admit(uri); } },
    min: Math.min, receive: () => environment.feed,
    type: value => Number.isInteger(value) ? 'int' : typeof value,
    json: JSON.parse, sprintf: (_format, value) => JSON.stringify(value),
    digest: { sha256: value => createHash('sha256').update(value).digest('hex') },
    engine: { guard_mutation: () => { if (environment.busy) throw Error('busy'); } },
    fs: {open: () => ({ lock: () => true, close() {} }), lstat: () => ({}), stat: () => ({ type: 'file' }) },
    store: { target() {}, file_metadata: () => true,
      read: () => JSON.stringify(environment.state), write: (_path, raw) => { environment.state = JSON.parse(raw); } },
    runtime: { hysteria_config: () => ({}) },
    die: reason => { throw Error(reason); },
    handoff: { public_address: address => !/^(10\.|127\.|192\.168\.)/.test(address), hostname: host => { if (!/^[a-z0-9.-]+\.[a-z][a-z]+$/.test(host) || /\.(local|lan|localhost)$/.test(host)) throw Error('address'); return host; } },
    model: { validate_state: value => value, defaults: () => ({}), parse_config: uri => {
      if (uri.includes('malformed') || environment.strictLegacy && /[?&](alpn|mport)=/.test(uri)) throw Error('invalid');
      const match = uri.match(/^hy(?:steria)?2:\/\/[^@]+@([^#?]+)(?:\?[^#]*)?#(\S+)$/);
      return { endpoint: match[1], name: match[2], config: { tls: { insecure: uri.includes('insecure=1') } } };
    } },
  };
  const code = source().replace(/^import .*;$/gm, '').replace(/^export /gm, '')
    .replace(/\bfor\s*\(let (\w+) in /g, 'for (let $1 of ')
    .replaceAll('[[:cntrl:]]', '[\x00-\x1f\x7f]')
    .replace('function receive(raw) {', 'function receive_native(raw) {');
  return new Function(...Object.keys(bindings), `${code}\nreturn {source_url,http_body,nodes,selection,save_refresh,apply_pending,materialize,initial,web_source};`)(...Object.values(bindings));
}

test('subscription URL and response accept HTTPS identity only', () => {
  const service = fixture();
  assert.equal(service.source_url('https://example.test/path?opaque=a').path, '/path?opaque=a');
  for (const url of ['http://example.test/','https://my.lan/a','https://user@example.test','https://example.test:444','https://127.0.0.1/', 'https://example.test/a\r\nHost: a'])
    assert.throws(() => service.source_url(url));
  assert.equal(service.http_body('HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc'), 'abc');
  for (const raw of ['HTTP/1.0 301 Moved\r\nLocation: https://my.lan/\r\n\r\nabc',
    'HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nabc', 'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nabc'])
    assert.throws(() => service.http_body(raw));
});

test('plain and base64 feed use the same typed nodes and refuse an ambiguous re-selection', () => {
  const service = fixture();
  const raw = 'vless://unsupported\nhy2://credential@node1.example.test:443#Alpha\nhysteria2://credential@node2.example.test:443#Beta\nhy2://credential@node3.example.test:443?insecure=1#Bad';
  const nodes = service.nodes(raw);
  assert.deepEqual(service.nodes(Buffer.from(raw).toString('base64')), nodes);
  assert.deepEqual(nodes.map(node => node.name), ['Alpha', 'Beta', 'Bad']);
  assert.equal(service.selection(nodes, 'hysteria2', 'Beta', 'node1.example.test:443').endpoint, 'node2.example.test:443');
  assert.equal(service.selection(nodes, 'hysteria2', 'Former name', 'node1.example.test:443').name, 'Alpha');
  assert.equal(service.selection([...nodes, { ...nodes[0], endpoint: 'other.example.test:443' }], 'hysteria2', 'Alpha', 'node1.example.test:443'), null);
  assert.equal(service.selection(nodes, 'hysteria2', 'Removed', 'other.example.test:443'), null);
});


test('refresh stages active changes and preserves edits made while downloading', () => {
  const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const selected = { id: 'server-111111111111', name: 'My VPN',
    config: 'hy2://old@node1.example.test:443#Alpha', endpoint: 'node1.example.test:443',
    subscription: { sourceUrl: 'https://example.test/synthetic', selectedProtocol: 'hysteria2',
      selectedNodeName: 'Alpha', selectedOptionId: 'selected-id', phoneProfileId: 'stable-phone' } };
  const next = 'hy2://new@node1.example.test:443#Renamed';
  const environment = { state: { revision: 4, activeServerId: selected.id, servers: [selected] } };
  const service = fixture(environment);
  const updates = { [selected.id]: { before: digest(selected), uri: next, name: 'Renamed',
    value: { config: next, endpoint: selected.endpoint } } };
  environment.state.servers[0].name = 'New name';
  service.save_refresh(updates);
  assert.equal(environment.state.revision, 4);
  assert.equal(environment.state.servers[0].name, 'New name');
  updates[selected.id].before = digest(environment.state.servers[0]);
  service.save_refresh(updates);
  const [saved] = environment.state.servers;
  assert.equal(environment.state.revision, 5);
  assert.equal(saved.id, selected.id);
  assert.equal(saved.config, selected.config);
  assert.equal(saved.subscriptionPending, next);
  assert.equal(saved.subscription.selectedNodeName, 'Renamed');
  assert.equal(saved.subscription.selectedOptionId, 'selected-id');
  assert.equal(service.apply_pending(saved), true);
  assert.equal(saved.config, next);
  assert.equal(saved.subscriptionPending, undefined);
});

test('scheduled fetch fixes the validated IPv4 and transmits the URL only over TLS stdin', () => {
  const helper = readFileSync(new URL('usr/libexec/foxhole-subscription-fetch', root), 'utf8');
  assert.match(helper, /safe\.public_address\(addr\)/);
  assert.match(helper, /-verify_return_error -verify_hostname "\$host"/);
  assert.match(helper, /-connect "\$address:443"/);
  assert.match(helper, /< "\$directory\/request" > "\$directory\/response" 2>\/dev\/null/);
  assert.match(source(), /now - last < 3600/);
  assert.match(source(), /store\.write\(input, 'GET ' \+ target\.path/);
  assert.doesNotMatch(source(), /system[^\n]*target\.path/);
});


test('installed VLESS and WireGuard use native admission and protocol-scoped matching', () => {
  const input = {
    vless: 'vless://synthetic@edge.example.test:443?security=tls#Selected%20Name',
    wireguard: 'wireguard://synthetic@wg.example.test?publickey=synthetic#Selected%20Name',
  };
  const environment = { installed: ['vless', 'wireguard'] };
  const service = fixture(environment);
  const rows = service.nodes(Object.values(input).join('\n') + '\nvless://synthetic@127.0.0.1:443#Local');
  assert.equal(rows.length, 2);
  assert.equal(service.selection(rows, 'vless', 'Selected Name', '').uri, input.vless);
  assert.equal(service.selection(rows, 'wireguard', 'Selected Name', '').endpoint, 'wg.example.test:51820');
  for (const protocol of ['vless', 'wireguard']) {
    const outbound = { type: protocol, server: 'edge.example.test', port: 443 };
    environment.admit = () => ({ protocol, endpoint: 'edge.example.test:443',
      config: { outbound }, raw: JSON.stringify({ outbound }), portableProfile: { content: input[protocol] } });
    assert.equal(service.materialize(input[protocol], 'core', protocol).portableProfile.content, input[protocol]);
    assert.throws(() => service.materialize(input[protocol], '', protocol));
  }
  environment.installed = [];
  assert.throws(() => service.materialize(input.wireguard, 'core', 'wireguard'));
  assert.throws(() => service.nodes('[Interface]\nPrivateKey = synthetic\n[Peer]'));
});

test('native refresh cannot remove transport trust or replace pinned identities', () => {
  const uri = 'vless://synthetic@edge.example.test:443?security=tls#Selected';
  const previous = { type:'vless', server:'edge.example.test', tls:{ enabled:true, pinned_spki_sha256:'pin' } };
  let outbound = { ...previous, tls: { ...previous.tls } };
  const service = fixture({ installed:['vless'], admit: () => ({ protocol:'vless', config:{ outbound } }) });
  const before = JSON.stringify({ outbound:previous });
  assert.doesNotThrow(() => service.materialize(uri,'core','vless',before));
  for (const tls of [{ insecure:true }, {enabled:false}, {enabled:true,pinned_spki_sha256:'changed'}]) {
    outbound = { ...previous, tls };
    assert.throws(() => service.materialize(uri,'core','vless',before));
  }
  outbound = { ...previous, server_ip:'192.168.1.2' };
  assert.throws(() => service.materialize(uri,'core','vless',before));
  assert.doesNotMatch(source(), /\(\?:/);
});


test('direct import keeps provider order across installed protocols and skips a rejected prefix', () => {
  const good = 'wireguard://synthetic@wg.example.test#Chosen';
  const later = 'hy2://synthetic@hy.example.test:443#Later';
  const feed = Array.from({length:6}, (_, n) => `vless://invalid${n}@vpn.example.test:443#Reject${n}`);
  feed.push(good, later);
  const tested = [];
  const environment = { now:0, feed:feed.join('\n'), installed:['vless','wireguard'], admit:uri => {
    tested.push(uri);
    environment.now += 100;
    if (uri !== good) throw new Error('native rejection');
    const outbound = { type:'wireguard', server:'wg.example.test', port:51820 };
    return {protocol:'wireguard', endpoint:'wg.example.test:51820', raw:JSON.stringify({outbound}),
      config:{outbound}, portableProfile:{content:uri}};
  } };
  const service = fixture(environment);
  const result = service.initial('https://example.test/feed');
  assert.equal(result.mode,'core');
  assert.equal(result.metadata.selectedProtocol, 'wireguard');
  assert.equal(result.value.portableProfile.content, good);
  assert.deepEqual(tested, feed.slice(0,-1));
});

test('direct import exhausts its shared deadline without saving a partially validated node', () => {
  const environment = { now:0, installed:['vless'],
    feed:'vless://synthetic@vpn.example.test:443#Late', admit:() => {
      environment.now = 16000;
      const outbound = {type:'vless',server:'vpn.example.test',port:443};
      return {protocol:'vless',config:{outbound}};
    } };
  assert.throws(() => fixture(environment).initial('https://example.test/feed'));
});

test('Hy2 options go through the installed native parser without a legacy-parser veto', () => {
  const uri = 'hy2://synthetic@edge.example.test:443?alpn=h3&mport=5000-5002#Synthetic';
  const outbound = {type:'hysteria2',server:'edge.example.test',port:443,tls:{enabled:true}};
  const environment = {installed:['hysteria2'],strictLegacy:true,admit:() => ({
    protocol:'hysteria2',endpoint:'edge.example.test:443',config:{outbound},raw:JSON.stringify({outbound})
  })};
  const service = fixture(environment);
  assert.equal(service.nodes(uri)[0].uri, uri);
  assert.equal(service.materialize(uri, 'core', 'hysteria2').endpoint, 'edge.example.test:443');
  assert.throws(() => service.materialize(uri, '', 'hysteria2'));
  outbound.tls.insecure = true;
  assert.throws(() => service.materialize(uri, 'core', 'hysteria2'));
});


test('new-server Save canonicalizes only a missing leading h and uses the default name', async () => {
  const model = fixture();
  const raw = 'hy2://synthetic@edge.example.test:443#Synthetic';
  const profile = { id:'server-000000000001',name:'Previous',endpoint:'edge.example.test:443',config:raw };
  const current = { revision:5,servers:[profile] };
  const requests = [];
  const bindings = {
    engine_service:{guard_mutation(){}}, session:()=>{}, valid_revision:input=>input,
    subscriptions:{web_source:model.web_source,initial:source=>{
      requests.push(source);
      assert.equal(source, 'https://example.test/synthetic');
      return {mode:'',value:{config:raw,endpoint:profile.endpoint},metadata:{sourceUrl:source,
        selectedProtocol:'hysteria2',selectedNodeName:'Synthetic',selectedOptionId:'stable',phoneProfileId:'stable'}};
    }},
    admit_server:config=>{ if (config !== raw) throw Error('unsupported_config'); return {endpoint:profile.endpoint}; },
    core_model:{subscription:value=>value??null}, trim:value=>value.trim(),
    next_id:()=> 'server-000000000002', match:(value,re)=>value.match(re), model:{server_name:value=>value},
    locked:fn=>fn(), state_record:()=>current, push:(list,value)=>list.push(value), fail:code=>{throw Error(code);},
    STATE_PATH:'state', write_json(){}, public_state:value=>({revision:value.revision,
      servers:value.servers.map(({id,name,endpoint})=>({id,name,endpoint}))}),
  };
  const rpc = readFileSync(new URL('usr/share/rpcd/ucode/foxhole.uc', root),'utf8');
  const body = functionBody(rpc,'save_server').replace(/\bfor \(let (\w+) in /g,'for (let $1 of ');
  const save = new Function(...Object.keys(bindings), `return function(request) ${body}`)(...Object.values(bindings));
  const saved = save({args:{revision:5,config:'  ttps://example.test/synthetic  ',name:''}});
  assert.equal(saved.servers[1].name,'VPN SERVER 01');
  assert.equal(saved.servers[1].id,'server-000000000002');
  assert.equal(current.servers[1].subscription.sourceUrl, 'https://example.test/synthetic');
  assert.doesNotMatch(JSON.stringify(saved), /synthetic|sourceUrl/i);
  assert.throws(()=>save({args:{revision:6,id:profile.id,config:'ttps://example.test/synthetic'}}), /unsupported_config/);
  for (const invalid of ['http://example.test/synthetic','hhttps://example.test/synthetic','ftp://example.test/synthetic'])
    assert.throws(()=>save({args:{revision:6,config:invalid}}), /unsupported_config/);
  assert.deepEqual(requests,['https://example.test/synthetic']);
  assert.equal(current.revision,6);
  const html = await read(`${panelRoot}/shell.html`);
  assert.match(html, /<input id="server-name-input"[^>]+data-server-name>/);
  const frontend = functionBody(await read(`${panelRoot}/app.js`),'saveServer');
  assert.doesNotMatch(frontend, /if\s*\(!name\)/);
});
