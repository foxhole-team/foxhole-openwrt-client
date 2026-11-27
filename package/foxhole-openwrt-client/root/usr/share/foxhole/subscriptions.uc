'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as model from './model.uc';
import * as runtime from './runtime-model.uc';
import * as handoff from './handoff.uc';
import * as server_check from './server-check.uc';
import * as registry from './engine-registry.uc';
import * as core from './core-adapter.uc';
import * as store from './private-store.uc';
import * as engine from './engine-service.uc';

const MAX_BODY = 49152;
const MAX_RESPONSE = 57344;
const MAX_STATE = 262144;
const STATE = '/etc/foxhole/state.json';
const LOCK = '/etc/foxhole/state.lock';
const ATTEMPTS = '/tmp/foxhole/subscription-attempts.json';
const PROTOCOLS = ['hysteria2', 'vless', 'wireguard'];

function fail() { die('subscription_unavailable'); };

export function web_source(config) {
 if (type(config) != 'string') return null;
 let raw = trim(config);
 if (match(raw, /^https:\/\//)) return raw;
 if (match(raw, /^ttps:\/\//)) return 'h' + raw;
 return null;
};

export function source_url(raw) {
 if (type(raw) != 'string' || length(raw) > 4096) fail();
 let value = match(raw, /^https:\/\/([A-Za-z0-9.-]+)(:443)?(\/[^#]*)?$/);
 if (!value || match(value[1], /^[0-9.]+$/)) fail();
 let host = handoff.hostname(value[1]), path = value[3] || '/';
 if (!match(path, /^\/[A-Za-z0-9_~.%/?&=+:!$'()*@,-]*$/)) fail();
 return { host, path };
};

export function http_body(raw) {
 if (type(raw) != 'string' || length(raw) > MAX_RESPONSE) fail();
 let boundary = index(raw, '\r\n\r\n');
 if (boundary < 1 || boundary > 8192) fail();
 let headers = split(substr(raw, 0, boundary), '\r\n'), body = substr(raw, boundary + 4);
 if (!match(headers[0], /^HTTP\/1\.[01] 200( [^\r\n]*)?$/) || length(headers) > 64 ||
  !length(body) || length(body) > MAX_BODY) fail();
 let count = null;
 for (let i = 1; i < length(headers); i++) {
  let part = match(headers[i], /^([A-Za-z0-9-]+):[ \t]*(.*)$/);
  if (!part) fail();
  let name = lc(part[1]), value = lc(trim(part[2]));
  if (name == 'transfer-encoding' || name == 'content-encoding' && value != 'identity') fail();
  if (name == 'content-length') {
   if (count != null || !match(value, /^[0-9]{1,5}$/)) fail();
   count = int(value, 10);
  }
 }
 if (count != null && count != length(body)) fail();
 return body;
};

function receive(raw) {
 let memory = match(fs.readfile('/proc/meminfo', 8192) || '', /(^|\n)MemAvailable:[ \t]+([0-9]+) kB/);
 if (!memory || +memory[2] < 16384) fail();
 let target = source_url(raw), addresses = server_check.resolve_public(target.host);
 if (!length(addresses) || !handoff.public_address(addresses[0]) || length(iptoarr(addresses[0])) != 4) fail();
 store.directory('/tmp/foxhole');
 let entropy = fs.readfile('/dev/urandom', 12);
 if (length(entropy || '') != 12) fail();
 let directory = '/tmp/foxhole/subscription-' + hexenc(entropy);
 if (!fs.mkdir(directory, 0o700)) fail();
 let input = directory + '/request', output = directory + '/response', result = null;
 try {
  store.write(input, 'GET ' + target.path + ' HTTP/1.0\r\nHost: ' + target.host +
   '\r\nUser-Agent: FoxHole-OpenWrt\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n');
  if (system(['/usr/libexec/foxhole-subscription-fetch', target.host, addresses[0], directory], 6000) == 0)
   result = http_body(store.read(output, MAX_RESPONSE));
 } catch (_) {}
 try { fs.unlink(input); fs.unlink(output); fs.rmdir(directory); } catch (_) {}
 if (result == null) fail();
 return result;
};

function endpoint_address(host) {
 let ip = iptoarr(host);
 if (length(ip || []) == 4 || length(ip || []) == 16) {
  if (!handoff.public_address(arrtoip(ip))) fail();
 } else {
  if (match(host, /^[0-9.]+$/)) fail();
  handoff.hostname(host);
 }
};

function portable_node(uri, protocol) {
 let parts = split(uri, '#');
 if (length(parts) > 2) fail();
 let authority = match(parts[0], /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^@?#]+@([^\/?#]+)/);
 if (!authority) fail();
 let endpoint = authority[1];
 if (index(endpoint, ':') < 0 || substr(endpoint, -1) == ']')
  endpoint += protocol == 'wireguard' ? ':51820' : ':443';
 endpoint_address(server_check.endpoint(endpoint).host);
 let label = parts[1] || endpoint;
 if (match(replace(label, /%[a-fA-F0-9]{2}/g, ''), /%/)) fail();
 let name = replace(label, /%([a-fA-F0-9]{2})/g, (_, byte) => chr(int(byte, 16)));
 if (!length(name) || length(name) > 512 || match(name, /[[:cntrl:]]/)) fail();
 return { uri, protocol, name, endpoint };
};

export function nodes(raw) {
 if (type(raw) != 'string' || length(raw) > MAX_BODY) fail();
 let body = trim(raw);
 if (index(body, '://') < 0) {
  let encoded = replace(body, /[ \t\r\n]/g, '');
  if (!match(encoded, /^[A-Za-z0-9+\/_-]+={0,2}$/)) fail();
  encoded = replace(replace(encoded, /-/g, '+'), /_/g, '/');
  while (length(encoded) % 4) encoded += '=';
  body = b64dec(encoded);
  if (!body || length(body) > MAX_BODY) fail();
 }
 let output = [], lines = split(body, '\n');
 if (length(lines) > 256) fail();
 for (let value in lines) {
  let uri = trim(value);
  if (length(uri) > 4096 || match(uri, /[[:cntrl:]]/)) continue;
  try {
   let protocol = registry.profile_protocol(uri);
   if (index(PROTOCOLS, protocol) >= 0) push(output, portable_node(uri, protocol));
  } catch (_) {}
 }
 if (!length(output)) fail();
 return output;
};

export function selection(rows, protocol, name, endpoint) {
 let supported = filter(rows, row => row.protocol == protocol);
 let matches = filter(supported, row => row.name == name);
 if (length(matches) == 1) return matches[0];
 if (length(matches) > 1) return null;
 matches = filter(supported, row => row.endpoint == endpoint);
 return length(matches) == 1 ? matches[0] : null;
};

function preserve_trust(previous, candidate) {
 if (candidate.tls?.insecure == true || previous?.tls?.enabled == true && candidate.tls?.enabled != true) fail();
 for (let field in ['pinned_certificate_sha256', 'pinned_spki_sha256', 'pinSHA256'])
  if (previous?.tls?.[field] != null && previous.tls[field] != candidate.tls?.[field]) fail();
 if (previous?.reality?.public_key != null && previous.reality.public_key != candidate.reality?.public_key) fail();
 if (previous?.peer_public_key != null && previous.peer_public_key != candidate.peer_public_key) fail();
};

function materialize(uri, mode, protocol, previous, timeout) {
 if (type(uri) != 'string' || length(uri) > 4096 || index(PROTOCOLS, protocol) < 0 ||
  registry.profile_protocol(uri) != protocol) fail();
 portable_node(uri, protocol);
 if (mode == 'core') {
  if (!registry.select_protocol(protocol) && index(registry.legacy_protocols(), protocol) < 0) fail();
  let value = core.admit(uri, timeout ?? 1000), outbound = value.config?.outbound;
  if (value.protocol != protocol || outbound == null) fail();
  endpoint_address(outbound.server);
  if (outbound.server_ip != null && !handoff.public_address(outbound.server_ip)) fail();
  preserve_trust(previous ? json(previous).outbound : null, outbound);
  return { config: value.raw, endpoint: value.endpoint, portableProfile: value.portableProfile };
 }
 if (protocol != 'hysteria2' || fs.stat('/usr/bin/hysteria')?.type != 'file') fail();
 let parsed = model.parse_config(uri);
 preserve_trust(previous ? model.parse_config(previous).config : null, parsed.config);
 let state = model.defaults();
 state.activeServerId = 'server-000000000000';
 state.servers = [{ id: state.activeServerId, config: uri }];
 runtime.hysteria_config(state, null);
 return { config: uri, endpoint: parsed.endpoint };
};

function import_timeout(deadline) {
 let now = core.clock_ms();
 if (now == null || now >= deadline) fail();
 return min(1000, deadline - now);
};

export function initial(raw) {
 let started = core.clock_ms();
 if (started == null) fail();
 let deadline = started + 14000, rows = nodes(receive(raw));
 let modes = {}, legacy = registry.legacy_protocols();
 for (let protocol in PROTOCOLS) {
  modes[protocol] = [];
  try {
   if (registry.select_protocol(protocol) || index(legacy, protocol) >= 0) push(modes[protocol], 'core');
  } catch (_) {}
 }
 if (fs.stat('/usr/bin/hysteria')?.type == 'file') push(modes.hysteria2, '');
 for (let row in rows) {
  let selected_modes = modes[row.protocol];
  for (let mode in selected_modes) {
   let timeout = import_timeout(deadline), value = null;
   try { value = materialize(row.uri, mode, row.protocol, null, timeout); } catch (_) {}
   if (value == null) continue;
   import_timeout(deadline);
   let identity = digest.sha256(row.uri);
   return { value, mode, metadata: { sourceUrl: raw, selectedProtocol:row.protocol, selectedNodeName:row.name,
    selectedOptionId:identity, phoneProfileId:'web-' + identity } };
  }
 }
 fail();
};

export function apply_pending(server) {
 if (server.subscriptionPending == null) return false;
 let value = materialize(server.subscriptionPending, server.engine, server.subscription?.selectedProtocol, server.config);
 server.config = value.config; server.endpoint = value.endpoint;
 if (server.engine == 'core') server.portableProfile = value.portableProfile;
 delete server.subscriptionPending;
 return true;
};

function state() {
 let raw = store.read(STATE, MAX_STATE);
 return raw == null ? null : model.validate_state(json(raw));
};

function save_refresh(updates) {
 store.target(LOCK);
 let handle = fs.open(LOCK, 'a+', 0o600);
 if (!handle || !handle.lock('xn') || !store.file_metadata(fs.lstat(LOCK))) {
  if (handle) handle.close();
  return;
 }
 try {
  engine.guard_mutation();
  let live = state(), changed = false;
  if (live != null && live.revision < 0x7ffffffe) for (let server in live.servers) {
   let update = updates[server.id];
   if (!update || digest.sha256(sprintf('%J', server)) != update.before) continue;
   if (update.name != server.subscription.selectedNodeName) {
    server.subscription.selectedNodeName = update.name; changed = true;
   }
   let value = update.value;
   if (server.config == value.config) {
    if (server.subscriptionPending == null) continue;
    delete server.subscriptionPending;
   } else if (live.activeServerId == server.id) {
    if (server.subscriptionPending == update.uri) continue;
    server.subscriptionPending = update.uri;
   } else {
    server.config = value.config; server.endpoint = value.endpoint;
    if (server.engine == 'core') server.portableProfile = value.portableProfile;
    delete server.subscriptionPending;
   }
   changed = true;
  }
  if (changed) {
   live.revision++;
   let raw = sprintf('%J', live);
   if (length(raw) <= MAX_STATE) store.write(STATE, raw);
  }
 } catch (_) {}
 handle.lock('u'); handle.close();
};

export function tick() {
 let live = state(); if (live == null) return;
 let raw = store.read(ATTEMPTS, 65536), attempts = raw ? json(raw) : {}, now = time();
 let next = {}, source = null;
 for (let server in live.servers) {
  let selection = server.subscription;
  if (index(PROTOCOLS, selection?.selectedProtocol) < 0 || !match(selection.sourceUrl || '', /^https:\/\//)) continue;
  let key = digest.sha256(selection.sourceUrl), last = attempts[key];
  if (type(last) == 'int' && last <= now && now - last < 3600) next[key] = last;
  else if (source == null) { source = selection.sourceUrl; next[key] = now; }
 }
 if (source == null) return;
 store.write(ATTEMPTS, sprintf('%J', next));
 let rows = nodes(receive(source)), updates = {};
 for (let server in live.servers) {
  let record = server.subscription;
  if (record?.sourceUrl != source || index(PROTOCOLS, record.selectedProtocol) < 0) continue;
  let row = selection(rows, record.selectedProtocol, record.selectedNodeName, server.endpoint);
  if (row == null) continue;
  try { updates[server.id] = { before: digest.sha256(sprintf('%J', server)),
    uri: row.uri, name: row.name, value: materialize(row.uri, server.engine, record.selectedProtocol, server.config) }; }
  catch (_) {}
 }
 if (length(keys(updates))) save_refresh(updates);
};
