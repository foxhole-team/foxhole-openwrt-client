'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as registry from './engine-registry.uc';
import * as engines from './engine-model.uc';

const WRAPPER = '/usr/bin/hysteria';
const CACHE = '/tmp/foxhole-hysteria';
const TEMPLATES = {
 '314f7efb63010d92d94c0f4f3dc6e1efb74b18a5511c5a4c629d30f95e847d3b': 'flat',
 'fd37e345fcd73a5af72b1fc61e65b50266375d4415c1e7aadab80609c64da2cb': 'pinned'
};
let wrapper_memo = null;
let cache_memo = null;
function fail() { die('protocol_facts_unknown'); };
function identity(info) {
 if (!info) fail();
 for (let name in ['uid','gid','mode','nlink','size','inode','mtime','ctime']) {
  if (type(info[name]) != 'int' || info[name] < 0) fail();
 }
 if (type(info.dev?.major) != 'int' || type(info.dev?.minor) != 'int' ||
     info.dev.major < 0 || info.dev.minor < 0 || info.inode < 1) fail();
 return sprintf('%J', [info.type,info.uid,info.gid,info.mode,info.nlink,info.size,
  info.dev.major,info.dev.minor,info.inode,info.mtime,info.ctime]);
};
function parent_key(paths) {
 let values = [];
 for (let path in paths) {
  let info = fs.lstat(path);
  if (info?.type != 'directory' || info.uid != 0 || info.gid != 0) fail();
  let mode = info.mode & 0o7777;
  if (path == '/tmp') { if (mode != 0o1777) fail(); }
  else if (path == CACHE || substr(path,0,length(CACHE)+1) == CACHE + '/') {
   if (mode != 0o700) fail();
  } else if (info.mode & 0o7022) fail();
  push(values, identity(info));
 }
 return sprintf('%J', values);
};
function file_info(path, maximum, private_file) {
 let info = fs.lstat(path);
 if (info?.type != 'file' || info.uid != 0 || info.gid != 0 || info.nlink != 1 ||
     info.size < 1 || info.size > maximum || (info.mode & 0o7022) ||
     (private_file && (info.mode & 0o7777) != 0o700)) fail();
 identity(info);
 return info;
};
function wrapper_profile(raw) {
 if (type(raw) != 'string' || length(raw) < 1 || length(raw) > 8192) return null;
 let normalized = [], pin = null, pin_count = 0, url_count = 0;
 for (let line in split(raw,'\n')) {
  let found = match(line, /^digest=([a-f0-9]{64})$/);
  if (found) { pin = found[1]; pin_count++; push(normalized,'digest=@PIN@'); }
  else if (match(line, /^url=https:\/\/github\.com\/HyNetworks\/hysteria\/releases\/download\/app%2Fv[0-9]+\.[0-9]+\.[0-9]+\/hysteria-linux-arm64$/)) {
   url_count++; push(normalized,'url=@URL@');
  } else push(normalized,line);
 }
 let format = TEMPLATES[digest.sha256(join('\n',normalized))];
 if (!format || pin_count != 1 || url_count != 1) return null;
 return { pin, path: format == 'flat' ? CACHE + '/hysteria' : CACHE + '/' + pin + '/hysteria', format };
};
function hysteria_ram() {
 let paths = ['/', '/usr', '/usr/bin'];
 let info = file_info(WRAPPER,8192,false), parents = parent_key(paths);
 if (!(info.mode & 0o111)) fail();
 let key = identity(info) + parents, parsed = null;
 if (wrapper_memo?.key == key) parsed = wrapper_memo.value;
 else {
  let raw = fs.readfile(WRAPPER,8193);
  if (raw == null || length(raw) != info.size || identity(file_info(WRAPPER,8192,false)) != identity(info) || parent_key(paths) != parents) fail();
  parsed = wrapper_profile(raw);
  wrapper_memo = { key, value: parsed };
 }
 if (!parsed) return false;
 let cache_paths = ['/', '/tmp', CACHE];
 if (parsed.format == 'pinned') push(cache_paths,CACHE + '/' + parsed.pin);
 let cache_parents = parent_key(cache_paths), binary = file_info(parsed.path,134217728,true);
 let binary_key = identity(binary) + cache_parents + key;
 if (cache_memo?.key == binary_key) return true;
 let file = fs.open(parsed.path,'re'), header = null;
 try { if (file) header = file.read(20); }
 catch (_) { if (file) file.close(); fail(); }
 if (file) file.close();
 if (length(header || '') != 20 || substr(header,0,4) != '\x7fELF' ||
     ord(substr(header,4,1)) != 2 || ord(substr(header,5,1)) != 1 ||
     ord(substr(header,18,1)) + 256 * ord(substr(header,19,1)) != 183) fail();
 if (registry.hash_file(parsed.path) != parsed.pin || identity(file_info(parsed.path,134217728,true)) != identity(binary) ||
     parent_key(cache_paths) != cache_parents || identity(file_info(WRAPPER,8192,false)) + parent_key(paths) != key) fail();
 cache_memo = { key: binary_key };
 return true;
};
export function installed() {
 let known = engines.protocols(), positive = {};
 try { for (let id in registry.legacy_protocols()) { if (index(known,id) >= 0) positive[id] = true; } } catch (_) {}
 try {
  let slots = registry.read().slots;
  if (type(slots) != 'array' || length(slots) > 48) fail();
  for (let row in slots) {
   if (index(known,row?.id) < 0 || positive[row.id]) continue;
   try { registry.verify_slot(row); positive[row.id] = true; } catch (_) {}
  }
 } catch (_) {}
 try { if (hysteria_ram()) positive.hysteria2 = true; } catch (_) {}
 let protocols = filter(known,id => positive[id]);
 return length(protocols) ? { schema: 1, protocols } : null;
};
