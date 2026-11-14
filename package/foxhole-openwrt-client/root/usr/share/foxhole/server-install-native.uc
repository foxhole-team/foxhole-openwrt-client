'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as store from './private-store.uc';
import * as model from './server-install-model.uc';
import * as state_model from './model.uc';
import * as native from './update-native.uc';
import * as packages from './package-operations.uc';
import * as registry from './engine-registry.uc';
import * as engine from './engine-service.uc';
import * as ram from './ram-switch-service.uc';

const CATALOG = '/usr/share/foxhole/server-install-catalog.json';
const ACTIVE = '/etc/foxhole/server-install-active.json';
let binary_memo = {};
function fail(code) { die('vpn_server_' + (code || 'verification_failed')); };
function same(a, b) { return sprintf('%J', a) == sprintf('%J', b); };
function read(path, maximum) {
 let before = fs.lstat(path);
 if (before?.type != 'file' || before.uid != 0 || before.nlink != 1 ||
     (before.mode & 0o022) || before.size > maximum) fail();
 let raw = fs.readfile(path, maximum + 1), after = fs.lstat(path);
 if (raw == null || length(raw) != before.size ||
     !same([before.dev,before.inode,before.size,before.mtime,before.ctime],
      [after?.dev,after?.inode,after?.size,after?.mtime,after?.ctime])) fail();
 return raw;
};
function write(path, raw, mode) {
 let output = fs.open(path, 'wxe', mode || 0o600);
 if (!output || output.write(raw) != length(raw) || !output.flush()) fail();
 output.close();
};
function directory(path, mode) {
 if (fs.lstat(path) || !fs.mkdir(path, mode) || !fs.chmod(path, mode)) fail();
};
export function catalog() {
 let raw = native.public_raw(CATALOG, 1048576);
 return { value: model.catalog(json(raw)), sha256: digest.sha256(raw) };
};
function identities(raw) {
 let result = {}, count = 0;
 for (let block in split(raw, '\n\n')) {
  if (!length(trim(block))) continue;
  let fields = {};
  for (let line in split(block, '\n')) if (index(['P','V','A','C','f'], substr(line,0,1)) >= 0 && substr(line,1,1) == ':') {
   let key = substr(line,0,1); if (fields[key] != null) fail(); fields[key] = substr(line,2);
  }
  if (!match(fields.P || '', /^[A-Za-z0-9][A-Za-z0-9+_.-]{0,255}$/) || result[fields.P] ||
      !length(fields.V || '') || !length(fields.A || '') || ++count > 4096 ||
      !match(fields.C || '', /^Q1[A-Za-z0-9+/]{27}=$/)) fail();
  let hash = b64dec(substr(fields.C,2)); if (length(hash || '') != 20) fail();
  result[fields.P] = { name: fields.P, version: fields.V, arch: fields.A,
   cas: (index(fields.f || '', 'S') >= 0 ? 'sha256-160:' : 'sha1:') + hexenc(hash) };
 }
 return result;
};
export function context(principal) {
 let target = native.target(), root = '', source = null;
 if (fs.lstat('/tmp/foxhole-ram-active.json')) {
  source = ram.core_context(); root = source.stage + '/root';
 }
 let files = [], total = 0;
 for (let path in fs.glob(root + '/lib/apk/db/*') || []) {
  let name = fs.basename(path);
  if (!match(name, /^[A-Za-z0-9_.-]{1,64}$/)) fail();
  let raw = read(path,4194304); total += length(raw);
  push(files,{name,sha256:digest.sha256(raw),bytes:length(raw),mode:fs.lstat(path).mode & 0o777});
 }
 if (!length(files) || length(files) > 16 || total < 1 || total > 8388608) fail();
 let database = read(root + '/lib/apk/db/installed',4194304), world = read(root + '/etc/apk/world',65536);
 if (source && digest.sha256(database) != source.stageDbSha256) fail();
 let state = state_model.validate_state(json(store.read('/etc/foxhole/state.json',262144)));
 let resources = registry.snapshot_context(state), installed = identities(database), current = catalog();
 return { root, files, installed, world, state,
  binding: { architecture:target.architecture,target:target.target,openwrtRelease:target.release,
   nativeDbSha256:digest.sha256(database),worldSha256:digest.sha256(world),
   owner:digest.sha256(sprintf('%J',principal)),catalogSha256:current.sha256,
   stateRevision:state.revision,bootId:engine.update_boot(),databaseBytes:total,
   flashAvailableBytes:resources.flashAvailableBytes,ramAvailableBytes:resources.ramAvailableBytes } };
};
export function cached(assets) {
 let result = {};
 for (let asset in assets) {
  let path = '/tmp/foxhole/engine-assets/' + asset.sha256, info = fs.lstat(path);
  if (store.file_metadata(info) && info.size == asset.bytes && registry.hash_file(path) == asset.sha256)
   result[asset.sha256] = asset.bytes;
 }
 return result;
};
export function asset(value) {
 let path = packages.asset(value.url,value.sha256,value.bytes), info = fs.lstat(path);
 if (!store.file_metadata(info) || info.size != value.bytes) fail();
 return path;
};
function command(argv, maximum, timeout) {
 return registry.capture(argv,maximum || 1048576,timeout || 30000);
};
function apk(root, architecture, keys, repositories, args) {
 let flags = ['/usr/bin/apk','--root',root,'--arch',architecture,'--no-network','--no-cache',
  '--repositories-file',repositories,'--keys-dir',keys];
 // --no-scripts belongs to add. Read-only query/fetch do not
 // accept it.
 if (args[0] == 'add') push(flags,'--no-scripts');
 return command([...flags,...args],1048576,120000);
};
function copy(source,target,hash,maximum) {
 if (digest.sha256(read(source,maximum)) != hash || fs.lstat(target) ||
     system(['/bin/cp',source,target],10000) != 0 || digest.sha256(read(target,maximum)) != hash) fail();
};
function payload(document, item) {
 if (document?.info?.name != item.name || document.info.version != item.version ||
     document.info.arch != item.architecture || document.info['installed-size'] != item.installedBytes ||
     (document.scripts != null && (type(document.scripts) != 'object' || length(keys(document.scripts)))) ||
     (document.triggers != null && (type(document.triggers) != 'array' || length(document.triggers))) ||
     type(document.paths) != 'array' || length(document.paths) > 4096) fail();
 let expected = {}, seen = {};
 for (let file in item.payload) expected[file.path] = file;
 for (let dir in document.paths) {
  if (dir.acl?.user != 'root' || dir.acl.group != 'root' || dir.acl.mode != 0o755 ||
      type(dir.name || '') != 'string' || match(dir.name || '', /(^|\/)\.\.(\/|$)/) ||
      index(dir.name || '', '/') == 0) fail();
  for (let file in dir.files || []) {
   let path = (length(dir.name || '') ? dir.name + '/' : '') + file.name, wanted = expected[path];
   if (!wanted || seen[path] || file.acl?.user != 'root' || file.acl.group != 'root' ||
       file.acl.mode != wanted.mode || file.size != wanted.bytes ||
       (wanted.target == null ? file.hash != wanted.sha256 || file.target != null : file.target != wanted.target)) fail();
   seen[path] = true;
  }
 }
 if (length(keys(seen)) != length(item.payload)) fail();
};
function readback(root,item) {
 for (let file in item.payload) {
  let path = root + '/' + file.path, info = fs.lstat(path);
  if (file.target != null) {
   if (info?.type != 'link' || info.uid != 0 || fs.readlink(path) != file.target) fail();
  } else if (info?.type != 'file' || info.uid != 0 || info.nlink != 1 ||
      (info.mode & 0o7777) != file.mode || info.size != file.bytes || registry.hash_file(path) != file.sha256) fail();
 }
};
function unchanged(before,after,additions,descriptor) {
 for (let name in keys(before)) if (!same(before[name],after[name])) fail();
 for (let name in keys(after)) if (before[name] == null) {
  let expected = filter(descriptor.packages,row => row.name == name)[0];
  if (index(additions,name) < 0 || !expected || after[name].version != expected.version ||
      after[name].arch != expected.architecture || after[name].cas != native.native_cas(expected.nativeId)) fail();
 }
 for (let name in additions) if (after[name] == null) fail();
};
function u32(data,offset) { return ord(substr(data,offset,1)) + 256 * ord(substr(data,offset+1,1)) +
 65536 * ord(substr(data,offset+2,1)) + 16777216 * ord(substr(data,offset+3,1)); };
function binary_identity(info) {
 return sprintf('%J',[info?.type,info?.uid,info?.gid,info?.nlink,info?.mode,
  info?.size,info?.dev,info?.inode,info?.mtime,info?.ctime]);
};
function binary_parents(path) {
 let values = [], parent = fs.dirname(path);
 while (true) {
  let info = fs.lstat(parent);
  if (info?.type != 'directory' || info.uid != 0 ||
      (parent == '/tmp' ? (info.mode & 0o7777) != 0o1777 : (info.mode & 0o022))) fail();
  push(values,[info.type,info.uid,info.gid,info.mode,info.dev,info.inode]);
  if (parent == '/') break;
  parent = fs.dirname(parent);
 }
 return sprintf('%J',values);
};
export function verify_binary(path,descriptor) {
 let info = fs.lstat(path);
 if (info?.type != 'file' || info.uid != 0 || info.nlink != 1 || (info.mode & 0o022) ||
     !(info.mode & 0o111) || info.size != descriptor.server.binaryBytes) fail();
 let parents = binary_parents(path), identity = binary_identity(info);
 let key = identity + parents + descriptor.architecture + descriptor.server.binarySha256;
 if (binary_memo[path] == key) return path;
 if (registry.hash_file(path) != descriptor.server.binarySha256) fail();
 let file = fs.open(path,'re'), header = file ? file.read(65536) : null;
 if (file) file.close();
 if (length(header || '') < 64 || substr(header,0,4) != '\x7fELF' ||
     ord(substr(header,4,1)) != 2 || ord(substr(header,5,1)) != 1 ||
     ord(substr(header,18,1)) + 256 * ord(substr(header,19,1)) != (descriptor.architecture == 'x86_64' ? 62 : 183) ||
     u32(header,36) != 0) fail();
 let offset = u32(header,32), size = ord(substr(header,54,1)) + 256 * ord(substr(header,55,1));
 let count = ord(substr(header,56,1)) + 256 * ord(substr(header,57,1));
 if (offset < 64 || size != 56 || count < 1 || count > 128 || offset + size * count > length(header)) fail();
 for (let i = 0; i < count; i++) if (u32(header,offset + i * size) == 3) fail();
 if (binary_identity(fs.lstat(path)) != identity || binary_parents(path) != parents) fail();
 binary_memo[path] = key;
 return path;
};

export function stage(plan,snapshot,progress,job_id) {
 if (!match(job_id || '', /^vpn-server-job-[a-f0-9]{32}$/)) fail();
 let parent = (plan.storage == 'RAM' ? '/tmp' : '/etc') + '/foxhole/server-generations';
 store.directory(parent);
 let generation = plan.planSha256 + '-' + substr(job_id,15);
 let directory_path = parent + '/' + generation;
 directory(directory_path,0o700);
 let root = directory_path + '/root', repository = directory_path + '/repository';
 directory(root,0o755); directory(repository,0o700); directory(directory_path + '/keys',0o700);
 for (let name in ['lib','lib/apk','lib/apk/db','etc','etc/apk']) directory(root + '/' + name,0o755);
 for (let row in snapshot.files) {
  let source = snapshot.root + '/lib/apk/db/' + row.name;
  copy(source,root + '/lib/apk/db/' + row.name,row.sha256,4194304);
  fs.chmod(root + '/lib/apk/db/' + row.name,row.mode);
 }
 write(root + '/etc/apk/world',snapshot.world,0o644);
 let assets = {}, indexes = [], index_directories = {}, keys = directory_path + '/keys', done = 0;
 for (let value in plan.assets) {
  let source = asset(value); assets[value.file] = source;
  if (value.role == 'key') copy(source,keys + '/' + value.file,value.sha256,16384);
  if (value.role == 'index') {
   let selected = repository + '/' + value.sha256;
   directory(selected,0o700);
   copy(source,selected + '/packages.adb',value.sha256,value.bytes);
   index_directories[value.file] = selected;
   push(indexes,selected + '/packages.adb');
  }
  done += value.bytes; progress('DOWNLOADING',min(65,5 + int(60 * done / max(1,plan.downloadBytes))));
 }
 let repositories = directory_path + '/repositories'; write(repositories,join('\n',indexes) + '\n');
 let roots = [], fetch_names = [];
 for (let item in plan.descriptor.packages) if (index(plan.additions,item.name) >= 0) {
  let source = assets[item.file], index_path = assets[item.indexFile];
  command(['/usr/bin/apk','--keys-dir',keys,'verify',source,index_path],65536);
  let document = json(command(['/usr/bin/apk','adbdump','--format','json',source],8388608));
  payload(document,item);
  let rows = json(command(['/usr/bin/apk','adbdump','--format','json',index_path],8388608)).packages;
  let selected = type(rows) == 'array' ? filter(rows,row => row.name == item.name) : [];
  if (length(selected) != 1 || selected[0].version != item.version || selected[0].arch != item.architecture ||
      selected[0]['file-size'] != item.archiveBytes || selected[0].hashes != item.nativeId) fail();
  if (!index_directories[item.indexFile]) fail();
  copy(source,index_directories[item.indexFile] + '/' + item.name + '-' + item.version + '.apk',item.sha256,item.archiveBytes);
  push(roots,item.name + '=' + item.version);
  push(fetch_names,item.name);
 }
 let common = [root,plan.binding.architecture,keys,repositories];
 progress('VERIFYING',70);
 let selected = json(apk(...common,['query','--format','json','--recursive',...roots]));
 if (type(selected) != 'array' || length(selected) != length(plan.descriptor.packages)) fail();
 let seen = {};
 for (let row in selected) {
  let expected = filter(plan.descriptor.packages,item => item.name == row.name);
  if (length(expected) != 1 || seen[row.name] || row.version != expected[0].version ||
      row.arch != expected[0].architecture) fail();
  seen[row.name] = true;
 }
 apk(...common,['add','--simulate',...roots]);
 directory(directory_path + '/fetched',0o700);
 // Non-recursive fetch matches package names. Query/add retain
 // exact versions;
 // fetched filenames and archive hashes below bind the requested
 // version too.
 apk(...common,['fetch','--output',directory_path + '/fetched',...fetch_names]);
 for (let item in plan.descriptor.packages) if (index(plan.additions,item.name) >= 0) {
  let fetched = directory_path + '/fetched/' + item.name + '-' + item.version + '.apk';
  if (registry.hash_file(fetched) != item.sha256) fail();
  if (!fs.unlink(fetched)) fail();
 }
 progress('INSTALLING',80);
 apk(...common,['add','--initdb',...roots]);
 let after = identities(read(root + '/lib/apk/db/installed',4194304));
 unchanged(snapshot.installed,after,plan.additions,plan.descriptor);
 for (let item in plan.descriptor.packages) if (index(plan.additions,item.name) >= 0) readback(root,item);
 let binary = root + '/usr/bin/hysteria';
 if (plan.storage == 'RAM') {
  let value = filter(plan.assets,row => row.role == 'binary')[0];
  binary = directory_path + '/hysteria'; copy(assets[value.file],binary,value.sha256,value.bytes);
  if (!fs.chmod(binary,0o700)) fail();
 }
 verify_binary(binary,plan.descriptor);
 return { schema:1,kind:'verified-server-generation-v1',generation,planSha256:plan.planSha256,catalogSha256:plan.binding.catalogSha256,
  descriptorSha256:digest.sha256(sprintf('%J',plan.descriptor)),
  directory:directory_path,root,binary,descriptor:plan.descriptor,
  databaseSha256:digest.sha256(read(root + '/lib/apk/db/installed',4194304)) };
};
export function active() {
 let raw = store.read(ACTIVE,1048576); if (!raw) return null;
 let value = json(raw);
 if (value?.schema != 1 || value.kind != 'verified-server-generation-v1' ||
     !model.sha(value.planSha256) || !model.sha(value.catalogSha256) ||
     digest.sha256(sprintf('%J',value.descriptor)) != value.descriptorSha256) fail();
 model.entry(value.descriptor);
 if (!match(value.generation || '', /^[a-f0-9]{64}-[a-f0-9]{32}$/) || substr(value.generation,0,64) != value.planSha256) fail();
 let parent = (value.descriptor?.storage == 'RAM' ? '/tmp' : '/etc') + '/foxhole/server-generations/' + value.generation;
 if (value.directory != parent || value.root != parent + '/root' ||
     value.binary != (value.descriptor.storage == 'RAM' ? parent + '/hysteria' : parent + '/root/usr/bin/hysteria')) fail();
 if (!fs.lstat(value.directory)) return null;
 store.directory(value.directory);
 if (digest.sha256(read(value.root + '/lib/apk/db/installed',4194304)) != value.databaseSha256) fail();
 verify_binary(value.binary,value.descriptor);
 return value;
};
export function publish(value) { store.write(ACTIVE,sprintf('%J',value)); };
export function previous() { let raw = store.read(ACTIVE,1048576); return raw ? json(raw) : null; };
export function remove_owned(expected) {
 let current = active();
 if (!current || type(expected) != 'object' ||
     sprintf('%J',current) != sprintf('%J',expected)) fail();
 // active() admits only a verified, root-owned server generation.
 // Never touch
 // the host APK database, legacy binaries, Core slots or user
 // configuration.
 store.directory(current.directory);
 if (system(['/bin/rm','-rf','--',current.directory],120000) != 0 ||
     fs.lstat(current.directory) != null) fail();
 store.target(ACTIVE);
 if (!fs.unlink(ACTIVE)) fail();
};
export function restore(value) { if (value) publish(value); else if (fs.lstat(ACTIVE) && !fs.unlink(ACTIVE)) fail(); };
function system_installed() {
 let path = '/usr/bin/hysteria', info = fs.lstat(path);
 if (info?.type != 'file' || info.uid != 0 || info.nlink != 1 || (info.mode & 0o022) || !(info.mode & 0o111)) return null;
 let file = fs.open(path,'re'), header = file ? file.read(4) : null;
 if (file) file.close();
 if (header != '\x7fELF') return null;
 let current = catalog(), architecture = registry.architecture();
 let entries = filter(current.value.entries,row => row.storage == 'FLASH' && row.architecture == architecture);
 if (length(entries) != 1) return null;
 let value = entries[0], row = filter(value.packages,item => item.name == value.server.name)[0];
 let installed = native.installed_identities()[row.name];
 if (!installed || installed.version != row.version || installed.arch != row.architecture ||
     installed.cas != native.native_cas(row.nativeId) ||
     registry.hash_file('/usr/share/foxhole/hysteria-producer.json') != value.server.producerSha256) return null;
 verify_binary(path,value);
 return {schema:1,protocol:'hysteria2',kind:'verified-legacy-server',version:split(value.server.version,'-r')[0],
  binarySha256:value.server.binarySha256,binaryBytes:value.server.binaryBytes,executable:path};
};
export function installed() {
 let value = active(); if (!value) return system_installed();
 return { schema:1,protocol:'hysteria2',kind:'verified-managed-server',
  version:split(value.descriptor.server.version,'-r')[0],binarySha256:value.descriptor.server.binarySha256,
  binaryBytes:value.descriptor.server.binaryBytes,executable:value.binary };
};
