'use strict';

import * as digest from 'digest';

function fail(code) { die('vpn_server_' + (code || 'invalid_plan')); };
function same(a, b) { return sprintf('%J', a) == sprintf('%J', b); };
function exact(value, fields) {
 if (type(value) != 'object' || length(keys(value)) != length(fields)) fail();
 for (let key in keys(value)) if (index(fields, key) < 0) fail();
};
export function sha(value) { return type(value) == 'string' && match(value, /^[a-f0-9]{64}$/) != null; };
function integer(value, minimum, maximum) {
 return type(value) == 'int' && value >= minimum && value <= maximum;
};
function name(value) { return type(value) == 'string' && match(value, /^[A-Za-z0-9][A-Za-z0-9_.+-]{0,159}$/) != null; };
function filename(value) { return name(value) && value != '.' && value != '..'; };
function version(value) { return type(value) == 'string' && match(value, /^[0-9][A-Za-z0-9_.~+-]{0,159}$/) != null; };
function path(value) {
 return type(value) == 'string' && length(value) <= 240 &&
  match(value, /^(usr|etc|lib|bin|sbin)\/[A-Za-z0-9_+./@-]+$/) &&
  !match(value, /(^|\/)(\.|\.\.)(\/|$)/) && index(value, '//') < 0;
};
export function entry(value) {
 exact(value, ['schema', 'kind', 'architecture', 'target', 'openwrtRelease', 'storage',
  'releaseTag', 'sourceCatalogSha256', 'sourceBudgetSha256', 'server', 'packages',
  'assets', 'memoryEvidence', 'flashReserveBytes', 'ramReserveBytes']);
 if (length(sprintf('%J',value)) > 131072) fail();
 let targets = { x86_64: 'x86/64', 'aarch64_cortex-a53': 'mediatek/filogic' };
 if (type(value.schema) != 'int' || value.schema != 1 || value.kind != 'server-install-entry-v1' ||
     targets[value.architecture] != value.target || !targets[value.architecture] ||
     index(['25.12.5','25.12.6'], value.openwrtRelease) < 0 || index(['RAM', 'FLASH'], value.storage) < 0 ||
     !match(value.releaseTag || '', /^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$/) ||
     !sha(value.sourceCatalogSha256) || !sha(value.sourceBudgetSha256) ||
     !integer(value.flashReserveBytes, 16777216, 2147483648) ||
     !integer(value.ramReserveBytes, 16777216, 2147483648)) fail();
 let server = value.server;
 exact(server, ['name', 'version', 'binarySha256', 'binaryBytes', 'executableSha256',
  'producerSha256', 'securityReceiptSha256', 'runtimeMemoryBytes', 'staticExecutable']);
 if (server.name != (value.storage == 'RAM' ? 'hysteria-server-ram' : 'hysteria') ||
     !version(server.version) || !sha(server.binarySha256) || !sha(server.executableSha256) ||
     !sha(server.producerSha256) || !sha(server.securityReceiptSha256) ||
     !integer(server.binaryBytes, 20, 67108864) || !integer(server.runtimeMemoryBytes, 1, 2147483648) ||
     type(server.staticExecutable) != 'bool' || server.staticExecutable != true) fail();
 exact(value.memoryEvidence, ['schema', 'type', 'description', 'runtimeMemoryBytes', 'acceptedForRelease']);
 if (type(value.memoryEvidence.schema) != 'int' || value.memoryEvidence.schema != 1 || index(['measured', 'conservative'], value.memoryEvidence.type) < 0 ||
     type(value.memoryEvidence.description) != 'string' || length(value.memoryEvidence.description) < 1 ||
     length(value.memoryEvidence.description) > 4096 || type(value.memoryEvidence.acceptedForRelease) != 'bool' || value.memoryEvidence.acceptedForRelease != true ||
     value.memoryEvidence.runtimeMemoryBytes != server.runtimeMemoryBytes) fail();
 if (type(value.assets) != 'array' || !length(value.assets) || length(value.assets) > 160 ||
     type(value.packages) != 'array' || !length(value.packages) || length(value.packages) > 64) fail();
 let assets = {}, packages = {}, binary = 0, root = 0, used_assets = {}, all_paths = {};
 for (let asset in value.assets) {
  exact(asset, ['file', 'sha256', 'bytes', 'role', 'url']);
  if (!filename(asset.file) || assets[asset.file] || !sha(asset.sha256) ||
      !integer(asset.bytes, 1, 134217728) || index(['package', 'index', 'key', 'binary'], asset.role) < 0 ||
      asset.url != 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/' + value.releaseTag + '/' + asset.file) fail();
  assets[asset.file] = asset;
  if (asset.role == 'binary') {
   used_assets[asset.file] = true;
   binary++;
   if (value.storage != 'RAM' || asset.sha256 != server.binarySha256 || asset.bytes != server.binaryBytes) fail();
  }
 }
 if (binary != (value.storage == 'RAM' ? 1 : 0)) fail();
 for (let item in value.packages) {
  let fields = ['name', 'version', 'architecture', 'file', 'sha256', 'archiveBytes',
   'installedBytes', 'nativeId', 'indexFile', 'keyFiles', 'depends', 'payload'];
  if (item.preinstalledOnly != null) push(fields,'preinstalledOnly');
  exact(item, fields);
  if (item.preinstalledOnly != null && type(item.preinstalledOnly) != 'bool') fail();
  let preinstalled = item.preinstalledOnly == true;
  if (item.name == server.name ? preinstalled : !preinstalled) fail();
  if (!name(item.name) || packages[item.name] ||
      item.name == 'kernel' || item.name == 'foxhole-openwrt-client' ||
      match(item.name, /^foxcore-/) ||
      (index(['hysteria', 'hysteria-server-ram', 'hysteria-ram'], item.name) >= 0 && item.name != server.name) ||
      !version(item.version) || index([value.architecture, 'all', 'noarch'], item.architecture) < 0 ||
      !sha(item.nativeId) || !sha(item.sha256) ||
      !integer(item.archiveBytes, 1, 134217728) || !integer(item.installedBytes, 1, 134217728) ||
      assets[item.file]?.role != 'package' || assets[item.file].sha256 != item.sha256 ||
      assets[item.file].bytes != item.archiveBytes || assets[item.indexFile]?.role != 'index' ||
      type(item.keyFiles) != 'array' || !length(item.keyFiles) || length(item.keyFiles) > 4 ||
      type(item.depends) != 'array' || length(item.depends) > 128 ||
      type(item.payload) != 'array' || length(item.payload) > 4096 ||
      (preinstalled ? length(item.payload) != 0 : !length(item.payload))) fail();
  used_assets[item.file] = true; used_assets[item.indexFile] = true;
  for (let key in item.keyFiles) { if (assets[key]?.role != 'key') fail(); used_assets[key] = true; }
  let paths = {};
  for (let file in item.payload) {
   exact(file, ['path', 'bytes', 'sha256', 'mode', 'target']);
   if (!path(file.path) || paths[file.path] || all_paths[file.path] || !integer(file.bytes, 0, 134217728) ||
       !integer(file.mode, 0, 0o777) || (file.target == null && (file.mode & 0o022)) ||
       (file.target == null ? !sha(file.sha256) : (file.sha256 != null ||
        type(file.target) != 'string' || length(file.target) > 240 ||
        match(file.target, /^(\/)|(^|\/)\.\.(\/|$)/)))) fail();
   paths[file.path] = true; all_paths[file.path] = true;
  }
  packages[item.name] = item;
  if (item.name == server.name) {
   root++;
   if (item.version != server.version || item.architecture != value.architecture) fail();
   let executable = filter(item.payload, file => file.path == 'usr/bin/hysteria');
   let producer = filter(item.payload, file => file.path == 'usr/share/foxhole/hysteria-producer.json');
   if (length(executable) != 1 || executable[0].sha256 != server.executableSha256 ||
       executable[0].mode != 0o755 || executable[0].target != null ||
       length(producer) != 1 || producer[0].sha256 != server.producerSha256) fail();
   if (value.storage == 'FLASH' && (executable[0].sha256 != server.binarySha256 || executable[0].bytes != server.binaryBytes)) fail();
  }
 }
 if (root != 1 || length(keys(used_assets)) != length(value.assets)) fail();
 let pending = [server.name], closure = {};
 for (let i = 0; i < length(pending); i++) {
  let item = packages[pending[i]];
  if (!item) fail();
  closure[item.name] = true;
  for (let dependency in item.depends) {
   if (!name(dependency) || !packages[dependency]) fail();
   if (index(pending, dependency) < 0) push(pending, dependency);
  }
 }
 if (length(keys(closure)) != length(value.packages)) fail();
 return value;
};
export function catalog(value) {
 exact(value, ['schema', 'kind', 'entries']);
 if (type(value.schema) != 'int' || value.schema != 1 || value.kind != 'verified-server-install-catalog-v1' ||
     type(value.entries) != 'array' || length(value.entries) > 4) fail();
 let seen = {};
 for (let row in value.entries) {
  entry(row);
  let id = row.architecture + ':' + row.storage;
  if (seen[id]) fail(); seen[id] = true;
 }
 return value;
};
export function missing(value, installed) {
 entry(value);
 let result = [];
 for (let item in value.packages) {
  let before = installed[item.name];
  if (before != null && (before.version != item.version || before.arch != item.architecture || before.cas != 'sha256-160:' + substr(item.nativeId, 0, 40)))
   fail('dependency_conflict');
  if (item.preinstalledOnly == true && before == null) fail('dependency_conflict');
  if (before == null) push(result, item.name);
 }
 return result;
};
export function make_plan(value, binding, installed, cached) {
 entry(value);
 if (installed[value.server.name] != null) fail('verification_failed');
 if (binding.architecture != value.architecture || binding.target != value.target ||
     binding.openwrtRelease != value.openwrtRelease ||
     !sha(binding.nativeDbSha256) || !sha(binding.worldSha256) || !sha(binding.owner) ||
     !sha(binding.catalogSha256) || !integer(binding.stateRevision, 0, 2147483646) ||
     type(binding.bootId) != 'string' || !match(binding.bootId, /^[a-f0-9-]{36}$/) ||
     !integer(binding.databaseBytes, 1, 8388608) ||
     !integer(binding.flashAvailableBytes, 0, 9007199254740991) ||
     !integer(binding.ramAvailableBytes, 0, 9007199254740991)) fail();
 let additions = missing(value, installed), needed = {}, installed_bytes = 0;
 for (let item in value.packages) {
  // Native fetch resolves dependencies against signed repository
  // metadata even
  // when their exact identities are already installed. Their APKs
  // stay unused.
  needed[item.indexFile] = true;
  for (let key in item.keyFiles) needed[key] = true;
  if (index(additions, item.name) >= 0) {
   needed[item.file] = true;
   installed_bytes += item.installedBytes;
  }
 }
 let assets = [], download = 0, compressed = 0, indexes = 0, key_bytes = 0, volatile_bytes = 0;
 for (let asset in value.assets) {
  if (asset.role == 'binary') needed[asset.file] = true;
  if (!needed[asset.file]) continue;
  push(assets, asset);
  if (cached[asset.sha256] != asset.bytes) download += asset.bytes;
  if (asset.role == 'package') compressed += asset.bytes;
  else if (asset.role == 'index') indexes += asset.bytes;
  else if (asset.role == 'key') key_bytes += asset.bytes;
  else volatile_bytes += asset.bytes;
 }
 // Count each native fetch, install and database snapshot copy.
 let metadata = 12 * length(sprintf('%J',value)) + 589824;
 let staging = 3 * compressed + installed_bytes + 2 * volatile_bytes + 2 * indexes + 2 * key_bytes + 2 * binding.databaseBytes + metadata;
 let flash = value.flashReserveBytes + metadata + (value.storage == 'FLASH' ? installed_bytes + 2 * binding.databaseBytes : 0);
 let ram = staging + value.server.runtimeMemoryBytes + value.ramReserveBytes;
 if (binding.flashAvailableBytes < flash || binding.ramAvailableBytes < ram) fail('no_space');
 let plan = { schema: 1, action: 'install', available: true, storage: value.storage,
  revision: binding.stateRevision, binding, descriptor: value, additions, assets,
  downloadBytes: download, budget: { stagingBytes: staging, flashRequiredBytes: flash,
   ramRequiredBytes: ram, reservedFlashBytes: value.flashReserveBytes, reservedRamBytes: value.ramReserveBytes },
  component: { protocol: 'hysteria2', kind: 'verified-server-package', version: value.server.version,
   binarySha256: value.server.binarySha256, binaryBytes: value.server.binaryBytes } };
 return { ...plan, planSha256: digest.sha256(sprintf('%J', plan)) };
};
export function admit(plan, request, binding) {
 if (type(request.confirmed) != 'bool' || request.confirmed != true ||
     type(request.revision) != 'int' || request.planSha256 != plan.planSha256 ||
     request.revision != plan.revision) fail('stale_plan');
 let previous = { ...plan.binding }, current = { ...binding };
 for (let key in ['flashAvailableBytes', 'ramAvailableBytes']) { delete previous[key]; delete current[key]; }
 if (!same(previous, current)) fail('stale_plan');
 if (binding.flashAvailableBytes < plan.budget.flashRequiredBytes ||
     binding.ramAvailableBytes < plan.budget.ramRequiredBytes) fail('no_space');
 let unsigned = { ...plan }; delete unsigned.planSha256;
 if (digest.sha256(sprintf('%J', unsigned)) != plan.planSha256) fail();
 entry(plan.descriptor);
 return plan;
};
