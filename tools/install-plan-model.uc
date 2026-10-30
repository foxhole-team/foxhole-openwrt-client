'use strict';

import * as fs from 'fs';

const protocols = ['anytls', 'http', 'hysteria2', 'naive', 'shadowsocks', 'shadowtls',
 'socks', 'trojan', 'tuic', 'vless', 'vmess', 'wireguard'];

function reject() { die('Invalid or unavailable verified installation plan\n'); };
export function hash(value) { return type(value) == 'string' && match(value, /^[a-f0-9]{64}$/); };
function name(value) { return type(value) == 'string' && match(value, /^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$/); };
function number(value) { return type(value) == 'int' && value >= 0 && value <= 9007199254740991; };
function packageName(value) {
 return type(value) == 'string' && match(value, /^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$/);
};
function version(value) {
 return type(value) == 'string' && match(value, /^[A-Za-z0-9][A-Za-z0-9_.~+-]{0,159}$/);
};
const ownPackages = ['foxcore-cli','foxcore-cli-ram','foxhole-openwrt-client','hysteria','hysteria-server-ram'];
function upstreamUrl(value, url) {
 let parts = split(url, '/');
 if (parts[0] != 'https:' || parts[1] != '' || parts[2] != 'downloads.openwrt.org' ||
     parts[3] != 'releases' || index(value.supportedOpenWrt || [], parts[4]) < 0) return false;
 if (length(parts) == 9 && parts[5] == 'packages' && parts[6] == value.architecture &&
     packageName(parts[7]) && parts[8] == 'packages.adb') return true;
 if (parts[5] != 'targets' || index(value.supportedTargets || [], parts[6] + '/' + parts[7]) < 0) return false;
 return (length(parts) == 10 && parts[8] == 'packages' && parts[9] == 'packages.adb') ||
  (length(parts) == 11 && parts[8] == 'kmods' && name(parts[9]) && parts[10] == 'packages.adb');
};

let compact_authentication;
export function authentication(value) {
 if (value.schema == 2 && value.kind == 'compact-selected-budget-v1') return compact_authentication(value);
 if (value.verification?.signatureModel != 'canonical-apk-and-upstream-index-v1' ||
     !hash(value.verification.factorySourceSha256) ||
     type(value.repositoryIndexes) != 'array' || !length(value.repositoryIndexes) ||
     length(value.repositoryIndexes) > 16 || type(value.packageAuthentications) != 'array' ||
     length(value.packageAuthentications) != length(value.packages || [])) reject();
 let indexes = {}, files = {}, trustKeys = {}, total = 0;
 for (let item in value.repositoryIndexes) {
  if (!name(item.file) || indexes[item.file] || !hash(item.sha256) ||
      !number(item.bytes) || !item.bytes || item.bytes > 8388608 ||
      index(['foxhole','upstream'], item.role) < 0 || type(item.sourceUrl) != 'string' ||
      length(item.sourceUrl) > 4096 ||
      !match(item.sourceUrl, /^https:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9_./~+-]+$/) ||
      index(split(item.sourceUrl, '/'), '.') >= 0 ||
      index(split(item.sourceUrl, '/'), '..') >= 0 ||
      (item.role == 'foxhole' && !match(item.sourceUrl,
       /^https:\/\/github\.com\/foxhole-team\/foxhole-openwrt-client\/releases\/download\/v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?\/[A-Za-z0-9][A-Za-z0-9._-]{0,159}\.adb$/)) ||
      (item.role == 'upstream' && !upstreamUrl(value, item.sourceUrl)) ||
      type(item.trustKeyFiles) != 'array' || !length(item.trustKeyFiles) ||
      length(item.trustKeyFiles) > 16 || value.filesSha256?.[item.file] != item.sha256) reject();
  if (item.role == 'foxhole' && join(',', item.trustKeyFiles) != 'foxhole-openwrt-apk.pem') reject();
  let seen = {};
  for (let key in item.trustKeyFiles) {
   if (!name(key) || seen[key] || !hash(value.filesSha256?.[key])) reject();
   if (trustKeys[key] && trustKeys[key] != item.role) reject();
   seen[key] = true; trustKeys[key] = item.role;
  }
  indexes[item.file] = item; files[item.file] = true; total += item.bytes;
 }
 if (length(keys(trustKeys)) > 32 || total != value.repositoryIndexBytes ||
     !number(value.trustKeyBytes) || !value.trustKeyBytes) reject();
 if (type(value.trustKeys) != 'array' || length(value.trustKeys) != length(keys(trustKeys))) reject();
 let recorded = {}, keyHashes = {}, keyBytes = 0;
 for (let item in value.trustKeys) {
  if (!name(item.file) || !trustKeys[item.file] || recorded[item.file] ||
      !hash(item.sha256) || keyHashes[item.sha256] || value.filesSha256[item.file] != item.sha256 ||
      !number(item.bytes) || !item.bytes || item.bytes > 16384) reject();
  if ((trustKeys[item.file] == 'foxhole') !=
      (item.sha256 == 'fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1')) reject();
  recorded[item.file] = true; keyBytes += item.bytes;
  keyHashes[item.sha256] = true;
 }
 if (keyBytes != value.trustKeyBytes) reject();
 for (let key in trustKeys) {
  if (files[key]) reject();
  files[key] = true;
 }
 let packages = {}, bound = {};
 for (let item in value.packages) {
  if (!name(item.file) || files[item.file] || !packageName(item.name) || !version(item.version) ||
      !name(item.arch) || packages[item.file]) reject();
  packages[item.file] = item; files[item.file] = true;
 }
 for (let item in value.packageAuthentications) {
  let record = packages[item.file], repo = indexes[item.indexFile];
  if (!record || !repo || bound[item.file] || !hash(item.packageIdentity) ||
      item.name != record.name || item.version != record.version || item.architecture != record.arch ||
      ((repo.role == 'foxhole') != (index(ownPackages, record.name) >= 0))) reject();
  bound[item.file] = true;
 }
 if (length(keys(bound)) != length(value.packages) ||
     length(keys(files)) != length(keys(value.filesSha256 || {}))) reject();
 for (let key in value.filesSha256) if (!files[key] || !hash(value.filesSha256[key])) reject();
 return value;
};
export function read(path) {
 let info = fs.lstat(path);
 if (info?.type != 'file' || info.size > 2097152) reject();
 let raw = fs.readfile(path, 2097153);
 if (raw == null || length(raw) != info.size) reject();
 let value = json(raw);
 if (type(value) != 'object' || type(value.schema) != 'int') reject();
 if (value.schema == 2 && index(['compact-client-engines-v1', 'compact-package-universe-v1', 'compact-selected-budget-v1'], value.kind) >= 0) return value;
 if (value.schema != 1) reject();
 return value;
};

function compact_reject() { die('Invalid or unavailable compact installation plan\n'); };
function compact_exact(value, fields) {
 if (type(value) != 'object') compact_reject();
 for (let key in keys(value)) if (index(fields, key) < 0) compact_reject();
};
function compact_asset(value) {
 compact_exact(value, ['file', 'sha256']);
 if (!name(value.file) || !hash(value.sha256)) compact_reject();
 return value;
};
function compact_ids(requested) {
 let wanted = requested == 'all' ? protocols : split(requested || 'hysteria2', ',');
 let seen = {}, result = [];
 for (let id in wanted) {
  if (index(protocols, id) < 0) compact_reject();
  if (!seen[id]) { seen[id] = true; push(result, id); }
 }
 if (!length(result) || length(result) > 12) compact_reject();
 return sort(result);
};
function compact_client(value, architecture) {
 compact_exact(value, ['id', 'storage', 'entry', 'producer', 'capabilities', 'slotManifest']);
 let item = value.entry, fields = ['id', 'storage', 'version', 'architecture', 'binarySha256',
  'executableSha256', 'producerSha256', 'capabilitiesSha256', 'legalProvenanceSha256', 'manifestSha256', 'sourceCommit',
  'binaryBytes', 'archiveBytes', 'indexBytes', 'installedBytes', 'runtimeMemoryBytes', 'reserveBytes',
  'packageName', 'packageVersion', 'packageSha256', 'indexSha256', 'packageUrl', 'indexUrl'];
 compact_exact(item, fields);
 if (index(protocols, value.id) < 0 || index(['flash', 'ram'], value.storage) < 0 ||
     item.id != value.id || item.architecture != architecture ||
     item.storage != (value.storage == 'flash' ? 'FLASH' : 'RAM') ||
     type(item.version) != 'string' || !match(item.version, /^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$/) ||
     !version(item.packageVersion) || type(item.sourceCommit) != 'string' || !match(item.sourceCommit, /^[a-f0-9]{40}$/)) compact_reject();
 for (let key in ['binarySha256', 'executableSha256', 'producerSha256', 'capabilitiesSha256',
  'legalProvenanceSha256', 'manifestSha256', 'packageSha256', 'indexSha256']) if (!hash(item[key])) compact_reject();
 for (let key in ['binaryBytes', 'archiveBytes', 'indexBytes', 'installedBytes', 'runtimeMemoryBytes', 'reserveBytes'])
  if (!number(item[key]) || !item[key] || item[key] > 2147483648) compact_reject();
 if (item.binaryBytes > 67108864 || item.archiveBytes > 134217728 || item.indexBytes > 8388608 ||
     item.installedBytes > 536870912 || item.reserveBytes < 16777216 ||
     (value.storage == 'flash' && item.binarySha256 != item.executableSha256)) compact_reject();
 let expected = 'foxcore-engine-' + value.id + '-' + value.storage + '-' + item.manifestSha256;
 let base = 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v' + item.version + '/';
 if (item.packageName != expected || item.packageUrl != base + expected + '-' + item.packageVersion + '.apk' ||
     item.indexUrl != base + 'engines.adb' || compact_asset(value.producer).sha256 != item.producerSha256 ||
     compact_asset(value.capabilities).sha256 != item.capabilitiesSha256 ||
     compact_asset(value.slotManifest).sha256 != item.manifestSha256) compact_reject();
 return value;
};
export function compact_selection(catalog, architecture, release, requested, development, target, include_server) {
 compact_exact(catalog, ['schema', 'kind', 'development', 'defaultProtocols', 'allProtocols', 'platforms']);
 if (type(catalog.schema) != 'int' || catalog.schema != 2 || catalog.kind != 'compact-client-engines-v1' || type(catalog.development) != 'bool' ||
     (catalog.development && !development) || join(',', catalog.defaultProtocols || []) != 'hysteria2' ||
     join(',', catalog.allProtocols || []) != join(',', protocols) || type(catalog.platforms) != 'array' ||
     !length(catalog.platforms) || length(catalog.platforms) > 16 || type(include_server) != 'bool') compact_reject();
 let wanted = requested == 'all' ? null : compact_ids(requested), platform = null;
 for (let value in catalog.platforms) {
  compact_exact(value, ['id', 'architecture', 'supportedTargets', 'supportedOpenWrt', 'basePackage',
   'engineCatalog', 'packageUniverse', 'clients', 'server']);
  if (value.architecture != architecture || index(value.supportedTargets || [], target) < 0 ||
      index(value.supportedOpenWrt || [], release) < 0) continue;
  if (platform || !name(value.id) || type(value.clients) != 'array' || length(value.clients) > 24 ||
      type(value.supportedTargets) != 'array' || length(value.supportedTargets) != 1 ||
      type(value.supportedOpenWrt) != 'array' || !length(value.supportedOpenWrt) || length(value.supportedOpenWrt) > 32) compact_reject();
  let expected_target = { x86_64: 'x86/64', aarch64_generic: 'armsr/armv8', 'aarch64_cortex-a53': 'mediatek/filogic' }[architecture];
  if (expected_target != target) compact_reject();
  let releases = {};
  for (let version in value.supportedOpenWrt) {
   if (type(version) != 'string' || !match(version, /^[0-9]{2}\.[0-9]{2}\.[0-9]{1,3}$/) || releases[version]) compact_reject();
   releases[version] = true;
  }
  compact_exact(value.basePackage, ['name', 'file', 'sha256', 'packageIdentity']);
  if (value.basePackage.name != 'foxhole-openwrt-client' || !name(value.basePackage.file) ||
      !hash(value.basePackage.sha256) || !hash(value.basePackage.packageIdentity)) compact_reject();
  compact_asset(value.engineCatalog); compact_asset(value.packageUniverse);
  let unique = {}, available = {};
  for (let client in value.clients) {
   compact_client(client, architecture);
   let key = client.id + ':' + client.storage;
   if (unique[key]) compact_reject();
   unique[key] = true; available[client.id] = true;
  }
  if (requested == 'all') wanted = sort(keys(available));
  if (!length(wanted)) compact_reject();
  for (let id in wanted) if (!available[id]) compact_reject();
  if (include_server) {
   compact_exact(value.server, ['producer', 'modes']); compact_asset(value.server.producer);
   if (type(value.server.modes) != 'object' || !length(keys(value.server.modes))) compact_reject();
   for (let mode, server in value.server.modes) {
    compact_exact(server, ['name', 'file', 'sha256']);
    if (index(['flash', 'ram'], mode) < 0 || server.name != (mode == 'flash' ? 'hysteria' : 'hysteria-server-ram') ||
        !name(server.file) || !hash(server.sha256)) compact_reject();
   }
  }
  platform = value;
 }
 if (!platform) compact_reject();
 let modes = [];
 for (let mode in ['flash', 'ram']) {
  let available = !include_server || platform.server.modes[mode] != null;
  for (let id in wanted) if (!length(filter(platform.clients, row => row.id == id && row.storage == mode))) available = false;
  if (available) push(modes, mode);
 }
 if (!length(modes)) compact_reject();
 return { schema: 2, kind: 'compact-selection-v1', platform, protocols: wanted, includeServer: include_server, storageModes: modes };
};

export function compact_metadata(selected) {
 let files = {}, result = [], platform = selected.platform;
 function add(value) {
  compact_asset(value);
  if (files[value.file] && files[value.file] != value.sha256) compact_reject();
  if (!files[value.file]) { files[value.file] = value.sha256; push(result, value); }
 }
 add(platform.engineCatalog); add(platform.packageUniverse);
 for (let client in platform.clients) if (index(selected.protocols, client.id) >= 0) {
  add(client.producer); add(client.capabilities); add(client.slotManifest);
 }
 if (selected.includeServer) add(platform.server.producer);
 return result;
};

function compact_own(value) {
 if (type(value.schema) != 'int' || value.schema != 2 || value.kind != 'compact-selected-budget-v1' ||
     index(['flash', 'ram'], value.mode) < 0 || type(value.includeServer) != 'bool' ||
     type(value.modules) != 'array' || !length(value.modules) || length(value.modules) > 12 ||
     type(value.protocols) != 'array' || !length(value.protocols) || length(value.protocols) > 12 ||
     type(value.verification) != 'object' || value.verification.signatures != true ||
     type(value.verification.signatures) != 'bool' || value.verification.resolver != 'apk add --simulate --no-network') compact_reject();
 let wanted = compact_ids(join(',', value.protocols)), names = ['foxhole-openwrt-client'], seen = {}, ids = [];
 if (length(wanted) != length(value.protocols)) compact_reject();
 for (let client in value.modules) {
  compact_client(client, value.architecture);
  if (seen[client.id] || index(wanted, client.id) < 0 || client.storage != value.mode) compact_reject();
  seen[client.id] = true; push(ids, client.id); push(names, client.entry.packageName);
 }
 if (join(',', sort(ids)) != join(',', wanted)) compact_reject();
 if (value.includeServer) {
  let server = value.server;
  if (type(server) != 'object' || server.name != (value.mode == 'flash' ? 'hysteria' : 'hysteria-server-ram') ||
      !name(server.file) || !hash(server.sha256) || !hash(server.producerSha256) || !hash(server.binarySha256) || !hash(server.executableSha256)) compact_reject();
  push(names, server.name);
 } else if (value.server != null) compact_reject();
 if (type(value.rootPackages) != 'array' || join(',', sort(value.rootPackages)) != join(',', sort(names))) compact_reject();
 for (let item in value.packages || []) {
  if (index(['foxcore-cli', 'foxcore-cli-ram'], item.name) >= 0 ||
      (match(item.name || '', /^foxcore-engine-/) && index(names, item.name) < 0) ||
      (index(['hysteria', 'hysteria-server-ram'], item.name) >= 0 && index(names, item.name) < 0)) compact_reject();
 }
 let panel = value.basePackage;
 compact_exact(panel, ['name', 'file', 'sha256', 'packageIdentity']);
 if (panel.name != 'foxhole-openwrt-client' || !name(panel.file) || !hash(panel.sha256) || !hash(panel.packageIdentity)) compact_reject();
 let base = filter(value.packages || [], row => row.name == panel.name);
 let base_binding = filter(value.packageAuthentications || [], row => row.file == panel.file);
 if (length(base) != 1 || base[0].file != panel.file || base[0].sha256 != panel.sha256 ||
     length(base_binding) != 1 || base_binding[0].packageIdentity != panel.packageIdentity) compact_reject();
 for (let client in value.modules) {
  let entry = client.entry, parts = split(entry.packageUrl, '/');
  let file = parts[length(parts) - 1];
  let records = filter(value.packages || [], row => row.name == entry.packageName);
  let bindings = filter(value.packageAuthentications || [], row => row.file == file);
  if (length(records) != 1 || records[0].file != file || records[0].sha256 != entry.packageSha256 ||
      records[0].version != entry.packageVersion || records[0].arch != entry.architecture ||
      records[0].archiveBytes != entry.archiveBytes || records[0].installedBytes != entry.installedBytes ||
      length(bindings) != 1) compact_reject();
  let indexes = filter(value.repositoryIndexes || [], row => row.file == bindings[0].indexFile);
  if (length(indexes) != 1 || indexes[0].role != 'foxhole' || indexes[0].sha256 != entry.indexSha256 ||
      indexes[0].bytes != entry.indexBytes || indexes[0].sourceUrl != entry.indexUrl) compact_reject();
 }
 if (value.server) {
  let records = filter(value.packages || [], row => row.name == value.server.name);
  if (length(records) != 1 || records[0].file != value.server.file || records[0].sha256 != value.server.sha256) compact_reject();
 }
 return names;
};

export function selection(catalog, architecture, release, requested, development, target) {
 if (type(catalog.schema) != 'int' || catalog.schema != 1 || type(catalog.variants) != 'array' || !length(catalog.variants) ||
     length(catalog.variants) > 256 || type(catalog.development) != 'bool' ||
     (catalog.development == true && !development) ||
     join(',', catalog.defaultProtocols || []) != 'hysteria2' ||
     join(',', catalog.allProtocols || []) != join(',', protocols)) reject();
 let wanted = requested == 'all' ? protocols : split(requested || 'hysteria2', ',');
 let seen = {}, unique = [];
 for (let item in wanted) if (!seen[item]) { seen[item] = true; push(unique, item); }
 wanted = sort(unique);
 if (!length(wanted) || length(wanted) > length(protocols)) reject();
 for (let protocol in wanted) if (index(protocols, protocol) < 0) reject();
 let found = null;
 for (let variant in catalog.variants) {
  if (variant.architecture != architecture ||
      index(variant.supportedTargets || [], target) < 0 ||
      index(variant.supportedOpenWrt || [], release) < 0 ||
      join(',', variant.protocols || []) != join(',', wanted)) continue;
  if (found || !name(variant.id) || !name(variant.coreProducerFile) ||
      !name(variant.capabilitiesFile) || !hash(variant.coreProducerSha256) ||
      !hash(variant.coreBinarySha256) || !hash(variant.coreSourceSha256) ||
      !hash(variant.capabilitiesSha256) || !name(variant.serverProducerFile) ||
      !hash(variant.serverProducerSha256) || type(variant.modes) != 'object') reject();
  for (let mode, entry in variant.modes) {
   if ((mode != 'flash' && mode != 'ram') || !name(entry.budgetFile) || !hash(entry.budgetSha256)) reject();
  }
  found = variant;
 }
 if (!found) reject();
 return found;
};

export function budget(value, variant, mode, development) {
 if (type(value.schema) != 'int' || value.schema != 1 || value.mode != mode || value.architecture != variant.architecture ||
     join(',', value.protocols || []) != join(',', variant.protocols) ||
     value.coreProducerSha256 != variant.coreProducerSha256 ||
     value.capabilitiesSha256 != variant.capabilitiesSha256 ||
     value.serverProducerSha256 != variant.serverProducerSha256 ||
     join(',', value.supportedOpenWrt || []) != join(',', variant.supportedOpenWrt) ||
     join(',', value.supportedTargets || []) != join(',', variant.supportedTargets) ||
     value.verification?.resolver != 'apk add --simulate --no-network' ||
     value.verification.signatures != true ||
     type(value.packages) != 'array' || !length(value.packages) || length(value.packages) > 256) reject();
 for (let key in ['compressedBytes','installedFlashBytes','installedRamBytes',
                  'dependencyInstalledBytes','stagingBytes','flashReserveBytes','ramReserveBytes',
                  'runtimeMemoryBytes','requiredFlashBytes','requiredRamBytes',
                  'repositoryIndexBytes','trustKeyBytes'])
  if (!number(value[key])) reject();
 let names = {}, compressed = 0, installed = 0;
 let kernel = null;
 for (let item in value.packages) {
  if (!name(item.file) || !match(item.file, /\.apk$/) || names[item.file] || !hash(item.sha256) ||
      !number(item.archiveBytes) || !number(item.installedBytes) ||
      value.filesSha256?.[item.file] != item.sha256) reject();
  names[item.file] = true;
  if (item.name == 'kernel') {
   if (kernel != null || type(item.version) != 'string' || !match(item.version, /^[A-Za-z0-9_.~+-]+$/)) reject();
   kernel = item.version;
  }
  compressed += item.archiveBytes; installed += item.installedBytes;
 }
 authentication(value);
 let expectedRoots = sort([mode == 'flash' ? 'foxcore-cli' : 'foxcore-cli-ram',
  'foxhole-openwrt-client', mode == 'flash' ? 'hysteria' : 'hysteria-server-ram']);
 if (type(value.rootPackages) != 'array' || length(value.rootPackages) != 3 ||
     join(',', sort(value.rootPackages)) != join(',', expectedRoots)) reject();
 let native = ['corePackage','serverPackage'];
 for (let key in native) {
  let receipt = value[key], found = null;
  for (let item in value.packages) if (item.file == receipt?.file) found = item;
  let expected = key == 'corePackage' ? (mode == 'flash' ? 'foxcore-cli' : 'foxcore-cli-ram') :
   (mode == 'flash' ? 'hysteria' : 'hysteria-server-ram');
  if (!found || found.name != expected || receipt.sha256 != found.sha256 ||
      !hash(receipt.binarySha256) || type(receipt.payloadVerified) != 'bool' || receipt.payloadVerified != true ||
      receipt.producerSha256 != (key == 'corePackage' ? variant.coreProducerSha256 : variant.serverProducerSha256)) reject();
 }
 if (value.corePackage.binarySha256 != variant.coreBinarySha256) reject();
 if (compressed != value.compressedBytes || installed != value.installedFlashBytes ||
     kernel == null || value.platformPackages?.kernel != kernel) reject();
 let volatile = 0;
 let dependencies = value.volatileDependencies || [];
 if (type(dependencies) != 'array' || length(dependencies) > 1) reject();
 if (mode == 'ram') {
  let entry = value.volatileBinary;
  if (!name(entry?.file) || !number(entry.bytes) || !entry.bytes ||
      entry.sha256 != variant.coreBinarySha256) reject();
  volatile = entry.bytes;
  for (let dependency in dependencies) {
   if (!name(dependency.file) || names[dependency.file] || dependency.file == entry.file ||
       !number(dependency.bytes) || !dependency.bytes || !hash(dependency.sha256) ||
       !name(dependency.producerFile) || !hash(dependency.producerSha256) ||
       dependency.producerFile != variant.serverProducerFile ||
       dependency.producerSha256 != variant.serverProducerSha256) reject();
   names[dependency.file] = true;
   volatile += dependency.bytes;
  }
  if (volatile != value.installedRamBytes) reject();
  if (entry.sha256 != value.corePackage.binarySha256 ||
      length(dependencies) != 1 || dependencies[0].sha256 != value.serverPackage.binarySha256) reject();
 } else if (value.volatileBinary != null || value.installedRamBytes != 0 || length(dependencies)) reject();
 if (value.stagingBytes < 2 * compressed + installed + volatile +
      2 * value.repositoryIndexBytes + value.trustKeyBytes ||
     value.stagingBytes > 9007199254740991 - value.ramReserveBytes - value.runtimeMemoryBytes ||
     value.requiredFlashBytes != installed + value.flashReserveBytes ||
     value.requiredRamBytes != value.stagingBytes + value.runtimeMemoryBytes + value.ramReserveBytes ||
     !value.runtimeMemoryBytes || type(value.memoryEvidence?.schema) != 'int' ||
     value.memoryEvidence.schema != 1 ||
     type(value.memoryEvidence.description) != 'string' || !length(value.memoryEvidence.description) ||
     length(value.memoryEvidence.description) > 4096 ||
     index(['measured','conservative'], value.memoryEvidence.type) < 0 ||
     value.memoryEvidence.runtimeMemoryBytes != value.runtimeMemoryBytes) reject();
 for (let key in ['provisional','acceptedForRelease','measured'])
  if (index(keys(value.memoryEvidence), key) >= 0 && type(value.memoryEvidence[key]) != 'bool') reject();
 if (!development && (value.memoryEvidence.provisional == true ||
                      value.memoryEvidence.acceptedForRelease == false)) reject();
 return value;
};

export function fits(value, flash, ram, backup) {
 return number(flash) && number(ram) && number(backup) &&
  value.requiredRamBytes <= 9007199254740991 - backup &&
  value.requiredFlashBytes <= flash && value.requiredRamBytes + backup <= ram;
};


export function installedPackages(rows, expected) {
 if (type(rows) != 'array' || type(expected) != 'object' || !length(rows) ||
     length(rows) != length(keys(expected)) || length(rows) > 16) return false;
 let seen = {};
 for (let item in rows) {
  if (type(item) != 'object' || !packageName(item.name) || seen[item.name]) return false;
  let wanted = expected[item.name];
  if (type(wanted) != 'object' || !version(wanted.version) || !name(wanted.arch) ||
      item.version != wanted.version || item.arch != wanted.arch ||
      type(item.status) != 'array' || length(item.status) != 1 || item.status[0] != 'installed' ||
      type(item.depends) != 'array' || length(item.depends) > 128) return false;
  for (let dependency in item.depends)
   if (type(dependency) != 'string' || !length(dependency) || length(dependency) > 256) return false;
  if (wanted.dependency != null && (type(wanted.dependency) != 'string' ||
      index(item.depends, wanted.dependency) < 0)) return false;
  seen[item.name] = true;
 }
 return true;
};

export function readInstalled(path) {
 let info = fs.lstat(path);
 if (info?.type != 'file' || info.size > 65536) reject();
 let raw = fs.readfile(path, 65537);
 if (raw == null || length(raw) != info.size) reject();
 let rows = json(raw);
 if (type(rows) != 'array' || !length(rows) || length(rows) > 16) reject();
 return rows;
};

compact_authentication = function(value) {
 let allowed_own = compact_own(value);
 if (value.verification?.signatureModel != 'canonical-apk-and-upstream-index-v1' ||
     !hash(value.verification.factorySourceSha256) ||
     type(value.repositoryIndexes) != 'array' || !length(value.repositoryIndexes) ||
     length(value.repositoryIndexes) > 16 || type(value.packageAuthentications) != 'array' ||
     length(value.packageAuthentications) != length(value.packages || [])) reject();
 let indexes = {}, files = {}, trustKeys = {}, total = 0;
 for (let item in value.repositoryIndexes) {
  if (!name(item.file) || indexes[item.file] || !hash(item.sha256) ||
      !number(item.bytes) || !item.bytes || item.bytes > 8388608 ||
      index(['foxhole','upstream'], item.role) < 0 || type(item.sourceUrl) != 'string' ||
      length(item.sourceUrl) > 4096 ||
      !match(item.sourceUrl, /^https:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9_./~+-]+$/) ||
      index(split(item.sourceUrl, '/'), '.') >= 0 ||
      index(split(item.sourceUrl, '/'), '..') >= 0 ||
      (item.role == 'foxhole' && !match(item.sourceUrl,
       /^https:\/\/github\.com\/foxhole-team\/foxhole-openwrt-client\/releases\/download\/v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?\/[A-Za-z0-9][A-Za-z0-9._-]{0,159}\.adb$/)) ||
      (item.role == 'upstream' && !upstreamUrl(value, item.sourceUrl)) ||
      type(item.trustKeyFiles) != 'array' || !length(item.trustKeyFiles) ||
      length(item.trustKeyFiles) > 16 || value.filesSha256?.[item.file] != item.sha256) reject();
  if (item.role == 'foxhole' && join(',', item.trustKeyFiles) != 'foxhole-openwrt-apk.pem') reject();
  let seen = {};
  for (let key in item.trustKeyFiles) {
   if (!name(key) || seen[key] || !hash(value.filesSha256?.[key])) reject();
   if (trustKeys[key] && trustKeys[key] != item.role) reject();
   seen[key] = true; trustKeys[key] = item.role;
  }
  indexes[item.file] = item; files[item.file] = true; total += item.bytes;
 }
 if (length(keys(trustKeys)) > 32 || total != value.repositoryIndexBytes ||
     !number(value.trustKeyBytes) || !value.trustKeyBytes) reject();
 if (type(value.trustKeys) != 'array' || length(value.trustKeys) != length(keys(trustKeys))) reject();
 let recorded = {}, keyHashes = {}, keyBytes = 0;
 for (let item in value.trustKeys) {
  if (!name(item.file) || !trustKeys[item.file] || recorded[item.file] ||
      !hash(item.sha256) || keyHashes[item.sha256] || value.filesSha256[item.file] != item.sha256 ||
      !number(item.bytes) || !item.bytes || item.bytes > 16384) reject();
  if ((trustKeys[item.file] == 'foxhole') !=
      (item.sha256 == 'fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1')) reject();
  recorded[item.file] = true; keyBytes += item.bytes;
  keyHashes[item.sha256] = true;
 }
 if (keyBytes != value.trustKeyBytes) reject();
 for (let key in trustKeys) {
  if (files[key]) reject();
  files[key] = true;
 }
 let packages = {}, bound = {};
 for (let item in value.packages) {
  if (!name(item.file) || files[item.file] || !packageName(item.name) || !version(item.version) ||
      !name(item.arch) || packages[item.file]) reject();
  packages[item.file] = item; files[item.file] = true;
 }
 for (let item in value.packageAuthentications) {
  let record = packages[item.file], repo = indexes[item.indexFile];
  if (!record || !repo || bound[item.file] || !hash(item.packageIdentity) ||
      item.name != record.name || item.version != record.version || item.architecture != record.arch ||
      ((repo.role == 'foxhole') != (index(allowed_own, record.name) >= 0))) reject();
  bound[item.file] = true;
 }
 if (length(keys(bound)) != length(value.packages) ||
     length(keys(files)) != length(keys(value.filesSha256 || {}))) reject();
 for (let key in value.filesSha256) if (!files[key] || !hash(value.filesSha256[key])) reject();
 return value;
};

export function compact_read(path, maximum) {
 let info = fs.lstat(path);
 if (info?.type != 'file' || info.size <= 0 || info.size > maximum) compact_reject();
 let raw = fs.readfile(path, maximum + 1);
 if (raw == null || length(raw) != info.size) compact_reject();
 let value = json(raw);
 if (type(value) != 'object') compact_reject();
 return value;
};
function compact_payloads(selected, directory, mode) {
 let modules = [], arch = selected.platform.architecture;
 for (let id in selected.protocols) {
  let found = filter(selected.platform.clients, row => row.id == id && row.storage == mode);
  if (length(found) != 1) compact_reject();
  let client = found[0], entry = client.entry;
  let producer = compact_read(directory + '/' + client.producer.file, 131072);
  let caps = compact_read(directory + '/' + client.capabilities.file, 131072);
  let slot = compact_read(directory + '/' + client.slotManifest.file, 131072);
  if (producer.schema != 1 || producer.exitCode != 0 || type(producer.exitCode) != 'int' ||
      producer.target != (arch == 'x86_64' ? 'x86_64' : 'aarch64') + '-unknown-linux-musl' ||
      producer.binarySha256 != entry.binarySha256 || producer.sourceCommit != entry.sourceCommit ||
      !hash(producer.sourceSha256) || producer.coreVersion != entry.version ||
      join(',', producer.protocols || []) != id ||
      type(caps.schema_version) != 'int' || caps.schema_version != 1 ||
      type(caps.router_contract_version) != 'int' || caps.router_contract_version != 1 ||
      caps.platform != 'linux' || caps.core_version != producer.coreVersion || join(',', caps.protocols || []) != id ||
      type(slot.schema) != 'int' || slot.schema != 1) compact_reject();
  for (let field in ['id', 'storage', 'version', 'architecture', 'binarySha256', 'executableSha256',
   'producerSha256', 'capabilitiesSha256', 'legalProvenanceSha256', 'sourceCommit', 'binaryBytes', 'runtimeMemoryBytes', 'reserveBytes'])
   if (slot[field] != entry[field]) compact_reject();
  push(modules, client);
 }
 let actual_catalog = compact_read(directory + '/' + selected.platform.engineCatalog.file, 524288);
 compact_exact(actual_catalog, ['schema', 'entries']);
 if (type(actual_catalog.schema) != 'int' || actual_catalog.schema != 1 ||
     type(actual_catalog.entries) != 'array' || length(actual_catalog.entries) > 72) compact_reject();
 let all = filter(actual_catalog.entries, row => row.architecture == arch);
 if (length(all) != length(selected.platform.clients)) compact_reject();
 for (let client in selected.platform.clients) {
  let matching = filter(all, row => row.id == client.id && row.storage == client.entry.storage);
  if (length(matching) != 1 || length(keys(matching[0])) != length(keys(client.entry))) compact_reject();
  for (let key in keys(client.entry)) if (matching[0][key] != client.entry[key]) compact_reject();
 }
 return modules;
};
function compact_server(selected, universe, directory, mode) {
 if (!selected.includeServer) return null;
 let declared = selected.platform.server.modes[mode], server = universe.server?.[mode];
 let server_fields = ['name', 'file', 'sha256', 'producerSha256', 'binarySha256', 'executableSha256',
  'runtimeMemoryBytes', 'securityReceiptSha256'];
 if (mode == 'ram') { push(server_fields, 'volatileFile'); push(server_fields, 'binaryBytes'); }
 compact_exact(server, server_fields);
 if (type(declared) != 'object' || type(server) != 'object' ||
     server.name != declared.name || server.file != declared.file || server.sha256 != declared.sha256 ||
     server.producerSha256 != selected.platform.server.producer.sha256 || !hash(server.binarySha256) || !hash(server.executableSha256) ||
     !number(server.runtimeMemoryBytes) || !server.runtimeMemoryBytes || server.runtimeMemoryBytes > 2147483648 ||
     !hash(server.securityReceiptSha256)) compact_reject();
 let producer = compact_read(directory + '/' + selected.platform.server.producer.file, 131072);
 if (producer.schema != 1 || producer.exitCode != 0 || type(producer.exitCode) != 'int' ||
     producer.target != (selected.platform.architecture == 'x86_64' ? 'linux-amd64' : 'linux-arm64') ||
     producer.binarySha256 != server.binarySha256 || producer.sourcePatch?.receiptSha256 != server.securityReceiptSha256 ||
     (mode == 'flash' && server.executableSha256 != server.binarySha256)) compact_reject();
 if (mode == 'ram' && (!name(server.volatileFile) || !number(server.binaryBytes) || !server.binaryBytes || server.binaryBytes > 67108864)) compact_reject();
 return server;
};
export function compact_budget(selected, directory, mode, development) {
 if (index(['flash', 'ram'], mode) < 0) compact_reject();
 let platform = selected.platform, universe = compact_read(directory + '/' + platform.packageUniverse.file, 2097152);
 compact_exact(universe, ['schema', 'kind', 'architecture', 'supportedTargets', 'supportedOpenWrt', 'verification',
  'packages', 'packageAuthentications', 'repositoryIndexes', 'trustKeys', 'filesSha256', 'requires',
  'server', 'baseRuntimeMemoryBytes', 'flashReserveBytes', 'ramReserveBytes', 'memoryEvidence']);
 if (type(universe.schema) != 'int' || universe.schema != 2 || universe.kind != 'compact-package-universe-v1' ||
     universe.architecture != platform.architecture ||
     join(',', universe.supportedTargets || []) != join(',', platform.supportedTargets) ||
     join(',', universe.supportedOpenWrt || []) != join(',', platform.supportedOpenWrt) ||
     type(universe.packages) != 'array' || !length(universe.packages) || length(universe.packages) > 512 ||
     type(universe.requires) != 'object' || type(universe.packageAuthentications) != 'array' ||
     length(universe.packageAuthentications) != length(universe.packages)) compact_reject();
 let modules = compact_payloads(selected, directory, mode), server = compact_server(selected, universe, directory, mode);
 let by_name = {}, roots = ['foxhole-openwrt-client'], wanted = {}, pending = ['kernel'], queued = { kernel: true };
 for (let client in modules) push(roots, client.entry.packageName);
 if (server) push(roots, server.name);
 for (let item in universe.packages) {
  if (!packageName(item.name) || by_name[item.name]) compact_reject();
  by_name[item.name] = item;
 }
 for (let name in roots) if (!queued[name]) { queued[name] = true; push(pending, name); }
 for (let position = 0; position < length(pending); position++) {
  if (position >= 512) compact_reject();
  let name = pending[position]; if (wanted[name]) continue;
  if (!by_name[name] || type(universe.requires[name]) != 'array' || length(universe.requires[name]) > 64) compact_reject();
  wanted[name] = true;
  let seen = {};
  for (let dependency in universe.requires[name]) {
   if (!packageName(dependency) || seen[dependency] || !by_name[dependency]) compact_reject();
   seen[dependency] = true;
   if (!wanted[dependency] && !queued[dependency]) { queued[dependency] = true; push(pending, dependency); }
  }
 }
 let packages = filter(universe.packages, row => wanted[row.name]);
 let authentications = filter(universe.packageAuthentications, row => wanted[row.name]);
 let used_indexes = {}, used_keys = {}, files = {}, compressed = 0, installed = 0, root_installed = 0;
 for (let item in packages) {
  if (!name(item.file) || !match(item.file, /\.apk$/) || !hash(item.sha256) ||
      !number(item.archiveBytes) || !item.archiveBytes || item.archiveBytes > 536870912 ||
      !number(item.installedBytes) || item.installedBytes > 2147483648 ||
      universe.filesSha256?.[item.file] != item.sha256) compact_reject();
  compressed += item.archiveBytes; installed += item.installedBytes; files[item.file] = item.sha256;
  if (index(roots, item.name) >= 0) root_installed += item.installedBytes;
 }
 for (let binding in authentications) used_indexes[binding.indexFile] = true;
 let indexes = filter(universe.repositoryIndexes || [], row => used_indexes[row.file]);
 let index_bytes = 0, key_bytes = 0;
 for (let index in indexes) {
  index_bytes += index.bytes; files[index.file] = index.sha256;
  for (let key in index.trustKeyFiles || []) used_keys[key] = true;
 }
 let trust = filter(universe.trustKeys || [], row => used_keys[row.file]);
 for (let key in trust) { key_bytes += key.bytes; files[key.file] = key.sha256; }
 let volatile = [], volatile_bytes = 0, runtime = 0;
 for (let client in modules) {
  runtime = max(runtime, client.entry.runtimeMemoryBytes);
  if (mode == 'ram') {
   let entry = client.entry;
   let file = 'engine-' + client.id + '-' + platform.architecture + '-' + entry.binarySha256 + '.bin';
   push(volatile, { id: client.id, file, sha256: entry.binarySha256, bytes: entry.binaryBytes });
   volatile_bytes += entry.binaryBytes;
  }
 }
 for (let key in ['baseRuntimeMemoryBytes', 'flashReserveBytes', 'ramReserveBytes'])
  if (!number(universe[key]) || !universe[key] || universe[key] > 2147483648) compact_reject();
 if (universe.flashReserveBytes < 16777216 || universe.ramReserveBytes < 16777216) compact_reject();
 runtime += universe.baseRuntimeMemoryBytes + (server ? server.runtimeMemoryBytes : 0);
 if (server && mode == 'ram') {
  push(volatile, { id: 'server', file: server.volatileFile, sha256: server.binarySha256, bytes: server.binaryBytes });
  volatile_bytes += server.binaryBytes;
 }
 let staging = 2 * compressed + installed + volatile_bytes + 2 * index_bytes + key_bytes;
 let evidence = universe.memoryEvidence;
 if (type(evidence) != 'object' || type(evidence.schema) != 'int' || evidence.schema != 1 ||
     evidence.type != 'conservative' || type(evidence.description) != 'string' ||
     !length(evidence.description) || length(evidence.description) > 4096 ||
     (!development && (evidence.provisional == true || evidence.acceptedForRelease == false))) compact_reject();
 for (let key in ['provisional', 'acceptedForRelease', 'measured'])
  if (index(keys(evidence), key) >= 0 && type(evidence[key]) != 'bool') compact_reject();
 if (evidence.measured == true) compact_reject();
 let value = { schema: 2, kind: 'compact-selected-budget-v1', architecture: platform.architecture,
  mode, supportedTargets: platform.supportedTargets, supportedOpenWrt: platform.supportedOpenWrt,
  protocols: selected.protocols, includeServer: selected.includeServer, modules, server,
  basePackage: platform.basePackage, engineCatalogSha256: platform.engineCatalog.sha256,
  verification: universe.verification, packages, packageAuthentications: authentications,
  repositoryIndexes: indexes, trustKeys: trust, filesSha256: files, rootPackages: roots,
  repositoryIndexBytes: index_bytes, trustKeyBytes: key_bytes, volatile,
  platformPackages: { kernel: by_name.kernel?.version }, compressedBytes: compressed,
  installedFlashBytes: installed, installedRamBytes: volatile_bytes,
  dependencyInstalledBytes: installed - root_installed, stagingBytes: staging,
  runtimeMemoryBytes: runtime, flashReserveBytes: universe.flashReserveBytes, ramReserveBytes: universe.ramReserveBytes,
  requiredFlashBytes: installed + universe.flashReserveBytes,
  requiredRamBytes: staging + runtime + universe.ramReserveBytes,
  memoryEvidence: { schema: 1, type: evidence.type, description: evidence.description, runtimeMemoryBytes: runtime } };
 for (let key in ['compressedBytes', 'installedFlashBytes', 'installedRamBytes', 'dependencyInstalledBytes', 'stagingBytes',
  'runtimeMemoryBytes', 'flashReserveBytes', 'ramReserveBytes', 'requiredFlashBytes', 'requiredRamBytes', 'repositoryIndexBytes', 'trustKeyBytes'])
  if (!number(value[key])) compact_reject();
 return authentication(value);
};
