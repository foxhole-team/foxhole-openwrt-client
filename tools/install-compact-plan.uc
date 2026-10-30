'use strict';

import * as fs from 'fs';
import { compact_selection, compact_metadata, compact_budget, compact_read, authentication, fits, read, hash } from './install-plan-model.uc';
import * as package_format from './engine-package-layout.uc';

function reject() { die('Invalid compact installation operation\n'); };
function budget(path) {
 let value = read(path);
 if (value.schema != 2 || value.kind != 'compact-selected-budget-v1') reject();
 return authentication(value);
};
let action = ARGV[0];
if (action == 'budget') {
 let catalog = read(ARGV[1]), option = ARGV[12];
 if (option != '0' && option != '1') reject();
 let selected = compact_selection(catalog, ARGV[2], ARGV[3], ARGV[4], ARGV[5] == '1', ARGV[6], option == '1');
 let mode = ARGV[8], flash = int(ARGV[9]), ram = int(ARGV[10]), backup = int(ARGV[11]), chosen = null;
 if (index(['auto', 'flash', 'ram'], mode) < 0) reject();
 for (let candidate in ['flash', 'ram']) {
  if (mode != 'auto' && mode != candidate) continue;
  let supported = true;
  for (let id in selected.protocols)
   if (!length(filter(selected.platform.clients, row => row.id == id && row.storage == candidate))) supported = false;
  if (selected.includeServer && selected.platform.server.modes[candidate] == null) supported = false;
  if (!supported) continue;
  let value = compact_budget(selected, ARGV[7], candidate, ARGV[5] == '1');
  if (fits(value, flash, ram, backup)) { chosen = value; break; }
 }
 if (!chosen) die('Insufficient verified compact flash/RAM budget; nothing installed\n');
 printf('%J\n', chosen);
} else if (action == 'list') {
 let value = budget(ARGV[1]);
 printf('mode %s\nkernel %s\nbudget compact-budget.json\n', value.mode, value.platformPackages.kernel);
 for (let item in value.packages)
  printf('%s %s %s %d\n', item.name == 'kernel' ? 'kernelAsset' : 'asset', item.file, item.sha256, item.archiveBytes);
 for (let item in value.repositoryIndexes) printf('index %s %s %d\n', item.file, item.sha256, item.bytes);
 for (let item in value.trustKeys) printf('trustKey %s %s %d\n', item.file, item.sha256, item.bytes);
 for (let item in value.volatile)
  printf('%s %s %s %d\n', item.id == 'server' ? 'serverVolatile' : 'engineVolatile:' + item.id, item.file, item.sha256, item.bytes);
} else if (action == 'layout') {
 let value = budget(ARGV[1]), id = ARGV[2], document = compact_read(ARGV[3], 8388608);
 let matching = filter(value.modules, row => row.entry.packageName == id);
 if (length(matching) != 1 || !package_format.layout(document, matching[0].entry)) reject();
} else if (action == 'installed') {
 let value = budget(ARGV[1]);
 for (let module in value.modules) {
  let entry = module.entry, folder = '/usr/libexec/foxhole/engines/' + entry.id + '/' + entry.manifestSha256;
  printf('file %s/foxcore-cli %s\n', folder, entry.executableSha256);
  printf('file %s/slot.json %s\n', folder, entry.manifestSha256);
  printf('file %s/core-producer.json %s\n', folder, entry.producerSha256);
  printf('file %s/capabilities.json %s\n', folder, entry.capabilitiesSha256);
  printf('capabilities %s/foxcore-cli %s\n', folder, entry.capabilitiesSha256);
  printf('file /usr/share/licenses/%s/LEGAL-PROVENANCE.json %s\n', entry.packageName, entry.legalProvenanceSha256);
 }
 printf('file /usr/share/foxhole/engine-catalog.json %s\n', value.engineCatalogSha256);
 if (value.server) {
  printf('file /usr/bin/hysteria %s\n', value.server.executableSha256);
  printf('file /usr/share/foxhole/hysteria-producer.json %s\n', value.server.producerSha256);
 }
} else if (action == 'receipt') {
 let value = budget(ARGV[1]); if (!hash(ARGV[2])) reject();
 printf('%J\n', { schema: 2, kind: 'compact-installed-package-v1', architecture: value.architecture,
  supportedTargets: value.supportedTargets, supportedOpenWrt: value.supportedOpenWrt,
  protocols: value.protocols, includeServer: value.includeServer, mode: value.mode, catalogSha256: ARGV[2],
  engineCatalogSha256: value.engineCatalogSha256, basePackage: value.basePackage,
  modules: map(value.modules, row => ({ id: row.id, storage: row.storage, entry: row.entry })),
  server: value.server, packages: map(value.packages, row => ({ name: row.name, version: row.version, file: row.file, sha256: row.sha256 })) });
} else if (action == 'register') {
 // Register only after native payload readback.
 let value = budget(ARGV[1]);
 for (let module in value.modules) printf('%J\n', module.entry);
} else reject();
