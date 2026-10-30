'use strict';

import { selection, budget, fits, read, hash, installedPackages, readInstalled, compact_selection, compact_metadata } from './install-plan-model.uc';

if (ARGV[0] == 'select' || ARGV[0] == 'plan' || ARGV[0] == 'receipt') {
 let action = ARGV[0], path = ARGV[1], architecture = ARGV[2], release = ARGV[3];
 let requested = ARGV[4], development = ARGV[5];
 let catalog = read(path);
 if (catalog.schema == 2) {
  let option = ARGV[action == 'select' ? 7 : action == 'receipt' ? 13 : 12] || '0';
  if (option != '0' && option != '1') die('Invalid compact server intent\n');
  let selected = compact_selection(catalog, architecture, release, requested, development == '1', ARGV[6], option == '1');
  if (action == 'select') {
   for (let item in compact_metadata(selected)) printf('%s %s\n', item.file, item.sha256);
   exit(0);
  }
  die('Compact package budget unavailable\n');
 }
 let variant = selection(read(path), architecture, release, requested, development == '1', ARGV[6]);
 if (action == 'select') {
  printf('%s %s\n%s %s\n', variant.coreProducerFile, variant.coreProducerSha256,
         variant.capabilitiesFile, variant.capabilitiesSha256);
  if (variant.serverProducerFile)
   printf('%s %s\n', variant.serverProducerFile, variant.serverProducerSha256);
  for (let mode in ['flash', 'ram']) if (variant.modes[mode])
   printf('%s %s\n', variant.modes[mode].budgetFile, variant.modes[mode].budgetSha256);
 } else {
  let directory = ARGV[7], requestedMode = ARGV[8];
  let flash = int(ARGV[9]), ram = int(ARGV[10]), backup = int(ARGV[11]);
  let chosen = null;
  for (let mode in ['flash', 'ram']) {
   if (requestedMode != 'auto' && requestedMode != mode) continue;
   if (!variant.modes[mode]) continue;
   let value = budget(read(directory + '/' + variant.modes[mode].budgetFile), variant, mode, development == '1');
   if (fits(value, flash, ram, backup)) { chosen = value; break; }
  }
  if (!chosen) die('Insufficient verified flash/RAM budget; nothing installed\n');
  if (action == 'receipt') {
   if (!hash(ARGV[12])) die('Invalid catalog identity\n');
   printf('%J\n', { schema: 1, variantId: variant.id, architecture: variant.architecture,
    supportedTargets: variant.supportedTargets, supportedOpenWrt: variant.supportedOpenWrt,
    protocols: variant.protocols, coreBinarySha256: variant.coreBinarySha256,
    capabilitiesSha256: variant.capabilitiesSha256, coreProducerSha256: variant.coreProducerSha256,
    coreSourceSha256: variant.coreSourceSha256, serverProducerSha256: variant.serverProducerSha256, mode: chosen.mode, catalogSha256: ARGV[12],
    packages: map(chosen.packages, item => ({ name: item.name, version: item.version,
     file: item.file, sha256: item.sha256 })) });
   exit(0);
  }
  printf('mode %s\nvariant %s\nkernel %s\nbudget %s\n', chosen.mode, variant.id,
         chosen.platformPackages.kernel, variant.modes[chosen.mode].budgetFile);
  for (let item in chosen.packages)
   printf('%s %s %s %d\n', item.name == 'kernel' ? 'kernelAsset' : 'asset', item.file, item.sha256, item.archiveBytes);
  let trust = {};
  for (let item in chosen.repositoryIndexes) {
   printf('index %s %s %d\n', item.file, item.sha256, item.bytes);
   for (let key in item.trustKeyFiles) trust[key] = true;
  }
  for (let item in chosen.trustKeys)
   printf('trustKey %s %s %d\n', item.file, item.sha256, item.bytes);
  if (chosen.volatileBinary)
   printf('volatile %s %s %d\n', chosen.volatileBinary.file, chosen.volatileBinary.sha256, chosen.volatileBinary.bytes);
  for (let entry in chosen.volatileDependencies || [])
   printf('serverVolatile %s %s %d\n', entry.file, entry.sha256, entry.bytes);
 }
}
 else if (ARGV[0] == 'installed-kernel' && length(ARGV) == 4) {
 let expected = { kernel: { version: ARGV[2], arch: ARGV[3] } };
 if (!installedPackages(readInstalled(ARGV[1]), expected))
  die('Kernel ABI differs; firmware is never replaced by this installer\n');
}
