'use strict';

import * as fs from 'fs';
import { compact_selection, compact_metadata, compact_budget, compact_read, authentication, fits, read, hash, fresh_board_mode } from './install-plan-model.uc';
import * as package_format from './engine-package-layout.uc';

function reject() { die('Invalid compact installation operation\n'); };
function budget(path) {
 let value = read(path);
 if (!((value.schema == 2 && value.kind == 'compact-selected-budget-v1') ||
       (value.schema == 3 && value.kind == 'compact-selected-budget-v2'))) reject();
 return authentication(value);
};
let action = ARGV[0];
if (action == 'ram-requirements') {
 let plan=compact_read(ARGV[1],32768), catalog=read(ARGV[2]);
 let selection=compact_selection(catalog,'aarch64_cortex-a53','25.12.5','hysteria2',false,'mediatek/filogic',false);
 let p=selection.platform, client=filter(p.clients,c=>c.id=='hysteria2' && c.storage=='ram');
 if (length(client)!=1 || fresh_board_mode(p,'25.12.5','cudy,wr3000-v1','ram')!='ram' ||
     plan?.schema!=1 || plan.kind!='ram-root-install-plan-v1' || plan.boardName!='cudy,wr3000-v1' ||
     plan.firmware!='25.12.5' || plan.architecture!='aarch64_cortex-a53' || plan.target!='mediatek/filogic' ||
     plan.storageMode!='ram' || plan.deployment!='isolated-apk-root' || join(',',plan.protocols||[])!='hysteria2' ||
     plan.packageCatalogSha256!=ARGV[3] || plan.packageUniverseSha256!=p.packageUniverse.sha256 ||
     plan.basePackageSha256!=p.basePackage.sha256 || type(plan.hostApkWorldMutation)!='bool' || plan.hostApkWorldMutation ||
     type(plan.hostPackageFlashBytes)!='int' || plan.hostPackageFlashBytes!=0 || type(plan.coldBootRecovery)!='bool' ||
     plan.coldBootRecovery || type(plan.activationQualified)!='bool' || plan.activationQualified) reject();
 let e=client[0].entry, sizes=plan.bytes, limits=plan.phaseBytes;
 if (plan.client?.packageSha256!=e.packageSha256 || plan.client.indexSha256!=e.indexSha256 ||
     plan.client.executableSha256!=e.executableSha256 || plan.client.capabilitiesSha256!=e.capabilitiesSha256 ||
     plan.client.volatileElfSha256!=e.binarySha256 || plan.client.slotManifestSha256!=e.manifestSha256 ||
     type(sizes)!='object' || type(limits)!='object') reject();
 let required_sizes=['selectedFlatInputBytes','transportArchiveBytes','transportDescriptorBytes','outerManifestBytes',
  'packageArchiveBytes','repositoryIndexBytes','trustKeyBytes','installedPackageBytes','volatileExecutableBytes',
  'largestArchiveBytes','nativeApkOverheadBytes','metadataAllowanceBytes','baseRuntimeMemoryBytes','moduleRuntimeMemoryBytes','ramReserveBytes'];
 if (length(keys(sizes))!=length(required_sizes) || length(keys(limits))!=4) reject();
 for (let k in required_sizes) if (type(sizes[k])!='int' || sizes[k]<=0 || sizes[k]>2147483648) reject();
 if (sizes.ramReserveBytes<33554432 || sizes.baseRuntimeMemoryBytes<67108864 ||
     sizes.moduleRuntimeMemoryBytes!=e.runtimeMemoryBytes || sizes.volatileExecutableBytes!=e.binaryBytes) reject();
 let steady=sizes.installedPackageBytes+sizes.volatileExecutableBytes+sizes.metadataAllowanceBytes;
 let intake=sizes.selectedFlatInputBytes+sizes.packageArchiveBytes+sizes.repositoryIndexBytes+sizes.trustKeyBytes+steady;
 let minimum={download:sizes.selectedFlatInputBytes+sizes.transportArchiveBytes+sizes.transportDescriptorBytes+sizes.outerManifestBytes,
  prepare:intake+2*sizes.largestArchiveBytes+sizes.nativeApkOverheadBytes,
  activation:steady+sizes.baseRuntimeMemoryBytes+sizes.moduleRuntimeMemoryBytes,rollback:steady+sizes.metadataAllowanceBytes};
 for (let k in keys(minimum)) if (type(limits[k])!='int' || limits[k]<minimum[k] || limits[k]>2147483648) reject();
 if (plan.requiredMemAvailableBytes!=max(max(limits.download,limits.prepare),max(limits.activation,limits.rollback))+sizes.ramReserveBytes ||
     plan.requiredTmpfsAvailableBytes!=max(intake,max(limits.download,limits.rollback))+sizes.ramReserveBytes ||
     !match(ARGV[4]||'',/^[0-9]+$/) || !match(ARGV[5]||'',/^[0-9]+$/)) reject();
 let available=int(ARGV[4])*1024, tmp=int(ARGV[5])*1024;
 printf('RAM root requires %d bytes of available memory and %d bytes of free tmpfs, observed %d and %d\n',
  plan.requiredMemAvailableBytes,plan.requiredTmpfsAvailableBytes,available,tmp);
 if (available<plan.requiredMemAvailableBytes || tmp<plan.requiredTmpfsAvailableBytes) exit(1);
} else if (action == 'board-mode') {
 let selected = compact_selection(read(ARGV[1]), ARGV[2], ARGV[3], ARGV[4], ARGV[5] == '1', ARGV[6], ARGV[7] == '1');
 let board = null;
 if (ARGV[6] == 'mediatek/filogic') {
  let path = '/tmp/sysinfo/board_name', dir = fs.lstat('/tmp/sysinfo'), info = fs.lstat(path);
  if (dir?.type != 'directory' || dir.uid != 0 || (dir.mode & 0o022) ||
      info?.type != 'file' || info.uid != 0 || info.nlink != 1 || (info.mode & 0o022) ||
      info.size < 1 || info.size > 128) reject();
  let value = fs.readfile(path,129);
  if (!match(value || '',/^[a-z0-9,.-]+\n?$/) || length(value) != info.size) reject();
  board = trim(value);
 }
 print(fresh_board_mode(selected.platform,ARGV[3],board,ARGV[8]));
} else if (action == 'witness') {
 let selected=compact_selection(read(ARGV[1]), ARGV[2], ARGV[3], ARGV[4], ARGV[5]=='1', ARGV[6], ARGV[7]=='1');
 if (ARGV[6]=='mediatek/filogic') {
  let board=selected.platform.freshInstallBoard, witness=selected.platform.stockFactoryInventory;
  if (join(',',selected.protocols)!='hysteria2' || selected.includeServer || !board || !witness ||
      witness.file!='stock-factory-'+replace(board.boardName,',','-')+'.json' || !hash(witness.sha256)) reject();
  print(witness.file,' ',witness.sha256);
 }
} else if (action == 'profile') {
 let selected = compact_selection(read(ARGV[1]), ARGV[2], ARGV[3], ARGV[4], ARGV[5] == '1', ARGV[6], ARGV[7] == '1');
 if (selected.platform.freshInstallAccounting != null) print(selected.platform.freshInstallAccounting.file);
} else if (action == 'budget' || action == 'factory-budget') {
 let catalog = read(ARGV[1]), option = ARGV[12];
 if (option != '0' && option != '1') reject();
 let selected = compact_selection(catalog, ARGV[2], ARGV[3], ARGV[4], ARGV[5] == '1', ARGV[6], option == '1');
 let mode = ARGV[8], flash = int(ARGV[9]), ram = int(ARGV[10]), backup = int(ARGV[11]), chosen = null;
 if (index(['auto', 'flash', 'ram'], mode) < 0 || (selected.platform.freshInstallAccounting != null && mode != 'flash')) reject();
 for (let candidate in ['flash', 'ram']) {
  if (mode != 'auto' && mode != candidate) continue;
  if (index(selected.storageModes, candidate) < 0) continue;
  let supported = true;
  for (let id in selected.protocols)
   if (!length(filter(selected.platform.clients, row => row.id == id && row.storage == candidate))) supported = false;
  if (selected.includeServer && selected.platform.server.modes[candidate] == null) supported = false;
  if (!supported) continue;
  let value = compact_budget(selected, ARGV[7], candidate, ARGV[5] == '1', action == 'factory-budget');
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
