import * as fs from 'fs';
import * as engines from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/engine-model.uc';

let previous = json(fs.readfile('/workspace/tests/fixtures/engine-catalog-v1.0.3.json', 262144));
let current;
if (ARGV[0]) current = json(fs.readfile(ARGV[0], 262144));
else {
 // Synthetic release-only transition; actual repack qualification supplies its real catalog.
 current = json(sprintf('%J', previous));
 for (let entry in current.entries) if (entry.storage == 'RAM') {
  entry.packageVersion = '1.0.2-r2';
  entry.packageUrl = replace(entry.packageUrl, '-1.0.2-r1.apk', '-1.0.2-r2.apk');
 }
}
let passed = 0;
for (let arch in ['aarch64_cortex-a53', 'x86_64']) for (let storage in ['RAM', 'FLASH']) {
 let slots = filter(previous.entries, value => value.architecture == arch && value.storage == storage);
 let registry = {schema:1,revision:1,slots,
  selected:map(slots,value=>({id:value.id,slotId:engines.slot_id(value)}))};
 let context = {routerId:'synthetic',architecture:arch,catalogSha256:'synthetic',activeEngineId:null,activeProfileId:null};
 let status = engines.status(current,registry,context);
 for (let old in slots) {
  let row = filter(status.entries,value=>value.id==old.id)[0];
  let next = filter(current.entries,value=>value.id==old.id&&value.storage==storage&&value.architecture==arch)[0];
  if (!row || !next || row.updateAvailable != (storage=='RAM') ||
      next.binarySha256 != old.binarySha256 || next.version != '1.0.2' ||
      next.packageVersion != (storage=='RAM'?'1.0.2-r2':'1.0.2-r1')) die('package_release_status_failed');
  passed++;
 }
}
print('# Engine RAM r2 / FLASH r1 status: ',passed,' passed\n');
