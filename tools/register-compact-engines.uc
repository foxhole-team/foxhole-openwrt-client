'use strict';

import * as fs from 'fs';
import * as registry from '/usr/share/foxhole/engine-registry.uc';
import * as engines from '/usr/share/foxhole/engine-model.uc';
import * as store from '/usr/share/foxhole/private-store.uc';
import { read, authentication } from './install-plan-model.uc';

if (system(['/bin/sh', '-c', '[ "$(id -u)" = 0 ]']) != 0) die('Compact registration requires root\n');
let info = fs.lstat(ARGV[0]);
if (info?.type != 'file' || info.uid != 0 || info.nlink != 1 || (info.mode & 0o077) || info.size > 2097152)
 die('Invalid compact registration input\n');
let value = authentication(read(ARGV[0]));
if (value.schema != 2 || value.kind != 'compact-selected-budget-v1') die('Compact schema required\n');
function register() {
 let old = registry.read(), current = registry.catalog();
 if (old.revision != 0 || length(old.slots) || length(old.selected) || current.sha256 != value.engineCatalogSha256)
  die('Existing engine state requires paired management\n');
 let additions = [];
 for (let module in value.modules) {
  let matching = filter(current.value.entries, row => row.id == module.id && row.storage == module.entry.storage &&
   row.architecture == module.entry.architecture && row.manifestSha256 == module.entry.manifestSha256);
  if (length(matching) != 1 || length(keys(matching[0])) != length(keys(module.entry))) die('Installed engine catalog differs\n');
  for (let key in keys(module.entry)) if (matching[0][key] != module.entry[key]) die('Installed engine catalog differs\n');
  registry.verify_slot(module.entry);
  push(additions, module.entry);
 }
 let next = engines.commit(old, additions, [], 0);
 registry.write(next);
 let after = registry.read();
 for (let module in value.modules) {
  let selected = engines.selected(after, module.id);
  if (selected?.manifestSha256 != module.entry.manifestSha256 || registry.verify_slot(selected) == null)
   die('Compact registration readback failed\n');
 }
}
store.directory('/etc/foxhole');
let path = '/etc/foxhole/engine.lock', lock = fs.open(path, 'a+', 0o600);
if (!lock || !lock.lock('xn') || !store.file_metadata(fs.lstat(path))) {
 try { if (lock) lock.close(); } catch (_) {}
 die('Compact registration is busy\n');
}
try { register(); } catch (error) {
 try { lock.lock('u'); lock.close(); } catch (_) {}
 die(error);
}
lock.lock('u'); lock.close();
print('Verified compact client engines registered\n');
