'use strict';

import * as fs from 'fs';
import * as store from './private-store.uc';
import * as updates from './update-model.uc';

const PATH='/etc/foxhole/initial-package-update.json';
const ACTIVE='/var/run/foxhole-initial-auto-update';

function read(path, maximum) {
 let raw=store.read(path,maximum);
 return raw==null ? null : json(raw);
};
export function pending() {
 let value=read(PATH,1024);
 if (value==null) return null;
 if (value.schema!=1 || type(value.enabled)!='bool') die('storage_error');
 return value.enabled;
};
function record_fresh() {
 if (pending()!=null || fs.lstat('/etc/foxhole/update-policy.json')) return;
 let auth=read('/etc/foxhole/auth.json',4096), state=read('/etc/foxhole/state.json',1048576), pairs=read('/etc/foxhole/pairing.json',32768);
 if (!updates.empty_install(state,pairs) || (auth!=null && !updates.fresh_setup(auth,state,pairs,false))) return;
 let active=fs.lstat(ACTIVE), off=null;
 if (active) {
  if (active.type!='directory' || active.uid!=0 || (active.mode & 0o7777)!=0o700) die('storage_error');
  off=fs.lstat(ACTIVE+'/off');
  if (off && (off.type!='directory' || off.uid!=0 || (off.mode & 0o7777)!=0o700)) die('storage_error');
 }
 store.write(PATH,sprintf('%J',{schema:1,enabled:!off}));
 if (pending()!=(!off)) die('storage_error');
};
export function initialize() {
 store.target('/etc/foxhole/state.lock');
 let lock=fs.open('/etc/foxhole/state.lock','a+',0o600);
 if (!lock || !lock.lock('x') || !store.file_metadata(fs.lstat('/etc/foxhole/state.lock'))) die('storage_error');
 try { record_fresh(); } catch (error) { lock.lock('u');lock.close();die(error); }
 lock.lock('u');lock.close();
};
