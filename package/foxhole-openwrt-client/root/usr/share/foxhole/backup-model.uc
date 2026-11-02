'use strict';

import * as digest from 'digest';
import * as model from './model.uc';
import * as mobile from './mobile.uc';

export const maximum_bytes = 294912;
export const panel_options = ['mode','telemetry_interval','standalone','lan_devices','mobile_devices',
 'dns_via_tunnel','preserve_loopback_socks','tun_mtu'];

function fail(code) { die(code || 'backup_invalid'); };
function integer(value) { return type(value)=='int' && value>=0 && value<=9007199254740991; };
function exact(value,fields) {
 if(type(value)!='object'||length(keys(value))!=length(fields))fail();
 for(let key in keys(value))if(index(fields,key)<0)fail();
};
function copy(value) { return json(sprintf('%J',value)); };
function check_tree(value,depth) {
 if(depth>16)fail();
 if(type(value)=='array') {for(let item in value)check_tree(item,depth+1);return;}
 if(type(value)!='object')return;
 for(let key in keys(value)) {
  if(index(['__proto__','prototype','constructor'],key)>=0)fail();
  check_tree(value[key],depth+1);
 }
};
function canonical(value,depth) {
 if(depth>16)fail();
 if(type(value)=='array')return map(value,item=>canonical(item,depth+1));
 if(type(value)!='object')return value;
 let result={};for(let key in sort(keys(value)))result[key]=canonical(value[key],depth+1);return result;
};
export function fingerprint(value) { return digest.sha256(sprintf('%J',canonical(value,0))); };
export function without_stop(value) {
 let state=copy(value);state.revision=0;state.activeServerId=null;return fingerprint(state);
};
function state(value) {
 if(type(value)!='object'||length(sprintf('%J',value))>262144)fail();
 exact(value,['schema','revision','activeServerId','settings','countries','devices','sites','servers','clients']);
 for(let name in ['countries','devices','sites','servers','clients'])
  if(type(value[name])!='array'||length(value[name])>512)fail();
 try { return model.validate_state(copy(value)); } catch (_) { fail(); }
};
export function panel(value) {
 if(type(value)=='object'&&length(keys(value))==length(panel_options)-1&&value.mobile_devices==null)
  value={...value,mobile_devices:null};
 exact(value,panel_options);let result=copy(value);
 for(let key in panel_options) {
  let item=value[key];if(item==null)continue;
  if(key=='lan_devices'||key=='mobile_devices') {
   if(type(item)!='array'||length(item)>(key=='mobile_devices'?8:32)||key=='mobile_devices'&&!length(item))fail();let seen={};
   for(let device in item) {
    if(type(device)!='string'||!match(device,/^[A-Za-z0-9_.:-]{1,32}$/)||seen[device])fail();seen[device]=true;
   }
  } else if(key=='mode') {
   if(index(['runtime','off'],item)<0)fail();
  } else if(index(['standalone','dns_via_tunnel','preserve_loopback_socks'],key)>=0) {
   if(index(['0','1'],item)<0)fail();
  } else {
   if(type(item)!='string'||!match(item,/^[0-9]{1,4}$/))fail();
   if(key=='tun_mtu'&&(+item<1280||+item>1500)||key=='telemetry_interval'&&(+item<1||+item>3600))fail();
  }
 }
 return result;
};
export function validate_document(value) {
 check_tree(value,0);
 if(length(sprintf('%J',value))>maximum_bytes)fail();
 exact(value,['schema','kind','createdAtUnixMs','state','panel','autoUpdate']);
 if(value.schema!=1||value.kind!='foxhole-settings-backup-v1'||!integer(value.createdAtUnixMs))fail();
 exact(value.autoUpdate,['enabled']);if(type(value.autoUpdate.enabled)!='bool')fail();
 let result={schema:1,kind:value.kind,createdAtUnixMs:value.createdAtUnixMs,
  state:state(value.state),panel:panel(value.panel),autoUpdate:{enabled:value.autoUpdate.enabled}};
 if(result.state.settings.standaloneAccess!=(result.panel.standalone!='0'))fail();
 return result;
};
export function export_document(current,panel_value,enabled,now) {
 let checked=state(current);checked.settings.standaloneAccess=panel_value.standalone!='0';
 return validate_document({schema:1,kind:'foxhole-settings-backup-v1',createdAtUnixMs:now,
  state:checked,panel:panel_value,autoUpdate:{enabled}});
};
function bound_records(restored,current,phones) {
 let records=mobile.journal(phones);
 for(let phone in records.phones) {
  for(let role in [['remoteClientId','clients'],['lanDeviceId','devices']]) {
   let id=phone[role[0]];if(id==null)continue;
   let incoming=filter(restored[role[1]],item=>item.id==id),live=filter(current[role[1]],item=>item.id==id);
   if(role[0]=='remoteClientId'&&phone.remoteRevoked==true) {
    if(length(incoming))fail('backup_pairing_conflict');
   } else if(length(live)!=1||length(incoming)!=1||fingerprint(live[0])!=fingerprint(incoming[0]))
    fail('backup_pairing_conflict');
  }
 }
};
export function candidate(document,current,phones) {
 let value=validate_document(document),live=state(current);
 if(live.revision>=0x7ffffffe)fail('revision_conflict');
 bound_records(value.state,live,phones);
 value.state.revision=live.revision+1;
 if(length(sprintf('%J',value.state))>262144)fail();return value;
};
export function summary(document) {
 let value=validate_document(document);
 return {schema:1,backupSha256:fingerprint(value),createdAtUnixMs:value.createdAtUnixMs,
  servers:length(value.state.servers),clients:length(value.state.clients),devices:length(value.state.devices),
  sites:length(value.state.sites),countries:length(value.state.countries),
  reconnectRequired:true,confirmationRequired:true};
};
