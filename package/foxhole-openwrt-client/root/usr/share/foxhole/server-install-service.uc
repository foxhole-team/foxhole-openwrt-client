'use strict';

import * as fs from 'fs';
import * as ubus from 'ubus';
import * as registry from './engine-registry.uc';
import * as digest from 'digest';
import * as store from './private-store.uc';
import * as model from './server-install-model.uc';
import * as control from './server-mode.uc';
import * as state_model from './model.uc';
import * as native from './server-install-native.uc';
import * as engine from './engine-service.uc';
import * as facts from './protocol-facts.uc';
import * as backup from './backup-service.uc';

const PLAN = '/etc/foxhole/vpn-server-plan.json';
const JOB = '/etc/foxhole/vpn-server-job.json';
const CONSENT = '/etc/foxhole/vpn-server-consent.json';
const TERMINAL = ['SUCCEEDED','FAILED'];
const REASONS = ['vpn_server_verification_failed','vpn_server_stale_plan','vpn_server_no_space',
 'vpn_server_unavailable','vpn_server_unauthorized','vpn_server_recovery_required',
 'engine_download_failed','engine_package_verification_failed','storage_error'];
function sync() { if (system(['/bin/sync'],5000) != 0) fail('unavailable'); };
function fail(code) { die('vpn_server_' + (code || 'verification_failed')); };
function same(a,b) { return sprintf('%J',a) == sprintf('%J',b); };
function read(path) { let raw = store.read(path,2097152); return raw ? json(raw) : null; };
function write(path,value) {
 let raw = sprintf('%J',value); if (length(raw) > 2097152) fail(); store.write(path,raw);
};
function state() { return state_model.validate_state(read('/etc/foxhole/state.json') || state_model.defaults()); };
function state_locked(fn) {
 store.target('/etc/foxhole/state.lock');
 let handle = fs.open('/etc/foxhole/state.lock','a+',0o600);
 if (!handle?.lock('xn') || !store.file_metadata(fs.lstat('/etc/foxhole/state.lock'))) fail('busy');
 try { let result = fn(); handle.lock('u'); handle.close(); return result; }
 catch (error) { try { handle.lock('u'); handle.close(); } catch (_) {} die(error); }
};
function owner(principal) { return digest.sha256(sprintf('%J',principal)); };
function public_plan(value) {
 return { schema:1,action:value.action,available:value.available,revision:value.revision,
  planSha256:value.planSha256,downloadBytes:value.downloadBytes,component:value.component,
  budget:value.budget,storage:value.storage,components:map(value.additions,name => {
   let item = filter(value.descriptor.packages,row => row.name == name)[0];
   return {name:item.name,version:item.version};
  }) };
};
function public_job(value) {
 return { schema:1,jobId:value.jobId,state:value.state,step:value.step,
  progressPercent:value.progressPercent,failureReason:value.failureReason || null };
};
function active(value) { return value && index(TERMINAL,value.state) < 0; };
function binding_same(a,b) {
 let left = { ...a }, right = { ...b };
 for (let key in ['flashAvailableBytes','ramAvailableBytes']) { delete left[key]; delete right[key]; }
 return same(left,right);
};
function principal_current(principal) { return engine.update_principal_current(principal); };
export function installed() { try { return native.installed() || facts.server(); } catch (_) { return null; } };
export function remember_reuse(principal) {
 if (!principal_current(principal)) fail('unauthorized');
 let current = native.active();
 if (!current) return;
 write(CONSENT,{schema:1,principal,descriptor:current.descriptor,
  descriptorSha256:digest.sha256(sprintf('%J',current.descriptor)),confirmed:true});
 sync();
};
export function plan(principal) {
 let current = state(), component = installed();
 if (component) return { ...control.plan(current,component),removalAvailable:native.active() != null };
 let catalog = native.catalog();
 if (!length(catalog.value.entries)) return control.plan(current,null);
 return engine.update_locked(() => {
  engine.guard_mutation();
  let snapshot = native.context(principal), selected = null, error = null;
  for (let value in catalog.value.entries) {
   if (value.architecture != snapshot.binding.architecture || value.target != snapshot.binding.target ||
       value.openwrtRelease != snapshot.binding.openwrtRelease) continue;
   try {
    let candidate = model.make_plan(value,snapshot.binding,snapshot.installed,native.cached(value.assets));
    if (!selected || candidate.storage == 'FLASH') selected = candidate;
   } catch (caught) { error = caught; }
  }
  if (!selected) { if (error) die(error); return control.plan(current,null); }
  write(PLAN,{schema:1,principal,expires:engine.update_now()+300000,value:selected});
  return public_plan(selected);
 });
};
function spawn(id) {
 if (!match(id || '', /^vpn-server-job-[a-f0-9]{32}$/)) fail();
 if (system(['/bin/sh','-c','umask 077; /usr/libexec/foxhole-vpn-server-job "$1" >/dev/null 2>&1 &',
     'foxhole-vpn-server-job',id],1000) != 0) fail('unavailable');
};
function create_job(plan,principal,restore) {
 let bytes = fs.readfile('/dev/urandom',16); if (length(bytes || '') != 16) fail('unavailable');
 let value = { schema:1,jobId:'vpn-server-job-'+hexenc(bytes),state:'QUEUED',step:'QUEUED',progressPercent:0,
  principal,owner:owner(principal),plan,created:engine.update_now(),bootId:engine.update_boot(),
  previous:native.previous(),previousConsent:read(CONSENT),previousEnabled:state().settings.vpnServerEnabled == true,
  restore:restore == true,activated:false,failureReason:null };
 write(JOB,value); return value;
};
export function disable(request,principal) {
 let result = engine.update_locked(() => {
  engine.guard_mutation();
  let current = state();
  if (!principal_current(principal) || type(request.revision) != 'int' ||
      request.revision != current.revision) fail('stale_plan');
  if (request.removeComponent != null && type(request.removeComponent) != 'bool') fail('invalid_plan');
  let remove = request.removeComponent == true, generation = null;
  if (remove) {
   generation = native.active();
   if (!generation) fail('unavailable');
   let approved = control.plan(current,native.installed());
   if (request.confirmed != true || request.planSha256 != approved.planSha256)
    fail('confirmation_required');
  }
  let bytes = fs.readfile('/dev/urandom',16); if (length(bytes || '') != 16) fail('unavailable');
  let value = {schema:1,operation:'DISABLE',jobId:'vpn-server-job-'+hexenc(bytes),
   state:'QUEUED',step:'QUEUED',progressPercent:0,principal,owner:owner(principal),
   revision:current.revision,created:engine.update_now(),bootId:engine.update_boot(),failureReason:null,
   removeComponent:remove,removalGeneration:generation};
  write(JOB,value); sync(); return value;
 });
 spawn(result.jobId); return public_job(result);
};
function managed_instances() {
 let connection = ubus.connect(), result = null;
 if (!connection) fail('unavailable');
 try { result = connection.call('service','list',{name:'foxhole-inbound-services'}); }
 catch (_) { connection.disconnect(); fail('unavailable'); }
 connection.disconnect();
 if (type(result) != 'object') fail('unavailable');
 let instances = result['foxhole-inbound-services']?.instances;
 if (instances == null) return [];
 if (type(instances) != 'object' || length(keys(instances)) > 4) fail('unavailable');
 let output = [];
 for (let name in keys(instances)) {
  let item = instances[name];
  if (item?.running != true) continue;
  if (!match(name,/^(shared|client-[a-f0-9]{12})$/) || type(item.pid) != 'int' || item.pid < 2 ||
      type(item.command) != 'array' || length(item.command) != 5 ||
      index(['/usr/libexec/foxhole-server-run','/usr/bin/hysteria'],item.command[0]) < 0 ||
      item.command[1] != 'server' || item.command[2] != '-c' ||
      item.command[3] != '/tmp/foxhole/inbound/' + name + '.json' ||
      item.command[4] != '--disable-update-check') fail('unavailable');
  let process = engine.update_process_snapshot(item.pid);
  if (!process || !process.root || process.zombie) fail('unavailable');
  push(output,{pid:item.pid,start:process.start});
 }
 return output;
};
function disabled_proof(previous) {
 for (let attempt = 0; attempt < 30; attempt++) {
  let alive = length(managed_instances()) > 0;
  for (let item in previous) {
   let process = engine.update_process_snapshot(item.pid);
   if (process && process.start == item.start && !process.zombie) alive = true;
  }
  if (!alive) {
   let document = json(registry.capture(['/usr/sbin/nft','-j','list','set','inet','fw4','foxhole_inbound_ports'],8192,5000));
   if (type(document?.nftables) != 'array' || length(document.nftables) > 4) fail('unavailable');
   let sets = filter(document.nftables,row => row.set?.family == 'inet' &&
    row.set?.table == 'fw4' && row.set?.name == 'foxhole_inbound_ports');
   if (length(sets) != 1 || (sets[0].set.elem != null &&
       (type(sets[0].set.elem) != 'array' || length(sets[0].set.elem)))) fail('unavailable');
   return true;
  }
  if (sleep(100) != true) fail('unavailable');
 }
 fail('unavailable');
};
function run_disable(value) {
 try {
  value.worker = engine.update_self_worker(); write(JOB,value);
  // Defer stopping so the queued response can leave the router.
  if (sleep(1000) != true || (!principal_current(value.principal) &&
      !(value.disableIntent == true && state().settings.vpnServerEnabled == false))) fail('unauthorized');
  let previous = managed_instances();
  progress(value,'ACTIVATING',10);
  state_locked(() => {
   let current = state(); if (current.revision != value.revision) fail('stale_plan');
   value.disableIntent = true; write(JOB,value); sync();
   current.settings.vpnServerEnabled = false; current.revision++;
   write('/etc/foxhole/state.json',current);
  });
  sync();
  if (system(['/usr/libexec/foxhole-inbound','force'],30000) != 0) fail('unavailable');
  managed('stop');
  disabled_proof(previous);
  if (value.removeComponent == true) {
   if (!value.removalGeneration || !same(native.active(),value.removalGeneration)) fail('verification_failed');
   if (read(CONSENT) != null) {
    store.target(CONSENT);
    if (!fs.unlink(CONSENT)) fail('verification_failed');
    sync();
   }
   native.remove_owned(value.removalGeneration);
  }
  progress(value,'SUCCEEDED',100); sync();
 } catch (error) {
  let reason = type(error) == 'string' ? error : error.message;
  value.failureReason = index(REASONS,reason) >= 0 ? reason : 'vpn_server_verification_failed';
  // Keep the requested OFF state after a partial stop.
  value.state = value.disableIntent == true && state().settings.vpnServerEnabled == false ? 'RECOVERY_REQUIRED' : 'FAILED';
  value.step = value.state; write(JOB,value); sync();
 }
 return public_job(value);
};
export function apply(request,principal) {
 let result = engine.update_locked(() => {
  engine.guard_mutation();
  let stored = read(PLAN);
  if (!stored || stored.schema != 1 || stored.expires < engine.update_now() ||
      !same(stored.principal,principal) || !principal_current(principal)) fail('stale_plan');
  let snapshot = native.context(principal), plan = model.admit(stored.value,request,snapshot.binding);
  let computed = model.make_plan(plan.descriptor,snapshot.binding,snapshot.installed,native.cached(plan.descriptor.assets));
  if (!same(plan.assets,computed.assets) || plan.downloadBytes != computed.downloadBytes) fail('stale_plan');
  return create_job(plan,principal,false);
 });
 spawn(result.jobId); return public_job(result);
};
export function job(id,principal) {
 let value = read(JOB);
 if (!value || value.schema != 1 || value.jobId != id || value.owner != owner(principal)) fail('not_found');
 if (!principal_current(principal)) fail('unauthorized');
 return public_job(value);
};
function progress(value,step,percent) {
 if (!principal_current(value.principal) && !(value.operation == 'DISABLE' &&
     value.disableIntent == true && state().settings.vpnServerEnabled == false)) fail('unauthorized');
 if (engine.update_boot() != value.bootId || engine.update_now() - value.created > 900000) fail('unavailable');
 value.state = step; value.step = step; value.progressPercent = percent; write(JOB,value);
};
function managed(action) {
 if (system(['/etc/init.d/foxhole-inbound',action],15000) != 0) fail('unavailable');
};
function flag(enabled) {
 return state_locked(() => {
  let current = state();
  if (current.settings.vpnServerEnabled != enabled) {
   current.settings.vpnServerEnabled = enabled; current.revision++;
   write('/etc/foxhole/state.json',current);
  }
  return current;
 });
};
function rollback(value) {
 managed('stop');
 let active_pointer = native.previous();
 if (!same(active_pointer,value.previous) &&
     (!value.staged || !same(active_pointer,value.staged))) fail('recovery_required');
 native.restore(value.previous);
 if (value.previousConsent) write(CONSENT,value.previousConsent);
 else if (fs.lstat(CONSENT) && !fs.unlink(CONSENT)) fail('recovery_required');
 // Restore only a generation whose current proof is valid.
 let previous_valid = false;
 try { previous_valid = native.installed() != null || facts.server() != null; } catch (_) {}
 flag(value.previousEnabled && previous_valid);
 if (value.previousEnabled && previous_valid) managed('start');
 if (system(['/usr/libexec/foxhole-inbound','force'],30000) != 0) fail('recovery_required');
 value.state = 'FAILED'; value.step = 'FAILED'; write(JOB,value); sync();
};
export function run(id) {
 backup.guard();
 return engine.update_locked(() => {
  let value = read(JOB);
  if (!value || value.schema != 1 || value.jobId != id || value.state != 'QUEUED' ||
      value.bootId != engine.update_boot()) fail('stale_plan');
  if (value.operation == 'DISABLE') return run_disable(value);
  try {
   if (!principal_current(value.principal)) fail('unauthorized');
   value.worker = engine.update_self_worker(); write(JOB,value);
   let snapshot = native.context(value.principal);
   model.admit(value.plan,{confirmed:true,revision:value.plan.revision,planSha256:value.plan.planSha256},snapshot.binding);
   let staged = native.stage(value.plan,snapshot,(step,percent) => progress(value,step,percent),value.jobId);
   let current = native.context(value.principal);
   if (!binding_same(value.plan.binding,current.binding)) fail('stale_plan');
   if (current.binding.flashAvailableBytes < value.plan.descriptor.flashReserveBytes ||
       current.binding.ramAvailableBytes < value.plan.descriptor.ramReserveBytes + value.plan.descriptor.server.runtimeMemoryBytes)
    fail('no_space');
   progress(value,'ACTIVATING',90);
   value.staged = staged; value.commitIntent = true; write(JOB,value); sync();
   managed('stop');
   state_locked(() => {
    let current_state = state();
    if (current_state.revision != value.plan.revision) fail('stale_plan');
    native.publish(staged);
    value.activated = true; write(JOB,value);
    current_state.settings.vpnServerEnabled = true; current_state.revision++;
    write('/etc/foxhole/state.json',current_state);
    write(CONSENT,{schema:1,principal:value.principal,descriptor:value.plan.descriptor,
     descriptorSha256:digest.sha256(sprintf('%J',value.plan.descriptor)),confirmed:true});
   });
   sync();
   managed('start');
   if (system(['/usr/libexec/foxhole-inbound','force'],30000) != 0 || !native.installed()) fail('unavailable');
   progress(value,'SUCCEEDED',100); sync();
  } catch (error) {
   let reason = type(error) == 'string' ? error : error.message;
   value.failureReason = index(REASONS,reason) >= 0 ? reason : 'vpn_server_verification_failed';
   try { rollback(value); }
   catch (_) { value.state = 'RECOVERY_REQUIRED'; value.step = 'RECOVERY_REQUIRED'; write(JOB,value); }
  }
  return public_job(value);
 });
};
export function ensure() {
 let current = state(), pending = read(JOB);
 if (active(pending)) {
  if (pending.bootId == engine.update_boot() &&
      engine.update_now() - pending.created < 15000 && pending.state == 'QUEUED') return;
  if (pending.worker && engine.update_process_snapshot(pending.worker.pid)?.start == pending.worker.start &&
      pending.bootId == engine.update_boot()) return;
  if (pending.operation == 'DISABLE') {
   pending.bootId = engine.update_boot(); pending.created = engine.update_now();
   pending.revision = current.revision; pending.state = 'QUEUED'; write(JOB,pending);
   engine.update_locked(() => run_disable(pending));
  } else engine.update_locked(() => rollback(pending));
  current = state();
 }
 if (!control.enabled(current) || installed()) return;
 let consent = read(CONSENT);
 if (consent?.schema != 1 || consent.confirmed != true ||
     digest.sha256(sprintf('%J',consent.descriptor)) != consent.descriptorSha256 ||
     !principal_current(consent.principal)) return;
 let result = engine.update_locked(() => {
  engine.guard_mutation();
  let catalog = native.catalog();
  if (!same(filter(catalog.value.entries,row => same(row,consent.descriptor)),[consent.descriptor])) fail();
  let snapshot = native.context(consent.principal);
  let plan = model.make_plan(consent.descriptor,snapshot.binding,snapshot.installed,native.cached(consent.descriptor.assets));
  return create_job(plan,consent.principal,true);
 });
 spawn(result.jobId);
};
