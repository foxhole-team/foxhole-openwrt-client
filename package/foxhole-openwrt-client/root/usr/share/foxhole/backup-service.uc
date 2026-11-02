'use strict';

import * as fs from 'fs';
import * as uci from 'uci';
import * as digest from 'digest';
import * as backup from './backup-model.uc';
import * as state_model from './model.uc';
import * as policy_model from './update-model.uc';
import * as mobile from './mobile.uc';
import * as store from './private-store.uc';

const DIRECTORY='/etc/foxhole/backup-restore';
const JOURNAL=DIRECTORY+'/journal.json';
const STATE='/etc/foxhole/state.json';
const CONFIG='/etc/config/foxhole';
const POLICY='/etc/foxhole/update-policy.json';
const FILES={state:STATE,config:CONFIG,policy:POLICY};
const TERMINAL=['COMMITTED','CANCELLED'];

function fail(code) { die(code||'backup_recovery_required'); };
function same(a,b) { return backup.fingerprint(a)==backup.fingerprint(b); };
function sha(raw) { return raw==null?null:digest.sha256(raw); };
function sync_files() { if(system(['/bin/sync'],5000)!=0)fail(); };
function private_json(path,limit) {
 let raw=store.read(path,limit);if(raw==null)return null;
 try { return json(raw); } catch (_) { fail(); }
};
function config_raw() {
 let parent=fs.lstat('/etc/config'),a=fs.lstat(CONFIG);
 if(parent?.type!='directory'||parent.uid!=0||(parent.mode&0o022)||a?.type!='file'||a.uid!=0||a.gid!=0||
  a.nlink!=1||(a.mode&0o022)||a.size<1||a.size>65536)fail();
 let raw=fs.readfile(CONFIG,65537),b=fs.lstat(CONFIG);
 if(raw==null||length(raw)!=a.size||sprintf('%J',[a.dev,a.inode,a.mode,a.size,a.mtime,a.ctime])!=
  sprintf('%J',[b?.dev,b?.inode,b?.mode,b?.size,b?.mtime,b?.ctime]))fail();return raw;
};
function file_raw(kind) {
 if(kind=='config')return config_raw();
 return store.read(FILES[kind],kind=='state'?262144:8192);
};
function state() {
 let value=private_json(STATE,262144);if(value==null)fail();
 try { return state_model.validate_state(value); } catch (_) { fail(); }
};
function phones() { return mobile.journal(private_json('/etc/foxhole/mobile.json',65536)); };
function policy() { return policy_model.policy(private_json(POLICY,8192)); };
function stop_intent() {
 let value=private_json('/etc/foxhole/engine-intent.json',4096)||{schema:1,revision:0};
 if(value.schema!=1||type(value.revision)!='int'||value.revision<0||value.revision>=0x7fffffff)fail();
 return value.revision;
};
function lock(path,fn) {
 store.target(path);let handle=fs.open(path,'a+',0o600);
 if(!handle||!handle.lock('xn')||!store.file_metadata(fs.lstat(path))) {
  if(handle)handle.close();fail('backup_busy');
 }
 try { let value=fn();handle.lock('u');handle.close();return value; }
 catch(error) { try {handle.lock('u');handle.close();}catch(_){}die(error); }
};
function state_locked(fn) { return lock('/etc/foxhole/state.lock',fn); };
function engine_locked(fn) { return lock('/etc/foxhole/engine.lock',fn); };
function authorized(context) {
 if(type(context?.authorize)!='function'||context.authorize()!=true||
  !match(context.owner||'',/^[a-f0-9]{64}$/))fail('unauthorized');
};
function principal(context) {
 let value=context.principal;
 if(type(value)!='object'||length(keys(value))!=3||!match(value.verifier||'',/^[a-f0-9]{64}$/)||
  context.owner!=digest.sha256(sprintf('%J',value)))fail('unauthorized');
 if(value.kind=='pair') {
  if(!match(value.id||'',/^pair-[a-f0-9]{32}$/))fail('unauthorized');
 } else if(value.kind!='admin'||type(value.user)!='string'||!length(value.user)||length(value.user)>128||
  match(value.user,/[[:cntrl:]]/))fail('unauthorized');
 return value;
};
function panel() {
 let cursor=uci.cursor(),result={};
 try {
  let changes=cursor.changes('foxhole');
  if(changes==null||length(keys(changes)))fail('backup_busy');
  if(cursor.get('foxhole','panel')!='foxhole')fail();
  for(let key in backup.panel_options) {
   let value=cursor.get('foxhole','panel',key);
   result[key]=index(['lan_devices','mobile_devices'],key)>=0&&value!=null&&type(value)!='array'?[value]:value;
  }
  cursor.unload('foxhole');return backup.panel(result);
 } catch(error) { try {cursor.unload('foxhole');}catch(_){}die(error); }
};
function identity_parent(path) {
 for(let parent=fs.dirname(path);parent!='/etc';parent=fs.dirname(parent)) {
  let s=fs.lstat(parent);if(s==null)return false;
  if(s.type!='directory'||s.uid!=0||(s.mode&0o7777)!=0o700)fail();
 }
 return true;
};
function security() {
 let result={};
 for(let path in ['/etc/foxhole/auth.json','/etc/foxhole/pairing.json','/etc/foxhole/mobile.json'])
  result[path]=sha(store.read(path,path=='/etc/foxhole/mobile.json'?65536:32768));
 // Identity files are never journaled or restored, only their stable metadata.
 for(let path in ['/etc/foxhole/mobile.crt','/etc/foxhole/mobile.key',
  '/etc/foxhole/mobile-identity/cert.pem','/etc/foxhole/mobile-identity/key.pem',
  '/etc/foxhole/remote-identity/cert.pem','/etc/foxhole/remote-identity/key.pem']) {
  if(!identity_parent(path)){result[path]=null;continue;}
  let s=fs.lstat(path);
  if(s==null){result[path]=null;continue;}
  if(s.type!='file'||s.uid!=0||(s.mode&0o022)||s.size<1||s.size>16384||
   s.nlink!=1&&!(match(path,/\.crt$|\/cert\.pem$/)&&s.nlink==2))fail();
  if(match(path,/\.key$|\/key\.pem$/)&&(s.mode&0o7777)!=0o600)fail();
  if(s.nlink==2) {
   let other=path=='/etc/foxhole/mobile.crt'?'/etc/foxhole/mobile-identity/cert.pem':
    path=='/etc/foxhole/mobile-identity/cert.pem'?'/etc/foxhole/mobile.crt':null;
   if(other==null||!identity_parent(other))fail();let alias=fs.lstat(other);
   if(alias?.type!='file'||alias.nlink!=2||s.inode!=alias.inode||sprintf('%J',s.dev)!=sprintf('%J',alias.dev))fail();
  }
  let raw=fs.readfile(path,16385),after=fs.lstat(path);
  if(raw==null||length(raw)!=s.size||sprintf('%J',[s.dev,s.inode,s.mode,s.nlink,s.size,s.mtime,s.ctime])!=
   sprintf('%J',[after?.dev,after?.inode,after?.mode,after?.nlink,after?.size,after?.mtime,after?.ctime]))fail();
  result[path]={sha256:sha(raw),mode:s.mode,nlink:s.nlink};
 }
 return result;
};
function read_journal() {
 let value=private_json(JOURNAL,16384);if(value==null)return null;
 if(value.schema!=1||!match(value.id||'',/^restore-[a-f0-9]{32}$/)||!match(value.owner||'',/^[a-f0-9]{64}$/)||
  index(['PREPARED','APPLYING','STATE_COMMITTING',...TERMINAL,'RECOVERY_REQUIRED'],value.phase)<0||
  type(value.files)!='object'||length(keys(value.files))!=3||type(value.security)!='object'||
  type(value.stopIntentBefore)!='int'||value.stopIntentBefore<0||value.stopIntentBefore>=0x7fffffff||
  type(value.beforeRevision)!='int'||value.beforeRevision<0||value.beforeRevision>=0x7ffffffe||
  value.afterRevision!=value.beforeRevision+1||!match(value.beforeWithoutStop||'',/^[a-f0-9]{64}$/)||
  !match(value.afterWithoutStop||'',/^[a-f0-9]{64}$/))fail();
 try {principal({owner:value.owner,principal:value.principal});}catch(_){fail();}
 for(let kind in ['state','config','policy']) {
  let row=value.files[kind];
  if(type(row)!='object'||length(keys(row))!=2||!match(row.after||'',/^[a-f0-9]{64}$/)||
   kind!='policy'&&row.before==null||
   row.before!=null&&!match(row.before,/^[a-f0-9]{64}$/))fail();
 }
 return value;
};
function publish(value) {
 store.write(JOURNAL,sprintf('%J',value));sync_files();
};
function pending() {
 let value=read_journal();return value!=null&&index(TERMINAL,value.phase)<0;
};
function package_jobs_idle() {
 for(let path in ['/etc/foxhole/engine-job.json','/etc/foxhole/update-job.json']) {
  let value=private_json(path,524288);
  if(value!=null&&index(['SUCCEEDED','FAILED'],value.state)<0)fail('backup_busy');
 }
};
function public_job(value) {
 if(value==null)return {schema:1,jobId:null,state:'IDLE'};
 return {schema:1,jobId:value.id,state:value.phase,revision:value.afterRevision,
  reconnectRequired:true,confirmationRequired:false};
};
function journal_raw(value,kind,which) {
 let expected=value.files[kind][which];if(expected==null)return null;
 let raw=store.read(DIRECTORY+'/'+value.id+'/'+which+'-'+kind,kind=='state'?262144:kind=='config'?65536:8192);
 if(raw==null||sha(raw)!=expected)fail();return raw;
};
function replace_file(kind,raw) {
 let path=FILES[kind];
 if(kind!='config') {
  if(raw==null){store.target(path);if(fs.lstat(path)&&!fs.unlink(path))fail();}
  else store.write(path,raw);
 } else {
  if(raw==null)fail();config_raw();let mode=fs.lstat(CONFIG).mode&0o7777;
  let random=fs.readfile('/dev/urandom',12);if(length(random||'')!=12)fail();
  let temporary=CONFIG+'.backup-'+hexenc(random),file=fs.open(temporary,'wxe',0o600);
  if(!file)fail();
  let ok=false;
  try {
   if(file.write(raw)!=length(raw)||!file.flush())fail();file.close();file=null;
   if(!fs.chmod(temporary,mode)||!fs.rename(temporary,CONFIG))fail();ok=true;
  } catch(error) {if(file)file.close();try {fs.unlink(temporary);}catch(_){}die(error);}
  if(!ok)fail();
 }
 sync_files();if(sha(file_raw(kind))!=sha(raw))fail();
};
function rollback_product_files(value) {
 for(let kind in ['config','policy']) {
  let current=sha(file_raw(kind)),row=value.files[kind];
  if(current==row.before)continue;
  if(current!=row.after)fail();replace_file(kind,journal_raw(value,kind,'before'));
 }
};
function products_after(value) {
 for(let kind in ['config','policy'])if(sha(file_raw(kind))!=value.files[kind].after)return false;
 return true;
};
function committed_files(value) {
 if(!products_after(value))fail();
};
function recover_locked() {
 let value=read_journal();if(value==null||index(TERMINAL,value.phase)>=0)return value;
 if(value.phase=='RECOVERY_REQUIRED')fail();
 try {
  let live=state(),raw_hash=sha(file_raw('state'));
  if(index(['PREPARED','APPLYING'],value.phase)>=0) {
   // The durable commit-attempt marker precedes any state replacement.
   // Preserve independent Stop/revocation changes and undo only our files.
   rollback_product_files(value);value.phase='CANCELLED';
  } else if(raw_hash==value.files.state.after||live.activeServerId==null&&
   live.revision>value.afterRevision&&backup.without_stop(live)==value.afterWithoutStop&&products_after(value)) {
   committed_files(value);value.phase='COMMITTED';
  } else if(raw_hash==value.files.state.before||live.revision>value.beforeRevision&&live.activeServerId==null&&
   backup.without_stop(live)==value.beforeWithoutStop) {
   rollback_product_files(value);value.phase='CANCELLED';
  } else fail();
  publish(value);return value;
 } catch (_) {value.phase='RECOVERY_REQUIRED';publish(value);fail();}
};
function stage_panel(directory,before,settings) {
 store.directory(directory+'/config');store.directory(directory+'/delta');
 store.write(directory+'/config/foxhole',before);
 let cursor=uci.cursor(directory+'/config',directory+'/delta');
 try {
  if(cursor.get('foxhole','panel')!='foxhole')fail();
  for(let key in backup.panel_options) {
   let value=settings[key];
   if(value==null)cursor.delete('foxhole','panel',key);
   else if(!cursor.set('foxhole','panel',key,value))fail();
  }
  if(!cursor.commit('foxhole'))fail();cursor.unload('foxhole');
 } catch(error) {try {cursor.unload('foxhole');}catch(_){}die(error);}
 // UCI may choose public config permissions even inside the private journal.
 let path=directory+'/config/foxhole',s=fs.lstat(path);
 if(s?.type!='file'||s.uid!=0||s.nlink!=1||(s.mode&0o022)||s.size<1||s.size>65536)fail();
 if(!fs.chmod(path,0o600))fail();return store.read(path,65536);
};
function prune_terminal(value) {
 if(value==null)return;
 if(index(TERMINAL,value.phase)<0)fail('backup_busy');
 let directory=DIRECTORY+'/'+value.id,paths=[];
 for(let kind in ['state','config','policy'])for(let which in ['before','after']) {
  let path=directory+'/'+which+'-'+kind;
  if(value.files[kind][which]==null) {if(fs.lstat(path))fail();continue;}
  journal_raw(value,kind,which);push(paths,path);
 }
 let config=directory+'/config/foxhole';
 if(sha(store.read(config,65536))!=value.files.config.after)fail();push(paths,config);
 let allowed=[...paths,directory+'/config',directory+'/delta'];
 for(let parent in [directory,directory+'/config',directory+'/delta']) {
  store.directory(parent);
  for(let path in [...(fs.glob(parent+'/*')||[]),...(fs.glob(parent+'/.*')||[])]) {
   if(match(path,/\/\.\.?$/))continue;
   if(index(allowed,path)<0)fail();
  }
 }
 for(let path in paths)if(!fs.unlink(path))fail();
 if(!fs.rmdir(directory+'/config')||!fs.rmdir(directory+'/delta')||!fs.rmdir(directory))fail();
};
function prepare_job(document,expected,id,context) {
 authorized(context);if(pending())fail('backup_busy');
 package_jobs_idle();
 if(type(expected)!='int'||expected<0||expected>=0x7ffffffe)fail('revision_conflict');
 let live=state();if(live.revision!=expected)fail('revision_conflict');
 let candidate=backup.candidate(document,live,phones()),before={state:file_raw('state'),config:config_raw(),policy:file_raw('policy')};
 panel();let current_policy=policy();
 let next_policy={...current_policy,enabled:candidate.autoUpdate.enabled,revision:current_policy.revision+1};
 if(next_policy.revision>=0x7fffffff)fail();
 store.directory(DIRECTORY);
 let previous=read_journal();
 if(previous!=null) {
  if(!fs.unlink(JOURNAL))fail();sync_files();prune_terminal(previous);
 }
 let space=fs.statvfs(DIRECTORY),required=length(before.state)+2*length(sprintf('%J',candidate.state))+
  4*length(before.config)+65536+32768+262144;
 if(space==null||space.frsize*space.bavail<required)fail('backup_no_space');
 let directory=DIRECTORY+'/'+id;
 if(fs.lstat(directory))fail('backup_busy');store.directory(directory);
 let after={state:sprintf('%J',candidate.state),config:stage_panel(directory,before.config,candidate.panel),policy:sprintf('%J',next_policy)};
 let value={schema:1,id,owner:context.owner,principal:principal(context),phase:'PREPARED',files:{},security:security(),stopIntentBefore:stop_intent(),
  beforeRevision:live.revision,afterRevision:candidate.state.revision,
  beforeWithoutStop:backup.without_stop(live),afterWithoutStop:backup.without_stop(candidate.state)};
 for(let kind in ['state','config','policy']) {
  value.files[kind]={before:sha(before[kind]),after:sha(after[kind])};
  if(before[kind]!=null)store.write(directory+'/before-'+kind,before[kind]);
  store.write(directory+'/after-'+kind,after[kind]);
 }
 if(sha(file_raw('state'))!=value.files.state.before||sha(config_raw())!=value.files.config.before||
  sha(file_raw('policy'))!=value.files.policy.before)fail('revision_conflict');
 publish(value);return value;
};

export function guard() {
 let value=read_journal();if(value?.phase=='RECOVERY_REQUIRED')fail();
 if(value!=null&&index(TERMINAL,value.phase)<0)fail('backup_busy');
};
export function stopped() { return state().activeServerId==null; };
export function revocation_revision_allowed(expected,current) {
 if(type(expected)!='int'||expected<0)return false;
 let value=read_journal();
 return value!=null&&index(['STATE_COMMITTING','COMMITTED'],value.phase)>=0&&
  expected==value.beforeRevision&&current.revision==value.afterRevision&&
  sha(file_raw('state'))==value.files.state.after;
};
export function recover() {
 let value=read_journal();
 if(value==null||index(TERMINAL,value.phase)>=0)return public_job(value);
 return engine_locked(()=>state_locked(()=>public_job(recover_locked())));
};
export function status(context) {
 return state_locked(()=>{authorized(context);let value=read_journal();
  if(value!=null&&value.owner!=context.owner)return {schema:1,jobId:null,state:index(TERMINAL,value.phase)>=0?'IDLE':'BUSY'};
  return public_job(value);});
};
export function export_backup(context) {
 return state_locked(()=>{authorized(context);guard();let raw_before=config_raw(),settings=panel(),current=state();
  if(sha(raw_before)!=sha(config_raw()))fail('backup_busy');
  return backup.export_document(current,settings,policy().enabled,time()*1000);});
};
export function validate_backup(document,expected,context) {
 return state_locked(()=>{authorized(context);guard();let live=state();
  if(type(expected)!='int'||live.revision!=expected)fail('revision_conflict');
  backup.candidate(document,live,phones());let result=backup.summary(document);result.revision=live.revision;return result;});
};
export function restore_backup(document,expected,confirmed,id,context) {
 if(type(confirmed)!='bool'||confirmed!=true||type(id)!='string'||!match(id,/^restore-[a-f0-9]{32}$/))fail('backup_invalid');
 if(type(context?.quiesce)!='function'||type(context?.resume)!='function')fail();
 return engine_locked(()=>{
  let value=state_locked(()=>{
   authorized(context);let previous=read_journal();
   if(previous?.id==id){if(previous.owner!=context.owner)fail('unauthorized');return previous;}
   return prepare_job(document,expected,id,context);
  });
  if(index(TERMINAL,value.phase)>=0)return public_job(value);
  if(value.phase=='RECOVERY_REQUIRED')fail();
  try {
   if(context.quiesce()!=true)fail('backup_busy');
   state_locked(()=>{
    authorized(context);if(stop_intent()!=value.stopIntentBefore||!same(security(),value.security)||sha(file_raw('state'))!=value.files.state.before||
     sha(config_raw())!=value.files.config.before||sha(file_raw('policy'))!=value.files.policy.before)fail('revision_conflict');
    value.phase='APPLYING';publish(value);
   });
   replace_file('config',journal_raw(value,'config','after'));
   replace_file('policy',journal_raw(value,'policy','after'));
   state_locked(()=>{
    authorized(context);if(stop_intent()!=value.stopIntentBefore||!same(security(),value.security)||sha(file_raw('state'))!=value.files.state.before)fail('revision_conflict');
    committed_files(value);value.phase='STATE_COMMITTING';publish(value);
    replace_file('state',journal_raw(value,'state','after'));
    value.phase='COMMITTED';publish(value);
   });
  } catch(error) {
   try {state_locked(()=>{value=recover_locked();});}catch(_){fail();}
   context.resume(state());die(error);
  }
  let resumed=context.resume(state());let result=public_job(value);result.runtimeResumed=resumed==true;return result;
 });
};
export function queue_backup(document,expected,confirmed,id,context) {
 if(type(confirmed)!='bool'||confirmed!=true||type(id)!='string'||!match(id,/^restore-[a-f0-9]{32}$/))fail('backup_invalid');
 return engine_locked(()=>state_locked(()=>{
  authorized(context);let previous=read_journal();
  if(previous?.id==id){if(previous.owner!=context.owner)fail('unauthorized');return public_job(previous);}
  return public_job(prepare_job(document,expected,id,context));
 }));
};
export function worker_context(id) {
 if(fs.stat('/proc/self')?.uid!=0||!match(id||'',/^restore-[a-f0-9]{32}$/))fail('unauthorized');
 let value=read_journal();if(value?.id!=id)fail();
 let context={owner:value.owner,principal:value.principal};principal(context);return context;
};
export function run_backup(id,context) {
 try { return restore_backup(null,null,true,id,context); }
 catch(error) {
  // An expired principal can fail before the worker's mutation block.
  // Cancel only this job, never a newer owner's pending restoration.
  try { if(read_journal()?.id==id)recover(); }catch(_){}
  die(error);
 }
};
