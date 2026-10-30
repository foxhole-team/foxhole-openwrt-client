#!/usr/bin/env python3
"""Run the complete engine-service module in native ucode with closed in-memory I/O."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
MODULE='package/foxhole-openwrt-client/root/usr/share/foxhole/engine-service.uc'
MOCKS={
'fixture-state.uc':'''export const memory={files:{},commands:[],lockCalls:0,badLock:false,workerCurrent:false,lockSnapshot:null,writeCalls:0,snapshotUnavailable:false,snapshotCalls:0,workerBoot:null};
export function reset(){memory.files={};memory.commands=[];memory.lockCalls=0;memory.badLock=false;memory.workerCurrent=false;memory.lockSnapshot=null;memory.writeCalls=0;memory.snapshotUnavailable=false;memory.snapshotCalls=0;memory.workerBoot=null;};
''',
'fixture-fs.uc':'''import { memory } from './fixture-state.uc';
export function readfile(path,limit){
 if(path=='/dev/urandom')return '01234567890123456789012345678901';
 if(path=='/proc/uptime')return '123.0 0.0';
 if(path=='/proc/sys/kernel/random/boot_id')return 'fixture-boot';
 die('fixture_refused_real_filesystem_read');
};
export function lstat(path){
 if(path=='/etc/foxhole/engine.lock'||path=='/etc/foxhole/state.lock')
  return {type:'file',uid:memory.badLock?1:0,gid:0,mode:0o600,nlink:1,inode:17};
 return null;
};
export function open(path,mode,permissions){
 if(path!='/etc/foxhole/engine.lock'||mode!='a+'||permissions!=0o600)die('fixture_refused_real_file_open');
 return {lock:value=>{memory.lockCalls++;if(value=='xn'&&memory.lockSnapshot!=null){memory.files['/etc/foxhole/engine-job.json']=memory.lockSnapshot;memory.lockSnapshot=null;}return true;},close:()=>true};
};
export function stat(path){return null;};
export function unlink(path){die('fixture_refused_real_unlink');};
''',
'fixture-digest.uc':'''export function sha256(value){return index(value,'different-fixture-principal')>=0?'2222222222222222222222222222222222222222222222222222222222222222':'1111111111111111111111111111111111111111111111111111111111111111';};
''',
'fixture-system.uc':'''import { memory } from './fixture-state.uc';
export function system(argv,timeout){
 if(length(argv)!=3||argv[0]!='/bin/sh'||argv[1]!='-c'||
    index(argv[2],'/usr/libexec/foxhole-engine-job engine-job-')<0||timeout!=1000)
  die('fixture_refused_process_action');
 push(memory.commands,{argc:length(argv),timeout});return 0;
};
''',
'model.uc':'''export function defaults(){return {schema:1,servers:[],activeServerId:null};};
export function validate_state(value){return value;};
''',
'engine-model.uc':'''import { memory } from './fixture-state.uc';
export function status(catalog,installed,context){return {entries:[],revision:installed.revision};};
export function plan(request,catalog,installed,context,owner,nonce,stamp){
 return {schema:1,planId:'fixture-plan',owner,impact:'NONE',createdAtUptimeMs:stamp};
};
export function public_plan(value){return {planId:value.planId};};
export function admit_apply(value,request,current,context,owner,stamp){
 if(value.planId!=request.planId||value.owner!=owner)die('engine_stale_plan');
 return true;
};
export function worker_current(worker,snapshot,bootId){memory.workerBoot=bootId;return memory.workerCurrent&&(worker?.bootId==null||worker.bootId==bootId);};
export function package_layout(a,b,c,d){die('fixture_refused_unexpected_engine_operation');};
export function world_pins(a,b,c,d){die('fixture_refused_unexpected_engine_operation');};
export function restart_allowed(a,b,c,d){die('fixture_refused_unexpected_engine_operation');};
export function commit(a,b,c,d){die('fixture_refused_unexpected_engine_operation');};
export function selected(a,b,c,d){die('fixture_refused_unexpected_engine_operation');};
export function slot_id(a,b,c,d){die('fixture_refused_unexpected_engine_operation');};
export function add_only_delta(a,b,c,d){die('fixture_refused_unexpected_engine_operation');};
export function purge_only(a,b,c,d){die('fixture_refused_unexpected_engine_operation');};
''',
'core-model.uc':'''export function proof_valid(proof,server,owner,stamp,boot,minimum){return false;};
''',
'core-adapter.uc':'''export const proof_path='/fixture/unused-proof';
export const config_path='/fixture/unused-config';
export const policy_path='/fixture/unused-policy';
export function receipt(a,b,c,d){die('fixture_refused_unexpected_adapter_operation');};
export function generation(a,b,c,d){die('fixture_refused_unexpected_adapter_operation');};
export function policy_identity(a,b,c,d){die('fixture_refused_unexpected_adapter_operation');};
export function kernel_policy(a,b,c,d){die('fixture_refused_unexpected_adapter_operation');};
''',
'engine-registry.uc':'''import { memory } from './fixture-state.uc';
export function catalog(){return {value:{}};};
export function read(){return {schema:1,revision:7,slots:[],selected:[]};};
export function snapshot_context(value){memory.snapshotCalls++;if(memory.snapshotUnavailable)die('engine_package_verification_failed');return {routerId:'fixture-router',bootId:'fixture-boot'};};
export function legacy_protocols(){return [];};
export function hash_file(a,b,c,d){die('fixture_refused_unexpected_registry_operation');};
export function capture(a,b,c,d){die('fixture_refused_unexpected_registry_operation');};
export function verify_slot(a,b,c,d){die('fixture_refused_unexpected_registry_operation');};
export function executable(a,b,c,d){die('fixture_refused_unexpected_registry_operation');};
export function write(a,b,c,d){die('fixture_refused_unexpected_registry_operation');};
''',
'pairing.uc':'''export function defaults(){return {schema:1};};
export function session_current(pairs,current){return false;};
''',
'private-store.uc':'''import { memory } from './fixture-state.uc';
function allowed(path){return index(['/etc/foxhole/state.json','/etc/foxhole/engine-job.json',
 '/etc/foxhole/engine-intent.json','/etc/foxhole/update-job.json','/etc/foxhole/auth.json','/etc/foxhole/pairing.json'],path)>=0||
 substr(path,0,25)=='/tmp/foxhole/engine-plan-';};
export function read(path,limit){
 if(!allowed(path))die('fixture_refused_real_store_read');
 return memory.files[path]??null;
};
export function write(path,raw){if(!allowed(path))die('fixture_refused_real_store_write');memory.writeCalls++;memory.files[path]=raw;};
export function target(path){if(path!='/etc/foxhole/engine.lock')die('fixture_refused_real_store_target');};
export function directory(path){die('fixture_refused_real_directory');};
export function file_metadata(info){return info?.type=='file'&&info.uid==0&&info.nlink==1&&!(info.mode&0o077)&&info.inode>0;};
'''
}
MAIN='''\
'use strict';
import * as service from './engine-service.uc';
import { memory,reset } from './fixture-state.uc';
import * as digest from './fixture-digest.uc';
const PRINCIPAL={kind:'admin',verifier:'synthetic-verifier'};
const CASE_SCOPE='__FIXTURE_CASE_SCOPE__';
let passed=0,failed=0;
function equal(actual,expected){if(sprintf('%J',actual)!=sprintf('%J',expected))die('fixture_result_mismatch');};
function error_code(error){return type(error)=='string'?error:error?.message;};
function own_job(phase){return {schema:1,routerId:'fixture-router',jobId:'fixture-job',planId:'fixture-plan',
 owner:digest.sha256(sprintf('%J',PRINCIPAL)),state:phase,progressPercent:100,step:'COMPLETED',revision:7,
 failureReason:null,previousConnectionRestored:null,plan:{impact:'NONE'}};};
function save_job(value){memory.files['/etc/foxhole/engine-job.json']=sprintf('%J',value);};
function refused(fn,wanted){let caught=null;try{fn();}catch(error){caught=error_code(error);}equal(caught,wanted);};
function test(name,fn){if(CASE_SCOPE=='terminal-reconcile'&&index(name,'terminal-reconcile:')!=0)return;reset();try{fn();passed++;print('ok ',name,'\\n');}
 catch(error){failed++;print('not ok ',name,': ',error_code(error),'\\n');}};
test('actual status reaches ordered reconcile with no job',()=>{
 let value=service.status(PRINCIPAL);equal(value.busy,false);equal(value.lastOwnJob,null);equal(length(value.entries),0);
});
test('actual plan keeps snapshot and stored-plan behavior',()=>{
 let value=service.plan({},PRINCIPAL);equal(value.planId,'fixture-plan');
 equal(length(keys(memory.files)),1);
});
test('actual job reaches ordered reconcile for its original owner',()=>{
 save_job(own_job('SUCCEEDED'));let value=service.job('fixture-job',PRINCIPAL);equal(value.state,'SUCCEEDED');
});
test('actual apply reaches already-declared job after queue and launch delegation',()=>{
 let plan=service.plan({},PRINCIPAL);let value=service.apply({planId:plan.planId},PRINCIPAL);
 equal(value.state,'QUEUED');equal(substr(value.jobId,0,11),'engine-job-');equal(length(memory.commands),1);
});
test('job wrong owner remains refused',()=>{
 save_job(own_job('SUCCEEDED'));
 refused(()=>service.job('fixture-job',{kind:'admin',verifier:'different-fixture-principal'}),'engine_authentication_failed');
});
test('plan still refuses recovery-required state',()=>{
 save_job(own_job('RECOVERY_REQUIRED'));refused(()=>service.plan({},PRINCIPAL),'engine_recovery_required');
});
test('apply still refuses a missing stored plan',()=>{
 refused(()=>service.apply({planId:'missing'},PRINCIPAL),'engine_stale_plan');
});
test('guard mutation still refuses queued work',()=>{
 save_job(own_job('QUEUED'));refused(()=>service.guard_mutation(),'engine_busy');
});
test('stop intent invalid revision remains refused',()=>{
 memory.files['/etc/foxhole/engine-intent.json']=sprintf('%J',{schema:1,revision:-1});
 refused(()=>service.stop_intent(),'engine_recovery_required');
});
test('stop intent still advances a valid revision',()=>{
 memory.files['/etc/foxhole/engine-intent.json']=sprintf('%J',{schema:1,revision:2});service.stop_intent();
 equal(json(memory.files['/etc/foxhole/engine-intent.json']).revision,3);
});
test('apply still rejects lock metadata with another owner',()=>{
 service.plan({},PRINCIPAL);memory.badLock=true;
 refused(()=>service.apply({planId:'fixture-plan'},PRINCIPAL),'engine_busy');
});
test('STOP deferral requires a live worker validation and an active atomic APK phase',()=>{
 memory.files['/etc/foxhole/update-job.json']=sprintf('%J',{state:'INSTALLING',operation:'APPLY',atomicPackagePhase:true,worker:{}});
 equal(service.defer_stop_for_update(),false);memory.workerCurrent=true;equal(service.defer_stop_for_update(),true);
});
test('dead or recovery-required update never suppresses native STOP',()=>{
 memory.workerCurrent=true;
 memory.files['/etc/foxhole/update-job.json']=sprintf('%J',{state:'RECOVERY_REQUIRED',operation:'APPLY',atomicPackagePhase:true,worker:{}});
 equal(service.defer_stop_for_update(),false);
});
test('post-APK checking phase does not defer native STOP',()=>{
 memory.workerCurrent=true;
 memory.files['/etc/foxhole/update-job.json']=sprintf('%J',{state:'CHECKING',operation:'APPLY',atomicPackagePhase:false,worker:{}});
 equal(service.defer_stop_for_update(),false);
});

function racing_job(phase){let job=own_job(phase);job.jobId='engine-job-00000000000000000000000000000000';job.bootId='fixture-boot';job.step=phase=='FAILED'?'FAILED':(phase=='SUCCEEDED'?'COMPLETED':'DOWNLOADING_PACKAGE');job.progressPercent=phase=='DOWNLOADING'?10:100;job.failureReason=phase=='FAILED'?'PACKAGE_VERIFICATION_FAILED':null;job.recoveryRequestedAt=null;return job;};
for(let terminal in ['FAILED','SUCCEEDED'])test('terminal-reconcile: locked '+terminal+' remains exact without write or recovery',()=>{
 let stale=racing_job('DOWNLOADING'),finished=racing_job(terminal),finished_raw=sprintf('%J',finished);
 save_job(stale);memory.lockSnapshot=finished_raw;
 let value=service.job(stale.jobId,PRINCIPAL);
 equal(value.state,terminal);equal(memory.files['/etc/foxhole/engine-job.json'],finished_raw);
 equal(memory.writeCalls,0);equal(length(memory.commands),0);equal(memory.lockCalls,2);
});
test('terminal-reconcile: dead nonterminal still enters owned recovery',()=>{
 let job=racing_job('DOWNLOADING');save_job(job);
 let value=service.job(job.jobId,PRINCIPAL),stored=json(memory.files['/etc/foxhole/engine-job.json']);
 equal(value.state,'RECOVERY_REQUIRED');equal(stored.failureReason,'ROUTER_UNAVAILABLE');
 equal(stored.recoveryRequestedAt,123000);equal(memory.writeCalls,1);equal(length(memory.commands),1);
});


for(let phase in ['SUCCEEDED','FAILED'])test('job-context: terminal '+phase+' survives unavailable snapshots',()=>{
 let job=racing_job(phase),raw=sprintf('%J',job);save_job(job);memory.snapshotUnavailable=true;
 equal(service.job(job.jobId,PRINCIPAL).state,phase);
 equal(memory.files['/etc/foxhole/engine-job.json'],raw);equal(memory.snapshotCalls,0);
 equal(memory.writeCalls,0);equal(length(memory.commands),0);
});
test('job-context: live worker keeps boot context without a snapshot',()=>{
 let job=racing_job('DOWNLOADING');job.worker={bootId:'fixture-boot'};save_job(job);
 memory.workerCurrent=true;memory.snapshotUnavailable=true;
 equal(service.job(job.jobId,PRINCIPAL).state,'DOWNLOADING');
 equal(memory.workerBoot,'fixture-boot');equal(memory.snapshotCalls,0);equal(memory.writeCalls,0);
});
test('job-context: dead worker still enters owned recovery',()=>{
 let job=racing_job('DOWNLOADING');save_job(job);memory.snapshotUnavailable=true;
 equal(service.job(job.jobId,PRINCIPAL).state,'RECOVERY_REQUIRED');
 equal(memory.snapshotCalls,0);equal(memory.writeCalls,1);equal(length(memory.commands),1);
});
test('job-context: wrong boot still refuses a live worker binding',()=>{
 let job=racing_job('DOWNLOADING');job.worker={bootId:'other-boot'};save_job(job);
 memory.workerCurrent=true;memory.snapshotUnavailable=true;
 equal(service.job(job.jobId,PRINCIPAL).state,'RECOVERY_REQUIRED');
 equal(memory.workerBoot,'fixture-boot');equal(memory.writeCalls,1);equal(length(memory.commands),1);
});
test('job-context: wrong owner remains refused before a snapshot',()=>{
 let job=racing_job('SUCCEEDED');save_job(job);memory.snapshotUnavailable=true;
 refused(()=>service.job(job.jobId,{kind:'admin',verifier:'different-fixture-principal'}),'engine_authentication_failed');
 equal(memory.snapshotCalls,0);equal(memory.writeCalls,0);equal(memory.lockCalls,0);
});
test('job-context: status retains full snapshot admission',()=>{
 memory.snapshotUnavailable=true;refused(()=>service.status(PRINCIPAL),'engine_package_verification_failed');
 equal(memory.snapshotCalls,1);
});
test('job-context: plan retains full snapshot admission',()=>{
 memory.snapshotUnavailable=true;refused(()=>service.plan({},PRINCIPAL),'engine_package_verification_failed');
 equal(memory.snapshotCalls,1);
});
test('job-context: apply retains full snapshot admission',()=>{
 let plan=service.plan({},PRINCIPAL);memory.snapshotUnavailable=true;
 refused(()=>service.apply({planId:plan.planId},PRINCIPAL),'engine_package_verification_failed');
 equal(memory.snapshotCalls,2);equal(length(memory.commands),0);
});

print('Native engine service module cases: ',passed,' passed, ',failed,' failed\\n');
exit(failed?1:0);
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,default=ROOT/MODULE);parser.add_argument('--only-terminal-reconcile',action='store_true');args=parser.parse_args()
    source=args.source.resolve(strict=True);assert source.is_file()and not args.source.is_symlink()and source.stat().st_size<=262144
    raw=source.read_text();module=raw
    for name in('fs','digest'):
        before="import * as "+name+" from '"+name+"';"
        after="import * as "+name+" from './fixture-"+name+".uc';"
        assert module.count(before)==1;module=module.replace(before,after)
    before="'use strict';\n";after=before+"import { system } from './fixture-system.uc';\n"
    assert module.startswith(before);module=module.replace(before,after,1)
    # The module declarations/exports and every function body are untouched. Only
    # external I/O imports point at the closed fixture; no JS translation or body extraction.
    reverse=module.replace(after,before,1)
    for name in('fs','digest'):
        reverse=reverse.replace("import * as "+name+" from './fixture-"+name+".uc';","import * as "+name+" from '"+name+"';")
    assert reverse==raw
    executable=shutil.which('ucode')
    if executable is None:raise SystemExit('Required native ucode unavailable')
    with tempfile.TemporaryDirectory(prefix='foxhole-engine-service-native-')as directory:
        work=Path(directory)
        main_case=MAIN.replace('__FIXTURE_CASE_SCOPE__','terminal-reconcile'if args.only_terminal_reconcile else'all')
        for name,text in {**MOCKS,'engine-service.uc':module,'main.uc':main_case}.items():(work/name).write_text(text)
        result=subprocess.run([executable,str(work/'main.uc')],cwd=work,capture_output=True,text=True,timeout=15)
        assert len(result.stdout.encode())+len(result.stderr.encode())<=1024**2
        sys.stdout.write(result.stdout);sys.stderr.write(result.stderr)
        return result.returncode


if __name__=='__main__':raise SystemExit(main())
