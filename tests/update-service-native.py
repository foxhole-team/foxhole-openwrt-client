#!/usr/bin/env python3
"""Run the actual update service with synthetic storage and process adapters."""
from pathlib import Path
import subprocess
import hashlib,json,os,tempfile

ROOT = Path(__file__).resolve().parent.parent
SERVICE = ROOT / 'package/foxhole-openwrt-client/root/usr/share/foxhole/update-service.uc'
MODEL = ROOT / 'package/foxhole-openwrt-client/root/usr/share/foxhole/update-model.uc'
NATIVE = ROOT / 'package/foxhole-openwrt-client/root/usr/share/foxhole/update-native.uc'
FIXTURE = r'''
import * as digest from 'digest';
import * as model from 'MODEL_PATH';
let memory, permitted, milliseconds, calls, serial, fixture_state, ctx_stop, held_state_lock, marker_held, fixture_registry, fixture_base_arch;
const H='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const principal={kind:'pair',id:'synthetic-pair',verifier:H};
function copy(value){return json(sprintf('%J',value));};
function reset(){memory={};fixture_base_arch='noarch';permitted=true;milliseconds=1000;calls=[];serial=0;ctx_stop=0;held_state_lock=false;marker_held=false;fixture_registry={schema:1,revision:0,slots:[],selected:[]};fixture_state={revision:5,activeServerId:null,servers:[{id:'server-a',config:'synthetic-profile'}]};};
let fs={
 readfile:(path,limit)=>{if(path!='/dev/urandom')die('unexpected_read');serial++;return sprintf('%016d',serial);},
 glob:path=>[],lstat:path=>path=='/etc/foxhole/state.lock'?{type:'file',uid:0,mode:0o600,nlink:1}:null,unlink:path=>die('unexpected_delete'),
 open:(path,mode,perm)=>{if(path!='/etc/foxhole/state.lock')die('unexpected_open');return{lock:kind=>{held_state_lock=kind!='u';return true;},close:()=>true};}
};
let store={read:(path,limit)=>memory[path]||null,write:(path,raw)=>{if(path=='/etc/foxhole/update-job.json'&&json(raw).mutationStarted)marker_held=held_state_lock;memory[path]=raw;},file_metadata:info=>info?.uid==0,directory:path=>{},target:path=>{}};
let engine={locked:fn=>fn(),now:()=>milliseconds,boot:()=>'synthetic-boot',
 principal_current:value=>permitted&&value?.verifier==H,
 installed:()=>({'foxhole-openwrt-client':{name:'foxhole-openwrt-client',version:'1.0.0-r3',arch:fixture_base_arch}}),
 state:()=>copy(fixture_state),process_snapshot:pid=>null,self_worker:()=>({pid:123,start:'1',commandSha256:H,bootId:'synthetic-boot'})};
for(let name in ['locked','now','boot','principal_current','installed','state','process_snapshot','self_worker'])engine['update_'+name]=engine[name];
let registry={read:()=>copy(fixture_registry),write:value=>{fixture_registry=copy(value);},snapshot_context:value=>({
 routerId:H,bootId:'synthetic-boot',worldSha256:H,catalogSha256:H,activeGeneration:null,
 activeConfigSha256:null,activeProfileId:fixture_state.activeServerId,activeEngineId:null,stopIntent:ctx_stop,
 flashAvailableBytes:1073741824,ramAvailableBytes:1073741824})};
let native={decode:raw=>json(raw),policy:(path,version)=>({}),target:()=>({}),selected_modules:value=>[]};
let engines={worker_current:(worker,process,boot)=>false};
let adapter={};
function system(argv,timeout){push(calls,argv);return 0;};
// ACTUAL_UPDATE_SERVICE
let passed=0,failed=0;
function equal(a,b){if(sprintf('%J',a)!=sprintf('%J',b))die('assertion_failed');};
function rejects(fn,code){let caught=null;try{fn();}catch(e){caught=type(e)=='string'?e:e.message;}equal(caught,'update_'+lc(code));};
function test(name,fn){reset();try{fn();passed++;print('ok ',name,'\n');}catch(e){failed++;print('not ok ',name,': ',type(e)=='string'?e:e.message,'\n');}};
function fixture_available(){
 let ctx=context(),v=current_state();v.revision=2;v.availability='AVAILABLE';v.availableVersion='1.0.1-r1';v.lastCheckedAtUnixMs=wall();
 v.candidate={base:{version:'1.0.1-r1'},rollback:{version:'1.0.0-r3'},fromVersion:'1.0.0-r3',baseChanged:true,
  changes:[{id:'foxhole',fromVersion:'1.0.0-r3',toVersion:'1.0.1-r1',storage:null}],
  artifacts:[],binding:binding(ctx),selected:registry.read(),budget:{downloadBytes:100,stagingBytes:100,
  flashRequiredBytes:100,flashAvailableBytes:1073741824,ramRequiredBytes:100,ramAvailableBytes:1073741824,reservedBytes:32}};
 write(STATE,v);return v;
};
function fixture_plan(){fixture_available();return plan({expectedRevision:2},principal);};
function apply_request(p){return{planId:p.planId,planSha256:p.planSha256,expectedRevision:p.revision,confirmed:true};};
test('new router reports NOT_CHECKED and auto off without any process launch',()=>{
 let v=status(principal);equal(v.availability,'NOT_CHECKED');equal(v.currentVersion,'1.0.0-r3');
 equal(v.autoUpdate.enabled,false);equal(v.activeOwnJob,null);equal(length(calls),0);
});
test('canonical installed BASE noarch is supported and all is refused',()=>{
 equal(current_version(),'1.0.0-r3');equal(status(principal).supported,true);
 fixture_base_arch='all';rejects(()=>current_version(),'UNSUPPORTED_TARGET');
 let visible=status(principal);equal(visible.supported,false);equal(visible.availability,'UNSUPPORTED');
 equal(visible.failureReason,'UNSUPPORTED_TARGET');equal(length(calls),0);
});
test('settings rejects stale revision and persists authoritative explicit opt-in',()=>{
 rejects(()=>settings({expectedRevision:1,autoUpdateEnabled:true},principal),'STALE_SESSION');
 equal(policy().enabled,false);
 let v=settings({expectedRevision:0,autoUpdateEnabled:true},principal);equal(v.autoUpdate.enabled,true);equal(v.revision,1);
 permitted=false;rejects(()=>settings({expectedRevision:1,autoUpdateEnabled:false},principal),'AUTHENTICATION_FAILED');
 equal(policy().enabled,true);
});
test('CHECK quick-ack creates exactly one manual CHECK job without doing discovery in RPC',()=>{
 let v=check({expectedRevision:0},principal);equal(v.operation,'CHECK');equal(v.planId,null);equal(v.automatic,false);
 equal(v.state,'QUEUED');equal(length(calls),1);
 rejects(()=>check({expectedRevision:1},principal),'BUSY');equal(length(calls),1);
});
test('shared engine activity blocks CHECK before launch',()=>{
 write('/etc/foxhole/engine-job.json',{state:'INSTALLING'});
 rejects(()=>check({expectedRevision:0},principal),'BUSY');equal(length(calls),0);
});
test('plan is explicit reconnect and cannot contain private binding or URLs',()=>{
 let value=fixture_plan();equal(value.impact,'RECONNECT_REQUIRED');equal(value.owner,null);equal(value.binding,null);
 equal(value.candidate,null);equal(value.fromVersion,'1.0.0-r3');equal(value.engineIds,[]);
});
test('changed Stop/profile binding invalidates a previously confirmed plan',()=>{
 let value=fixture_plan(),raw=read('/tmp/foxhole/update-plan-'+owner(principal));raw.binding.stopIntent++;
 write('/tmp/foxhole/update-plan-'+owner(principal),raw);
 rejects(()=>apply(apply_request(value),principal),'STALE_PLAN');equal(length(calls),0);
});
test('expired plan and missing confirmation do not launch mutation',()=>{
 let value=fixture_plan();milliseconds=301001;
 rejects(()=>apply(apply_request(value),principal),'STALE_PLAN');milliseconds=1000;
 let request=apply_request(value);request.confirmed=false;rejects(()=>apply(request,principal),'INVALID_REQUEST');
 equal(length(calls),0);
});
test('revoked pending manual principal is distinct from permanent router auto policy',()=>{
 settings({expectedRevision:0,autoUpdateEnabled:true},principal);let value=fixture_plan();permitted=false;
 rejects(()=>apply(apply_request(value),principal),'AUTHENTICATION_FAILED');equal(policy().enabled,true);equal(length(calls),0);
});
test('lost APPLY response is rediscovered by same principal status without replay',()=>{
 let p=fixture_plan(),accepted=apply(apply_request(p),principal),v=status(principal);
 equal(v.activeOwnJob.jobId,accepted.jobId);equal(v.lastOwnJob.jobId,accepted.jobId);equal(length(calls),1);
 equal(job(accepted.jobId,principal).jobId,accepted.jobId);
 let other={...principal,verifier:'another'};equal(status(other).activeOwnJob,null);
 rejects(()=>job(accepted.jobId,other),'AUTHENTICATION_FAILED');equal(length(calls),1);
});
test('status of a dead worker after mutation reports recovery and never spawns a replacement',()=>{
 let p=fixture_plan(),accepted=apply(apply_request(p),principal),saved=read(JOB);saved.mutationStarted=true;write(JOB,saved);
 milliseconds=20000;let value=status(principal);equal(value.lastOwnJob.state,'RECOVERY_REQUIRED');equal(value.busy,true);
 equal(length(calls),1);
});
test('automatic progress is sanitized and cannot be queried as caller-owned work',()=>{
 let value=new_job('CHECK',null,true,null);save_job(value);let visible=status(principal);
 equal(visible.activeOwnJob,null);equal(visible.activeAutomaticJob.automatic,true);equal(visible.activeAutomaticJob.jobId,null);
 rejects(()=>job(value.jobId,principal),'AUTHENTICATION_FAILED');equal(length(calls),0);
});
test('critical marker is persisted under state lock so STOP can fence atomic entry',()=>{
 let p=fixture_plan(),accepted=apply(apply_request(p),principal),saved=read(JOB);
 begin_mutation(saved);equal(saved.mutationStarted,true);equal(marker_held,true);equal(held_state_lock,false);
});
test('STOP before critical entry invalidates the old binding without mutation',()=>{
 let p=fixture_plan(),accepted=apply(apply_request(p),principal),saved=read(JOB);ctx_stop=1;
 rejects(()=>begin_mutation(saved),'STALE_PLAN');equal(saved.mutationStarted,false);equal(marker_held,false);
});
test('STOP-only preservation exception requires normalized profile hash and exact revision',()=>{
 fixture_state.activeServerId='server-a';
 let saved={plan:{binding:{activeProfileId:'server-a',stopIntent:0}},stateRevisionBefore:5,stateWithoutStopSha256:state_without_stop(fixture_state)};
 fixture_state.activeServerId=null;fixture_state.revision=6;ctx_stop=1;equal(stopped_by_request(saved),true);
 fixture_state.servers[0].config='changed-profile';equal(stopped_by_request(saved),false);
 fixture_state.servers[0].config='synthetic-profile';ctx_stop=0;equal(stopped_by_request(saved),false);
 ctx_stop=1;fixture_state.revision=7;equal(stopped_by_request(saved),false);
});
test('automatic CHECK cannot overwrite a newly accepted manual job',()=>{
 settings({expectedRevision:0,autoUpdateEnabled:true},principal);
 let automatic=new_job('CHECK',null,true,null);automatic.state='SUCCEEDED';save_job(automatic);
 equal(auto_conversion_allowed(automatic),true);
 let manual=new_job('CHECK',principal,false,null);save_job(manual);
 equal(auto_conversion_allowed(automatic),false);equal(read(JOB).jobId,manual.jobId);
});
test('active legacy connection blocks a plan with actionable reason before any process launch',()=>{
 fixture_state.activeServerId='server-a';let value=fixture_available();
 value.candidate.binding=binding(context());value.candidate.stateRevisionBefore=fixture_state.revision;
 value.candidate.stateWithoutStopSha256=state_without_stop(fixture_state);write(STATE,value);
 rejects(()=>plan({expectedRevision:2},principal),'LEGACY_CONNECTION_ACTIVE');equal(length(calls),0);
 let visible=status(principal);equal(visible.supported,true);equal(visible.availability,'AVAILABLE');equal(visible.failureReason,'LEGACY_CONNECTION_ACTIVE');
});
test('explicit STOP can prepare a fresh plan from verified cached cohort without replaying old plan',()=>{
 fixture_state.activeServerId='server-a';let value=fixture_available();
 value.candidate.binding=binding(context());value.candidate.stateRevisionBefore=fixture_state.revision;
 value.candidate.stateWithoutStopSha256=state_without_stop(fixture_state);write(STATE,value);
 fixture_state.activeServerId=null;fixture_state.revision++;ctx_stop++;
 let fresh=plan({expectedRevision:2},principal);equal(fresh.impact,'RECONNECT_REQUIRED');equal(length(calls),0);
 equal(status(principal).failureReason,null);
});
test('registry recovery role is exact and does not exempt configuration or history',()=>{
 equal(admitted_private_role('/etc/foxhole/engines.json'),true);
 for(let path in ['/etc/foxhole/state.json','/etc/foxhole/auth.json','/etc/foxhole/pairing.json',
  '/etc/foxhole/history.json.gz','/etc/foxhole/engine-registry-backup.json'])equal(admitted_private_role(path),false);
});
test('restored registry retains exact old slots and selection with monotonic revision',()=>{
 let previous={schema:1,revision:2,slots:[{id:'old-slot'}],selected:[{id:'vless',slotId:'old-slot'}]};
 fixture_registry={schema:1,revision:4,slots:[{id:'new-slot'}],selected:[{id:'vless',slotId:'new-slot'}]};
 let restored=restore_registry(previous);equal(restored.revision,5);equal(restored.slots,previous.slots);
 equal(restored.selected,previous.selected);equal(registry.read(),restored);
});
test('unsupported target keeps status and last-job readable with supported false',()=>{
 let original=native.target;native.target=()=>model.fail('UNSUPPORTED_TARGET');
 let visible=status(principal);native.target=original;
 equal(visible.supported,false);equal(visible.availability,'UNSUPPORTED');equal(visible.failureReason,'UNSUPPORTED_TARGET');
});
test('pre-mutation APPLY failure invalidates candidate while preserving exact owned outcome',()=>{
 let p=fixture_plan(),accepted=apply(apply_request(p),principal),original=registry.snapshot_context;
 registry.snapshot_context=value=>({...original(value),flashAvailableBytes:0});
 let outcome=run(accepted.jobId);registry.snapshot_context=original;
 equal(outcome.state,'FAILED');equal(outcome.failureReason,'NO_SPACE');
 let visible=status(principal);equal(visible.supported,true);equal(visible.availability,'NOT_CHECKED');
 equal(visible.availableVersion,null);equal(visible.failureReason,'NO_SPACE');equal(visible.lastOwnJob.jobId,accepted.jobId);
 equal(visible.lastOwnJob.failureReason,'NO_SPACE');equal(visible.busy,false);
});
test('disabled automatic policy is rejected before CHECK staging or network',()=>{
 let flag=policy();flag.enabled=true;flag.revision=1;write(POLICY,flag);
 let automatic=new_job('CHECK',null,true,null);flag.enabled=false;flag.revision=2;write(POLICY,flag);
 rejects(()=>perform_check(automatic),'STALE_PLAN');equal(length(calls),0);
});
test('cached Stop-only rebind preserves router boot world and catalog identity',()=>{
 for(let field in ['routerId','bootId','worldSha256','catalogSha256']){
  reset();fixture_state.activeServerId='server-a';let value=fixture_available();
  value.candidate.binding=binding(context());value.candidate.stateRevisionBefore=fixture_state.revision;
  value.candidate.stateWithoutStopSha256=state_without_stop(fixture_state);write(STATE,value);
  fixture_state.activeServerId=null;fixture_state.revision++;ctx_stop++;
  let original=registry.snapshot_context;
  registry.snapshot_context=state=>{let value=original(state);value[field]='changed-fixed-identity';return value;};
  rejects(()=>plan({expectedRevision:2},principal),'STALE_PLAN');registry.snapshot_context=original;
 }
});
test('pending hourly history is a single bounded optional writer role',()=>{
 let valid={type:'file',uid:0,gid:0,nlink:1,mode:0o600,size:0},pending='/etc/foxhole/history.json.gz.new';
 equal(history_writer_role(pending,null),'ephemeral-hourly-history-checkpoint');
 equal(history_writer_role(pending,valid),'ephemeral-hourly-history-checkpoint');
 equal(history_writer_role(pending+'.backup',valid),null);
 for(let patch in [{type:'link'},{type:'directory'},{uid:1000},{gid:1000},{nlink:2},{mode:0o644},{size:6291457}])
  rejects(()=>history_writer_role(pending,{...valid,...patch}),'PACKAGE_VERIFICATION_FAILED');
 rejects(()=>history_writer_role('/etc/foxhole/history.json.gz',valid),'PACKAGE_VERIFICATION_FAILED');
 equal(history_writer_role('/etc/foxhole/history.json.gz',{...valid,size:337047}),'bounded-hourly-history-checkpoint');
});
print('Update service cases: ',passed,' passed, ',failed,' failed\n');exit(failed?1:0);
'''




INSTALLED_BASE_FIXTURE = "\nimport * as realfs from 'fs';\nimport * as digest from 'digest';\nconst ROOT=FIXTURE_ROOT,UID=FIXTURE_UID;\nlet fs={lstat:path=>realfs.lstat(ROOT+path)};\nlet engine={update_installed:()=>({'foxhole-openwrt-client':{arch:'noarch',version:'1.0.0-r3'}})};\nlet guard={fail:reason=>die('update_'+lc(reason))};\nlet registry={hash_file:path=>{\n let p=ROOT+path,s=realfs.lstat(p);\n if(s?.type!='file'||s.uid!=UID||s.nlink!=1||(s.mode&0o022))die('engine_package_verification_failed');\n let raw=realfs.readfile(p,1048576);if(raw==null||length(raw)!=s.size)die('engine_package_verification_failed');\n return digest.sha256(raw);\n}};\n// ACTUAL_INSTALLED_BASE\nlet value=FIXTURE_PAYLOAD,passed=0,failed=0;\nconst SETUP='/etc/uci-defaults/99-foxhole-openwrt-client';\nconst POLICY='/usr/share/foxhole/update-policy.json';\nfunction check(label,fn,reason){let error=null,result=null;try{result=fn();}catch(e){error=type(e)=='string'?e:e.message;}\n if(reason==null?error==null&&result==true:error==reason)passed++;else{failed++;print('not ok installed BASE ',label,': ',error,'\\n');}};\ncheck('present setup',()=>installed_base(value),null);\nif(!realfs.unlink(ROOT+SETUP))die('fixture_setup_delete_failed');\ncheck('consumed setup',()=>installed_base(value),null);\nrealfs.writefile(ROOT+SETUP,'wrong present setup');realfs.chmod(ROOT+SETUP,0o600);\ncheck('wrong present setup',()=>installed_base(value),'update_version_identity_conflict');\nrealfs.unlink(ROOT+SETUP);realfs.unlink(ROOT+POLICY);\ncheck('other missing file',()=>installed_base(value),'engine_package_verification_failed');\ncheck('wrong version',()=>installed_base({...value,version:'wrong'}),'update_rollback_unavailable');\nprint('Installed BASE lifecycle cases: ',passed,' passed, ',failed,' failed\\n');exit(failed?1:0);\n"

def installed_base_regressions():
    native = NATIVE.read_text()
    start = native.index('export function installed_base(')
    end = native.index('export function selected_modules', start)
    body = native[start:end].replace('export function ', 'function ')
    with tempfile.TemporaryDirectory(prefix='foxhole-installed-base-') as directory:
        root = Path(directory)
        data = {'etc/uci-defaults/99-foxhole-openwrt-client': b'successful setup fixture\n',
                'usr/share/foxhole/update-policy.json': b'immutable policy fixture\n'}
        folders = {}
        for name, content in data.items():
            path = root / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o600)
            folder, leaf = name.rsplit('/', 1)
            folders.setdefault(folder, {'name': folder, 'files': []})['files'].append(
                {'name': leaf, 'hash': hashlib.sha256(content).hexdigest()})
        payload = {'version': '1.0.0-r3', 'payload': {'paths': list(folders.values())}}
        program = INSTALLED_BASE_FIXTURE.replace('FIXTURE_ROOT', json.dumps(directory))
        program = program.replace('FIXTURE_UID', str(os.getuid())).replace('FIXTURE_PAYLOAD', json.dumps(payload))
        program = program.replace('// ACTUAL_INSTALLED_BASE', body)
        result = subprocess.run(['ucode', '-'], input=program, text=True, capture_output=True, timeout=20)
        assert len(result.stdout) + len(result.stderr) <= 1048576
        print(result.stdout, end='')
        print(result.stderr, end='')
        return result.returncode


def main():
    body = SERVICE.read_text()
    lines = [line for line in body.splitlines() if not line.startswith('import ')]
    body = '\n'.join(lines).replace('export function ', 'function ')
    assert FIXTURE.count('// ACTUAL_UPDATE_SERVICE') == 1
    program = FIXTURE.replace('MODEL_PATH', str(MODEL)).replace('// ACTUAL_UPDATE_SERVICE', body)
    result = subprocess.run(['ucode', '-'], input=program, text=True, capture_output=True, timeout=20)
    assert len(result.stdout) + len(result.stderr) <= 1048576
    print(result.stdout, end='')
    print(result.stderr, end='')
    return result.returncode if result.returncode else installed_base_regressions()


if __name__ == '__main__':
    raise SystemExit(main())
