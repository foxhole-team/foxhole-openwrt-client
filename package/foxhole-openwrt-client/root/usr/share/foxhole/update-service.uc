'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as model from './update-model.uc';
import * as native from './update-native.uc';
import * as engine from './engine-service.uc';
import * as engines from './engine-model.uc';
import * as registry from './engine-registry.uc';
import * as adapter from './core-adapter.uc';
import * as store from './private-store.uc';

const JOB = '/etc/foxhole/update-job.json';
const STATE = '/etc/foxhole/update-state.json';
const POLICY = '/etc/foxhole/update-policy.json';
const TERMINAL = ['SUCCEEDED','FAILED','RECOVERY_REQUIRED'];
function read(path, limit) { let raw = store.read(path,limit || 524288); return raw ? native.decode(raw) : null; };
function write(path,value) {
	let raw = sprintf('%J',value);
	if (length(raw) > 524288) model.fail('PACKAGE_VERIFICATION_FAILED');
	store.write(path,raw);
	if (store.read(path,524288) != raw) model.fail('PACKAGE_VERIFICATION_FAILED');
};
function transaction(fn) {
	try { return engine.update_locked(fn); }
	catch (e) { if ((type(e)=='string'?e:e.message) == 'engine_busy') model.fail('BUSY'); die(e); }
};
function random() { let raw=fs.readfile('/dev/urandom',16); if (length(raw||'')!=16) model.fail('ROUTER_UNAVAILABLE'); return hexenc(raw); };
function wall() { return time()*1000; };
function owner(principal) { return digest.sha256(sprintf('%J',principal)); };
function current_state() {
	let value = read(STATE) || {schema:1,revision:0,availability:'NOT_CHECKED',availableVersion:null,lastCheckedAtUnixMs:null,failureReason:null,candidate:null};
	if (value.schema != 1 || type(value.revision) != 'int' || value.revision < 0 || value.revision >= 0x7ffffffe ||
	    index(['NOT_CHECKED','CURRENT','AVAILABLE','UNSUPPORTED','CHECK_FAILED'],value.availability) < 0) model.fail('RECOVERY_REQUIRED');
	return value;
};
function policy() { return model.policy(read(POLICY,8192)); };
function active(job) { return job != null && index(TERMINAL,job.state) < 0; };
function blocked(job) { return active(job) || job?.state == 'RECOVERY_REQUIRED'; };
function engine_busy() { let job=read('/etc/foxhole/engine-job.json'); return blocked(job); };
function reason(error) {
	let text = type(error)=='string'?error:error?.message;
	let value = substr(text||'',0,7)=='update_' ? uc(substr(text,7)) :
		substr(text||'',0,7)=='engine_' ? uc(substr(text,7)) : 'PACKAGE_VERIFICATION_FAILED';
	return index(model.reasons,value)>=0 ? value : 'PACKAGE_VERIFICATION_FAILED';
};
function context() { return registry.snapshot_context(engine.update_state()); };
function binding(value) {
	return {routerId:value.routerId,bootId:value.bootId,worldSha256:value.worldSha256,catalogSha256:value.catalogSha256,
		activeGeneration:value.activeGeneration,activeConfigSha256:value.activeConfigSha256,
		activeProfileId:value.activeProfileId,activeEngineId:value.activeEngineId,stopIntent:value.stopIntent};
};
function state_without_stop(value) {
	return digest.sha256(sprintf('%J',{...value,revision:0,activeServerId:null}));
};
function stopped_by_request(job) {
	let state=engine.update_state();
	return state.activeServerId==null&&state_without_stop(state)==job.stateWithoutStopSha256&&
		state.revision==job.stateRevisionBefore+(job.plan.binding.activeProfileId==null?0:1)&&
		context().stopIntent>job.plan.binding.stopIntent;
};
function same(a,b) { return sprintf('%J',a)==sprintf('%J',b); };
function resources(budget,ctx) {
	if(ctx.flashAvailableBytes<budget.flashRequiredBytes||ctx.ramAvailableBytes<budget.ramRequiredBytes)model.fail('NO_SPACE');
};
function authorized(job) {
	return job.automatic ? model.auto_authorized(job,policy()) : engine.update_principal_current(job.principal);
};
function require_authorized(job) {
 if(!authorized(job))model.fail(job.automatic?'STALE_PLAN':'AUTHENTICATION_FAILED');
};
function public_job(value) {
	return {schema:1,routerId:value.routerId,jobId:value.jobId,planId:value.planId,
		operation:value.operation,automatic:value.automatic,state:value.state,step:value.step,
		progressPercent:value.progressPercent,revision:value.revision,failureReason:value.failureReason,
		previousConnectionRestored:value.previousConnectionRestored};
};
function job_ref(value,identity) {
	if (!value || value.automatic || value.owner != identity) return null;
	return public_job(value);
};
function save_job(job) {
	write(JOB,job);
	if (!active(job) && !job.automatic) {
		write('/etc/foxhole/update-last-'+job.owner+'.json',job);
		let rows = fs.glob('/etc/foxhole/update-last-*.json') || [];
		rows = sort(rows,(a,b)=>(fs.lstat(a)?.mtime||0)-(fs.lstat(b)?.mtime||0));
		while (length(rows)>32) { let path=shift(rows); if (store.file_metadata(fs.lstat(path))) fs.unlink(path); }
	}
};
function progress(job,state,step,percent) {
	job.state=state; job.step=step; job.progressPercent=percent; save_job(job);
};
function reconcile(value) {
	if (!active(value) || engines.worker_current(value.worker,engine.update_process_snapshot(value.worker?.pid),engine.update_boot())) return value;
	if (value.state=='QUEUED' && value.bootId==engine.update_boot() && engine.update_now()<=value.createdAtUptimeMs+10000) return value;
	try {
		return transaction(()=>{
			let job=read(JOB);
			if (job?.jobId!=value.jobId || !active(job) || engines.worker_current(job.worker,engine.update_process_snapshot(job.worker?.pid),engine.update_boot())) return job;
			job.failureReason=job.mutationStarted?'RECOVERY_REQUIRED':'ROUTER_UNAVAILABLE';
			progress(job,job.mutationStarted?'RECOVERY_REQUIRED':'FAILED',job.mutationStarted?'RECOVERY_REQUIRED':'FAILED',job.progressPercent);
			return job;
		});
	} catch (_) { return value; }
};
function current_version() {
	let row=engine.update_installed()['foxhole-openwrt-client'];
	if (!row || row.arch!='noarch') model.fail('UNSUPPORTED_TARGET');
	native.policy('/usr/share/foxhole/update-policy.json',row.version); native.target();
	return row.version;
};
export function status(principal) {
	let value=current_state(), flag=policy(), job=reconcile(read(JOB)), ctx=context();
	let version=null, installed=[];
	try { version=current_version(); installed=native.selected_modules(registry.read()); }
	catch (e) { value.availability='UNSUPPORTED'; value.failureReason=reason(e); }
	let last=read('/etc/foxhole/update-last-'+owner(principal)+'.json');
	let suspended=job?.state=='RECOVERY_REQUIRED'?'RECOVERY_REQUIRED':
		index(['UNSUPPORTED_TARGET','ROLLBACK_UNAVAILABLE','RAM_STAGE_UNAVAILABLE','LEGACY_CONNECTION_ACTIVE'],value.failureReason)>=0?value.failureReason:null;
	if(version!=null&&ctx.activeProfileId!=null&&ctx.activeEngineId==null){
		if(value.availability=='AVAILABLE')value.failureReason='LEGACY_CONNECTION_ACTIVE';
		if(flag.enabled&&suspended!='RECOVERY_REQUIRED')suspended='LEGACY_CONNECTION_ACTIVE';
	}
	return {schema:1,supported:value.availability!='UNSUPPORTED',routerId:ctx.routerId,revision:value.revision,currentVersion:version,
		availableVersion:value.availableVersion,availability:value.availability,lastCheckedAtUnixMs:value.lastCheckedAtUnixMs,
		failureReason:value.failureReason,busy:blocked(job)||engine_busy(),
		autoUpdate:{enabled:flag.enabled,intervalSeconds:86400,lastAttemptAtUnixMs:flag.lastAttemptAtUnixMs,
			nextCheckAtUnixMs:flag.enabled?(flag.lastAttemptAtUnixMs==null?wall():flag.lastAttemptAtUnixMs+86400000):null,suspendedReason:suspended},
		installedModules:map(installed,row=>({id:row.id,storage:row.storage,version:row.version})),
		activeOwnJob:active(job)?job_ref(job,owner(principal)):null,lastOwnJob:job_ref(job,owner(principal))||job_ref(last,owner(principal)),
		activeAutomaticJob:active(job)&&job.automatic?{operation:job.operation,automatic:true,state:job.state,step:job.step,
			progressPercent:job.progressPercent,failureReason:job.failureReason}:null};
};
function check_revision(expected,value) {
	if (type(expected)!='int' || expected!=value.revision) model.fail('STALE_SESSION');
};
export function settings(request,principal) {
	transaction(()=>{
		if (!engine.update_principal_current(principal)) model.fail('AUTHENTICATION_FAILED');
		if (type(request.autoUpdateEnabled)!='bool') model.fail('INVALID_REQUEST');
		let value=current_state(), flag=policy(); check_revision(request.expectedRevision,value);
		flag.enabled=request.autoUpdateEnabled; flag.revision++;
		write(POLICY,flag); value.revision++; write(STATE,value);
	});
	return status(principal);
};
function new_job(operation,principal,automatic,plan) {
	let value=current_state(),ctx=context(); value.revision++; write(STATE,value);
	let flag=policy();
	return {schema:1,routerId:ctx.routerId,jobId:'update-job-'+random(),planId:plan?.planId||null,
		operation,automatic,owner:automatic?null:owner(principal),principal:automatic?null:principal,
		policyRevision:flag.revision,plan:plan||null,state:'QUEUED',step:'PREPARING',progressPercent:0,
		revision:value.revision,failureReason:null,previousConnectionRestored:null,mutationStarted:false,
		createdAtUptimeMs:engine.update_now(),bootId:engine.update_boot(),worker:null};
};
function launch(value) {
	if (system(['/bin/sh','-c','umask 077; /usr/libexec/foxhole-update-job '+value.jobId+' >/dev/null 2>&1 &'],1000)!=0) {
		transaction(()=>{let job=read(JOB);if(job?.jobId==value.jobId&&job.state=='QUEUED'){
			job.failureReason='ROUTER_UNAVAILABLE';progress(job,'FAILED','FAILED',0);}});
	}
	return public_job(read(JOB));
};
export function check(request,principal) {
	let value=transaction(()=>{
		if (!engine.update_principal_current(principal)) model.fail('AUTHENTICATION_FAILED');
		check_revision(request.expectedRevision,current_state());
		if (blocked(read(JOB))||engine_busy()) model.fail('BUSY');
		let job=new_job('CHECK',principal,false,null); save_job(job); return job;
	});
	return launch(value);
};
function digest_plan(plan) { let value={...plan}; delete value.planSha256; return digest.sha256(sprintf('%J',value)); };
function public_plan(plan) { let value={...plan}; for(let name in ['owner','binding','candidate','createdAtUptimeMs'])delete value[name]; return value; };
function legacy_guard(ctx) {
	if(ctx.activeProfileId!=null&&ctx.activeEngineId==null)model.fail('LEGACY_CONNECTION_ACTIVE');
};
function make_plan(principal,automatic) {
	let value=current_state(),candidate=value.candidate,ctx=context(),current=registry.read();
	legacy_guard(ctx);
	if (value.availability!='AVAILABLE'||!candidate) model.fail('NOT_CHECKED');
	if (wall()-value.lastCheckedAtUnixMs>300000 || wall()<value.lastCheckedAtUnixMs || !same(candidate.selected,current)) model.fail('STALE_PLAN');
	if(!same(candidate.binding,binding(ctx))){
		let previous={plan:{binding:candidate.binding},stateRevisionBefore:candidate.stateRevisionBefore,stateWithoutStopSha256:candidate.stateWithoutStopSha256};
		for(let field in ['routerId','bootId','worldSha256','catalogSha256'])
			if(candidate.binding[field]!=ctx[field])model.fail('STALE_PLAN');
		if(!stopped_by_request(previous))model.fail('STALE_PLAN');
		candidate={...candidate,binding:binding(ctx)};
	}
	if (!length(candidate.changes)) model.fail('INVALID_REQUEST');
	resources(candidate.budget,ctx);
	let budget={...candidate.budget,flashAvailableBytes:ctx.flashAvailableBytes,ramAvailableBytes:ctx.ramAvailableBytes};
	let plan={schema:1,routerId:ctx.routerId,revision:value.revision,planId:'update-plan-'+random(),
		fromVersion:candidate.fromVersion,toVersion:candidate.base.version,engineIds:sort(map(current.selected,row=>row.id)),
		changes:candidate.changes,impact:candidate.baseChanged||ctx.activeProfileId!=null?'RECONNECT_REQUIRED':'KEEP_ACTIVE',
		confirmationRequired:true,expiresAtUptimeMs:engine.update_now()+300000,bootId:ctx.bootId,budget,
		owner:automatic?null:owner(principal),binding:candidate.binding,candidate,createdAtUptimeMs:engine.update_now()};
	plan.planSha256=digest_plan(plan); return plan;
};
export function plan(request,principal) {
	return transaction(()=>{
		if (!engine.update_principal_current(principal)) model.fail('AUTHENTICATION_FAILED');
		check_revision(request.expectedRevision,current_state());
		if(blocked(read(JOB))||engine_busy())model.fail('BUSY');
		let result=make_plan(principal,false);write('/tmp/foxhole/update-plan-'+owner(principal),result);return public_plan(result);
	});
};
function admit(plan,request,principal) {
	if (request.confirmed!=true || type(request.confirmed)!='bool') model.fail('INVALID_REQUEST');
	if (!plan || plan.owner!=owner(principal)) model.fail('AUTHENTICATION_FAILED');
	if (plan.planId!=request.planId || plan.planSha256!=request.planSha256 || digest_plan(plan)!=plan.planSha256 ||
	    plan.revision!=request.expectedRevision || current_state().revision!=plan.revision ||
	    engine.update_now()<plan.createdAtUptimeMs || engine.update_now()>plan.expiresAtUptimeMs ||
	    !same(plan.binding,binding(context())) || !same(plan.candidate.selected,registry.read())) model.fail('STALE_PLAN');
};
export function apply(request,principal) {
	let value=transaction(()=>{
		if (!engine.update_principal_current(principal)) model.fail('AUTHENTICATION_FAILED');
		if(blocked(read(JOB))||engine_busy())model.fail('BUSY');
		let plan=read('/tmp/foxhole/update-plan-'+owner(principal));admit(plan,request,principal);
		let job=new_job('APPLY',principal,false,plan);save_job(job);return job;
	});
	return launch(value);
};
export function job(id,principal) {
	let current=reconcile(read(JOB));
	if(current?.jobId!=id)current=read('/etc/foxhole/update-last-'+owner(principal)+'.json');
	if(!current||current.jobId!=id||current.automatic||current.owner!=owner(principal))model.fail('AUTHENTICATION_FAILED');
	return public_job(current);
};
function minimal_base(base) {
	let result={};for(let field in ['archive','index','filename','version','sha256','archiveBytes','installedBytes',
		'indexSha256','catalogSha256','tag','directory','nativeId'])result[field]=base[field];return result;
};
function checked_assets(value,keys) {
	for(let item in [value.base,value.rollback]){
		if(registry.hash_file(item.archive)!=item.sha256||registry.hash_file(item.index)!=item.indexSha256)model.fail('PACKAGE_VERIFICATION_FAILED');
		engine.update_apk(['--keys-dir',keys,'verify',item.archive,item.index]);
	}
};
function clear_previous_staging(id) {
	store.directory('/tmp/foxhole');
	let folders=fs.glob('/tmp/foxhole/update-job-*')||[];
	if(length(folders)>64)model.fail('NO_SPACE');
	for(let path in folders){
		if(path=='/tmp/foxhole/'+id)continue;
		if(!match(path,/^\/tmp\/foxhole\/update-job-[a-f0-9]{32}$/)||!store.directory_metadata(fs.lstat(path)))model.fail('PACKAGE_VERIFICATION_FAILED');
		if(system(['/bin/rm','-rf','--',path],10000)!=0||fs.lstat(path))model.fail('NO_SPACE');
	}
	let files=fs.glob('/tmp/foxhole/engine-assets/update-*')||[];
	if(length(files)>512)model.fail('NO_SPACE');
	for(let path in files){
		if(!match(path,/^\/tmp\/foxhole\/engine-assets\/update-[a-f0-9]{32}$/)||!store.file_metadata(fs.lstat(path)))model.fail('PACKAGE_VERIFICATION_FAILED');
		if(!fs.unlink(path))model.fail('NO_SPACE');
	}
};
function prune_recovery_cache(value,job) {
	let keep=[value.base.sha256,value.base.indexSha256,value.rollback.sha256,value.rollback.indexSha256];
	let tx=job?.nativeTransaction;if(tx){push(keep,tx.tool.gzipSha256);for(let name in keys(tx.tool.helpers))push(keep,tx.tool.helpers[name].sha256);for(let item in tx.modules)push(keep,item.archiveSha256,item.indexSha256);}
	let paths=fs.glob('/etc/foxhole/update-cache/*')||[];
	if(length(paths)>64)return;
	for(let path in paths){
		let name=fs.basename(path);
		if(match(name,/^[a-f0-9]{64}$/)&&index(keep,name)<0&&store.file_metadata(fs.lstat(path)))fs.unlink(path);
	}
};
function perform_check(job) {
	require_authorized(job);
	clear_previous_staging(job.jobId);
	let directory='/tmp/foxhole/'+job.jobId;store.directory(directory);let keys=native.prepare_keys(directory);
	require_authorized(job);
	progress(job,'DOWNLOADING','CHECKING_RELEASE',5);
	let version=current_version(),target=native.target(),local=native.policy('/usr/share/foxhole/update-policy.json',version);
	let ctx=context(),selected=registry.read();
	if(job.automatic)legacy_guard(ctx);
	resources({flashRequiredBytes:33554432,ramRequiredBytes:33554432},ctx);
	let tag=native.latest(directory); progress(job,'DOWNLOADING','DOWNLOADING_INDEX',15);
	let next=native.base(tag,directory+'/candidate',keys);
	progress(job,'VERIFYING','VERIFYING_PACKAGE',35);
	let previous=tag==local.releaseTag&&next.version==version?next:native.base(local.releaseTag,directory+'/rollback',keys);
	if(previous.version!=version)model.fail('ROLLBACK_UNAVAILABLE');
	native.installed_base(previous);
	let base_changed=model.version_admit(native.compare(version,next.version),previous.sha256,next.sha256);
	let old_modules=native.selected_modules(selected),modules=native.module_changes(old_modules,next.catalog,target.architecture);
	engines.commit(selected,modules.artifacts,[],selected.revision);
	let changes=modules.changes;
	if(base_changed)unshift(changes,{id:'foxhole',fromVersion:version,toVersion:next.version,storage:null});
	let download=next.archiveBytes+previous.archiveBytes,staging=next.installedBytes+previous.installedBytes,ram=0;
	for(let artifact in modules.artifacts){
		download+=artifact.archiveBytes+artifact.indexBytes;staging+=artifact.installedBytes;
		if(artifact.storage=='RAM'){ram+=artifact.binaryBytes+artifact.reserveBytes;download+=artifact.binaryBytes;}
	}
	for(let artifact in old_modules)if(artifact.storage=='RAM'){ram+=artifact.binaryBytes+artifact.reserveBytes;download+=artifact.binaryBytes;}
	let tool_budget=native.tool_budget();
	let budget={downloadBytes:download,stagingBytes:staging,flashRequiredBytes:staging+2*download+33554432+tool_budget.flashBytes,
		flashAvailableBytes:ctx.flashAvailableBytes,ramRequiredBytes:download+staging+ram+16777216+tool_budget.ramBytes,
		ramAvailableBytes:ctx.ramAvailableBytes,reservedBytes:33554432};
	resources(budget,context());
	if(!authorized(job)||!same(binding(ctx),binding(context()))||!same(selected,registry.read()))model.fail('STALE_PLAN');
	transaction(()=>{
		let value=current_state();require_authorized(job);
		value.availability=length(changes)?'AVAILABLE':'CURRENT';value.availableVersion=next.version;
		value.lastCheckedAtUnixMs=wall();value.failureReason=null;value.revision++;
		value.candidate={base:minimal_base(next),rollback:minimal_base(previous),baseChanged:base_changed,
			fromVersion:version,artifacts:modules.artifacts,changes,binding:binding(ctx),selected,budget,
			stateRevisionBefore:engine.update_state().revision,stateWithoutStopSha256:state_without_stop(engine.update_state())};
		write(STATE,value);job.revision=value.revision;progress(job,'SUCCEEDED','COMPLETED',100);
	});
};
function admitted_private_role(path) {
	return index(['/etc/foxhole/update-state.json','/etc/foxhole/update-job.json','/etc/foxhole/update-cache',
		'/etc/foxhole/engines.json','/etc/foxhole/engine-job.json'],path)>=0||
		match(path,/^\/etc\/foxhole\/update-last-[a-f0-9]{64}\.json$/)!=null;
};
function history_writer_role(path,info) {
 let pending=path=='/etc/foxhole/history.json.gz.new';
 if(!pending&&path!='/etc/foxhole/history.json.gz')return null;
 if(pending&&info==null)return 'ephemeral-hourly-history-checkpoint';
 if(info?.type!='file'||info.uid!=0||info.gid!=0||info.nlink!=1||
  info.size<(pending?0:20)||info.size>6291456||
  index(pending?[0o600]:[0o600,0o644],info.mode&0o7777)<0)model.fail('PACKAGE_VERIFICATION_FAILED');
 return pending?'ephemeral-hourly-history-checkpoint':'bounded-hourly-history-checkpoint';
};
function preserve() {
	let result={};
	let pending=['/etc/foxhole'],paths=['/etc/config/foxhole'];
	while(length(pending)){
		let directory=shift(pending),parent=fs.lstat(directory);
		if(!store.directory_metadata(parent)||length(split(directory,'/'))>8)model.fail('PACKAGE_VERIFICATION_FAILED');
		for(let path in fs.glob(directory+'/*')||[]){
			if(admitted_private_role(path))continue;
			if(index(['/etc/foxhole/history.json.gz','/etc/foxhole/history.json.gz.new'],path)>=0)push(paths,path);
			else if(fs.lstat(path)?.type=='directory')push(pending,path);else push(paths,path);
			if(length(paths)+length(pending)>512)model.fail('PACKAGE_VERIFICATION_FAILED');
		}
	}
	let total=0;
	for(let path in paths){
			let info=fs.lstat(path),history_role=history_writer_role(path,info);
			if(history_role){result[path]={role:history_role};continue;}
			let alias=index(['/etc/foxhole/mobile.crt','/etc/foxhole/mobile-identity/cert.pem'],path)>=0;
			if(info?.type!='file'||info.uid!=0||(info.mode&0o022)||(info.nlink!=1&&!(alias&&info.nlink==2)))model.fail('PACKAGE_VERIFICATION_FAILED');
			// Only hashes are journaled; TLS aliases have a typed nlink2
			// role.

			let maximum=1048576,raw=fs.readfile(path,maximum+1);
			total+=length(raw||'');
			let after=fs.lstat(path);
			if(raw==null||length(raw)>maximum||length(raw)!=info.size||total>8388608||
			    !same([info.dev,info.inode,info.size,info.mode,info.mtime,info.ctime],
				[after?.dev,after?.inode,after?.size,after?.mode,after?.mtime,after?.ctime]))model.fail('PACKAGE_VERIFICATION_FAILED');
			result[path]={sha256:digest.sha256(raw),mode:info.mode,uid:info.uid,gid:info.gid,nlink:info.nlink};
	}
	return result;
};
function preserved(before,job) {
	let after=preserve();
	before={...before};after={...after};
	let history='/etc/foxhole/history.json.gz';
	if(before[history]&&!after[history])model.fail('RECOVERY_REQUIRED');
	delete before[history];delete after[history];
	delete before[history+'.new'];delete after[history+'.new'];
	if(stopped_by_request(job)){
		before={...before};after={...after};
		for(let path in ['/etc/foxhole/state.json','/etc/foxhole/engine-intent.json']){delete before[path];delete after[path];}
	}
	// No privileged restoration of stale auth/profile data is ever
	// attempted.
	if(!same(before,after))model.fail('RECOVERY_REQUIRED');
};
function begin_mutation(job) {
	let path='/etc/foxhole/state.lock';store.target(path);let lock=fs.open(path,'a+',0o600);
	if(!lock||!lock.lock('xn')||!store.file_metadata(fs.lstat(path))){try{if(lock)lock.close();}catch(_){}model.fail('BUSY');}
	try{
		if(!authorized(job)||!same(job.plan.binding,binding(context())))model.fail('STALE_PLAN');
		job.mutationStarted=true;job.atomicPackagePhase=true;progress(job,'INSTALLING','INSTALLING_PACKAGE',40);
		lock.lock('u');lock.close();
	}catch(e){try{lock.lock('u');lock.close();}catch(_){}die(e);}
};
function end_package_phase(job) {
	let path='/etc/foxhole/state.lock';store.target(path);let lock=fs.open(path,'a+',0o600);
	if(!lock||!lock.lock('xn')||!store.file_metadata(fs.lstat(path))){try{if(lock)lock.close();}catch(_){}model.fail('BUSY');}
	try{
		if(stopped_by_request(job)&&system(['/etc/init.d/foxhole-runtime','stop'],15000)!=0)model.fail('RECOVERY_REQUIRED');
		job.atomicPackagePhase=false;save_job(job);lock.lock('u');lock.close();
	}catch(e){try{lock.lock('u');lock.close();}catch(_){}die(e);}
};
function restart(job) {
	let path='/etc/foxhole/state.lock';store.target(path);let lock=fs.open(path,'a+',0o600);
	if(!lock||!lock.lock('xn')||!store.file_metadata(fs.lstat(path))){try{if(lock)lock.close();}catch(_){}return false;}
	try{
		let allowed=(job.automatic?job.mutationStarted:engine.update_principal_current(job.principal))&&engines.restart_allowed(job.plan.binding,context());
		let result=allowed&&system(['/etc/init.d/foxhole-runtime','start'],15000)==0;
		lock.lock('u');lock.close();return result;
	}catch(_){try{lock.lock('u');lock.close();}catch(_){}return false;}
};
function terminal(job,state) {
	let path='/etc/foxhole/state.lock';store.target(path);let lock=fs.open(path,'a+',0o600);
	if(!lock||!lock.lock('xn')||!store.file_metadata(fs.lstat(path))){try{if(lock)lock.close();}catch(_){}model.fail('BUSY');}
	try{
		if(stopped_by_request(job)){
			if(system(['/etc/init.d/foxhole-runtime','stop'],15000)!=0)model.fail('RECOVERY_REQUIRED');
			job.stoppedByRequest=true;job.previousConnectionRestored=false;
		}
		let value=current_state();value.revision++;
		if(state=='SUCCEEDED'){value.availability='CURRENT';value.failureReason=null;value.candidate=null;}
		write(STATE,value);job.revision=value.revision;
		progress(job,state,state=='SUCCEEDED'?'COMPLETED':'FAILED',state=='SUCCEEDED'?100:job.progressPercent);
		lock.lock('u');lock.close();
	}catch(e){try{lock.lock('u');lock.close();}catch(_){}die(e);}
};
function perform_apply(job) {
	return transaction(()=>{
		let plan=job.plan,value=plan.candidate,old=registry.read(),ctx=context();
		legacy_guard(ctx);
		if(engine_busy())model.fail('BUSY');
		if(!authorized(job)||current_state().revision!=job.revision||!same(value.selected,old)||
		    !same(plan.binding,binding(ctx))||engine.update_now()>plan.expiresAtUptimeMs)model.fail('STALE_PLAN');
		resources(plan.budget,ctx);
		let directory='/tmp/foxhole/'+job.jobId;store.directory(directory);let key_dir=native.prepare_keys(directory);
		progress(job,'VERIFYING','VERIFYING_PACKAGE',10);checked_assets(value,key_dir);
        let before=engine.update_installed(),identities=native.installed_identities(),prepared=[],allowed=[];
        if(length(keys(before))!=length(keys(identities)))model.fail('STALE_PLAN');
        for(let name in keys(before))if(before[name].version!=identities[name]?.version||before[name].arch!=identities[name]?.arch)model.fail('STALE_PLAN');
        if(before['foxhole-openwrt-client']?.version!=plan.fromVersion)model.fail('STALE_PLAN');
        native.installed_base({...value.rollback,payload:native.decode(engine.update_apk(['adbdump','--format','json',value.rollback.archive]))});
        if(value.baseChanged)push(allowed,{name:'foxhole-openwrt-client',version:value.base.version,arch:'noarch'});
        for(let artifact in value.artifacts){
            let candidate=engine.update_candidate(artifact,directory,key_dir);
            native.stage_ram(artifact);
            if(!before[artifact.packageName]){
                push(prepared,candidate);push(allowed,{name:artifact.packageName,version:artifact.packageVersion,arch:artifact.architecture});
            }else{
                if(before[artifact.packageName].version!=artifact.packageVersion||before[artifact.packageName].arch!=artifact.architecture||
                   identities[artifact.packageName]?.cas!=native.native_cas(candidate.nativeId))model.fail('VERSION_IDENTITY_CONFLICT');
                registry.verify_slot(artifact);
                native.cache_asset(candidate.package,artifact.packageSha256,artifact.archiveBytes);
                native.cache_asset(candidate.index,artifact.indexSha256,artifact.indexBytes);
            }
        }
        for(let artifact in native.selected_modules(old))native.stage_ram(artifact);
        for(let artifact in old.slots)registry.verify_slot(artifact);
        let world_current=native.world_state(),world=native.world_plan(world_current.raw,map(prepared,item=>item.value.packageName));
        let tool=native.prepare_tool(),tx=native.prepare_transaction(job.jobId,value,prepared,world,tool);
        if(identities['foxhole-openwrt-client']?.cas!=tx.oldCas)model.fail('VERSION_IDENTITY_CONFLICT');
        if(!authorized(job)||!same(plan.binding,binding(context())))model.fail('STALE_PLAN');
        resources(plan.budget,context());
        job.installedBefore=before;job.packageIdentitiesBefore=identities;job.worldBefore=engine.update_world();job.worldMetadataBefore=world_current.metadata;job.nativeTransaction=tx;
        job.previousRegistry=old;job.protectedBefore=preserve();job.newPackageNames=map(tx.modules,item=>item.name);
        job.stateRevisionBefore=engine.update_state().revision;job.stateWithoutStopSha256=state_without_stop(engine.update_state());
        job.previousGeneration=adapter.generation(adapter.receipt('owner'));job.restartStarted=engine.update_now();
        progress(job,'INSTALLING','BACKING_UP',30);
        begin_mutation(job);
        if(system(['/bin/sync'],30000)!=0)model.fail('RECOVERY_REQUIRED');
        if(plan.impact=='RECONNECT_REQUIRED'&&system(['/etc/init.d/foxhole-runtime','stop'],15000)!=0)model.fail('ROUTER_UNAVAILABLE');
        let commit_world=native.world_state();
        if(commit_world.sha256!=tx.beforeSha256||!same(commit_world.metadata,job.worldMetadataBefore))model.fail('RECOVERY_REQUIRED');
        native.transaction_capture(tx.tool,native.native_args(tx,false,commit_world.sha256));
        end_package_phase(job);
		progress(job,'CHECKING','CHECKING_PACKAGE',65);
		model.package_delta(before,engine.update_installed(),allowed);
        native.assert_identities(job.packageIdentitiesBefore,native.installed_identities(),job.nativeTransaction,false);
        for(let artifact in job.previousRegistry.slots)registry.verify_slot(artifact);
        let after_world=native.world_state();
        if(after_world.sha256!=job.nativeTransaction.afterSha256||!same(after_world.metadata,job.worldMetadataBefore))model.fail('PACKAGE_VERIFICATION_FAILED');
        native.installed_base({...job.nativeTransaction.newBase,payload:native.decode(engine.update_apk(['adbdump','--format','json',job.nativeTransaction.newBase.archive]))});
		if(value.baseChanged&&registry.catalog().sha256!=value.base.catalogSha256)model.fail('PACKAGE_VERIFICATION_FAILED');
		preserved(job.protectedBefore,job);
		for(let artifact in value.artifacts){
			let path=registry.verify_slot(artifact),caps=native.decode(registry.capture([path,'capabilities'],131072,130000));
			if(caps.router_contract_version!=1||caps.platform!='linux'||caps.core_version!=artifact.version||!same(caps.protocols,[artifact.id]))model.fail('PACKAGE_VERIFICATION_FAILED');
			if(artifact.id==plan.binding.activeEngineId){
				let profile=filter(engine.update_state().servers,row=>row.id==plan.binding.activeProfileId)[0];
				if(!profile||digest.sha256(profile.config)!=plan.binding.activeConfigSha256)model.fail('STALE_PLAN');
				store.write(directory+'/check-config',profile.config);
				registry.capture([path,'check','--config',directory+'/check-config'],65536,130000);
				fs.unlink(directory+'/check-config');
			}
		}
		let next=engines.commit(old,value.artifacts,[],old.revision);registry.write(next);
		if(stopped_by_request(job)){
			if(system(['/etc/init.d/foxhole-runtime','stop'],15000)!=0)model.fail('RECOVERY_REQUIRED');
			job.stoppedByRequest=true;job.previousConnectionRestored=false;
		}else if(plan.impact=='RECONNECT_REQUIRED'&&ctx.activeProfileId!=null){
			progress(job,'RECONNECTING','RECONNECTING_VPN',85);
			if((!restart(job)||!engine.update_wait_reconnect(job,engines.selected(next,ctx.activeEngineId),job.restartStarted,job.previousGeneration))&&
			    !stopped_by_request(job))model.fail('RECOVERY_REQUIRED');
		}
		terminal(job,'SUCCEEDED');
		try{prune_recovery_cache(value,job);}catch(_){}
		return public_job(job);
	});
};
function restore_registry(old) {
	let current=registry.read(),restored={...old,revision:max(old.revision,current.revision)+1};
	registry.write(restored);
	if(!same(registry.read(),restored)||restored.revision<=old.revision||restored.revision<=current.revision)model.fail('RECOVERY_REQUIRED');
	return restored;
};
function attempt_recovery(job) {
	return transaction(()=>{
		if(!job.mutationStarted||job.recoveryAttempted)return false;
		job.recoveryAttempted=true;save_job(job);
        let tx=job.nativeTransaction;
        if(!tx||!job.packageIdentitiesBefore)model.fail('RECOVERY_REQUIRED');
        native.verify_transaction(job.jobId,tx);
        let before=job.installedBefore,actual=engine.update_installed(['foxhole-openwrt-client',...job.newPackageNames]),old=job.previousRegistry;
        let identities=native.installed_identities(),current_world=native.world_state(),current=current_world.sha256;
        if(!same(current_world.metadata,job.worldMetadataBefore))model.fail('RECOVERY_REQUIRED');
        for(let name in keys(job.packageIdentitiesBefore))if(name!='foxhole-openwrt-client'&&!same(identities[name],job.packageIdentitiesBefore[name]))model.fail('RECOVERY_REQUIRED');
        for(let name in keys(identities))if(!job.packageIdentitiesBefore[name]&&index(job.newPackageNames,name)<0)model.fail('RECOVERY_REQUIRED');
        let base=identities['foxhole-openwrt-client'];
        if(!base||!((base.version==tx.oldBase.version&&base.cas==tx.oldCas)||(base.version==tx.newBase.version&&base.cas==tx.newCas)))model.fail('RECOVERY_REQUIRED');
        let argv=native.native_args(tx,true,current);
        job.atomicPackagePhase=true;progress(job,'INSTALLING','INSTALLING_PACKAGE',job.progressPercent);
        if(system(['/bin/sync'],30000)!=0)model.fail('RECOVERY_REQUIRED');
        if(job.plan.impact=='RECONNECT_REQUIRED'&&system(['/etc/init.d/foxhole-runtime','stop'],15000)!=0)model.fail('RECOVERY_REQUIRED');
        native.transaction_capture(tx.tool,argv);
        end_package_phase(job);
        model.package_delta(before,engine.update_installed(),[]);
        native.assert_identities(job.packageIdentitiesBefore,native.installed_identities(),tx,true);
        for(let artifact in job.previousRegistry.slots)registry.verify_slot(artifact);
        let restored_world=native.world_state();
        if(restored_world.sha256!=tx.beforeSha256||!same(restored_world.metadata,job.worldMetadataBefore))model.fail('RECOVERY_REQUIRED');
        native.installed_base({...tx.oldBase,payload:native.decode(engine.update_apk(['adbdump','--format','json',tx.oldBase.archive]))});
		restore_registry(old);
		preserved(job.protectedBefore,job);
		if(stopped_by_request(job)){
			if(system(['/etc/init.d/foxhole-runtime','stop'],15000)!=0)model.fail('RECOVERY_REQUIRED');
			job.previousConnectionRestored=false;
		}else if(job.plan.impact=='RECONNECT_REQUIRED'&&job.plan.binding.activeProfileId!=null){
			job.previousConnectionRestored=false;
			let previous_generation=adapter.generation(adapter.receipt('owner')),started=engine.update_now();
			if((!restart(job)||!engine.update_wait_reconnect(job,engines.selected(old,job.plan.binding.activeEngineId),started,previous_generation))&&!stopped_by_request(job))model.fail('RECOVERY_REQUIRED');
			job.previousConnectionRestored=!stopped_by_request(job);
		}
		job.recoverySucceeded=true;terminal(job,'FAILED');return true;
	});
};
function auto_conversion_allowed(job) {
 let current=read(JOB);
 return current?.jobId==job.jobId&&current.operation=='CHECK'&&current.state=='SUCCEEDED'&&current.automatic&&
  model.auto_authorized(job,policy())&&!engine_busy();
};
export function run(id) {
	let job=transaction(()=>{let value=read(JOB);if(value?.jobId!=id||value.state!='QUEUED')model.fail('STALE_PLAN');
		value.worker=engine.update_self_worker();progress(value,'VERIFYING','PREPARING',1);return value;});
	try{
		if(job.operation=='CHECK'){
			perform_check(job);
			if(job.automatic&&policy().enabled&&current_state().availability=='AVAILABLE'){
				job=transaction(()=>{if(!auto_conversion_allowed(job))return null;
					let plan=make_plan(null,true),value=new_job('APPLY',null,true,plan);value.worker=engine.update_self_worker();save_job(value);return value;});
				if(job)perform_apply(job);else return public_job(read(JOB));
			}
		}else perform_apply(job);
	}catch(e){
		transaction(()=>{let current=read(JOB);if(current?.jobId!=job.jobId)return;
			job.failureReason=reason(e);progress(job,job.mutationStarted?'RECOVERY_REQUIRED':'FAILED',job.mutationStarted?'RECOVERY_REQUIRED':'FAILED',job.progressPercent);
			let value=current_state();value.revision++;value.availability=job.operation=='CHECK'?'CHECK_FAILED':'NOT_CHECKED';value.availableVersion=null;value.candidate=null;
			if(job.operation=='CHECK')value.lastCheckedAtUnixMs=wall();
			value.failureReason=job.failureReason;write(STATE,value);
		});
		if(job.mutationStarted)try{attempt_recovery(job);}catch(_){job.failureReason='RECOVERY_REQUIRED';progress(job,'RECOVERY_REQUIRED','RECOVERY_REQUIRED',job.progressPercent);}
	}
	try{fs.unlink('/tmp/foxhole/'+job.jobId+'/check-config');}catch(_){}
	// Ordinary package hooks were deferred by the exact live journal.
	// Publish terminal state first.
	if(job.mutationStarted&&(job.state=='SUCCEEDED'||job.recoverySucceeded))system(['/bin/sh','-c',
		'/etc/init.d/foxhole-history restart; /etc/init.d/foxhole-mobile restart; /etc/init.d/foxhole-inbound restart; /etc/init.d/firewall reload; /etc/init.d/rpcd restart; /etc/init.d/uhttpd reload'],30000);
	return public_job(read(JOB));
};
export function hooks_deferred() {
	let job=read(JOB);
	return active(job)&&job.operation=='APPLY'&&job.mutationStarted&&
		engines.worker_current(job.worker,engine.update_process_snapshot(job.worker?.pid),engine.update_boot());
};
export function tick() {
	let value=null;
	try{reconcile(read(JOB));value=transaction(()=>{
		let flag=policy(),job=read(JOB);
		if(!model.due(flag,wall(),blocked(job)||engine_busy()))return null;
		flag.lastAttemptAtUnixMs=wall();write(POLICY,flag);
		current_version();let result=new_job('CHECK',null,true,null);save_job(result);return result;
	});}catch(_){}
	if(value)launch(value);
};
