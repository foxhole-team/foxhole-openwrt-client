'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as model from './model.uc';
import * as engines from './engine-model.uc';
import * as core from './core-model.uc';
import * as adapter from './core-adapter.uc';
import * as registry from './engine-registry.uc';
import * as pairing from './pairing.uc';
import * as backup_service from './backup-service.uc';
import * as store from './private-store.uc';
import * as packages from './package-operations.uc';
import * as native_identity from './update-native.uc';
import * as protocol_facts from './protocol-facts.uc';

const JOB = '/etc/foxhole/engine-job.json';
const LOCK = '/etc/foxhole/engine.lock';
const KEY = '/usr/share/foxhole/foxhole-openwrt-apk.pem';
const PUBLIC_RELEASE_PEM_DIGEST = 'fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1';
const TERMINAL = ['SUCCEEDED', 'FAILED', 'RECOVERY_REQUIRED'];
const REASONS = ['UNKNOWN_PROTOCOL', 'NOT_RELEASED', 'UNSUPPORTED_TARGET', 'UNSUPPORTED_PROFILE_GRAPH',
	'STALE_PLAN', 'STALE_SESSION', 'ROUTER_UNAVAILABLE', 'BUSY', 'NO_SPACE', 'AUTHENTICATION_FAILED',
	'DOWNLOAD_FAILED', 'PACKAGE_VERIFICATION_FAILED', 'CANDIDATE_CHECK_FAILED', 'RECONNECT_FAILED',
	'RECOVERY_REQUIRED', 'INVALID_REQUEST', 'IN_USE'];
function fail(reason) { die('engine_' + lc(reason)); };
function read(path, limit) { let raw = store.read(path, limit); return raw ? json(raw) : null; };
function write(path, value) {
	let raw = sprintf('%J', value);
	if (length(raw) > 524288) fail('PACKAGE_VERIFICATION_FAILED');
	store.write(path, raw);
	if (store.read(path, 524288) != raw) fail('PACKAGE_VERIFICATION_FAILED');
};
function nonce() {
	let raw = fs.readfile('/dev/urandom', 32);
	if (length(raw || '') != 32) fail('ROUTER_UNAVAILABLE');
	return hexenc(raw);
};
function now() {
	let raw = fs.readfile('/proc/uptime', 128), found = match(raw || '', /^([0-9]+\.[0-9]+) /);
	if (!found) fail('ROUTER_UNAVAILABLE');
	return int(+found[1] * 1000);
};
function state() { return model.validate_state(read('/etc/foxhole/state.json', 262144) || model.defaults()); };
function owner(principal) { return digest.sha256(sprintf('%J', principal)); };
function principal_current(principal) {
	if (principal.kind == 'pair') {
		let pairs = read('/etc/foxhole/pairing.json', 32768) || pairing.defaults();
		return pairing.session_current(pairs, { id: principal.id, verifier: principal.verifier });
	}
	let auth = read('/etc/foxhole/auth.json', 32768);
	return principal.kind == 'admin' && auth?.changed == true && digest.sha256(auth.hash || '') == principal.verifier;
};
function locked(fn) {
	store.target(LOCK);
	let lock = fs.open(LOCK, 'a+', 0o600);
	if (!lock || !lock.lock('xn') || !store.file_metadata(fs.lstat(LOCK))) {
		try { if (lock) lock.close(); } catch (_) {}
		fail('BUSY');
	}
	try {
		let value = fn(); lock.lock('u'); lock.close(); return value;
	} catch (error) {
		try { lock.lock('u'); lock.close(); } catch (_) {}
		die(error);
	}
};
function active(job) { return job != null && index(TERMINAL, job.state) < 0; };
function busy(job) { return active(job) || job?.state == 'RECOVERY_REQUIRED'; };
function boot() { return trim(fs.readfile('/proc/sys/kernel/random/boot_id', 128) || ''); };
export function guard_mutation() {
	backup_service.guard();
 let server_job = read('/etc/foxhole/vpn-server-job.json',2097152);
 if (server_job && index(['SUCCEEDED','FAILED'],server_job.state) < 0) fail('BUSY');
	let cohort=read('/tmp/foxhole/core-uploads/current.json',524288);
	if(cohort?.schema==1&&index(['RECEIVING','VERIFYING','WAITING'],cohort.phase)>=0&&
		cohort.bootId==boot()&&now()<=cohort.expiresAtUptimeMs&&
		principal_current(cohort.principal))fail('BUSY');
	let update = read('/etc/foxhole/update-job.json', 524288);
	if (active(update) || update?.state == 'RECOVERY_REQUIRED') fail('BUSY');
	let value = read(JOB, 524288);
	if (active(value) || value?.state == 'RECOVERY_REQUIRED' && value.plan.impact == 'RECONNECT_REQUIRED') fail('BUSY');
};
export function stop_intent() {
	let previous = read('/etc/foxhole/engine-intent.json', 4096) || { schema: 1, revision: 0 };
	if (previous.schema != 1 || type(previous.revision) != 'int' || previous.revision < 0 || previous.revision >= 0x7fffffff) fail('RECOVERY_REQUIRED');
	write('/etc/foxhole/engine-intent.json', { schema: 1, revision: previous.revision + 1 });
};
function public_job(job) {
	return { schema: 1, routerId: job.routerId, jobId: job.jobId, planId: job.planId,
		state: job.state, progressPercent: job.progressPercent, step: job.step,
		revision: job.revision, failureReason: job.failureReason,
		previousConnectionRestored: job.previousConnectionRestored };
};
function job_ref(job, current_owner) {
	if (!job || job.owner != current_owner) return null;
	return { jobId: job.jobId, planId: job.planId, state: job.state,
		progressPercent: job.progressPercent, step: job.step };
};
function progress(job, phase, step, percent) {
	job.state = phase; job.step = step; job.progressPercent = percent; write(JOB, job);
};
function world_after(before, additions, removals) {
	if (!engines.world_pins(before, packages.world(), additions, removals)) fail('PACKAGE_VERIFICATION_FAILED');
};

function process_snapshot(pid) {
	if (type(pid) != 'int' || pid < 2 || pid > 4194304) return null;
	let raw = fs.readfile('/proc/' + pid + '/stat', 8192), match_stat = match(raw || '', /^([0-9]+) \(.*\) (.*)$/);
	if (!match_stat) return null;
	let fields = split(trim(match_stat[2]), / +/);
	let command = fs.readfile('/proc/' + pid + '/cmdline', 8192), directory = fs.stat('/proc/' + pid);
	if (length(fields) < 20 || !match(fields[19] || '', /^[0-9]+$/) || !command) return null;
	return { pid, start: fields[19], commandSha256: digest.sha256(command),
		root: directory?.uid == 0, zombie: fields[0] == 'Z' };
};
function self_worker() {
	let raw = fs.readfile('/proc/self/stat', 8192), found = match(raw || '', /^([0-9]+) /);
	let value = found ? process_snapshot(+found[1]) : null;
	if (!value || !value.root || value.zombie) fail('ROUTER_UNAVAILABLE');
	return { pid: value.pid, start: value.start, commandSha256: value.commandSha256, bootId: boot() };
};
export function defer_stop_for_update() {
 let job = read('/etc/foxhole/update-job.json', 524288);
 return active(job) && job.operation == 'APPLY' && job.atomicPackagePhase == true &&
  engines.worker_current(job.worker, process_snapshot(job.worker?.pid), boot());
};
function reconcile(value, context) {
	let launch = false;
	if (!value || index(['SUCCEEDED', 'FAILED'], value.state) >= 0 ||
	    engines.worker_current(value.worker, process_snapshot(value.worker?.pid), context.bootId)) return value;
	if (value.state == 'QUEUED' && value.bootId == context.bootId && now() <= value.createdAtUptimeMs + 10000) return value;
	try {
		value = locked(() => {
			let current = read(JOB, 524288);
			if (index(['SUCCEEDED', 'FAILED'], current.state) >= 0) return current;
			if (current.jobId != value.jobId || engines.worker_current(current.worker,
			    process_snapshot(current.worker?.pid), context.bootId)) return current;
			if (current.recoveryRequestedAt != null && current.bootId == context.bootId && now() - current.recoveryRequestedAt < 5000)
				return current;
			if (index(REASONS, current.failureReason) < 0) current.failureReason = 'ROUTER_UNAVAILABLE';
			current.recoveryRequestedAt = now(); current.worker = null; launch = true;
			progress(current, 'RECOVERY_REQUIRED', 'RECOVERY_REQUIRED', current.progressPercent);
			return current;
		});
		if (launch) system(['/bin/sh', '-c', 'umask 077; /usr/libexec/foxhole-engine-job ' + value.jobId + ' recover >/dev/null 2>&1 &'], 1000);
	} catch (_) {}
	return value;
};
function apk_idle() {
	let path = '/lib/apk/db/lock', info = fs.lstat(path);
	if (info?.type != 'file' || info.uid != 0 || info.nlink != 1 || (info.mode & 0o077)) fail('BUSY');
	let handle = fs.open(path, 'r');
	if (!handle || !handle.lock('xn')) { try { if (handle) handle.close(); } catch (_) {} fail('BUSY'); }
	return handle;
};
function start_if_allowed(job, action) {
	if (index(['start', 'restart'], action) < 0) return false;
	let path = '/etc/foxhole/state.lock';
	store.target(path);
	let lock = fs.open(path, 'a+', 0o600), result = false;
	if (!lock || !lock.lock('xn') || !store.file_metadata(fs.lstat(path))) {
		try { if (lock) lock.close(); } catch (_) {}
		return false;
	}
	try {
		if (principal_current(job.principal) && engines.restart_allowed(job.plan.binding, registry.snapshot_context(state())))
			result = system(['/etc/init.d/foxhole-runtime', action], 15000) == 0;
	} catch (_) {}
	try { lock.lock('u'); lock.close(); } catch (_) { return false; }
	return result;
};
function reconnect_proven(job, selected, minimum, previous_key) {
	let current = state(), context = registry.snapshot_context(current);
	if (!engines.restart_allowed(job.plan.binding, context)) return false;
	let server = filter(current.servers, row => row.id == current.activeServerId)[0];
	if (server?.engine != 'core') return false;
	if (selected) registry.verify_slot(selected);
	let native = read('/tmp/foxhole/core-state.json', 8192), process = process_snapshot(native?.pid);
	let executable = fs.stat('/proc/' + native?.pid + '/exe');
	let expected = fs.stat(selected ? registry.running_executable(selected) : '/usr/bin/foxcore-cli');
	if (!process?.root || process.zombie || process.start != '' + native.process_start || native.phase != 'running' ||
	    !executable || executable.inode != expected?.inode ||
	    executable.dev?.major != expected.dev?.major || executable.dev?.minor != expected.dev?.minor) return false;
	let owner = adapter.receipt('owner'), key = adapter.generation(owner), stamp = now();
	let proof = read(adapter.proof_path, 4096);
	if (!key || key == previous_key || !core.proof_valid(proof, server, owner, stamp, context.bootId, minimum)) return false;
	let raw_config = store.read(adapter.config_path, 262144);
	if (!raw_config || digest.sha256(raw_config) != digest.sha256(server.config)) return false;
	let status = read('/tmp/foxhole/runtime.json', 8192), policy = read(adapter.policy_path, 4096);
	if (status?.phase != 'connected' || status.connected != true || status.enforced != true ||
	    status.activeServerId != server.id || policy?.generation_key != key || policy.serverId != server.id ||
	    policy.stateIdentity != adapter.policy_identity(current) ||
	    policy.kernelIdentity != adapter.kernel_policy(key, policy.stateIdentity)) return false;
	let after = adapter.receipt('owner');
	return after?.owned == true && adapter.generation(after) == key && boot() == context.bootId;
};
function wait_reconnect(job, selected, minimum, previous_key) {
	for (let attempt = 0; attempt < 45; attempt++) {
		if (!engines.restart_allowed(job.plan.binding, registry.snapshot_context(state()))) return false;
		if (reconnect_proven(job, selected, minimum, previous_key)) return true;
		system(['/bin/sleep', '1'], 1500);
	}
	return false;
};
export function status(principal) {
	let current = registry.catalog(), installed = registry.read(), context = registry.snapshot_context(state());
	let value = engines.status(current.value, installed, context), job = read(JOB, 524288);
	job = reconcile(job, context);
	let update = read('/etc/foxhole/update-job.json', 524288);
	value.busy = active(update) || update?.state == 'RECOVERY_REQUIRED' || active(job) || job?.state == 'RECOVERY_REQUIRED' && job.plan.impact == 'RECONNECT_REQUIRED';
	value.activeOwnJob = active(job) ? job_ref(job, owner(principal)) : null;
	value.lastOwnJob = job_ref(job, owner(principal));
	// Keep the existing provider without inventing module readiness.
	let legacy = registry.legacy_protocols();
	for (let row in value.entries) if (!row.installed && index(legacy, row.id) >= 0 && fs.lstat('/usr/bin/foxcore-cli')) {
		row.installed = true; row.version = null; row.storage = null;
		row.updateAvailable = row.availability == 'AVAILABLE';
	}
    let facts=protocol_facts.installed();
    for(let id in (facts?.schema==1&&type(facts.protocols)=='array'?facts.protocols:[])) {
        for(let row in value.entries)if(row.id==id&&!row.installed) {
            row.installed=true;row.storage=null;row.version=null;row.binarySha256=null;row.updateAvailable=false;
        }
    }
    if(fs.lstat('/tmp/foxhole-ram-active.json'))value.managementSupported=false;
	return value;
};
export function plan(request, principal) {
 if(fs.lstat('/tmp/foxhole-ram-active.json'))fail('UNSUPPORTED_TARGET');
	guard_mutation();
	if (read(JOB, 524288)?.state == 'RECOVERY_REQUIRED') fail('RECOVERY_REQUIRED');
	if (active(read(JOB, 524288))) fail('BUSY');
	let context = registry.snapshot_context(state());
	let value = engines.plan(request, registry.catalog().value, registry.read(), context, owner(principal), nonce(), now());
	write('/tmp/foxhole/engine-plan-' + owner(principal), value);
	return engines.public_plan(value);
};
export function job(id, principal) {
	let value = read(JOB, 524288);
	if (!value || value.jobId != id || value.owner != owner(principal)) fail('AUTHENTICATION_FAILED');
	value = reconcile(value, { bootId: boot() });
	if (value.jobId != id || value.owner != owner(principal)) fail('AUTHENTICATION_FAILED');
	return public_job(value);
};
export function apply(request, principal) {
 if(fs.lstat('/tmp/foxhole-ram-active.json'))fail('UNSUPPORTED_TARGET');
	let result = locked(() => {
		guard_mutation();
		if (read(JOB, 524288)?.state == 'RECOVERY_REQUIRED') fail('RECOVERY_REQUIRED');
	if (active(read(JOB, 524288))) fail('BUSY');
		let value = read('/tmp/foxhole/engine-plan-' + owner(principal), 262144);
		if (!value) fail('STALE_PLAN');
		let current = registry.read(), context = registry.snapshot_context(state());
		engines.admit_apply(value, request, current, context, owner(principal), now());
		let job = { schema: 1, routerId: context.routerId, jobId: 'engine-job-' + substr(nonce(), 0, 32),
			planId: value.planId, owner: owner(principal), principal, plan: value, previousRegistry: current,
			state: 'QUEUED', step: 'PREPARING', progressPercent: 0, revision: current.revision,
			failureReason: null, previousConnectionRestored: null, mutationStarted: false,
			createdAtUptimeMs: now(), bootId: context.bootId };
		write(JOB, job);

		return public_job(job);
	});
	if (system(['/bin/sh', '-c', 'umask 077; /usr/libexec/foxhole-engine-job ' + result.jobId + ' >/dev/null 2>&1 &'], 1000) != 0) {
		locked(() => {
			let value = read(JOB, 524288);
			if (value?.jobId == result.jobId && value.state == 'QUEUED') {
				value.state = 'FAILED'; value.step = 'FAILED'; value.failureReason = 'ROUTER_UNAVAILABLE'; write(JOB, value);
			}
		});
	}
	return job(result.jobId, principal);
};

function prepare_packages(job,directory,recovery) {
    store.directory(directory);store.directory(directory+'/keys');
    if(registry.hash_file(KEY)!=PUBLIC_RELEASE_PEM_DIGEST||
       system(['/bin/cp',KEY,directory+'/keys/foxhole.pem'],3000)!=0)fail('PACKAGE_VERIFICATION_FAILED');
    let items=[],indexes=[],roots=[];
    for(let v in job.plan.artifacts) {
        if(!principal_current(job.principal))fail('AUTHENTICATION_FAILED');
        if(!recovery&&now()>job.plan.expiresAtUptimeMs)fail('STALE_PLAN');
        progress(job,'DOWNLOADING','DOWNLOADING_PACKAGE',10);
        let item=packages.candidate(v,directory,directory+'/keys'),idx=directory+'/index-'+v.indexSha256+'.adb';
        if(!fs.lstat(idx)&&system(['/bin/cp',item.index,idx],3000)!=0)fail('PACKAGE_VERIFICATION_FAILED');
        if(index(indexes,idx)<0)push(indexes,idx);
        push(roots,v.packageName);push(items,item);
    }
    write(directory+'/repositories.json',indexes);
    store.write(directory+'/repositories',join('\n',indexes)+'\n');
    return {items,roots,common:['--no-network','--no-cache','--repositories-file',directory+'/repositories','--keys-dir',directory+'/keys']};
};
function reinstall_identity(prepared,directory) {
    let installed=native_identity.installed_identities(),identity=[];
    for(let item in prepared) {
        let v=item.value,row=installed[v.packageName];
        if(row?.version!=v.packageVersion||row.arch!=v.architecture||row.cas!=native_identity.native_cas(item.nativeId)||
           registry.hash_file(item.package)!=v.packageSha256||registry.hash_file(directory+'/index-'+v.indexSha256+'.adb')!=v.indexSha256)
            fail('PACKAGE_VERIFICATION_FAILED');
    }
    for(let name in sort(keys(installed))) {
        let row=installed[name];push(identity,[name,row.version,row.arch,row.cas,row.flags]);
    }
    return digest.sha256(sprintf('%J',identity));
};
function repair_state(job,old) {
    if(fs.lstat('/tmp/foxhole-ram-active.json')||!principal_current(job.principal))fail('STALE_PLAN');
    if(job.owner!=owner(job.principal)||job.plan.owner!=job.owner||job.planId!=job.plan.planId||
       job.bootId!=job.plan.binding.bootId)fail('STALE_PLAN');
    let ctx=registry.snapshot_context(state()),current=registry.read();
    engines.reinstall_bound(job.plan,old,current,ctx);
    if(current.revision!=old.revision&&job.reinstallCommitStarted!=true)fail('STALE_PLAN');
    if(!engines.world_pins(job.worldBefore,packages.world(),[],[]))fail('PACKAGE_VERIFICATION_FAILED');
    return current;
};
function reinstall(job,old,batch,directory,recovery) {
    let items=batch.items,roots=batch.roots,current=repair_state(job,old);
    let identity=reinstall_identity(items,directory),diagnosis=packages.repair_diagnosis(items);
    let damaged=length(filter(diagnosis,row=>row.damagedPackageFiles||row.ramBinaryVerified==false));
    if(!recovery) {
        job.reinstallInstalledSha256=identity;job.reinstallDiagnosis=diagnosis;write(JOB,job);
    } else if(job.reinstallInstalledSha256!=identity)fail('RECOVERY_REQUIRED');
    let unconfirmed=recovery&&job.reinstallRecoveryAttempted&&!job.reinstallNativeDone&&!damaged;
    if(!unconfirmed&&(!recovery||!job.reinstallNativeDone||damaged)) {
        if(recovery&&job.reinstallRecoveryAttempted)fail('RECOVERY_REQUIRED');
        let simulation=packages.apk([...batch.common,'fix','--simulate','--reinstall',...roots]);
        if(!engines.reinstall_only(simulation,job.plan.artifacts))fail('PACKAGE_VERIFICATION_FAILED');
        repair_state(job,old);
        if(reinstall_identity(items,directory)!=identity)fail('PACKAGE_VERIFICATION_FAILED');
        if(!recovery)engines.admit_apply(job.plan,{planId:job.planId,planSha256:job.plan.planSha256,
            expectedRevision:old.revision,confirmed:true},registry.read(),registry.snapshot_context(state()),job.owner,now());
        job.mutationStarted=true;if(recovery)job.reinstallRecoveryAttempted=true;
        progress(job,'INSTALLING','INSTALLING_PACKAGE',45);
        let result=packages.apk([...batch.common,'fix','--reinstall',...roots],120000);
        if(!engines.reinstall_only(result,job.plan.artifacts))fail('PACKAGE_VERIFICATION_FAILED');
        for(let item in items)packages.repair_ram(item.value,nonce());
        job.reinstallNativeDone=true;write(JOB,job);
    }
    progress(job,'CHECKING','CHECKING_ENGINE',75);
    if(reinstall_identity(items,directory)!=identity||
       length(filter(packages.repair_diagnosis(items),row=>row.damagedPackageFiles||row.ramBinaryVerified==false)))
        fail('PACKAGE_VERIFICATION_FAILED');
    for(let item in items) {
        let v=item.value,path=registry.verify_slot(v),cap=packages.decode(registry.capture([path,'capabilities'],131072,130000));
        if(cap.platform!='linux'||cap.router_contract_version!=1||cap.core_version!=v.version||
           sprintf('%J',cap.protocols)!=sprintf('%J',[v.id]))fail('CANDIDATE_CHECK_FAILED');
    }
    current=repair_state(job,old);
    if(current.revision==old.revision) {
        job.reinstallCommitStarted=true;write(JOB,job);
        registry.write({...old,revision:old.revision+1});
    }
    let published=registry.read();
    if(published.revision!=old.revision+1||sprintf('%J',published)!=sprintf('%J',{...old,revision:old.revision+1}))
        fail('RECOVERY_REQUIRED');
    job.revision=published.revision;
    if(unconfirmed) {
        job.failureReason='ROUTER_UNAVAILABLE';progress(job,'FAILED','FAILED',job.progressPercent);
    } else {
        job.failureReason=null;progress(job,'SUCCEEDED','COMPLETED',100);
    }
};
export function recover(id) {
	backup_service.guard();
	return locked(() => {
		let job = read(JOB, 524288), database_lock = null;
		if (!job || job.jobId != id || job.state != 'RECOVERY_REQUIRED') fail('STALE_PLAN');
		job.worker = self_worker(); write(JOB, job);
		try {
            if(job.mutationStarted&&job.plan.operation=='REINSTALL') {
                if(fs.lstat('/tmp/foxhole-ram-active.json')||job.bootId!=boot()||!principal_current(job.principal))fail('RECOVERY_REQUIRED');
                let old=job.previousRegistry;
                repair_state(job,old);
                // Revalidate the original private stage without allocating a second set of archives.
                let directory='/tmp/foxhole/'+id;
                reinstall(job,old,prepare_packages(job,directory,true),directory,true);
                return public_job(job);
            }
			database_lock = apk_idle();
			let before = job.installedBefore, before_world = job.worldBefore;
			if (!job.mutationStarted) {
				if (index(REASONS, job.failureReason) < 0) job.failureReason = 'ROUTER_UNAVAILABLE'; progress(job, 'FAILED', 'FAILED', job.progressPercent);
			} else {
				if (type(before) != 'object' || type(before_world) != 'array') fail('RECOVERY_REQUIRED');
				let after = packages.installed(), additions = map(job.plan.artifacts, item => item.packageName);
				let removals = map(filter(job.previousRegistry.slots, item => index(job.plan.removals, item.id) >= 0), item => item.packageName);
				for (let name, item in before)
					if (index(removals, name) < 0 && sprintf('%J', after[name]) != sprintf('%J', item)) fail('RECOVERY_REQUIRED');
				for (let name in keys(after)) if (!before[name] && index(additions, name) < 0) fail('RECOVERY_REQUIRED');
				let actual_world = packages.world();
				for (let pin in before_world)
					if (index(actual_world, pin) < 0 && index(removals, pin) < 0) fail('RECOVERY_REQUIRED');
				for (let pin in actual_world)
					if (index(before_world, pin) < 0 && index(additions, pin) < 0) fail('RECOVERY_REQUIRED');
				let old = job.previousRegistry, current = registry.read();
				let planned = engines.commit(old, job.plan.artifacts, job.plan.removals, old.revision);
				let same_old = sprintf('%J', { ...current, revision: 0 }) == sprintf('%J', { ...old, revision: 0 });
				let same_new = sprintf('%J', { ...current, revision: 0 }) == sprintf('%J', { ...planned, revision: 0 });
				if ((!same_old && !same_new) || current.revision < old.revision) fail('RECOVERY_REQUIRED');
				let restored = { ...old, revision: max(old.revision, current.revision) + 1 };
				restored.slots = filter(restored.slots, item => after[item.packageName] != null);
				restored.selected = filter(restored.selected, item => length(filter(restored.slots, slot => engines.slot_id(slot) == item.slotId)) > 0);
				let context = registry.snapshot_context(state());
				let restart = principal_current(job.principal) && job.plan.impact == 'RECONNECT_REQUIRED' && engines.restart_allowed(job.plan.binding, context);
				let old_key = restart ? adapter.generation(adapter.receipt('owner')) : null;
				if (restart && system(['/etc/init.d/foxhole-runtime', 'stop'], 15000) != 0) fail('RECOVERY_REQUIRED');
				registry.write(restored); job.revision = restored.revision;
				if (restart) {
					let started = now();
					if (!engines.restart_allowed(job.plan.binding, registry.snapshot_context(state())) ||
					    !start_if_allowed(job, 'start') ||
					    !wait_reconnect(job, engines.selected(restored, job.plan.binding.activeEngineId), started, old_key))
						fail('RECOVERY_REQUIRED');
					job.previousConnectionRestored = true;
				}
				if (index(REASONS, job.failureReason) < 0) job.failureReason = 'ROUTER_UNAVAILABLE'; progress(job, 'FAILED', 'FAILED', job.progressPercent);
			}
		} catch (_) { progress(job, 'RECOVERY_REQUIRED', 'RECOVERY_REQUIRED', job.progressPercent); }
		try { if (database_lock) { database_lock.lock('u'); database_lock.close(); } } catch (_) {}
		return public_job(job);
	});
};
export function run(id) {
 if(fs.lstat('/tmp/foxhole-ram-active.json'))fail('UNSUPPORTED_TARGET');
	backup_service.guard();
	return locked(() => {
		let update = read('/etc/foxhole/update-job.json', 524288);
		if (active(update) || update?.state == 'RECOVERY_REQUIRED') fail('BUSY');
		let job = read(JOB, 524288);
		if (!job || job.jobId != id || job.state != 'QUEUED') fail('STALE_PLAN');
		let old = job.previousRegistry, committed = false, stopped = false;
		job.worker = self_worker();
		progress(job, 'VERIFYING', 'PREPARING', 1);
		try {
			if (!principal_current(job.principal)) fail('AUTHENTICATION_FAILED');
			let apply_request = { planId: job.planId, planSha256: job.plan.planSha256,
				expectedRevision: old.revision, confirmed: true };
			engines.admit_apply(job.plan, apply_request, registry.read(), registry.snapshot_context(state()), job.owner, now());
			let directory = '/tmp/foxhole/' + id;
            let before=packages.installed(),before_world=packages.world(),removed_packages=[];
            job.installedBefore=before;job.worldBefore=before_world;write(JOB,job);
            let batch=prepare_packages(job,directory,false),prepared=batch.items,roots=batch.roots,common=batch.common;
            if(job.plan.operation=='REINSTALL') {
                reinstall(job,old,batch,directory,false);
                return public_job(job);
            }
			if (length(roots)) {
				let selected = packages.decode(packages.apk([...common, 'query', '--format', 'json', '--world', '--recursive', ...roots]));
				let delta = [];
				if (type(selected) != 'array' || length(selected) > 4096) fail('PACKAGE_VERIFICATION_FAILED');
				for (let row in selected) {
					if (before[row.name]) {
						if (before[row.name].version != row.version || before[row.name].arch != row.arch) fail('PACKAGE_VERIFICATION_FAILED');
					} else push(delta, { name: row.name, action: 'install' });
				}
				if (!engines.add_only_delta(delta, filter(job.plan.artifacts, item => before[item.packageName] == null))) fail('PACKAGE_VERIFICATION_FAILED');
				packages.apk([...common, 'add', '--simulate', ...roots]);
			}
			if (!principal_current(job.principal)) fail('AUTHENTICATION_FAILED');
			engines.admit_apply(job.plan, apply_request, registry.read(), registry.snapshot_context(state()), job.owner, now());
			if (length(roots)) {
				progress(job, 'INSTALLING', 'INSTALLING_PACKAGE', 40); job.mutationStarted = true; write(JOB, job);
				packages.apk([...common, 'add', ...roots], 120000);
			}
			if (length(job.plan.removals)) {
				let remove = filter(old.slots, item => index(job.plan.removals, item.id) >= 0);
				let names = map(remove, item => item.packageName); removed_packages = names;
				if (!length(names)) fail('INVALID_REQUEST');
				let simulated = packages.apk(['--no-network', '--repositories-file', '/dev/null', 'del', '--simulate', ...names]);
				if (!engines.purge_only(simulated, names, before)) fail('PACKAGE_VERIFICATION_FAILED');
				job.mutationStarted = true; progress(job, 'INSTALLING', 'INSTALLING_PACKAGE', 50);
				packages.apk(['--no-network', '--repositories-file', '/dev/null', 'del', ...names], 120000);
			}
			world_after(before_world, roots, removed_packages);
			let after = packages.installed();
			for (let name, row in before) {
				let removed = length(filter(old.slots, item => item.packageName == name && index(job.plan.removals, item.id) >= 0)) > 0;
				if (removed ? after[name] != null : sprintf('%J', after[name]) != sprintf('%J', row)) fail('PACKAGE_VERIFICATION_FAILED');
			}
			for (let name in keys(after))
				if (!before[name] && !length(filter(job.plan.artifacts, item => item.packageName == name))) fail('PACKAGE_VERIFICATION_FAILED');
			for (let value in job.plan.artifacts) {
				if (after[value.packageName]?.version != value.packageVersion) fail('PACKAGE_VERIFICATION_FAILED');
				progress(job, 'CHECKING', 'CHECKING_ENGINE', 65);
				registry.verify_slot(value);
				let path = registry.executable(value);
				let capabilities = packages.decode(registry.capture([path, 'capabilities'], 131072, 130000));
				if (capabilities.router_contract_version != 1 || capabilities.platform != 'linux' ||
				    capabilities.core_version != value.version || sprintf('%J', capabilities.protocols) != sprintf('%J', [value.id]))
					fail('CANDIDATE_CHECK_FAILED');
				if (job.plan.binding.activeEngineId == value.id) {
					let server = filter(state().servers, row => row.id == job.plan.binding.activeProfileId)[0];
					if (!server) fail('STALE_PLAN');
					store.write(directory + '/check-config', server.config);
					registry.capture([path, 'check', '--config', directory + '/check-config'], 65536, 130000);
				}
			}
			if (job.plan.impact == 'RECONNECT_REQUIRED') {
				if (!engines.restart_allowed(job.plan.binding, registry.snapshot_context(state()))) fail('STALE_PLAN');
				job.previousGeneration = adapter.generation(adapter.receipt('owner'));
				job.restartStarted = now(); write(JOB, job);
				if (system(['/etc/init.d/foxhole-runtime', 'stop'], 15000) != 0) fail('RECONNECT_FAILED');
				stopped = true;
			}
			progress(job, 'CHECKING', 'SWITCHING_ENGINE', 80);
			let next = engines.commit(old, job.plan.artifacts, job.plan.removals, old.revision);
			registry.write(next); committed = true; job.revision = next.revision;
			if (stopped) {
				progress(job, 'RECONNECTING', 'RECONNECTING_VPN', 85);
				if (!principal_current(job.principal) || !engines.restart_allowed(job.plan.binding, registry.snapshot_context(state())) ||
				    !start_if_allowed(job, 'start')) fail('RECONNECT_FAILED');
				if (!wait_reconnect(job, engines.selected(next, job.plan.binding.activeEngineId), job.restartStarted, job.previousGeneration))
					fail('RECONNECT_FAILED');
			}
			try { fs.unlink(directory + '/check-config'); } catch (_) {}
			progress(job, 'SUCCEEDED', 'COMPLETED', 100);
		} catch (error) {
			let code = type(error) == 'string' ? error : error.message;
			let reason = uc(substr(code || '', 0, 7) == 'engine_' ? substr(code, 7) : 'package_verification_failed');
			if (index(REASONS, reason) < 0) reason = 'PACKAGE_VERIFICATION_FAILED';
			if (committed) {
				try { let restored = { ...old, revision: job.revision + 1 }; registry.write(restored); job.revision = restored.revision; } catch (_) { reason = 'RECOVERY_REQUIRED'; }
			}
			if (stopped && engines.restart_allowed(job.plan.binding, registry.snapshot_context(state()))) {
				job.previousConnectionRestored = false;
				start_if_allowed(job, 'restart');
			}
			try { fs.unlink('/tmp/foxhole/' + id + '/check-config'); } catch (_) {}
			job.failureReason = reason;
			progress(job, job.mutationStarted || stopped ? 'RECOVERY_REQUIRED' : 'FAILED',
				job.mutationStarted || stopped ? 'RECOVERY_REQUIRED' : 'FAILED', job.progressPercent);
		}
		return public_job(job);
	});
};

// Internal updater adapters retain the original engine
// primitives.
export function update_locked(fn) { return locked(fn); };
export function update_principal_current(principal) { return principal_current(principal); };
export function update_apk(argv, timeout) { return packages.apk(argv, timeout); };
export function update_installed(tolerate) { return packages.installed(tolerate); };
export function update_asset(url, expected, maximum) { return packages.asset(url, expected, maximum); };
export function update_candidate(value, directory, keys) { return packages.candidate(value, directory, keys); };
export function update_world() { return packages.world(); };
export function update_state() { return state(); };
export function update_now() { return now(); };
export function update_process_snapshot(pid) { return process_snapshot(pid); };
export function update_self_worker() { return self_worker(); };
export function update_boot() { return boot(); };
export function update_wait_reconnect(job, selected, minimum, previous_key) { return wait_reconnect(job, selected, minimum, previous_key); };
