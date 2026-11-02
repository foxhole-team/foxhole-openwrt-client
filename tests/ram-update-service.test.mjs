// Actual controller source with in-memory OS/native-command adapters.
// These tests prove protocol ordering, not real APK signatures or switch QA.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const modules = resolve(root, 'package/foxhole-openwrt-client/root/usr/share/foxhole');
const sha = value => createHash('sha256').update(value).digest('hex');
const clone = value => JSON.parse(JSON.stringify(value));
const globals = {
  type: value => value == null ? 'null' : Array.isArray(value) ? 'array' : typeof value === 'boolean' ? 'bool' : Number.isInteger(value) ? 'int' : typeof value,
  length: value => Buffer.isBuffer(value) || Array.isArray(value) ? value.length : typeof value === 'string' ? Buffer.byteLength(value) : Object.keys(value).length,
  keys: Object.keys, map: (value, fn) => value.map(fn), filter: (value, fn) => value.filter(fn), sort: value => [...value].sort(),
  split: (value, separator) => value.split(separator), join: (separator, value) => value.join(separator), shift: value => value.shift(), push: (value, item) => value.push(item),
  index: (value, item) => value.indexOf(item), match: (value, pattern) => String(value).match(pattern),
  substr: (value, from, count) => value.substr(from, count), slice: (value, from, to) => value.slice(from, to),
  replace: (value, search, replacement) => value.replace(search, replacement), trim: value => value.trim(),
  lc: value => value.toLowerCase(), uc: value => value.toUpperCase(), int: Math.trunc, min: Math.min,
  json: JSON.parse, sprintf: (format, value) => { assert.equal(format, '%J'); return JSON.stringify(value); },
  b64dec: value => Buffer.from(value, 'base64'), b64enc: value => Buffer.from(value).toString('base64'),
  hexenc: value => Buffer.from(value).toString('hex'), digest: { sha256: sha },
  die: error => { throw error instanceof Error ? error : new Error(String(error)); }
};
function load(name, bindings, replaceCapture = false) {
  let source = readFileSync(resolve(modules, name), 'utf8');
  const exported = [...source.matchAll(/^export (?:function|const) (\w+)/gm)].map(found => found[1]);
  source = source.replace(/^import .*;\n/gm, '').replace(/^export /gm, '')
    .replace(/for \(let (\w+), (\w+) in (\w+)\)/g, 'for (let [$1,$2] of Object.entries($3))')
    .replace(/\bfor\(let (\w+) in /g, 'for(let $1 of ').replace(/\bfor \(let (\w+) in /g, 'for (let $1 of ')
    .replaceAll('[[:cntrl:]]', '[\\u0000-\\u001f\\u007f]');
  if (replaceCapture) source = source.replace('function capture(', 'function native_capture_not_executed(')
    .replace('}catch(error){failed(job,error);}', '}catch(error){test_failure(error);failed(job,error);}');
  const values = { ...globals, ...bindings };
  return new Function(...Object.keys(values), `${source}\nreturn {${exported.join(',')}};`)(...Object.values(values));
}
class Memory {
  files = new Map(); serial = 20; clock = 1000; random = 1; crashAppend = false;
  put(path, raw, mode = 0o600) {
    this.dir(dirname(path));this.files.set(path, { type: 'file', uid: 0, gid: 0, nlink: 1, mode,
      size: Buffer.byteLength(raw), inode: ++this.serial, dev: { major: 0, minor: 1 }, mtime: this.serial, ctime: this.serial, raw });
  }
  dir(path, mode = 0o700) {
    if (this.files.has(path)) return;
    if (path !== '/') this.dir(dirname(path), 0o755);
    this.files.set(path, { type: 'directory', uid: 0, gid: 0, nlink: 1, mode, size: 0, inode: ++this.serial,
      dev: { major: 0, minor: 1 }, mtime: this.serial, ctime: this.serial });
  }
  get(path) {return this.files.get(path)?.raw ?? null;}
  json(path) {const raw=this.get(path);return raw==null?null:JSON.parse(raw);}
  open(path, flags, mode = 0o600) {
    if (flags.includes('x') && this.files.has(path)) return null;
    if (!this.files.has(path)) this.put(path, '', mode);
    let position = flags === 'a' ? this.get(path).length : 0;
    return { lock: () => true, close: () => {}, flush: () => true,
      seek: value => { position = value; return true; },
      read: count => { const value=this.get(path).slice(position,position+count);position+=value.length;return value; },
      write: bytes => {
        const value=typeof bytes==='string'?bytes:bytes.toString('latin1');
        this.put(path, this.get(path) + value, mode);
        if (this.crashAppend && path.endsWith('/payload')) {this.crashAppend=false;throw new Error('injected after append');}
        return value.length;
      }
    };
  }
  fs() {
    return { dirname, lstat: path => this.files.has(path) ? { ...this.files.get(path) } : null,
      readfile: (path, maximum) => path === '/dev/urandom' ? Buffer.alloc(maximum,this.random++)
        : path === '/proc/uptime' ? `${(this.clock/1000).toFixed(2)} 0.00` : path === '/proc/meminfo' ? 'MemAvailable: 131072 kB\n'
        : path === '/proc/sys/kernel/random/boot_id' ? '12345678-1234-1234-1234-123456789abc'
        : path === '/proc/self/mountinfo' ? '' : this.get(path)?.slice(0,maximum) ?? null,
      open: (...args) => this.open(...args), unlink: path => this.files.delete(path),
      rmdir: path => this.files.delete(path), rename: (from,to) => {if(!this.files.has(from))return false;this.files.set(to,this.files.get(from));this.files.delete(from);return true;},
      glob: pattern => {const p=dirname(pattern),hidden=pattern.endsWith('/.*');return [...this.files.keys()].filter(path=>path!==p&&dirname(path)===p&&(path.slice(p.length+1).startsWith('.')===hidden));} };
  }
  store() {return { directory: path=>this.dir(path), target: ()=>{}, file_metadata:()=>true,
    read:(path,max)=>{const raw=this.get(path);if(raw!=null&&Buffer.byteLength(raw)>max)throw new Error('oversized');return raw;},
    write:(path,raw)=>this.put(path,raw) };}
}
const STATE='/etc/foxhole/update-state.json', JOB='/etc/foxhole/update-job.json', ROOT='/tmp/foxhole/ram-updates';
const PROFILE='/etc/foxhole/state.json', MARKER='/tmp/foxhole-ram-active.json';
function fixture() {
  const memory=new Memory(), environment={ authorized:true, signature:true, switched:true, nativeVersion:'1.0.1-r1', captures:[], launched:[] };
  const updates=load('update-model.uc',{}),model=load('ram-update-model.uc',{updates});
  const publicKey=readFileSync(resolve(root,'config/foxhole-openwrt-apk.pem'),'utf8');assert.equal(sha(publicKey),model.signer_sha256);
  memory.dir('/tmp',0o1777);memory.dir('/tmp/foxhole');memory.dir('/etc/foxhole');memory.dir('/etc/config',0o755);
  const initial='/tmp/foxhole-ram-stage-20261031-ninth';memory.dir(initial);memory.put(`${initial}/root/lib/apk/db/installed`,'stage-db',0o644);
  memory.put(MARKER,JSON.stringify({schema:1,storage:'RAM',phase:'active',stage:initial,version:'1.0.1',baseSha256:'c'.repeat(64)}));
  memory.put('/usr/share/foxhole/foxhole-openwrt-apk.pem',publicKey,0o644);memory.put('/usr/libexec/foxhole-ram-switch','trusted-fixture',0o755);
  memory.put(PROFILE,JSON.stringify({schema:1,revision:5,activeServerId:null,settings:{language:'ru'},servers:[],clients:[],countries:[],devices:[],sites:[]}));
  memory.put('/etc/foxhole/auth.json',JSON.stringify({schema:1,hash:'synthetic-private'}));
  memory.put('/etc/foxhole/pairing.json',JSON.stringify({schema:1,devices:[]}));
  for(const file of ['foxhole','network','dhcp','firewall','uhttpd'])memory.put(`/etc/config/${file}`,`${file}-private-config`,0o644);
  memory.put('/etc/apk/world','host-world\n',0o644);memory.put('/lib/apk/db/installed','host-db-185',0o644);
  const policy={schema:1,transactionAbi:1,stateAbi:1,osRelease:'25.12.5',packageVersion:'1.0.2-r1',releaseTag:'v1.0.2',targets:['x86/64','mediatek/filogic']};
  const bodies=new Map([
    ['usr/share/foxhole/update-policy.json',JSON.stringify(policy)],['usr/share/foxhole/engine-catalog.json','{}'],
    ['usr/share/foxhole/update-service.uc','fixture'],['usr/libexec/foxhole-update-job','fixture'],['www/foxhole.html','fixture'],
    ['usr/share/rpcd/ucode/foxhole.uc','fixture'],['etc/config/foxhole','fixture'],['lib/apk/packages/foxhole-openwrt-client.list','fixture'],
    ['usr/share/foxhole/foxhole-openwrt-apk.pem',publicKey]
  ]);
  const folders=new Map();for(const [path,body]of bodies){const parent=dirname(path);if(!folders.has(parent))folders.set(parent,[]);folders.get(parent).push({name:path.slice(parent.length+1),size:body.length,hash:sha(body),acl:{mode:0o644,user:'0',group:'0'}});}
  const payload={info:{name:'foxhole-openwrt-client',version:'1.0.2-r1',arch:'noarch','installed-size':2000,depends:['libc']},scripts:{},triggers:[],paths:[...folders].map(([name,files])=>({name,acl:{mode:0o755,user:'0',group:'0'},files}))};
  const apk='signed-fixture-apk',manifest={expectedRevision:0,requestId:'a'.repeat(32),releaseTag:'v1.0.2',version:'1.0.2-r1',fileSha256:sha(apk),fileBytes:apk.length};
  const principal={kind:'admin',user:'root',verifier:'a'.repeat(64)};
  const binding=profile=>({routerId:sha('router'),bootId:'12345678-1234-1234-1234-123456789abc',architecture:'aarch64_cortex-a53',worldSha256:sha(memory.get('/etc/apk/world')),
    catalogSha256:sha('catalog'),stopIntent:memory.json('/etc/foxhole/engine-intent.json')?.revision??0,activeProfileId:profile.activeServerId,
    activeConfigSha256:null,flashAvailableBytes:100000000,ramAvailableBytes:100000000});
  const capture=(operation,args)=>{
    environment.captures.push(operation);
    environment.beforeCapture?.(operation,args);
    if(operation==='current')return {code:0,stdout:JSON.stringify([{name:'foxhole-openwrt-client',version:environment.nativeVersion,arch:'noarch',status:['installed']}]),stderr:''};
    if(operation==='probe')return environment.probe??{code:4,stdout:'',stderr:'Connection error: Connection failed'};
    if(operation==='verify')return {code:environment.signature?0:1,stdout:'',stderr:environment.signature?'':'signature rejected'};
    if(operation==='dump')return {code:0,stdout:JSON.stringify(payload),stderr:''};
    if(operation==='dependencies')return {code:environment.missingDependency?1:0,stdout:JSON.stringify([{name:'libc',status:['installed']}]),stderr:''};
    if(operation==='extract') {for(const [path,body]of bodies){memory.dir(`${args[2]}/${dirname(path)}`,0o755);memory.files.get(`${args[2]}/${dirname(path)}`).mode=0o755;memory.put(`${args[2]}/${path}`,body,0o644);}return {code:0,stdout:'',stderr:''};}
    if(operation==='fetch') {
      if(args[0]===model.release_api)return {code:0,stdout:JSON.stringify([{draft:false,prerelease:true,tag_name:'v1.0.2',assets:[{name:'SHA256SUMS',size:100},{name:'foxhole-openwrt-client-1.0.2-r1.apk',size:apk.length}]}]),stderr:''};
      return {code:0,stdout:args[0].endsWith('SHA256SUMS')?`${sha(apk)}  foxhole-openwrt-client-1.0.2-r1.apk\n`:apk,stderr:''};
    }
    if(operation==='switch') {
      const job=memory.json(JOB),candidate=job.candidate;
      if(environment.switched){environment.nativeVersion=candidate.version;memory.put(`${candidate.root}/lib/apk/db/installed`,'new-stage-db',0o644);}
      memory.put(MARKER,JSON.stringify({schema:1,storage:'RAM',phase:'active',stage:dirname(candidate.root),version:'1.0.2',baseSha256:candidate.sha256}));
      environment.afterSwitch?.();
      return {code:0,stdout:'',stderr:''};
    }
    throw new Error(`unexpected native operation ${operation}`);
  };
  const service=load('ram-update-service.uc',{model,updates,fs:memory.fs(),store:memory.store(),capture,
    native:{target:()=>({architecture:'aarch64_cortex-a53',release:'25.12.5',target:'mediatek/filogic'})},
    engine:{update_locked:fn=>fn(),update_principal_current:()=>environment.authorized,update_process_snapshot:()=>({pid:100}),update_self_worker:()=>({pid:100,start:'1',commandSha256:sha('worker'),bootId:'12345678-1234-1234-1234-123456789abc'})},
    registry:{snapshot_context:binding,read:()=>({schema:1,revision:0,selected:[],slots:[]})},engines:{selected:()=>null,worker_current:()=>environment.workerAlive!==false},
    backup:{guard:()=>{}},backup_model:{without_stop:value=>{const copy=clone(value);copy.revision=0;copy.activeServerId=null;return sha(JSON.stringify(copy));}},
    state_model:{validate_state:clone},time:()=>1700000000,test_failure:error=>{environment.lastError=error.stack;},system:args=>{environment.launched.push(args);return 0;}
  },true);
  function checkOffline(){const job=service.check({expectedRevision:service.status(principal).revision},principal);service.run(job.jobId);assert.equal(service.status(principal).deviceDownloadRequired,true);}
  function begin(){checkOffline();return service.device_begin({...manifest,expectedRevision:service.status(principal).revision},principal);}
  function chunk(uploadId,offset=0,data=apk){return {uploadId,offset,dataBase64:Buffer.from(data).toString('base64'),chunkSha256:sha(data)};}
  return {memory,environment,model,service,principal,manifest,apk,payload,checkOffline,begin,chunk};
}

test('unreachable direct check is the only path enabling upload fallback',()=>{
  const f=fixture();f.checkOffline();
  assert.equal(f.service.status(f.principal).availability,'CHECK_FAILED');assert.deepEqual(f.environment.captures.filter(x=>x==='probe'),['probe']);
});
test('TLS failure cannot enable phone relay',()=>{
  const f=fixture();f.environment.probe={code:5,stdout:'',stderr:'Invalid SSL certificate'};
  const job=f.service.check({expectedRevision:0},f.principal);f.service.run(job.jobId);
  assert.equal(f.service.status(f.principal).deviceDownloadRequired,false);
  assert.throws(()=>f.service.device_begin({...f.manifest,expectedRevision:f.service.status(f.principal).revision},f.principal));
});
test('begin retries are idempotent and another active request is refused',()=>{
  const f=fixture(),begun=f.begin(),revision=f.service.status(f.principal).revision;
  const again=f.service.device_begin({...f.manifest,expectedRevision:revision-1},f.principal);assert.equal(again.uploadId,begun.uploadId);
  assert.throws(()=>f.service.device_begin({...f.manifest,requestId:'b'.repeat(32),expectedRevision:revision},f.principal),/busy/);
});
test('last chunk retry does not append twice and changed/reordered chunks are refused',()=>{
  const f=fixture(),begun=f.begin(),request=f.chunk(begun.uploadId);
  assert.equal(f.service.device_chunk(request,f.principal).nextOffset,f.apk.length);
  assert.equal(f.service.device_chunk(request,f.principal).nextOffset,f.apk.length);
  assert.equal(f.memory.get(`${ROOT}/uploads/${begun.uploadId}/payload`),f.apk);
  assert.throws(()=>f.service.device_chunk(f.chunk(begun.uploadId,0,'different'),f.principal));
});
test('status reconciles an append completed before metadata acknowledgement',()=>{
  const f=fixture(),begun=f.begin();f.memory.crashAppend=true;
  assert.throws(()=>f.service.device_chunk(f.chunk(begun.uploadId),f.principal));
  assert.equal(f.service.device_status({uploadId:begun.uploadId},f.principal).nextOffset,f.apk.length);
  assert.equal(f.service.device_chunk(f.chunk(begun.uploadId),f.principal).nextOffset,f.apk.length);
});
test('finish verifies signature, policy, dependencies and payload before AVAILABLE',()=>{
  const f=fixture(),begun=f.begin();f.service.device_chunk(f.chunk(begun.uploadId),f.principal);
  const result=f.service.device_finish({uploadId:begun.uploadId},f.principal);assert.equal(result.availability,'AVAILABLE');
  const calls=f.environment.captures;assert.ok(calls.indexOf('verify')<calls.indexOf('dump'));assert.ok(calls.includes('dependencies'));assert.ok(calls.includes('extract'));
  assert.equal(f.service.device_finish({uploadId:begun.uploadId},f.principal).availability,'AVAILABLE');
});
test('signature and new dependency failures never produce AVAILABLE or new relay evidence',()=>{
  for(const field of ['signature','missingDependency']){const f=fixture(),begun=f.begin();f.service.device_chunk(f.chunk(begun.uploadId),f.principal);
    if(field==='signature')f.environment.signature=false;else f.environment.missingDependency=true;
    assert.throws(()=>f.service.device_finish({uploadId:begun.uploadId},f.principal));
    assert.equal(f.service.status(f.principal).availability,'CHECK_FAILED');assert.equal(f.service.status(f.principal).deviceDownloadRequired,false);}
});
test('upload expires and Stop invalidates buffered data before apply',()=>{
  const f=fixture(),begun=f.begin();f.memory.clock+=600100;assert.throws(()=>f.service.device_status({uploadId:begun.uploadId},f.principal));
  assert.throws(()=>f.service.device_begin({...f.manifest,expectedRevision:f.service.status(f.principal).revision},f.principal));
  const g=fixture(),upload=g.begin();g.memory.put('/etc/foxhole/engine-intent.json',JSON.stringify({schema:1,revision:1}));
  assert.throws(()=>g.service.device_chunk(g.chunk(upload.uploadId),g.principal));assert.equal(g.memory.get(`${ROOT}/uploads/${upload.uploadId}/payload`),'');
});
test('direct online download reaches the same verified candidate path',()=>{
  const f=fixture();f.environment.probe={code:0,stdout:'',stderr:''};
  const job=f.service.check({expectedRevision:0},f.principal);f.service.run(job.jobId);
  assert.equal(f.service.status(f.principal).availability,'AVAILABLE');assert.equal(f.service.status(f.principal).deviceDownloadRequired,false);
});
test('switch success requires the real isolated native package version, not a marker alone',()=>{
  for(const works of [true,false]){const f=fixture(),begun=f.begin();f.service.device_chunk(f.chunk(begun.uploadId),f.principal);f.service.device_finish({uploadId:begun.uploadId},f.principal);
    const plan=f.service.plan({expectedRevision:f.service.status(f.principal).revision},f.principal);
    const job=f.service.apply({expectedRevision:plan.revision,planId:plan.planId,planSha256:plan.planSha256,confirmed:true},f.principal);
    f.environment.switched=works;f.service.run(job.jobId);
    assert.equal(f.service.job(job.jobId,f.principal).state,works?'SUCCEEDED':'RECOVERY_REQUIRED',f.environment.lastError);
    assert.equal(f.memory.get('/lib/apk/db/installed'),'host-db-185');}
});
test('automatic updates default off and an explicit opt-in queues the same verified apply path',()=>{
  const f=fixture();f.environment.probe={code:0,stdout:'',stderr:''};assert.equal(f.service.tick(),null);
  f.service.settings({expectedRevision:0,autoUpdateEnabled:true},f.principal);
  const check=f.service.tick();assert.equal(check.operation,'CHECK');
  const queued=f.service.run(check.jobId);assert.equal(queued.operation,'APPLY');assert.equal(queued.state,'QUEUED');
  assert.equal(f.service.status(f.principal).autoUpdate.enabled,true);
});
test('disabling automatic policy during pre-mutation verification prevents switch',()=>{
  const f=fixture();f.environment.probe={code:0,stdout:'',stderr:''};
  f.service.settings({expectedRevision:0,autoUpdateEnabled:true},f.principal);
  const queued=f.service.run(f.service.tick().jobId);
  f.environment.beforeCapture=operation=>{if(operation!=='verify')return;f.environment.beforeCapture=null;
    f.service.settings({expectedRevision:f.service.status(f.principal).revision,autoUpdateEnabled:false},f.principal);};
  f.service.run(queued.jobId);assert.equal(f.service.status(f.principal).autoUpdate.enabled,false);
  assert.equal(f.memory.json(JOB).state,'FAILED');assert.equal(f.environment.captures.includes('switch'),false);
});
test('a queued worker that never starts becomes a failed readback, not a replay',()=>{
  const f=fixture();const queued=f.service.check({expectedRevision:0},f.principal);f.memory.clock+=10100;
  const status=f.service.status(f.principal);assert.equal(status.lastOwnJob.jobId,queued.jobId);
  assert.equal(status.lastOwnJob.state,'FAILED');assert.equal(status.deviceDownloadRequired,false);
});
test('Stop deferred during the selector is applied after the atomic phase without reconnect proof',()=>{
  const f=fixture(),begun=f.begin();f.service.device_chunk(f.chunk(begun.uploadId),f.principal);
  const profile=f.memory.json(PROFILE);profile.activeServerId='server-aaaaaaaaaaaa';profile.servers=[{id:'server-aaaaaaaaaaaa',config:'synthetic'}];f.memory.put(PROFILE,JSON.stringify(profile));
  f.service.device_finish({uploadId:begun.uploadId},f.principal);
  const plan=f.service.plan({expectedRevision:f.service.status(f.principal).revision},f.principal);
  const job=f.service.apply({expectedRevision:plan.revision,planId:plan.planId,planSha256:plan.planSha256,confirmed:true},f.principal);
  f.environment.afterSwitch=()=>{const value=f.memory.json(PROFILE);value.activeServerId=null;value.revision++;f.memory.put(PROFILE,JSON.stringify(value));
    f.memory.put('/etc/foxhole/engine-intent.json',JSON.stringify({schema:1,revision:1}));};
  f.service.run(job.jobId);const result=f.service.job(job.jobId,f.principal);
  assert.equal(result.state,'SUCCEEDED');assert.equal(result.previousConnectionRestored,false);
  assert.ok(f.environment.launched.some(args=>args[0]==='/etc/init.d/foxhole-runtime'&&args[1]==='restart'));
  assert.equal(f.memory.json(PROFILE).activeServerId,null);
});
