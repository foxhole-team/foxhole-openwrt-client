import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { read, packageRoot, plain, functionBody } from './helpers.mjs';

const source = await read(`${packageRoot}/root/usr/share/foxhole/core-update-transaction.uc`);
const H = 'a'.repeat(64), J = 'b'.repeat(64);
function transaction(options = {}) {
 const events = [], journals = [], proofs = []; let clock = 1000, privateConfig = false;
 const base = { name: 'foxhole-openwrt-client', version: '1.0.5-r1', arch: 'noarch', cas: 'base-identity' };
 const old = { id: 'vless', storage: 'RAM', architecture: 'x86_64', version: '1.0.2',
  packageVersion: '1.0.2-r2', packageName: 'old-slot', manifestSha256: H };
 const next = { ...old, version: '1.0.4', packageVersion: '1.0.4-r1', packageName: 'new-slot', manifestSha256: J };
 const previous = { schema: 1, revision: 2, slots: [old], selected: [{ id: 'vless', slotId: 'old-slot' }] };
 let registry = structuredClone(previous), reference = { sequence: 1 }, locked = 0, stopped = false;
 let world = ['foxhole-openwrt-client', 'old-slot'], stop = 0, authorized = true;
 const identities = { 'foxhole-openwrt-client': base,
  'old-slot': { name: 'old-slot', version: old.packageVersion, arch: 'x86_64', cas: 'old-identity' } };
 const managed = { storage: 'RAM', version: '1.0.6-r1', stage: '/tmp/synthetic-stage',
  baseSha256: H, markerSha256: H, stageDbSha256: H, ledgerSha256: H };
 const protectedState = { profile: 'synthetic-unchanged-profile', pairing: 'synthetic-unchanged-verifier', enabled: false };
 const state = () => ({ revision: stop ? 2 : 1, activeServerId: stop ? null : 'profile',
  servers: [{ id: 'profile', config: protectedState.profile }] });
 const context = () => ({ routerId: H, bootId: 'boot', worldSha256: world.join('|'),
  catalogSha256: reference.sequence === 1 ? H : J, activeGeneration: 'old-generation',
  activeConfigSha256: stop ? null : protectedState.profile, activeProfileId: state().activeServerId,
  activeEngineId: stop ? null : 'vless', stopIntent: stop,
  flashAvailableBytes: 1e9, ramAvailableBytes: 1e9 });
 const initial = context();
 const job = { jobId: 'update-job-' + 'c'.repeat(32), operation: 'APPLY', automatic: false,
  plan: { impact: 'RECONNECT_REQUIRED', binding: initial, expiresAtUptimeMs: 10000,
   budget: { flashRequiredBytes: 1, ramRequiredBytes: 1 },
   candidate: { component: 'CORE', managed: { ...managed, hostBaseIdentity: base },
    selected: previous, artifacts: [next], reference: { sequence: 2 }, previousReference: { sequence: 1 } } } };
 const callbacks = {
  authorized: () => authorized,
  admit() {},
  journal() {},
  save(value) { journals.push(structuredClone(value)); events.push('journal'); },
  progress(value, phase, step) { value.state = phase; value.step = step; this.save(value); },
  protect() { return structuredClone(protectedState); },
  preserved(value) { assert.deepEqual(plain(value), protectedState); },
  beginAtomic(value) {
   if (options.stopBeforeMutation) { stop++; throw new Error('STALE_PLAN'); }
   value.mutationStarted = true; value.atomicPackagePhase = true;
   this.progress(value, 'INSTALLING', 'BACKING_UP');
  },
  endAtomic(value) {
   if (stop) { events.push('stop'); stopped = true; }
   value.atomicPackagePhase = false; this.save(value);
  },
  restart() {
   if (options.stopAtRestart) { stop++; return false; }
   if (!authorized || stop) return false;
   events.push('start'); stopped = false; return true;
  }
 };
 const scope = vm.createContext({
  sprintf: (_format, value) => JSON.stringify(value), length: value => value.length,
  type: value => Array.isArray(value) ? 'array' : Number.isInteger(value) ? 'int' : typeof value, keys: Object.keys,
  match: (value, expression) => value.match(expression),
  filter: (values, fn) => values.filter(fn), map: (values, fn) => values.map(fn),
  push: (values, value) => values.push(value), join: (separator, values) => values.join(separator), max: Math.max,
  die: value => { throw value instanceof Error ? value : new Error(String(value)); },
  guard: { fail: reason => { throw new Error(reason); } },
  fs: { lstat: path => path === '/tmp/foxhole-ram-active.json' ? {} : null, unlink(path) { if (path.endsWith('/check-config')) privateConfig = false; return true; } },
  digest: { sha256: value => value }, adapter: { receipt: () => ({}), generation: () => clock >= 11000 ? 'generation-during-install' : 'old-generation' },
  store: { directory() {}, write(path) { if (path.endsWith('/check-config')) privateConfig = true; } },
  ram: { core_context() {
   if (options.badManaged) throw new Error('managed-admission-refused');
   return structuredClone(managed);
  } },
  native: {
   installed_identities: () => structuredClone(identities), policy() {}, target() {},
   prepare_keys: () => '/fixture/keys', native_cas: () => 'sha256-160:' + 'b'.repeat(40), stage_ram() { if (options.expireDuringStaging) clock = 10001; },
   world_state: () => ({ raw: world.join('|') })
  },
  catalog: { current: () => structuredClone(reference), publish(value) { reference = plain(value); events.push('publish'); },
   restore(value) { reference = plain(value); events.push('restore-catalog'); } },
  registry: { read: () => structuredClone(registry), write(value) { registry = plain(value); events.push('registry'); },
   snapshot_context: context, verify_slot: value => '/' + value.packageName,
   catalog: () => ({}),
   capture(argv) {
    if (argv[1] === 'capabilities' && reference.sequence !== 2)
     throw new Error('verified candidate catalog must admit the new RAM launcher');
    if (argv[1] === 'check') {
     if (options.badConfiguration) throw new Error('candidate-config-refused');
     return '';
    }
    return { schema_version: options.capsSchema ?? 1, router_contract_version: 1, platform: 'linux', core_version: '1.0.4', protocols: ['vless'] };
   } },
  engines: {
   restart_allowed: (before, after) => ['routerId', 'bootId', 'activeProfileId', 'activeConfigSha256', 'stopIntent']
    .every(name => before[name] === after[name]),
   world_pins: (before, after, additions, removals) => JSON.stringify([...before.filter(x => !removals.includes(x)), ...additions].sort()) === JSON.stringify([...after].sort()),
   purge_only: () => true, add_only_delta: () => !options.foreignSolver,
   commit(value, additions) { return { ...plain(value), revision: value.revision + 1,
    slots: [...plain(value.slots), ...plain(additions)], selected: [{ id: 'vless', slotId: 'new-slot' }] }; },
   selected: (value, id) => value.slots.find(row => row.id === id && row.packageName === value.selected[0].slotId)
  },
  engine: { update_state: state, update_now: () => clock,
   update_locked(fn) { locked++; assert.equal(locked, 1); try { return fn(); } finally { locked--; } },
   update_wait_reconnect(_job, selected, minimum, previousGeneration) {
    proofs.push({ minimum, previousGeneration });
    events.push(selected.packageName === 'new-slot' ? 'probe-new' : 'probe-old');
    return !options.failNewTraffic || selected.packageName === 'old-slot';
   } },
  packages: { world: () => [...world], installed: () => structuredClone(identities), decode: value => value,
   candidate: value => ({ value, index: '/fixture/index', nativeId: J }),
   apk(argv) {
    if (argv.includes('query')) return [...Object.values(identities),
     { name: 'new-slot', version: next.packageVersion, arch: 'x86_64' }];
    if (argv.includes('--simulate')) return '';
    if (argv.includes('add')) {
     assert.ok(journals.some(row => row.mutationStarted && row.atomicPackagePhase));
     events.push('install'); if (options.slowAtomicInstall) clock = 11000; identities['new-slot'] = { name: 'new-slot', version: next.packageVersion,
      arch: 'x86_64', cas: 'sha256-160:' + 'b'.repeat(40) }; world.push('new-slot');
     if (options.stopDuringInstall) stop++;
     if (options.revokeDuringInstall) authorized = false;
    }
    if (argv.includes('del')) { events.push('remove'); delete identities['new-slot']; world = world.filter(x => x !== 'new-slot'); }
    return '';
   } },
  system(argv) {
   if (argv[0] === '/etc/init.d/foxhole-runtime') {
    events.push(argv[1]); stopped = argv[1] === 'stop';
   }
   return 0;
  }
 });
 const adapted = source.replace(/^import .*;\n/gm, '').replaceAll('export function ', 'function ')
  .replace(/for\(let (\w+) in keys\(([^)]+)\)\)/g, 'for(let $1 of keys($2))')
  .replace(/for\(let (\w+) in ([A-Za-z0-9_.]+)\)/g, 'for(let $1 of $2)');
 vm.runInContext(adapted, scope);
 return { run: () => scope.apply(job, callbacks), job,
  facts: () => ({ events, journals, identities: structuredClone(identities), registry,
   reference, world, protectedState, stopped, proofs, privateConfig }) };
}

test('Core-only transaction preserves BASE, managed RAM and owner data while verifying new traffic', () => {
 const current = transaction(); assert.equal(current.run(), true); const facts = current.facts();
 assert.equal(facts.identities['foxhole-openwrt-client'].cas, 'base-identity');
 assert.equal(facts.registry.selected[0].slotId, 'new-slot');
 assert.deepEqual(facts.events.filter(x => ['install', 'stop', 'start', 'probe-new'].includes(x)),
  ['install', 'stop', 'start', 'probe-new']);
});
test('bad managed admission or solver scope cannot enter mutation', () => {
 for (const options of [{ badManaged: true }, { foreignSolver: true }]) {
  const current = transaction(options); assert.throws(current.run);
  assert.ok(!current.facts().events.includes('install'));
 }
});
test('unknown CLI receipt schema rolls back new package before stopping the old tunnel', () => {
 const current = transaction({ capsSchema: 2 }); assert.throws(current.run, /PACKAGE_VERIFICATION_FAILED/);
 const facts = current.facts(); assert.equal(facts.identities['new-slot'], undefined);
 assert.ok(!facts.events.includes('stop')); assert.ok(!facts.events.includes('start'));
});
test('configuration refusal removes only the new slot and leaves the old tunnel running', () => {
 const current = transaction({ badConfiguration: true }); assert.throws(current.run, /candidate-config-refused/);
 const facts = current.facts(); assert.equal(facts.identities['new-slot'], undefined);
 assert.ok(!facts.events.includes('stop')); assert.ok(!facts.events.includes('start'));
 assert.equal(facts.registry.selected[0].slotId, 'old-slot');
 assert.equal(facts.privateConfig, false);
});
test('new traffic failure restores old catalog, packages and selection with old traffic proof', () => {
 const current = transaction({ failNewTraffic: true }); assert.throws(current.run, /ROUTER_UNAVAILABLE/);
 const facts = current.facts(); assert.equal(current.job.coreRecoverySucceeded, true);
 assert.equal(facts.reference.sequence, 1); assert.equal(facts.identities['new-slot'], undefined);
 assert.ok(facts.events.includes('probe-new')); assert.ok(facts.events.includes('probe-old'));
});
test('an owner Stop during atomic installation cannot reconnect an old intent', () => {
 const current = transaction({ stopDuringInstall: true }); assert.equal(current.run(), true);
 assert.ok(!current.facts().events.includes('start')); assert.ok(!current.facts().events.includes('probe-new'));
});
test('revocation after APK mutation rolls back before stopping the current connection', () => {
 const current = transaction({ revokeDuringInstall: true }); assert.throws(current.run, /AUTHENTICATION_FAILED/);
 assert.ok(!current.facts().events.includes('stop'));
 assert.equal(current.facts().identities['new-slot'], undefined);
});
test('state-lock admission rejects a Stop before mutation and closes the restart race', () => {
 const before = transaction({ stopBeforeMutation: true }); assert.throws(before.run, /STALE_PLAN/);
 assert.ok(!before.facts().events.includes('install'));
 const after = transaction({ stopAtRestart: true }); assert.equal(after.run(), true);
 assert.ok(!after.facts().events.includes('start'));
});

test('expiry reached during download or staging refuses atomic mutation', () => {
 const current = transaction({ expireDuringStaging: true }); assert.throws(current.run, /STALE_PLAN/);
 assert.ok(!current.facts().events.includes('install')); assert.ok(!current.job.mutationStarted);
});
test('slow atomic install completes with a post-staging reconnect watermark and owner generation', () => {
 const current = transaction({ slowAtomicInstall: true }); assert.equal(current.run(), true);
 assert.equal(current.facts().proofs[0].minimum, 11000);
 assert.equal(current.facts().proofs[0].previousGeneration, 'generation-during-install');
});

test('live FLASH and RAM atomic callbacks recheck Core plan expiry under their state lock', async () => {
 for (const name of ['update-service.uc','ram-update-service.uc']) {
  const text = await read(`${packageRoot}/root/usr/share/foxhole/${name}`);
  const scope = vm.createContext({
   fs:{open:()=>({lock:()=>true,close(){}}),lstat:()=>({})},store:{target(){},file_metadata:()=>true},
   engine:{update_now:()=>10001},now:()=>10001,authorized:()=>true,
   core_updates:{current_binding:()=>({})},same:()=>true,core_journal(){},require_job(){},
   transaction:fn=>fn(),profile_locked:fn=>fn(),save_job(){},progress(){},
   protected_snapshot(){},protected_unchanged(){},finish_atomic(){},
   fail:reason=>{throw new Error(reason)},model:{fail:reason=>{throw new Error(reason)}},
   die:error=>{throw error}
  });
  const job={plan:{candidate:{component:'CORE'},binding:{},expiresAtUptimeMs:10000}};
  if(name==='update-service.uc') {
   vm.runInContext(`function begin_mutation(job) ${functionBody(text,'begin_mutation')}`,scope);
   assert.throws(()=>scope.begin_mutation(job),/STALE_PLAN/);
  } else {
   vm.runInContext(`function core_callbacks() ${functionBody(text,'core_callbacks')}`,scope);
   assert.throws(()=>scope.core_callbacks().beginAtomic(job),/STALE_PLAN/);
  }
  assert.ok(!job.mutationStarted);
 }
});
