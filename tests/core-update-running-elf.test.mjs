import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { read, functionBody, packageRoot } from './helpers.mjs';
const service = await read(`${packageRoot}/root/usr/share/foxhole/engine-service.uc`);
const registry = await read(`${packageRoot}/root/usr/share/foxhole/engine-registry.uc`);
const digest = 'a'.repeat(64), wrapper = `/usr/libexec/foxhole/engines/vless/${digest}/foxcore-cli`;
const raw = `/tmp/foxhole/engine-binaries/vless/${digest}/foxcore-cli`;
function proof(options = {}) {
 const selected = { id: 'vless', storage: options.flash ? 'FLASH' : 'RAM', binarySha256: digest, binaryBytes: 100 };
 const server = { id: 'profile', engine: 'core', config: 'private-fixture-config' };
 const owner = { owned: true, key: 'new-generation' }; let ownerReads = 0;
 const body = vm.createContext({
  fs: { lstat: () => ({ type: 'file', uid: options.wrongUid ? 1 : 0, nlink: 1,
   mode: options.wrongMode ? 0o644 : 0o700, inode: 10, size: options.wrongSize ? 101 : 100 }) },
  store: { file_metadata: info => info.type === 'file' && info.uid === 0 && info.nlink === 1 },
  executable: () => wrapper, hash_file: () => options.wrongDigest ? 'b'.repeat(64) : digest,
  fail: () => { throw new Error('engine_package_verification_failed'); },
  die: error => { throw new Error(error); }
 });
 if (registry.includes('function running_executable('))
  vm.runInContext(`function running_executable(value) ${functionBody(registry, 'running_executable')}`, body);
 else body.running_executable = () => raw;
 const context = vm.createContext({
  state: () => ({ activeServerId: server.id, servers: [server] }),
  filter: (rows, fn) => rows.filter(fn), process_snapshot: () => ({ root: !options.unownedPid, zombie: false, start: options.wrongStart ? '124' : '123' }),
  read: path => path.includes('core-state') ? { pid: 77, process_start: 123, phase: 'running' }
   : path.includes('runtime.json') ? { phase: 'connected', connected: true, enforced: true, activeServerId: server.id }
   : path.includes('policy') ? { generation_key: owner.key, serverId: server.id, stateIdentity: 'policy', kernelIdentity: 'kernel' } : {},
  fs: { stat(path) {
   const inode = path === wrapper ? 20 : 10;
   return { inode: path.startsWith('/proc/') ? (options.wrongPidElf ? 30 : options.flash ? 20 : 10) : inode,
    dev: { major: 0, minor: 1 } };
  } },
  registry: { verify_slot: () => wrapper, executable: () => wrapper,
   running_executable: value => body.running_executable(value), snapshot_context: () => ({ bootId: 'boot' }) },
  engines: { restart_allowed: () => !options.stopped }, now: () => 2000, boot: () => 'boot',
  core: { proof_valid: () => !options.staleProof }, digest: { sha256: value => value },
  store: { read: () => server.config },
  adapter: { proof_path: '/proof', config_path: '/config', policy_path: '/policy',
   receipt: () => ++ownerReads === 2 && options.lateOwnerChange ? { ...owner, key: 'other-generation' } : owner,
   generation: value => value.key, policy_identity: () => 'policy', kernel_policy: () => 'kernel' }
 });
 vm.runInContext(`function reconnect_proven(job,selected,minimum,previous_key) ${functionBody(service, 'reconnect_proven')}`, context);
 return () => context.reconnect_proven({ plan: { binding: {} } }, selected, 1500, 'previous-generation');
}
test('RAM reconnect compares the owned PID to its admitted raw ELF rather than the launcher script', () => {
 assert.equal(proof()(), true);
});
test('FLASH reconnect keeps its installed ELF identity', () => {
 assert.equal(proof({ flash: true })(), true);
});
test('Stop unowned PID stale proof changed ELF and late owner replies remain refused', () => {
 for (const options of [{ stopped: true }, { unownedPid: true }, { staleProof: true },
  { wrongPidElf: true }, { wrongStart: true }, { lateOwnerChange: true }]) assert.equal(proof(options)(), false);
});

test('RAM process identity requires exact root-owned private binary bytes size and mode', () => {
 for (const options of [{wrongUid:true},{wrongMode:true},{wrongSize:true},{wrongDigest:true}])
  assert.throws(proof(options),/engine_ram_stage_unavailable/);
});
