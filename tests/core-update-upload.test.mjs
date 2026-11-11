import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createHash } from 'node:crypto';
import { read, packageRoot, plain } from './helpers.mjs';

const source = await read(`${packageRoot}/root/usr/share/foxhole/core-update-upload.uc`);
const hash = raw => createHash('sha256').update(raw).digest('hex');
const root = '/tmp/foxhole/core-uploads', record = `${root}/current.json`;
const statePath = '/etc/foxhole/update-state.json';
const principal = { kind: 'PHONE', id: 'fixture' }, owner = hash(JSON.stringify(principal));
const contents = { 'catalog-index': 'signed-index', 'catalog-apk': 'signed-metadata',
 'module-index': 'signed-module-index', 'module-apk': 'signed-module-apk' };
const cohortHash = hash('signed-cohort');
function harness(options = {}) {
 const files = new Map(), events = [], descriptors = new Map();
 let authorized = true, binding = { stopIntent: 0 }, verifyCount = 0, interrupted = false, processExited = false;
 const save = (path, raw, mode = 0o100600) => files.set(path, { raw, mode });
 const parse = path => JSON.parse(files.get(path).raw);
 save(statePath, JSON.stringify({ schema: 1, revision: 4, deviceDownloadRequired: true,
  relayEvidence: { owner, cohortKind: 'CORE', bootId: 'boot', observedAtUptimeMs: 100 } }));
 const candidate = { component: 'CORE', reference: { bodySha256: cohortHash },
  changes: options.current ? [] : [{ id: 'vless' }], selected: { selected: [{ id: 'vless' }] },
  artifacts: [{ id: 'vless', storage: 'FLASH', indexSha256: hash(contents['module-index']),
   indexBytes: contents['module-index'].length, indexUrl: 'https://github.com/foxhole-team/foxhole-core/releases/download/v1.0.4/engines.adb',
   packageSha256: hash(contents['module-apk']), archiveBytes: contents['module-apk'].length,
   packageUrl: 'https://github.com/foxhole-team/foxhole-core/releases/download/v1.0.4/foxcore-engine-vless.apk' }] };
 const scope = vm.createContext({
  type: value => value === null ? 'null' : typeof value === 'boolean' ? 'bool' : Array.isArray(value) ? 'array' :
   typeof value === 'number' && Number.isInteger(value) ? 'int' : typeof value,
  length: value => value.length, index: (rows, item) => rows.indexOf(item),
  match: (raw, expression) => raw.match(expression), sprintf: (_format, value) => JSON.stringify(value),
  substr: (value, start, count) => value.slice(start, count == null ? undefined : start + count),
  filter: (rows, fn) => rows.filter(fn), map: (rows, fn) => rows.map(fn), push: (rows, value) => rows.push(value),
  hexenc: raw => Buffer.from(raw).toString('hex'), time: () => 1793000000,
  die: error => { throw error; }, system: () => 0,
  digest: { sha256: hash },
  guard: { fail: reason => { throw new Error(reason); } },
  model: { cohort_asset_id: id => /^(catalog-(index|apk)|asset-[a-f0-9]{64})$/.test(id),
   cohort_begin() {}, cohort_action() {} },
  uploads: { upload_id: id => /^update-upload-[a-f0-9]{32}$/.test(id),
   integer: value => Number.isSafeInteger(value) && value >= 0,
   sha: value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value),
   chunk_request(request) {
    const bytes = Buffer.from(request.dataBase64, 'base64').toString();
    if (hash(bytes) !== request.chunkSha256) throw new Error('INVALID_REQUEST'); return bytes;
   } },
  engine: { update_principal_current: () => authorized, update_boot: () => 'boot', update_now: () => 100,
   update_locked: fn => fn(), update_state: () => ({}) },
  core: { current_binding: () => binding, from_verified: () => candidate, plan: () => ({}) },
  transaction: { context: () => ({ version: '1.0.6-r1' }) },
  catalog: { network_unreachable: () => options.noNetworkProof !== true, highest: () => null,
   verify_catalog() {
    events.push('verify'); verifyCount++;
    if (verifyCount === 2 && options.revokeAtFinalVerify) authorized = false;
    if (verifyCount === 2 && options.stopAtFinalVerify) binding = { stopIntent: 1 };
    return {};
   } },
  engines: { selected: () => ({ storage: 'FLASH' }) },
  registry: { snapshot_context: () => ({ ramAvailableBytes: 128 * 1024 * 1024 }),
   hash_file: path => files.has(path) ? hash(files.get(path).raw) : null },
  native: { decode: JSON.parse, prepare_keys: () => '/fixture/keys' },
  packages: { apk(argv) {
   events.push(argv[0]);
   return JSON.stringify({ packages: [{ name: 'foxcore-update-catalog', arch: 'noarch',
    version: '1.0.4-r1', 'file-size': contents['catalog-apk'].length, hashes: hash('native-CAS') }] });
  } },
  backup: { guard() {} }, mounts: { mounts: () => [] },
  store: { read: path => files.get(path)?.raw ?? null, write(path, raw) {
   if (processExited) throw new Error('simulated-process-exit');
   if (options.interruptAfterCache && !interrupted && path === record &&
       [...files.keys()].some(key => key.startsWith('/tmp/foxhole/engine-assets/'))) {
    interrupted = true; processExited = true; throw new Error('simulated-process-exit');
   }
   save(path, raw);
  }, directory: path => save(path, '', 0o040700), target() {},
  file_metadata: info => info != null && (info.mode & 0o170000) === 0o100000,
  directory_metadata: info => info != null && (info.mode & 0o170000) === 0o040000 },
  fs: { lstat: path => files.has(path) ? { mode: files.get(path).mode, size: files.get(path).raw.length } : null,
   readfile: path => path === '/dev/urandom' ? '0123456789abcdef' : '',
   rename(from, to) { if (!files.has(from)) return false; files.set(to, files.get(from)); files.delete(from); return true; },
   open(path) {
    if (!files.has(path)) save(path, ''); let position = 0;
    return { lock: () => true, close() {}, flush: () => true,
     seek(offset) { position = offset; return true; },
     read(bytes) { return files.get(path).raw.slice(position, position + bytes); },
     write(raw) { files.get(path).raw += raw; return raw.length; } };
   } }
 });
 vm.runInContext(source.replace(/^import .*;$/gm, '').replaceAll('export function ', 'function ')
  .replace(/for\(let (\w+) in /g, 'for(let $1 of '), scope);
 let uploadId = '';
 function begin(id, raw) {
  const result = scope.begin({ cohortKind: 'CORE', assetId: id, uploadId, expectedRevision: 4,
   requestId: 'b'.repeat(32), releaseTag: 'v1.0.4', version: '1.0.4', fileSha256: hash(raw), fileBytes: raw.length }, principal);
  uploadId = result.uploadId; descriptors.set(id, raw); return plain(result);
 }
 const action = id => ({ cohortKind: 'CORE', uploadId, assetId: id });
 function chunk(id, raw, offset = 0) {
  return plain(scope.chunk({ ...action(id), offset, dataBase64: Buffer.from(raw).toString('base64'), chunkSha256: hash(raw) }, principal));
 }
 function transfer(id, raw) { begin(id, raw); chunk(id, raw); return plain(scope.finish(action(id), principal)); }
 function metadata() { transfer('catalog-index', contents['catalog-index']); return transfer('catalog-apk', contents['catalog-apk']); }
 function rest() {
  transfer(`asset-${hash(contents['module-index'])}`, contents['module-index']);
  return transfer(`asset-${hash(contents['module-apk'])}`, contents['module-apk']);
 }
 return { begin, chunk, transfer, metadata, rest, events, files, parse, resume: () => { processExited = false; },
  finish: id => plain(scope.finish(action(id), principal)), status: id => plain(scope.status(action(id), principal)),
  updateState: () => parse(statePath) };
}

test('sequential signed cohort stages modules without applying or changing BASE identity', () => {
 const h = harness(); const metadata = h.metadata();
 assert.equal(metadata.phase, 'WAITING'); assert.equal(metadata.requiredAssets.length, 2);
 assert.equal(h.updateState().deviceDownloadRequired, true);
 const result = h.rest(); assert.equal(result.phase, 'STAGED');
 assert.equal(result.cohortSha256, cohortHash); assert.equal(h.updateState().availability, 'AVAILABLE');
 assert.equal(h.updateState().availableVersion, '1.0.6-r1');
 assert.ok(!h.events.includes('add')); assert.ok(!h.events.includes('del'));
});
test('duplicate accepted chunk is idempotent, conflicting offset and cross-asset chunk are refused', () => {
 const h = harness(), raw = contents['catalog-index']; h.begin('catalog-index', raw);
 assert.equal(h.chunk('catalog-index', raw).nextOffset, raw.length);
 assert.equal(h.chunk('catalog-index', raw).nextOffset, raw.length);
 assert.throws(() => h.chunk('catalog-index', 'x', 1), /STALE_PLAN/);
 assert.throws(() => h.chunk('catalog-apk', 'x'), /STALE_PLAN/);
});
test('no verified connection-failure evidence cannot authorize device fallback', () => {
 const h = harness({ noNetworkProof: true });
 assert.throws(() => h.begin('catalog-index', contents['catalog-index']), /STALE_PLAN/);
 assert.equal(h.files.has(record), false);
});
test('Stop and authentication changes during final verification prevent publication', () => {
 for (const options of [{ stopAtFinalVerify: true }, { revokeAtFinalVerify: true }]) {
  const h = harness(options); h.metadata(); assert.throws(() => h.rest(), /STALE_PLAN|AUTHENTICATION_FAILED/);
  assert.equal(h.updateState().deviceDownloadRequired, true); assert.equal(h.updateState().candidate, undefined);
 }
});
test('process exit after cache rename supports safe finish replay without another transfer', () => {
 const h = harness({ interruptAfterCache: true }); h.metadata();
 const id = `asset-${hash(contents['module-index'])}`;
 assert.throws(() => h.transfer(id, contents['module-index']), /simulated-process-exit/);
 h.resume();
 assert.equal(h.finish(id).phase, 'WAITING');
 assert.equal(h.status(id).requiredAssets.length, 1);
});

test('a current verified Core cohort retains bounded evidence for a later BASE check', () => {
 const h = harness({ current: true }); const result = h.metadata();
 assert.equal(result.phase, 'STAGED'); assert.equal(h.updateState().availability, 'NOT_CHECKED');
 assert.equal(h.updateState().coreCheckedCandidate.reference.bodySha256, cohortHash);
});
