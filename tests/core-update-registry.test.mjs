import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createHash } from 'node:crypto';
import { read, functionBody, packageRoot, plain } from './helpers.mjs';
const source = await read(`${packageRoot}/root/usr/share/foxhole/engine-registry.uc`);
const hash = raw => createHash('sha256').update(raw).digest('hex');
const signerFingerprint = 'fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1';
function loader() {
 const previous = { id: 'vless', storage: 'FLASH', architecture: 'x86_64', packageVersion: '1.0.2-r1', manifestSha256: 'a'.repeat(64) };
 const next = { ...previous, packageVersion: '1.0.4-r1', manifestSha256: 'b'.repeat(64) };
 const body = JSON.stringify({ catalog: { schema: 1, entries: [next] } });
 const ref = { bodySha256: hash(body), bodyBytes: body.length, archiveSha256: hash('archive'), archiveBytes: 20,
  indexSha256: hash('index'), indexBytes: 30, coreVersion: '1.0.4', packageVersion: '1.0.4-r1', sequence: 5 };
 const cache = '/etc/foxhole/update-cache/', key = `${cache}core-verifier/keys/foxhole.pem`;
 let release = "DISTRIB_RELEASE='25.12.5'\nDISTRIB_TARGET='x86/64'\n", arch = 'x86_64', badBody = false, abi = 1;
 const commands = [], bindings = [];
 const scope = vm.createContext({
  verified_core_catalog: null, json: JSON.parse, digest: { sha256: hash },
  sprintf: (_format, value) => JSON.stringify(value), length: value => value.length,
  filter: (rows, fn) => rows.filter(fn), push: (rows, value) => rows.push(value),
  trim: value => value.trim(), match: (raw, regex) => raw.match(regex),
  fail: () => { throw new Error('verification-failed'); }, architecture: () => arch,
  hash_file: path => path.endsWith('.pem') ? signerFingerprint : path.slice(cache.length),
  public_file(path) {
   if (path.endsWith('update-policy.json')) return JSON.stringify({ packageVersion: '1.0.6-r1' });
   if (path.endsWith('openwrt_release')) return release;
   return badBody ? body + 'tampered' : body;
  },
  fs: { lstat: path => ({ size: path.endsWith(ref.archiveSha256) ? ref.archiveBytes : ref.indexBytes }), glob: () => [key] },
  engines: { catalog: value => value },
  core_updates: { get FEED_ABI() { return abi; }, reference: value => value,
   metadata_layout: () => ({ sha256: ref.bodySha256, bytes: ref.bodyBytes }),
   comparison_inputs: () => ({ minimumBaseVersion: '1.0.6-r1' }),
   cached_feed(_value, binding) {
    bindings.push(binding);
    if (binding.osRelease !== '25.12.5' || binding.target !== 'x86/64' || binding.architecture !== 'x86_64')
     throw new Error('unsupported-target');
   } },
  capture(argv) {
   commands.push(argv);
   if (argv.includes('adbdump')) return '{}';
   if (argv.includes('version')) return argv.at(-2) === '1.0.6-r1' ? '=' : '<';
   return '';
  }
 });
 vm.runInContext(`function core_catalog(embedded,reference_raw) ${functionBody(source, 'core_catalog')}`
  .replace(/for\(let (\w+) in /g, 'for(let $1 of '), scope);
 const run = () => plain(scope.core_catalog({ value: { schema: 1, entries: [previous] }, sha256: hash('embedded') }, JSON.stringify(ref)));
 return { run, commands, bindings, changeOS: () => { release = release.replace('25.12.5', '26.01.0'); },
  changeArch: () => { arch = 'aarch64_cortex-a53'; }, tamper: () => { badBody = true; },
  changeAbi: () => { abi = 2; } };
}
test('installed signed catalog verifies before merge and exact cache hits retain byte checks', () => {
 const h = loader(); assert.equal(h.run().value.entries[0].packageVersion, '1.0.4-r1');
 const verifies = () => h.commands.filter(row => row.includes('verify')).length;
 assert.equal(verifies(), 1); h.run(); assert.equal(verifies(), 1);
 h.tamper(); assert.throws(h.run, /verification-failed/);
});
test('warm cache cannot reuse compatibility after OS architecture or ABI changes', () => {
 for (const mutate of ['changeOS', 'changeArch', 'changeAbi']) {
  const h = loader(); h.run(); h[mutate](); assert.throws(h.run, /unsupported-target|verification-failed/);
 }
});
