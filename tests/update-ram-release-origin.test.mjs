import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { functionBody, packageRoot, read } from './helpers.mjs';

const source = await read(`${packageRoot}/root/usr/share/foxhole/update-native.uc`);
const catalog = JSON.parse(await read(process.env.FOXHOLE_TEST_ENGINE_CATALOG ||
  'tests/fixtures/engine-catalog-v1.0.3.json'));
const ramEntries = catalog.entries.filter(value => value.storage === 'RAM');
const origin = source.match(/const ORIGIN = '([^']+)'/)[1];
function stage(value, { cached = false, digest = value.binarySha256,
    fetchedBytes = value.binaryBytes, copied = true, privateMode = true } = {}) {
  let installed = cached, copies = 0, directories = 0;
  const downloads = [];
  const info = { type: 'file', uid: 0, nlink: 1, mode: 0o700, size: value.binaryBytes };
  const scope = {
    ORIGIN: origin,
    length: value => value.length,
    substr: (value, start, size) => value.slice(start, size === undefined ? undefined : start + size),
    store: { directory() { directories++; }, file_metadata: value => value.type === 'file' && value.uid === 0 && value.nlink === 1 },
    fs: { lstat: path => path === '/fixture/download' ? { size: fetchedBytes } : installed ? info : null,
      chmod: () => privateMode },
    packages: { asset(url, sha256, bytes) { downloads.push({ url, sha256, bytes }); return '/fixture/download'; } },
    registry: { hash_file: () => digest },
    guard: { fail(reason) { throw new Error(reason); } },
    system(argv) { assert.equal(argv[0], '/bin/cp'); copies++; installed = copied; return copied ? 0 : 1; }
  };
  const run = vm.runInNewContext(`(function stage_ram(value) ${functionBody(source, 'stage_ram')})`, scope, { timeout: 1000 });
  return { run: () => run(value), state: () => ({ downloads, copies, directories }) };
}
const binaryName = value => `engine-${value.id}-${value.architecture}-${value.binarySha256}.bin`;

test('RAM staging follows each admitted catalog delivery tag instead of the Core version', () => {
  assert.equal(ramEntries.length, 6);
  for (const value of ramEntries) {
    const current = stage(value); current.run();
    assert.deepEqual(current.state().downloads, [{
      url: value.indexUrl.slice(0, -'engines.adb'.length) + binaryName(value),
      sha256: value.binarySha256, bytes: value.binaryBytes
    }]);
  }
});

test('legacy delivery whose tag equals the Core version remains compatible', () => {
  const value = { ...ramEntries[0], indexUrl: `${origin}v${ramEntries[0].version}/engines.adb` };
  const current = stage(value); current.run();
  assert.equal(current.state().downloads[0].url, `${origin}v${value.version}/${binaryName(value)}`);
});

test('a valid warm binary retains its exact slot without another download', () => {
  const current = stage(ramEntries[0], { cached: true }); current.run();
  assert.equal(current.state().downloads.length, 0); assert.equal(current.state().copies, 0);
});

test('a different warm binary is refused without fetching a replacement', () => {
  const current = stage(ramEntries[0], { cached: true, digest: 'f'.repeat(64) });
  assert.throws(current.run, /RAM_STAGE_UNAVAILABLE/); assert.equal(current.state().downloads.length, 0);
});

test('a downloaded binary with another size is refused before installation', () => {
  const current = stage(ramEntries[0], { fetchedBytes: ramEntries[0].binaryBytes + 1 });
  assert.throws(current.run, /RAM_STAGE_UNAVAILABLE/); assert.equal(current.state().copies, 0);
});

test('copy and private-mode failures remain explicit staging failures', () => {
  for (const options of [{ copied: false }, { privateMode: false }]) {
    assert.throws(stage(ramEntries[0], options).run, /RAM_STAGE_UNAVAILABLE/);
  }
});

test('FLASH modules do not allocate or download a RAM binary', () => {
  const current = stage(catalog.entries.find(value => value.storage === 'FLASH')); current.run();
  assert.deepEqual(current.state(), { downloads: [], copies: 0, directories: 0 });
});
