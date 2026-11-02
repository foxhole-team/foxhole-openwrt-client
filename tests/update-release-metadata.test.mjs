import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, lstat, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { functionBody, packageRoot, read } from './helpers.mjs';

const source = await read(`${packageRoot}/root/usr/share/foxhole/update-native.uc`);
const model = await read(`${packageRoot}/root/usr/share/foxhole/update-model.uc`);
const helper = await read(`${packageRoot}/root/usr/libexec/foxhole-update-hint`);
const maximum = 1048576, requiredMemory = 33554432 + 4 * maximum;
function release(bytes) {
  const value = { tag_name: 'v1.0.1', draft: false, prerelease: false,
    assets: Array.from({ length: 235 }, (_, i) => ({ name: `asset-${i}`, size: 1234 })), body: '' };
  value.body = 'x'.repeat(bytes - JSON.stringify(value).length);
  const raw = JSON.stringify(value); assert.equal(Buffer.byteLength(raw), bytes); return raw;
}
function native(raw, memory = [requiredMemory, requiredMemory]) {
  let created = false, fetches = 0, payloadReads = 0, memoryReads = 0;
  const context = vm.createContext({
    RELEASE_METADATA_BYTES: Number(source.match(/const RELEASE_METADATA_BYTES\s*=\s*([0-9]+)/)?.[1]),
    length: value => typeof value === 'string' ? Buffer.byteLength(value) : value.length,
    json: JSON.parse, type: value => typeof value,
    match: (value, expression) => value.match(expression), sprintf: (_format, value) => JSON.stringify(value),
    store: { target() {} }, guard: { fail: reason => { throw new Error(reason); } },
    system: () => { created = true; fetches++; return 0; },
    fs: {
      lstat: () => created ? { type: 'file', uid: 0, nlink: 1, mode: 0o600,
        dev: 1, inode: 2, mtime: 3, ctime: 3, size: Buffer.byteLength(raw) } : null,
      readfile: (path, limit) => {
        if (path === '/proc/meminfo') {
          const value = memory[Math.min(memoryReads++, memory.length - 1)];
          return value == null ? 'MemFree: 1 kB\n' : `MemAvailable: ${value / 1024} kB\n`;
        }
        payloadReads++; assert.equal(limit, maximum + 1); return raw;
      }
    }
  });
  for (const [name, args] of [['release_memory', ''], ['public_raw', 'path,maximum'], ['decode', 'raw'], ['latest', 'directory']])
    vm.runInContext(`function ${name}(${args}) ${functionBody(source, name)}`, context);
  vm.runInContext(`guard.release_tag = function(value) ${functionBody(model, 'release_tag')}`, context);
  context.fail = context.guard.fail;
  return { run: () => context.latest('/tmp/foxhole/update-job-' + 'a'.repeat(32)),
    counts: () => ({ fetches, payloadReads, memoryReads }) };
}
async function download(raw, status = 0, existing = false) {
  const directory = await mkdtemp(join(tmpdir(), 'foxhole-release-meta-'));
  try {
    const bin = join(directory, 'bin'), root = join(directory, 'foxhole');
    const job = join(root, 'update-job-' + 'a'.repeat(32));
    await mkdir(bin); await mkdir(job, { recursive: true });
    const input = join(directory, 'input.json'), bytes = join(directory, 'bytes'), output = join(job, 'release-hint.json');
    await writeFile(input, raw, { mode: 0o600 });
    await writeFile(join(bin, 'uclient-fetch'), `#!/bin/sh
[ "$#" -eq 5 ] && [ "$1" = '-T' ] && [ "$2" = '20' ] && [ "$3" = '-O' ] || exit 95
[ "$5" = 'https://api.github.com/repos/foxhole-team/foxhole-openwrt-client/releases/latest' ] || exit 96
cat "$FETCH_INPUT" > "$4"
result=$?
wc -c < "$4" > "$FETCH_BYTES"
[ "$result" -eq 0 ] || exit "$result"
exit "$FETCH_STATUS"
`, { mode: 0o755 });
    await writeFile(join(bin, 'ln'), '#!/bin/sh\n[ "$1" = -T ] || exit 97\nexec /bin/ln "$2" "$3"\n', { mode: 0o755 });
    const script = join(directory, 'hint.sh');
    // Darwin sh uses 1024-byte blocks; the target BusyBox uses 512-byte blocks.
    let adapted = helper.replaceAll('/tmp/foxhole', root);
    if (process.platform === 'darwin') adapted = adapted.replace('ulimit -f 2048', 'ulimit -f 1024');
    await writeFile(script, adapted);
    if (existing) await writeFile(output, 'preserved', { mode: 0o600 });
    const result = spawnSync('sh', [script, output], { encoding: 'utf8', timeout: 5000,
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, FETCH_INPUT: input,
        FETCH_BYTES: bytes, FETCH_STATUS: String(status) } });
    const names = await readdir(job), published = names.includes('release-hint.json');
    return { status: result.status, names, raw: published ? await readFile(output, 'utf8') : null,
      info: published ? await lstat(output) : null,
      downloadedBytes: await readFile(bytes, 'utf8').then(x => Number(x.trim()), () => null) };
  } finally { await rm(directory, { recursive: true, force: true }); }
}
test('native hint role admits 235-asset metadata at the observed size and at the exact 1 MiB bound', () => {
  assert.equal(Number(source.match(/const RELEASE_METADATA_BYTES\s*=\s*([0-9]+)/)?.[1]), maximum);
  for (const bytes of [393177, maximum]) assert.equal(native(release(bytes)).run(), 'v1.0.1');
  const oversized = native(release(maximum + 1));
  assert.throws(() => oversized.run(), /PACKAGE_VERIFICATION_FAILED/); assert.equal(oversized.counts().payloadReads, 0);
});
test('native hint retains the existing process reserve before fetch and before JSON parsing', () => {
  assert.equal(native(release(393177)).run(), 'v1.0.1');
  for (const memory of [[requiredMemory - 1024], [null]]) {
    const fixture = native(release(393177), memory);
    assert.throws(() => fixture.run(), /NO_SPACE/); assert.equal(fixture.counts().fetches, 0);
  }
  const dropped = native(release(393177), [requiredMemory, requiredMemory - 1024]);
  assert.throws(() => dropped.run(), /NO_SPACE/); assert.equal(dropped.counts().payloadReads, 0);
});
test('metadata admission does not change the existing normal-release/tag policy', () => {
  for (const value of [{ tag_name: 'v1.0.2', draft: false, prerelease: true },
    { tag_name: 'v1.0.2', draft: true, prerelease: false },
    { tag_name: 'v1.0.2-beta', draft: false, prerelease: false }])
    assert.throws(() => native(JSON.stringify(value)).run(), /RELEASE_UNAVAILABLE/);
});
test('helper publishes observed-size and exact-bound metadata with no partial files', async () => {
  assert.match(helper, /ulimit -f 2048/);
  for (const bytes of [393177, maximum]) {
    const raw = release(bytes), result = await download(raw);
    assert.equal(result.status, 0); assert.equal(result.raw, raw);
    assert.deepEqual(result.names, ['release-hint.json']); assert.equal(result.info.nlink, 1);
    assert.equal(result.info.mode & 0o777, 0o600);
  }
});
test('helper rejects over 1 MiB at the file-size limit and cleans every partial', async () => {
  const result = await download(release(maximum + 1));
  assert.notEqual(result.status, 0); assert.deepEqual(result.names, []);
  assert.equal(result.downloadedBytes, maximum);
});
test('failed fetch and pre-existing output cannot publish or overwrite metadata', async () => {
  const failed = await download(release(393177), 4);
  assert.notEqual(failed.status, 0); assert.deepEqual(failed.names, []);
  const exists = await download(release(393177), 0, true);
  assert.notEqual(exists.status, 0); assert.equal(exists.raw, 'preserved'); assert.equal(exists.downloadedBytes, null);
});
test('actual published release receipt passes without distributing its operational fixture',
  { skip: !process.env.FOXHOLE_FLASH_RELEASE_FIXTURE }, async () => {
    const path = process.env.FOXHOLE_FLASH_RELEASE_FIXTURE, info = await lstat(path);
    const parent = await lstat(join(path, '..'));
    assert.ok(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && !(info.mode & 0o022));
    assert.ok(parent.isDirectory() && !(parent.mode & 0o022));
    assert.equal(info.size, 393177);
    const raw = await readFile(path, 'utf8');
    assert.equal(createHash('sha256').update(raw).digest('hex'), '4d3fbf940ee914683385cb5158024438a510acd74096d06ad6c9d4aaac0b9b75');
    const value = JSON.parse(raw); assert.equal(value.assets.length, 235);
    assert.equal(native(raw).run(), 'v1.0.1');
    const result = await download(raw); assert.equal(result.status, 0); assert.equal(result.raw, raw);
  });
