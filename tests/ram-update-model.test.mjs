// Source-adapted Ucode model checks; native parser/signature QA is separate.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const source = readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/ram-update-model.uc', import.meta.url), 'utf8');
const exported = [...source.matchAll(/^export (?:function|const) (\w+)/gm)].map(found => found[1]);
const adapted = source.replace(/^import .*;\n/gm, '').replace(/^export /gm, '')
  .replace(/\bfor\(let (\w+) in /g, 'for(let $1 of ');
const sha = value => createHash('sha256').update(value).digest('hex');
const bindings = {
  digest: { sha256: sha }, updates: { fail: reason => { throw new Error(reason); }, base_layout: (value, version) => ({ value, version }) },
  type: value => value == null ? 'null' : Array.isArray(value) ? 'array' : typeof value === 'boolean' ? 'bool'
    : Number.isInteger(value) ? 'int' : typeof value,
  length: value => Buffer.isBuffer(value) || Array.isArray(value) ? value.length : typeof value === 'string' ? Buffer.byteLength(value) : Object.keys(value).length,
  keys: Object.keys, match: (value, pattern) => String(value).match(pattern), index: (value, item) => value.indexOf(item),
  split: (value, separator) => value.split(separator), replace: (value, search, replacement) => value.replace(search, replacement),
  sprintf: (format, value) => { assert.equal(format, '%J'); return JSON.stringify(value); },
  slice: (value, from, to) => value.slice(from, to), b64dec: value => Buffer.from(value, 'base64'), b64enc: value => Buffer.from(value).toString('base64'),
  substr: (value, from, count) => value.substr(from, count)
};
const model = new Function(...Object.keys(bindings), `${adapted}\nreturn {${exported.join(',')}};`)(...Object.values(bindings));
const begin = () => ({ expectedRevision: 3, requestId: 'a'.repeat(32), releaseTag: 'v1.0.2', version: '1.0.2-r1', fileSha256: 'b'.repeat(64), fileBytes: 1234 });
const release = (version, flags = {}) => ({ draft: false, prerelease: true, tag_name: `v${version.split('-r')[0]}`,
  assets: [{ name: `foxhole-openwrt-client-${version}.apk`, size: 2000 }, { name: 'SHA256SUMS', size: 300 }], ...flags });

test('native-style numeric version order is bounded to supported package versions', () => {
  assert.equal(model.compare('1.10.0-r1', '1.2.0-r9'), 1);
  assert.equal(model.compare('1.0.2-r10', '1.0.2-r2'), 1);
  assert.equal(model.compare('1.0.2-r1', '1.0.2-r1'), 0);
  assert.throws(() => model.compare('1.0.2-beta', '1.0.2-r1'));
});
test('device manifest rejects arbitrary URLs, keys, scripts, unknown and oversized fields', () => {
  assert.equal(model.begin_request(begin()).fileBytes, 1234);
  for (const field of ['url', 'keys', 'scripts']) assert.throws(() => model.begin_request({ ...begin(), [field]: 'untrusted' }), /INVALID_REQUEST/);
  assert.throws(() => model.begin_request({ ...begin(), fileBytes: 8388609 }), /INVALID_REQUEST/);
  assert.throws(() => model.begin_request({ ...begin(), releaseTag: 'v1.0.3' }), /INVALID_REQUEST/);
});
test('chunks require canonical base64 and exact decoded size and digest', () => {
  const raw = Buffer.from([0, 255, 128, 42]);
  const chunk = { uploadId: `update-upload-${'1'.repeat(32)}`, offset: 0, dataBase64: raw.toString('base64'), chunkSha256: sha(raw) };
  assert.deepEqual(model.chunk_request(chunk), raw);
  assert.throws(() => model.chunk_request({ ...chunk, chunkSha256: 'f'.repeat(64) }), /PACKAGE_VERIFICATION_FAILED/);
  const huge = Buffer.alloc(65537);
  assert.throws(() => model.chunk_request({ ...chunk, dataBase64: huge.toString('base64'), chunkSha256: sha(huge) }), /PACKAGE_VERIFICATION_FAILED/);
  assert.throws(() => model.chunk_request({ ...chunk, dataBase64: 'YR==', chunkSha256: sha(Buffer.from('a')) }), /PACKAGE_VERIFICATION_FAILED/);
});
test('only known network-connect or timeout exit4 enables device fallback', () => {
  for (const text of ['Connection error: Connection failed', 'Connection error: Connection timed out']) assert.equal(model.network_unreachable(4, text), true);
  for (const [code, text] of [[5, 'Connection error: Connection failed'], [8, 'HTTP error 404'], [124, ''], [4, 'Unknown error'],
    [4, 'SSL error: invalid peer\nConnection error: Connection failed'], [4, 'certificate rejected\nConnection error: Connection timed out'],
    [4, 'Connection reset prematurely'], [1, 'signature verification failed']]) assert.equal(model.network_unreachable(code, text), false);
});
test('selector includes prereleases, excludes drafts, ignores supplied asset URLs and chooses highest complete BASE', () => {
  const rows = [release('1.0.9-r1', { draft: true }), release('1.0.2-r1'), release('1.0.3-r2')];
  rows[2].assets[0].browser_download_url = 'https://attacker.invalid/payload';
  const selected = model.select_release(rows, '1.0.1-r1');
  assert.equal(selected.version, '1.0.3-r2'); assert.equal('url' in selected, false);
  assert.equal(model.select_release([release('1.0.1-r1')], '1.0.1-r1'), null);
  assert.throws(() => model.select_release([], '1.0.1-r1'), /RELEASE_UNAVAILABLE/);
});
test('SHA256SUMS binding is exact and duplicate or malformed roles fail closed', () => {
  const name = 'foxhole-openwrt-client-1.0.2-r1.apk', sum = 'a'.repeat(64);
  assert.equal(model.checksum(`${sum}  ${name}\n`, name), sum);
  assert.throws(() => model.checksum(`${sum}  ${name}\n${sum}  ${name}\n`, name));
  assert.throws(() => model.checksum(`${sum}  ../${name}\n`, name));
});
test('candidate signed policy must bind version, release and both ABI values', () => {
  const value = { schema: 1, transactionAbi: 1, stateAbi: 1, osRelease: '25.12.5', packageVersion: '1.0.2-r1', releaseTag: 'v1.0.2', targets: ['x86/64', 'mediatek/filogic'] };
  assert.equal(model.policy(value, '1.0.2-r1', 'v1.0.2'), value);
  assert.throws(() => model.policy({ ...value, packageVersion: '1.0.0-r3' }, '1.0.2-r1', 'v1.0.2'));
  assert.throws(() => model.policy({ ...value, stateAbi: 2 }, '1.0.2-r1', 'v1.0.2'));
  assert.throws(() => model.policy({ ...value, keys: [] }, '1.0.2-r1', 'v1.0.2'));
});
test('native capture admits only fixed transport, isolated stages and fixed switch job IDs', () => {
  const output = `/tmp/foxhole/ram-updates/io-${'a'.repeat(32)}`;
  assert.equal(model.capture_arguments(output, 'probe', [model.release_api]), true);
  assert.equal(model.capture_arguments(output, 'current', ['/tmp/foxhole-ram-stage-20261031-ninth/root', 'aarch64_cortex-a53']), true);
  assert.equal(model.capture_arguments(output, 'switch', [`update-job-${'a'.repeat(32)}`]), true);
  assert.throws(() => model.capture_arguments(output, 'fetch', ['http://github.com/payload']));
  assert.throws(() => model.capture_arguments(output, 'current', ['/', 'aarch64_cortex-a53']));
  assert.throws(() => model.capture_arguments(output, 'switch', ['/tmp/user-script']));
});
