import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { collectPublic, exportPublic, publicFiles, publicDirectories, validatePublicFile } from '../tools/public-export.mjs';

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'foxhole-export-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const source = join(directory, 'source');
  for (const path of publicDirectories)
    await mkdir(join(source, path), { recursive: true });
  await writeFile(join(source, 'media', 'dashboard.svg'), '<svg xmlns="http://www.w3.org/2000/svg"/>');
  for (const path of publicFiles) await writeFile(join(source, path), 'Public fixture\n');
  await writeFile(join(source, 'package', 'Makefile'), 'PKG_NAME:=foxhole-openwrt-client\n');
  await writeFile(join(source, 'LICENSES', 'example.txt'), 'License fixture\n');
  await writeFile(join(source, 'config', 'release-signers.asc'), 'Public verification key fixture\n');
  for (const directory of ['media', 'docs', 'examples', '.github'])
    await writeFile(join(source, directory, 'example.txt'), 'Public fixture\n');
  return { directory, source, destination: join(directory, 'public') };
}

test('public export includes only the explicit source allowlist', async (t) => {
  const item = await fixture(t);
  await writeFile(join(item.source, 'AGENTS.md'), 'Local instructions only\n');
  await writeFile(join(item.source, 'package', 'AGENTS.md'), 'Local instructions only\n');
  for (const path of ['private-notes', 'dist', '.git']) {
    await mkdir(join(item.source, path));
    await writeFile(join(item.source, path, 'private.txt'), 'Not exported\n');
  }
  const result = await exportPublic(item);
  assert.deepEqual((await readdir(item.destination)).sort(),
    [...publicFiles, ...publicDirectories.filter(name => !['tests', 'tools'].includes(name))].sort());
  assert.equal(result.files.length, publicFiles.length + 8);
  assert.ok(result.files.every(path => !path.split('/').includes('AGENTS.md')));
  assert.throws(() => validatePublicFile('package/AGENTS.md', Buffer.from('Local only')),
    /prohibited path/);
  assert.equal(await readFile(join(item.destination, 'config', 'release-signers.asc'), 'utf8'),
    'Public verification key fixture\n');
  assert.equal(await readFile(join(item.destination, 'package', 'Makefile'), 'utf8'),
    'PKG_NAME:=foxhole-openwrt-client\n');
});

test('public export preserves GIF assets and rejects arbitrary binaries', async (t) => {
  const item = await fixture(t);
  const gif = Buffer.from(
    'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
  await writeFile(join(item.source, 'media', 'fhg.gif'), gif);
  const result = await exportPublic(item);
  assert.ok(result.files.includes('media/fhg.gif'));
  assert.deepEqual(await readFile(join(item.destination, 'media', 'fhg.gif')), gif);
  assert.throws(() => validatePublicFile('media/unknown.bin', gif),
    /unexpected binary file/);
});

test('public export rejects symlinks before writing a destination', async (t) => {
  const item = await fixture(t);
  await symlink('../README.md', join(item.source, 'package', 'linked.txt'));
  await assert.rejects(exportPublic(item), /symbolic links/);
  assert.ok(!(await readdir(item.directory)).includes('public'));
});

test('public export never overwrites a destination or writes into source', async (t) => {
  const item = await fixture(t);
  await mkdir(item.destination);
  await writeFile(join(item.destination, 'keep.txt'), 'Keep me');
  await assert.rejects(exportPublic(item), { code: 'EEXIST' });
  assert.equal(await readFile(join(item.destination, 'keep.txt'), 'utf8'), 'Keep me');
  await assert.rejects(exportPublic({ source: item.source,
    destination: join(item.source, 'snapshot') }), /outside the source/);
});

test('public export rejects credential files and legacy identifiers', async (t) => {
  const item = await fixture(t);
  await writeFile(join(item.source, 'package', 'sample.key'), 'Fixture only');
  await assert.rejects(collectPublic(item.source), /prohibited path/);
  assert.throws(() => validatePublicFile('package/example.js',
    Buffer.from(['dae', 'mon'].join(''))), /private identifier/);
  assert.throws(() => validatePublicFile('package/example.js',
    Buffer.from('/' + ['Users', 'example', 'private'].join('/'))), /private identifier/);
  assert.throws(() => validatePublicFile('package/example.js',
    Buffer.from(['-----BEGIN ', 'PRIVATE KEY-----'].join(''))), /credential material/);
  for (const extension of ['png', 'gif']) {
    assert.throws(() => validatePublicFile('package/example.' + extension,
      Buffer.from(['\0', 'dae', 'mon'].join(''))), /private identifier/);
  }
});

test('public APK key exception accepts only a P-256 public key', () => {
  const path = 'config/foxhole-openwrt-apk.pem';
  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1'
  });
  const pem = Buffer.from(publicKey.export({ type: 'spki', format: 'pem' }));
  assert.doesNotThrow(() => validatePublicFile(path, pem));
  assert.throws(() => validatePublicFile('config/other.pem', pem), /prohibited path/);
  assert.throws(() => validatePublicFile(path,
    Buffer.from(privateKey.export({ type: 'pkcs8', format: 'pem' }))),
  /credential material/);
  assert.throws(() => validatePublicFile(path, Buffer.concat([pem, pem])),
    /Invalid public APK key/);
  const other = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  assert.throws(() => validatePublicFile(path,
    Buffer.from(other.publicKey.export({ type: 'spki', format: 'pem' }))), /P-256/);
});
