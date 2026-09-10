import assert from 'node:assert/strict';
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
  for (const directory of ['media', 'docs', 'examples', '.github'])
    await writeFile(join(source, directory, 'example.txt'), 'Public fixture\n');
  return { directory, source, destination: join(directory, 'public') };
}

test('public export includes only the explicit source allowlist', async (t) => {
  const item = await fixture(t);
  for (const path of ['private-notes', 'dist', '.git']) {
    await mkdir(join(item.source, path));
    await writeFile(join(item.source, path, 'private.txt'), 'Not exported\n');
  }
  const result = await exportPublic(item);
  assert.deepEqual((await readdir(item.destination)).sort(),
    [...publicFiles, ...publicDirectories.filter(name => !['tests', 'tools'].includes(name))].sort());
  assert.equal(result.files.length, publicFiles.length + 7);
  assert.equal(await readFile(join(item.destination, 'package', 'Makefile'), 'utf8'),
    'PKG_NAME:=foxhole-openwrt-client\n');
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
  assert.throws(() => validatePublicFile('package/example.png',
    Buffer.from(['\0', 'dae', 'mon'].join(''))), /private identifier/);
});
