import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { root } from './helpers.mjs';

test('source archive is byte-for-byte reproducible with a SHA-256 sidecar', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foxhole-source-build-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  for (const name of ['one.zip', 'two.zip']) {
    const run = spawnSync('python3', ['tools/build-source.py', '--output',
      join(directory, name)], { cwd: root, encoding: 'utf8', timeout: 30000 });
    assert.equal(run.status, 0, run.stderr);
  }
  assert.deepEqual(await readFile(join(directory, 'one.zip')),
    await readFile(join(directory, 'two.zip')));
  assert.match(await readFile(join(directory, 'one.zip.sha256'), 'utf8'),
    /^[0-9a-f]{64}  one\.zip\n$/);
});
