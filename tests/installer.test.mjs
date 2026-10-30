import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { root } from './helpers.mjs';

for (const args of [[], ['--ram'], ['--flash'], ['--development'], ['--ram', '--apply', '--development']]) {
  test('Stable installer refuses unqualified legacy assets before any mutation: ' + args.join(' '), async t => {
    const directory = await mkdtemp(join(tmpdir(), 'foxhole-legacy-refusal-'));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const bin = join(directory, 'bin'), marker = join(directory, 'mutation');
    await mkdir(bin);
    for (const tool of ['apk', 'id', 'uclient-fetch', 'sysupgrade']) {
      await writeFile(join(bin, tool), '#!/bin/sh\ntouch "$TEST_MUTATION"\nexit 88\n', { mode: 0o755 });
    }
    const result = spawnSync('/bin/sh', [join(root, 'install.sh'), '--legacy-hy2', ...args], {
      encoding: 'utf8', timeout: 10000,
      env: { ...process.env, PATH: bin + ':' + process.env.PATH, TEST_MUTATION: marker }
    });
    assert.ifError(result.error);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /not qualified for Stable/);
    await assert.rejects(access(marker), { code: 'ENOENT' });
  });
}
