import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const installer = fileURLToPath(new URL('../install.sh', import.meta.url));

test('CLI can display the complete versioned agreement without installing anything', () => {
  const result = spawnSync('sh', [installer, '--license'], { encoding: 'utf8', timeout: 3000 });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /FoxHole OpenWRT Client/);
  for (const point of [1, 2, 3, 4, 5]) assert.match(result.stdout, new RegExp(`(?:^|\\n)${point}\\. `));
});

test('CLI help exposes explicit acceptance and the agreement view', () => {
  const result = spawnSync('sh', [installer, '--help'], { encoding: 'utf8', timeout: 3000 });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /--accept-license/);
  assert.match(result.stdout, /--license/);
});

test('noninteractive installation refuses absent consent before staging or package work', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'foxhole-license-cli-'));
  try {
    await writeFile(join(dir, 'id'), '#!/bin/sh\nprintf "0\\n"\n');
    await chmod(join(dir, 'id'), 0o755);
    await writeFile(join(dir, 'mktemp'), '#!/bin/sh\necho UNEXPECTED_STAGING >&2\nexit 99\n');
    await chmod(join(dir, 'mktemp'), 0o755);
    const result = spawnSync('sh', [installer, '--apply', '--bundle', '/unavailable-test-bundle',
      '--manifest-sha256', 'a'.repeat(64)], {
      cwd: root, env: { ...process.env, PATH: `${dir}:${process.env.PATH}` },
      encoding: 'utf8', timeout: 3000, input: ''
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /license agreement|--accept-license/i);
    assert.doesNotMatch(result.stderr, /UNEXPECTED_STAGING/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
