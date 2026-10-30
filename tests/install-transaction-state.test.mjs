import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { root } from './helpers.mjs';

test('failed durable-root transaction keeps exact pending identity and private recovery state', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'foxhole-install-state-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const stage = join(directory, 'private-stage');
  await mkdir(stage, { mode: 0o700 });
  const backup = 'owned synthetic backup; no production data\n';
  await writeFile(join(stage, 'backup.txt'), backup, { mode: 0o600 });
  const world = join(directory, 'owner-world');
  await writeFile(world, 'unrelated=7-r1\nkernel=1-r1\n', { mode: 0o600 });
  const source = await readFile(join(root, 'tools/install-core.sh'), 'utf8');
  const start = source.indexOf('finish() {');
  assert.ok(start >= 0, 'Installer must retain an honest phase and pending constraint after a partial transaction');
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start);
  const body = source.slice(start, end + 3);
  const script = join(directory, 'finish.sh');
  await writeFile(script, '#!/bin/sh\numask 077\n' + body + `
stage=$1
keep_stage=1
transaction_phase=durable-roots
pending_constraint=.foxhole-exact-0123456789abcdef=20261015.120000
install_complete=false
(exit 42)
finish
`);
  const result = spawnSync('/bin/sh', [script, stage], { encoding: 'utf8', timeout: 5000 });
  assert.ifError(result.error);
  assert.equal(result.status, 42, result.stderr);
  const state = JSON.parse(await readFile(join(stage, 'transaction-state.json'), 'utf8'));
  assert.deepEqual(state, { schema: 1, exitCode: 42, phase: 'durable-roots',
    pendingConstraint: '.foxhole-exact-0123456789abcdef=20261015.120000', complete: false });
  assert.equal(await readFile(join(stage, 'backup.txt'), 'utf8'), backup);
  assert.equal(await readFile(world, 'utf8'), 'unrelated=7-r1\nkernel=1-r1\n');
  assert.match(result.stderr, /Installation incomplete/);
  assert.match(result.stderr, /temporary constraint retained or pending/);
});
