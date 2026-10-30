import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import test from 'node:test';
import { root } from './helpers.mjs';

const source = await readFile(join(root, 'tools/install-compact.sh'), 'utf8');
function functionBody(name) {
  const start = source.indexOf(`${name}() {\n`);
  assert.ok(start >= 0, `Missing ${name} in the actual installer`);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start);
  return source.slice(start, end + 3);
}
async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'foxhole-compact-lock-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const stage = join(directory, 'stage');
  await mkdir(stage, { mode: 0o700 });
  const prelude = `#!/bin/sh\nset -eu\numask 077\n${functionBody('acquire_transaction_lock')}\n${functionBody('finish')}\ntransaction_lock=$1\ntransaction_lock_held=0\nstage=$2\nkeep_stage=1\ntransaction_phase=testing\npending_constraint=''\ninstall_complete=false\n`;
  return { directory, stage, lock: join(directory, 'lock'), prelude };
}
function run(f, suffix) {
  const result = spawnSync('/bin/sh', ['-c', f.prelude + suffix, 'fixture', f.lock, f.stage],
    { encoding: 'utf8', timeout: 5000 });
  assert.ifError(result.error);
  return result;
}

test('a second installer is refused while the first process is alive and after its death', async t => {
  const f = await fixture(t);
  const first = spawn('/bin/sh', ['-c', f.prelude + '\nacquire_transaction_lock\nprintf "READY\\n"\nread -r release\n',
    'fixture', f.lock, f.stage], { stdio: ['pipe', 'pipe', 'pipe'] });
  t.after(() => { if (first.exitCode === null) first.kill('SIGKILL'); });
  const ready = await Promise.race([once(first.stdout, 'data'), once(first, 'exit').then(() => { throw new Error('First installer exited before acquisition'); })]);
  assert.equal(ready[0].toString(), 'READY\n');
  assert.equal(run(f, '\nacquire_transaction_lock\n').status, 1);
  const exited = once(first, 'exit');
  first.kill('SIGKILL');
  await exited;
  assert.equal(run(f, '\nacquire_transaction_lock\n').status, 1);
});

test('successful completion releases only its own lock', async t => {
  const f = await fixture(t);
  const result = run(f, '\ntrap finish EXIT\nacquire_transaction_lock\ninstall_complete=true\nexit 0\n');
  assert.equal(result.status, 0, result.stderr);
  const second = run(f, '\nacquire_transaction_lock\n');
  assert.equal(second.status, 0, second.stderr);
});

test('failed mutation retains the lock and original failure status', async t => {
  const f = await fixture(t);
  const result = run(f, '\ntrap finish EXIT\nacquire_transaction_lock\nexit 42\n');
  assert.equal(result.status, 42, result.stderr);
  assert.equal(run(f, '\nacquire_transaction_lock\n').status, 1);
  const state = JSON.parse(await readFile(join(f.stage, 'transaction-state.json'), 'utf8'));
  assert.equal(state.exitCode, 42);
  assert.equal(state.complete, false);
});

test('an existing symlink cannot be reclaimed or followed as an installer lock', async t => {
  const f = await fixture(t);
  const outside = join(f.directory, 'unrelated');
  await mkdir(outside);
  await writeFile(join(outside, 'keep'), 'unchanged');
  await symlink(outside, f.lock);
  assert.equal(run(f, '\nacquire_transaction_lock\n').status, 1);
  assert.equal(await readFile(join(outside, 'keep'), 'utf8'), 'unchanged');
});

test('fresh state and world are checked under the lock before the first mutation', () => {
  const apply = source.indexOf('[ "$apply" = 1 ] ||');
  const locked = source.indexOf('\nacquire_transaction_lock\n', apply);
  const mutate = source.indexOf('\ntransaction_phase=backup\n', apply);
  assert.ok(apply >= 0 && locked > apply && mutate > locked);
  const checks = source.slice(locked, mutate);
  assert.match(checks, /uci changes/);
  assert.match(checks, /Existing FoxHole state requires paired management/);
  assert.match(checks, /prior-owned-locked\.json/);
  assert.match(checks, /cmp -s \/etc\/apk\/world "\$stage\/world\.before"/);
});
