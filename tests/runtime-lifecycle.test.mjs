import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';

const sourcePath = new URL('../package/foxhole-openwrt-client/' +
  'root/usr/libexec/foxhole-supervisor', import.meta.url);

function alive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) {
    if (error.code === 'ESRCH') return false;
    throw error;
  }
}

async function until(condition) {
  const end = Date.now() + 3000;
  while (Date.now() < end) {
    const result = await condition();
    if (result) return result;
    await delay(10);
  }
  assert.fail('Supervisor fixture did not reach the expected state');
}

async function readOptional(path) {
  try { return await readFile(path, 'utf8'); }
  catch (error) {
    if (error.code === 'ENOENT') return '';
    throw error;
  }
}

async function harness(t, mode = 'tunnel', prepare = 'success') {
  const directory = await mkdtemp(join(tmpdir(), 'foxhole-lifecycle-'));
  const log = join(directory, 'events');
  const release = join(directory, 'release-prepare');
  const sleeper = join(directory, 'sleep.pid');
  const started = join(directory, 'hysteria.pid');
  let supervisor;
  t.after(async () => {
    if (supervisor?.pid) {
      try { process.kill(-supervisor.pid, 'SIGKILL'); }
      catch (error) { if (error.code !== 'ESRCH') throw error; }
    }
    await rm(directory, { recursive: true, force: true });
  });
  const executable = async (name, content) => {
    const path = join(directory, name);
    await writeFile(path, '#!/bin/sh\n' + content, { mode: 0o700 });
    return path;
  };
  const controller = await executable('controller', `
printf '%s\n' "$*" >> "$FH_TEST_LOG"
case "$1" in
  mode) printf '%s\n' "$FH_TEST_MODE" ;;
  prepare)
    case "$FH_TEST_PREPARE" in
      fail) exit 1 ;;
      wait)
        while [ ! -f "$FH_TEST_RELEASE" ]; do /bin/sleep 0.01; done
        ;;
    esac
    ;;
esac
exit 0
`);
  const hysteria = await executable('hysteria', `
printf '%s\n' "$$" > "$FH_TEST_STARTED"
exec /bin/sleep 60
`);
  await executable('sleep', `
if [ "$1" = 3600 ]; then
  printf '%s\n' "$$" > "$FH_TEST_SLEEPER"
fi
exec /bin/sleep "$@"
`);
  const quote = (value) => "'" + value.replaceAll("'", "'\\''") + "'";
  const original = await readFile(sourcePath, 'utf8');
  const adapted = original
    .replace("'/usr/libexec/foxhole-runtime'", quote(controller))
    .replace("'/tmp/foxhole/hysteria.json'", quote(join(directory, 'config')))
    .replace("'/sys/class/net/foxhole0'", quote(join(directory, 'tun')))
    .replace('/usr/bin/hysteria client', quote(hysteria) + ' client');
  assert.notEqual(adapted, original);
  const script = join(directory, 'supervisor');
  await writeFile(script, adapted, { mode: 0o700 });
  supervisor = spawn('/bin/sh', [script], {
    detached: true, stdio: 'ignore',
    env: { ...process.env, PATH: directory + ':' + process.env.PATH,
      FH_TEST_LOG: log, FH_TEST_MODE: mode, FH_TEST_PREPARE: prepare,
      FH_TEST_RELEASE: release, FH_TEST_SLEEPER: sleeper,
      FH_TEST_STARTED: started }
  });
  const exited = new Promise((resolve, reject) => {
    supervisor.once('error', reject);
    supervisor.once('exit', (code, signal) => resolve({ code, signal }));
  });
  return {
    supervisor, exited,
    events: async () => (await readOptional(log)).trim().split('\n'),
    release: () => writeFile(release, ''),
    started: () => readOptional(started),
    sleeper: async () => Number(await readOptional(sleeper))
  };
}

test('TERM during prepare cannot start Hysteria afterwards',
  { timeout: 5000 }, async (t) => {
    const fixture = await harness(t, 'tunnel', 'wait');
    await until(async () => (await fixture.events()).includes('prepare'));
    fixture.supervisor.kill('SIGTERM');
    await fixture.release();
    assert.deepEqual(await fixture.exited, { code: 0, signal: null });
    assert.equal(await fixture.started(), '');
    assert.deepEqual(await fixture.events(), [
      'mode', 'prepare', 'down runtime_stopped'
    ]);
  });

test('failed prepare runs the down controller before exiting',
  { timeout: 5000 }, async (t) => {
    const fixture = await harness(t, 'tunnel', 'fail');
    assert.deepEqual(await fixture.exited, { code: 1, signal: null });
    assert.equal(await fixture.started(), '');
    assert.deepEqual(await fixture.events(), [
      'mode', 'prepare', 'down tunnel_start_failed'
    ]);
  });

test('stopping blocked mode reaps its background sleep process',
  { timeout: 5000 }, async (t) => {
    const fixture = await harness(t, 'block');
    const sleeper = await until(() => fixture.sleeper());
    assert.equal(alive(sleeper), true);
    fixture.supervisor.kill('SIGTERM');
    assert.deepEqual(await fixture.exited, { code: 0, signal: null });
    assert.deepEqual(await fixture.events(), [
      'mode', 'apply blocked', 'down runtime_stopped'
    ]);
    assert.equal(alive(sleeper), false,
      'Blocked supervisor left its hourly sleep process running');
  });
