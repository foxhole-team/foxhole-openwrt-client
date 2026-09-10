import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { read } from './helpers.mjs';

const sha = data => createHash('sha256').update(data).digest('hex');
const artifacts = ['hysteria-2.12.2-r2.apk',
  'hysteria-ram-2.12.2-r1.apk', 'foxhole-openwrt-client-0.1.0-r41.apk'];

async function fixture(t, options = {}) {
  const root = await mkdtemp(join(tmpdir(), 'foxhole-installer-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const path of ['etc/config', 'proc', 'tmp', 'bundle', 'bin'])
    await mkdir(join(root, path), { recursive: true });
  await writeFile(join(root, 'etc/openwrt_release'),
    "DISTRIB_RELEASE='25.12.5'\n");
  await writeFile(join(root, 'etc/config/dhcp'), 'unchanged DHCP fixture\n');
  await writeFile(join(root, 'proc/meminfo'),
    'MemAvailable: ' + (options.ram ?? 196608) + ' kB\n');
  let manifest = '';
  for (const file of artifacts) {
    const data = Buffer.from('not an APK; isolated installer test: ' + file);
    await writeFile(join(root, 'bundle', file), data);
    manifest += sha(data) + '  ' + file + '\n';
  }
  await writeFile(join(root, 'bundle/SHA256SUMS'), manifest);
  if (options.corrupt)
    await writeFile(join(root, 'bundle', artifacts[0]), 'tampered fixture');
  const prelude = [
    'id() { printf "0\\n"; }',
    'uname() { printf "aarch64\\n"; }',
    'df() { printf "Filesystem 1024-blocks Used Available Capacity Mounted\\n"; printf "fixture 999999 0 %s 0%% /overlay\\n" "$TEST_FLASH"; }',
    'uci() { test "$TEST_PENDING" != 1 || printf "pending fixture\\n"; }',
    'apk() {',
    '  if [ "$1" = --print-arch ]; then printf "aarch64_generic\\n"; return; fi',
    '  printf "%s\\n" "$*" >> "$TEST_ROOT/apk.calls"',
    '  case "$*" in',
    '    *--simulate*) test "$TEST_SIMULATION_FAIL" != 1; return ;;',
    '    add*) test -f "$TEST_ROOT/backup-created" || return 2',
    '          printf "installed\\n" > "$TEST_ROOT/installed" ;;',
    '  esac',
    '}',
    'sysupgrade() { printf "fixture backup\\n" > "$3"; touch "$TEST_ROOT/backup-created"; }'
  ].join('\n');
  let script = await read('install.sh');
  script = script.replace(/\/(?:etc|proc|tmp)\//g, prefix => root + prefix);
  script = script.replace('set -eu', prelude + '\nset -eu');
  await writeFile(join(root, 'install.sh'), script);
  await writeFile(join(root, 'bin/uclient-fetch'),
    '#!/bin/sh\necho "unexpected network call" >&2\nexit 99\n');
  await chmod(join(root, 'bin/uclient-fetch'), 0o755);
  if (spawnSync('sha256sum', ['--version']).error) {
    await writeFile(join(root, 'bin/sha256sum'),
      '#!/bin/sh\nexec shasum -a 256 "$@"\n');
    await chmod(join(root, 'bin/sha256sum'), 0o755);
  }
  return {
    root,
    run(args = []) {
      return spawnSync('/bin/sh', [join(root, 'install.sh'),
        '--bundle', join(root, 'bundle'), '--manifest-sha256',
        options.badManifest ? '0'.repeat(64) : sha(manifest), ...args], {
        encoding: 'utf8', timeout: 10000,
        env: { ...process.env, PATH: join(root, 'bin') + ':' + process.env.PATH,
          TEST_ROOT: root, TEST_FLASH: String(options.flash ?? 65536),
          TEST_PENDING: options.pending ? '1' : '0',
          TEST_SIMULATION_FAIL: options.simulationFail ? '1' : '0' }
      });
    }
  };
}

test('installer defaults to flash; validation does not install', async t => {
  const f = await fixture(t);
  const result = f.run();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /mode=flash/);
  const calls = await readFile(join(f.root, 'apk.calls'), 'utf8');
  assert.match(calls, /hysteria-2.12.2-r2\.apk/);
  assert.doesNotMatch(calls, /hysteria-ram|allow-untrusted/);
  await assert.rejects(readFile(join(f.root, 'installed')), { code: 'ENOENT' });
});

test('low flash refuses automatic RAM fallback', async t => {
  const f = await fixture(t, { flash: 8192 });
  const result = f.run(['--apply']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /--ram/);
  await assert.rejects(readFile(join(f.root, 'apk.calls')), { code: 'ENOENT' });
});

test('explicit --ram selects RAM even when flash is sufficient', async t => {
  const f = await fixture(t);
  const result = f.run(['--ram']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /mode=ram/);
  assert.match(await readFile(join(f.root, 'apk.calls'), 'utf8'),
    /hysteria-ram-2.12.2-r1.apk/);
});

test('RAM apply on low flash backs up before install and preserves DHCP', async t => {
  const f = await fixture(t, { flash: 8192 });
  const result = f.run(['--ram', '--apply', '--development']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(await readFile(join(f.root, 'installed'), 'utf8'), 'installed\n');
  assert.equal(await readFile(join(f.root, 'etc/config/dhcp'), 'utf8'),
    'unchanged DHCP fixture\n');
  assert.match(await readFile(join(f.root, 'apk.calls'), 'utf8'), /allow-untrusted/);
});

for (const [name, options, args] of [
  ['low RAM', { ram: 32000 }, ['--ram']],
  ['RAM overlay headroom', { flash: 2048 }, ['--ram']],
  ['low flash-mode RAM', { ram: 32000 }, []],
  ['pending UCI changes', { pending: true }, []],
  ['untrusted manifest', { badManifest: true }, []],
  ['tampered APK', { corrupt: true }, []],
  ['failed dependency resolution', { simulationFail: true }, []],
  ['removed automatic-mode option', {}, ['--mode', 'auto']]
]) {
  test('installer refuses ' + name + ' without installation', async t => {
    const f = await fixture(t, options);
    const result = f.run([...args, '--apply']);
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.stderr, /not a valid identifier|Syntax error|syntax error/);
    await assert.rejects(readFile(join(f.root, 'installed')), { code: 'ENOENT' });
  });
}
