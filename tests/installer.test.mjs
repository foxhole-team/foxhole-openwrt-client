import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, mkdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { read, root as repo } from './helpers.mjs';

const sha = data => createHash('sha256').update(data).digest('hex');
const artifacts = ['hysteria-2.12.2-r2.apk',
  'hysteria-ram-2.12.2-r1.apk', 'foxhole-openwrt-client-0.1.0-r41.apk'];
const keyName = 'foxhole-openwrt-apk.pem';
const publicKey = await readFile(join(repo, 'config', keyName));

async function fixture(t, options = {}) {
  const root = await mkdtemp(join(tmpdir(), 'foxhole-installer-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const path of ['etc/config', 'etc/apk/keys', 'proc', 'tmp', 'bundle', 'bin'])
    await mkdir(join(root, path), { recursive: true });
  await writeFile(join(root, 'etc/apk/keys/openwrt.pem'), 'system trust fixture\n');
  await writeFile(join(root, 'etc/apk/arch'), options.arch ?? 'aarch64_generic\n');
  if (options.existingKey) {
    const path = join(root, 'etc/apk/keys', keyName);
    await writeFile(path, options.existingKey === 'matching' ? publicKey : 'existing different key\n');
    await chmod(path, 0o444);
  }
  if (options.symlinkKey)
    await symlink(join(root, 'etc/apk/keys/openwrt.pem'), join(root, 'etc/apk/keys', keyName));
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
  const downloadedKey = options.tamperedKey ? Buffer.from('untrusted replacement key\n') : publicKey;
  if (!options.missingKey) await writeFile(join(root, 'bundle', keyName), downloadedKey);
  if (!options.missingKeyEntry) {
    const hash = options.badKeyEntry ? '0'.repeat(64) : sha(downloadedKey);
    manifest += hash + '  ' + keyName + '\n';
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
    '  if [ "$1" = --print-arch ]; then printf "aarch64\\n"; return; fi',
    '  printf "%s\\n" "$*" >> "$TEST_ROOT/apk.calls"',
    '  if [ "$1" = --keys-dir ]; then',
    '    keys=$2; shift 2',
    '    cmp -s "$keys/foxhole-openwrt-apk.pem" "$TEST_REPO/config/foxhole-openwrt-apk.pem" || return 20',
    '    cmp -s "$keys/openwrt.pem" "$TEST_ROOT/etc/apk/keys/openwrt.pem" || return 21',
    '  elif [ "$1" != update ]; then',
    '    case "$*" in *--allow-untrusted*) ;; *) return 22 ;; esac',
    '  fi',
    '  case "$*" in',
    '    verify*) test "$TEST_SIGNATURE_FAIL" != 1 || return 23',
    '             touch "$TEST_ROOT/signatures-verified" ;;',
    '    *--simulate*) test "$TEST_SIMULATION_FAIL" != 1; return ;;',
    '    add*) test -f "$TEST_ROOT/backup-created" || return 2',
    '          case "$*" in *--allow-untrusted*) ;; *)',
    '            test -f "$TEST_ROOT/signatures-verified" || return 24',
    '            cmp -s "$TEST_ROOT/etc/apk/keys/foxhole-openwrt-apk.pem" "$TEST_REPO/config/foxhole-openwrt-apk.pem" || return 25 ;;',
    '          esac',
    '          printf "installed\\n" > "$TEST_ROOT/installed" ;;',
    '  esac',
    '}',
    'sysupgrade() {',
    '  if [ -e "$TEST_ROOT/etc/apk/keys/foxhole-openwrt-apk.pem" ]; then touch "$TEST_ROOT/key-before-backup"; fi',
    '  printf "fixture backup\\n" > "$3"; touch "$TEST_ROOT/backup-created";',
    '}'
  ].join('\n');
  let script = await read('install.sh');
  script = script.replace(/\/(?:etc|proc|tmp)\//g, prefix => root + prefix);
  script = script.replace('set -eu', prelude + '\nset -eu');
  await writeFile(join(root, 'install.sh'), script);
  await writeFile(join(root, 'bin/uclient-fetch'),
    '#!/bin/sh\nset -eu\n' +
    'test "$#" = 6 && test "$1 $2 $3 $4" = "-q -T 60 -O"\n' +
    'case "$6" in https://release.invalid/test/*) ;; *) exit 99 ;; esac\n' +
    'name=${6##*/}\ncase "$name" in SHA256SUMS|foxhole-openwrt-apk.pem|*.apk) ;; *) exit 99 ;; esac\n' +
    'printf "%s\\n" "$6" >> "$TEST_ROOT/downloads"\n' +
    'cp "$TEST_ROOT/bundle/$name" "$5"\n');
  await chmod(join(root, 'bin/uclient-fetch'), 0o755);
  await writeFile(join(root, 'bin/ln'), '#!/bin/sh\n' +
    'test "$TEST_KEY_INSTALL_FAIL" != 1 || exit 1\n' +
    'test "$#" = 3 && test "$1" = -T || exit 1\n' +
    'test ! -e "$3" && test ! -L "$3" || exit 1\n' +
    'exec /bin/ln "$2" "$3"\n');
  await chmod(join(root, 'bin/ln'), 0o755);
  if (spawnSync('sha256sum', ['--version']).error) {
    await writeFile(join(root, 'bin/sha256sum'),
      '#!/bin/sh\nexec shasum -a 256 "$@"\n');
    await chmod(join(root, 'bin/sha256sum'), 0o755);
  }
  return {
    root,
    run(args = []) {
      return spawnSync('/bin/sh', [join(root, 'install.sh'),
        ...(options.remote ? ['--base-url', 'https://release.invalid/test'] :
          ['--bundle', join(root, 'bundle')]), '--manifest-sha256',
        options.badManifest ? '0'.repeat(64) : sha(manifest), ...args], {
        encoding: 'utf8', timeout: 10000,
        env: { ...process.env, PATH: join(root, 'bin') + ':' + process.env.PATH,
          TEST_ROOT: root, TEST_REPO: repo, TEST_FLASH: String(options.flash ?? 65536),
          TEST_PENDING: options.pending ? '1' : '0',
          TEST_SIGNATURE_FAIL: options.signatureFail ? '1' : '0',
          TEST_KEY_INSTALL_FAIL: options.keyInstallFail ? '1' : '0',
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
  assert.match(calls, /^--keys-dir .+ verify .+\.apk .+\.apk\nupdate\n--keys-dir .+ add --simulate /);
  await assert.rejects(readFile(join(f.root, 'installed')), { code: 'ENOENT' });
  await assert.rejects(readFile(join(f.root, 'etc/apk/keys', keyName)), { code: 'ENOENT' });
  await assert.rejects(readFile(join(f.root, 'backup-created')), { code: 'ENOENT' });
});

test('installer pins the committed public key', async () => {
  assert.match(await read('install.sh'), new RegExp('public_sha256=' + sha(publicKey) + '\n'));
});

test('signed release downloads verify the key and both packages before applying', async t => {
  const f = await fixture(t, { remote: true });
  const result = f.run(['--apply']);
  assert.equal(result.status, 0, result.stderr);
  const downloads = (await readFile(join(f.root, 'downloads'), 'utf8')).trim().split('\n');
  assert.deepEqual(downloads.map(url => url.split('/').at(-1)), [
    'SHA256SUMS', keyName, artifacts[0], artifacts[2]
  ]);
  const installedKey = join(f.root, 'etc/apk/keys', keyName);
  assert.deepEqual(await readFile(installedKey), publicKey);
  assert.equal((await stat(installedKey)).mode & 0o777, 0o644);
  await assert.rejects(readFile(join(f.root, 'key-before-backup')), { code: 'ENOENT' });
  assert.equal(await readFile(join(f.root, 'installed'), 'utf8'), 'installed\n');
  assert.doesNotMatch(await readFile(join(f.root, 'apk.calls'), 'utf8'), /allow-untrusted/);
});

test('matching read-only installed key is reused without replacement', async t => {
  const f = await fixture(t, { existingKey: 'matching' });
  const path = join(f.root, 'etc/apk/keys', keyName);
  const before = await stat(path);
  const result = f.run(['--apply']);
  assert.equal(result.status, 0, result.stderr);
  const after = await stat(path);
  assert.equal(after.ino, before.ino);
  assert.equal(after.mode & 0o777, 0o444);
  assert.deepEqual(await readFile(path), publicKey);
});

test('different read-only installed key is preserved and installation refused', async t => {
  const f = await fixture(t, { existingKey: 'different' });
  const path = join(f.root, 'etc/apk/keys', keyName);
  const before = await stat(path);
  const result = f.run(['--apply']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Existing FoxHole APK key differs/);
  assert.equal(await readFile(path, 'utf8'), 'existing different key\n');
  assert.equal((await stat(path)).ino, before.ino);
  await assert.rejects(readFile(join(f.root, 'backup-created')), { code: 'ENOENT' });
  await assert.rejects(readFile(join(f.root, 'apk.calls')), { code: 'ENOENT' });
});

for (const [name, options] of [
  ['missing public key', { missingKey: true }],
  ['replacement key even in an authenticated manifest', { tamperedKey: true }],
  ['missing key manifest entry', { missingKeyEntry: true }],
  ['incorrect key manifest entry', { badKeyEntry: true }],
  ['existing key symlink', { symlinkKey: true }],
  ['rejected package signature', { signatureFail: true }],
  ['failed atomic key publication', { keyInstallFail: true }]
]) {
  test('installer refuses ' + name, async t => {
    const f = await fixture(t, options);
    const result = f.run(['--apply']);
    assert.notEqual(result.status, 0);
    await assert.rejects(readFile(join(f.root, 'installed')), { code: 'ENOENT' });
    if (!options.symlinkKey)
      await assert.rejects(readFile(join(f.root, 'etc/apk/keys', keyName)), { code: 'ENOENT' });
    if (options.signatureFail) {
      const calls = await readFile(join(f.root, 'apk.calls'), 'utf8');
      assert.match(calls, / verify /);
      assert.doesNotMatch(calls, /update| add |allow-untrusted/);
      await assert.rejects(readFile(join(f.root, 'backup-created')), { code: 'ENOENT' });
    }
  });
}

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
  const f = await fixture(t, { flash: 8192, missingKey: true, missingKeyEntry: true });
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
  ['incompatible package architecture', { arch: 'x86_64\n' }, []],
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
