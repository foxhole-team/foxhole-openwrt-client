import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { root } from './helpers.mjs';

const mocks = {
  uname: 'case "$1" in -s) echo Linux;; -m) echo x86_64;; esac',
  mktemp: 'mkdir "$MOCK_ROOT/scratch"; echo "$MOCK_ROOT/scratch"',
  curl: 'exit 0',
  sha256sum: 'cat >/dev/null',
  zstd: 'exit 0',
  git: 'exit 0',
  python3: 'exit 0',
  tar: `
    if [ "$1" = --zstd ]; then
      mkdir -p "$MOCK_ROOT/scratch/sdk/scripts"
      printf '#!/bin/sh\\nexit 0\\n' > "$MOCK_ROOT/scratch/sdk/scripts/feeds"
      chmod +x "$MOCK_ROOT/scratch/sdk/scripts/feeds"
      printf 'CONFIG_ALL=y\\nCONFIG_PACKAGE_kmod-unrelated=m\\n' \
        > "$MOCK_ROOT/scratch/sdk/.config"
    fi
  `,
  make: `
    if [ "$1" = defconfig ]; then
      cp .config "$MOCK_ROOT/requested.config"
      echo CONFIG_PACKAGE_kmod-tun=m >> .config
      exit 0
    fi
    printf '%s\\n' "$*" >> "$MOCK_ROOT/compile.args"
    if [ ! -d dl/go-mod-cache/module ]; then
      mkdir -p dl/go-mod-cache/module
      touch dl/go-mod-cache/module/source.go
      chmod a-w dl/go-mod-cache/module
    fi
    [ "$MOCK_BUILD_STATUS" = 0 ] || exit "$MOCK_BUILD_STATUS"
    mkdir -p bin/packages
    case "$*" in
      *hysteria/compile*)
        touch bin/packages/hysteria-2.12.2-r5.apk ;;
      *hysteria-ram/compile*)
        touch bin/packages/hysteria-ram-2.12.2-r2.apk ;;
      *hysteria-server-ram/compile*)
        touch bin/packages/hysteria-server-ram-2.12.2-r2.apk ;;
      *foxcore-cli/compile*)
        touch bin/packages/foxcore-cli-1.0.0-r1.apk ;;
      *foxcore-cli-ram/compile*)
        touch bin/packages/foxcore-cli-ram-1.0.0-r1.apk ;;
      *foxhole-openwrt-client/compile*)
        touch bin/packages/foxhole-openwrt-client-1.0.1-r1.apk ;;
    esac
  `
};

async function fixture(t, buildStatus, cleanupFails = false, args = []) {
  const directory = await mkdtemp(join(tmpdir(), 'foxhole-sdk-test-'));
  t.after(async () => {
    spawnSync('/bin/chmod', ['-R', 'u+w', directory]);
    await rm(directory, { recursive: true, force: true });
  });
  const bin = join(directory, 'bin');
  await mkdir(bin);
  for (const [name, source] of Object.entries(mocks)) {
    await writeFile(join(bin, name), '#!/bin/sh\nset -eu\n' + source + '\n',
      { mode: 0o755 });
  }
  if (cleanupFails) {
    await writeFile(join(bin, 'chmod'), `#!/bin/sh
if [ "$*" = "-R u+w $MOCK_ROOT/scratch" ]; then exit 41; fi
exec /bin/chmod "$@"
`, { mode: 0o755 });
  }
  const output = join(directory, 'output');
  const result = spawnSync('/bin/sh', [join(root, 'tools/build-openwrt.sh'), ...args, output], {
    cwd: root, encoding: 'utf8', timeout: 10000,
    env: { ...process.env, PATH: bin + ':' + process.env.PATH,
      MOCK_ROOT: directory, MOCK_BUILD_STATUS: String(buildStatus) }
  });
  assert.ifError(result.error);
  return { directory, output, result };
}

test('SDK build exports APKs and removes read-only Go module directories', async t => {
  const { directory, output, result } = await fixture(t, 0);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Unsigned APK bundle:/);
  for (const file of ['hysteria-2.12.2-r5.apk',
    'foxhole-openwrt-client-1.0.1-r1.apk', 'sdk.config', 'feeds.buildinfo']) {
    await readFile(join(output, file));
  }
  await assert.rejects(readFile(join(output, 'hysteria-ram-2.12.2-r2.apk')), { code: 'ENOENT' });
  const config = await readFile(join(output, 'sdk.config'), 'utf8');
  assert.doesNotMatch(config, /CONFIG_ALL=y|CONFIG_PACKAGE_kmod-unrelated/);
  assert.match(config, /^CONFIG_PACKAGE_kmod-tun=m$/m);
  await assert.rejects(readFile(join(directory, 'scratch')), { code: 'ENOENT' });
});

test('SDK cleanup preserves a compiler failure and removes its cache', async t => {
  const { directory, output, result } = await fixture(t, 37);
  assert.equal(result.status, 37, result.stderr);
  await assert.rejects(readFile(join(directory, 'scratch')), { code: 'ENOENT' });
  await assert.rejects(readFile(output), { code: 'ENOENT' });
});

for (const buildStatus of [0, 37]) {
  test('SDK cleanup failure preserves build status ' + buildStatus, async t => {
    const { result } = await fixture(t, buildStatus, true);
    assert.equal(result.status, buildStatus || 1, result.stderr);
  });
}

test('Core SDK mode selects both exact RAM producers without legacy RAM', async t => {
  const { output, result } = await fixture(t, 0, false, [
    '--core-input', '/synthetic/core', '--core-source-sha256', 'a'.repeat(64),
    '--core-download-url', 'https://example.invalid/core.bin', '--core-ram-reserve-bytes', '1048576',
    '--server-input', '/synthetic/server', '--server-download-url', 'https://example.invalid/server.bin',
    '--server-ram-reserve-bytes', '1048576', '--hy2'
  ]);
  assert.equal(result.status, 0, result.stderr);
  const config = await readFile(join(output, 'sdk.config'), 'utf8');
  assert.match(config, /^CONFIG_PACKAGE_foxcore-cli-ram=m$/m);
  assert.match(config, /^CONFIG_PACKAGE_hysteria-server-ram=m$/m);
  assert.doesNotMatch(config, /^CONFIG_PACKAGE_hysteria-ram=m$/m);
  await readFile(join(output, 'foxcore-cli-ram-1.0.0-r1.apk'));
  await readFile(join(output, 'hysteria-server-ram-2.12.2-r2.apk'));
  await assert.rejects(readFile(join(output, 'hysteria-ram-2.12.2-r2.apk')), { code: 'ENOENT' });
});

test('Server RAM without a verified native producer fails before SDK setup', async t => {
  const { directory, result } = await fixture(t, 0, false, [
    '--server-download-url', 'https://example.invalid/server.bin', '--server-ram-reserve-bytes', '1048576'
  ]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /verified native producer/);
  await assert.rejects(readFile(join(directory, 'scratch')), { code: 'ENOENT' });
});
