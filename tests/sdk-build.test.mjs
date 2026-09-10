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
    touch bin/packages/hysteria-2.12.2-r2.apk
    touch bin/packages/hysteria-ram-2.12.2-r1.apk
    touch bin/packages/foxhole-openwrt-client-0.1.0-r41.apk
  `
};

async function fixture(t, buildStatus, cleanupFails = false) {
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
  const result = spawnSync('/bin/sh', [join(root, 'tools/build-openwrt.sh'), output], {
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
  for (const file of ['hysteria-2.12.2-r2.apk', 'hysteria-ram-2.12.2-r1.apk',
    'foxhole-openwrt-client-0.1.0-r41.apk', 'sdk.config', 'feeds.buildinfo']) {
    await readFile(join(output, file));
  }
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
