import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { root } from './helpers.mjs';

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'foxhole-stock-tools-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const bin = join(directory, 'bin');
  await mkdir(bin);
  for (const name of ['sh', 'mktemp', 'rm', 'cp', 'wc', 'sha256sum', 'awk', 'ucode']) {
    const found = spawnSync('/bin/sh', ['-c', 'command -v "$1"', 'probe', name], {
      encoding: 'utf8', timeout: 5000
    });
    assert.equal(found.status, 0, name);
    await symlink(found.stdout.trim(), join(bin, name));
  }
  await writeFile(join(bin, 'id'), '#!/bin/sh\nprintf "0\\n"\n', { mode: 0o700 });
  const env = { ...process.env, PATH: bin };
  assert.notEqual(spawnSync('/bin/sh', ['-c', 'command -v stat'], { env }).status, 0);
  return { directory, env };
}

for (const kind of ['valid', 'compact', 'oversized-helper', 'oversized-manifest', 'symlink',
  'oversized-catalog', 'symlink-catalog', 'tampered-catalog', 'unknown-schema', 'wrong-kind']) {
  test('bootstrap uses stock tools and checks bounds before execution: ' + kind, async t => {
    const { directory, env } = await fixture(t);
    const bundle = join(directory, 'bundle');
    await mkdir(bundle);
    const marker = join(directory, 'executed');
    const helperName = kind === 'compact' ? 'install-compact.sh' : 'install-core.sh';
    const helper = join(bundle, helperName);
    const catalog = join(bundle, 'package-catalog.json');
    const catalogValue = kind === 'compact' ? { schema: 2, kind: 'compact-client-engines-v1' } :
      kind === 'wrong-kind' ? { schema: 2, kind: 'legacy' } : { schema: kind === 'unknown-schema' ? 3 : 1 };
    let catalogBody = JSON.stringify(catalogValue);
    if (kind === 'oversized-catalog') catalogBody = JSON.stringify({ schema: 1, padding: 'x'.repeat(524289) });
    await writeFile(catalog, catalogBody);
    const catalogDigest = createHash('sha256').update(catalogBody).digest('hex');
    let body = '#!/bin/sh\nprintf approved > ' + marker + '\n';
    if (kind === 'oversized-helper') body += '#'.repeat(2097153 - body.length);
    await writeFile(helper, body);
    const digest = createHash('sha256').update(await readFile(helper)).digest('hex');
    const manifest = join(bundle, 'SHA256SUMS');
    await writeFile(manifest, kind === 'oversized-manifest' ? 'x'.repeat(2097153) :
      digest + '  ' + helperName + '\n' + catalogDigest + '  package-catalog.json\n');
    if (kind === 'symlink') {
      await writeFile(join(bundle, 'actual-helper'), body);
      await rm(helper);
      await symlink('actual-helper', helper);
    }
    if (kind === 'symlink-catalog') {
      await writeFile(join(bundle, 'actual-catalog'), catalogBody);
      await rm(catalog);
      await symlink('actual-catalog', catalog);
    }
    if (kind === 'tampered-catalog') await writeFile(catalog, '{"schema":1,"changed":true}');
    const anchor = createHash('sha256').update(await readFile(manifest)).digest('hex');
    const result = spawnSync('/bin/sh', [join(root, 'install.sh'), '--bundle', bundle, '--manifest-sha256', anchor], {
      env, encoding: 'utf8', timeout: 10000
    });
    assert.ifError(result.error);
    if (kind === 'valid' || kind === 'compact') {
      assert.equal(result.status, 0, result.stderr);
      assert.equal(await readFile(marker, 'utf8'), 'approved');
    } else {
      assert.notEqual(result.status, 0);
      await assert.rejects(readFile(marker), { code: 'ENOENT' });
    }
  });
}

function metadataFunction(source) {
  const start = source.indexOf('file_info() {');
  assert.ok(start >= 0);
  return source.slice(start, source.indexOf('\n}\n', start) + 3);
}

test('stock metadata keeps exact owner, mode, links and no-follow type', async t => {
  const { directory, env } = await fixture(t);
  const functionText = metadataFunction(await readFile(join(root, 'tools/install-core.sh'), 'utf8'));
  for (const path of [
    ...['foxhole-mobile-identity', 'foxhole-country-fetch', 'foxhole-provider-resolve', 'foxhole-remote-identity']
      .map(name => 'package/foxhole-openwrt-client/root/usr/libexec/' + name),
    'package/foxcore-cli-ram/files/foxcore-cli', 'package/hysteria-server-ram/files/hysteria'
  ]) assert.equal(metadataFunction(await readFile(join(root, path), 'utf8')), functionText);
  const script = join(directory, 'metadata.sh');
  await writeFile(script, functionText + '\nfile_info "$1" "$2"\n');
  const inspect = (format, path) => spawnSync('/bin/sh', [script, format, path], {
    env, encoding: 'utf8', timeout: 5000
  });
  const privateDir = join(directory, 'private');
  await mkdir(privateDir, { mode: 0o700 });
  const file = join(privateDir, 'file');
  await writeFile(file, 'abcde', { mode: 0o600 });
  const uid = process.getuid();
  assert.equal(inspect('%F:%u:%a', privateDir).stdout, `directory:${uid}:700`);
  assert.equal(inspect('%u:%a:%h:%s', file).stdout, `${uid}:600:1:5`);
  await link(file, join(privateDir, 'hard'));
  assert.equal(inspect('%u:%a:%h:%s', file).stdout, `${uid}:600:2:5`);
  await chmod(privateDir, 0o775);
  assert.notEqual(inspect('%F:%u:%a', privateDir).stdout, `directory:${uid}:700`);
  const symbolic = join(directory, 'symbolic');
  await symlink(file, symbolic);
  assert.equal(inspect('%F:%u:%a', symbolic).stdout, `link:${uid}:777`);
  assert.notEqual(inspect('%u', join(directory, 'missing')).status, 0);
  assert.notEqual(inspect('%unsupported', file).status, 0);
});

test('engine command allowlist uses the same canonical native APK executable as service', async () => {
  const source = await readFile(new URL('../package/foxhole-openwrt-client/root/usr/libexec/foxhole-engine-command', import.meta.url), 'utf8');
  assert.match(source, /\/usr\/bin\/apk\|\/usr\/bin\/sha256sum/);
  assert.doesNotMatch(source, /\/sbin\/apk/);
});
