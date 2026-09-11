import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { root } from './helpers.mjs';

const sha = data => createHash('sha256').update(data).digest('hex');
const main = 'a'.repeat(40), dev = 'b'.repeat(40), tree = 'c'.repeat(40);
const names = ['foxhole-openwrt-client-0.1.0-r41.apk', 'hysteria-2.12.2-r2.apk',
  'hysteria-ram-2.12.2-r1.apk', 'install.sh', 'sdk.config', 'feeds.buildinfo',
  'CANDIDATE.json', 'foxhole-openwrt-client-source.zip',
  'foxhole-openwrt-client-source.zip.sha256'];
const verify = `
import importlib.util, pathlib, sys
path=pathlib.Path(sys.argv[1]) / 'tools/prepare-release.py'
spec=importlib.util.spec_from_file_location('prepare',path)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.verify(pathlib.Path(sys.argv[2]),sys.argv[3],sys.argv[4])
`;

async function fixture(t, mutation) {
  const directory = await mkdtemp(join(tmpdir(), 'foxhole-release-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const candidate = join(directory, 'release-candidate');
  await mkdir(candidate);
  const record = { schema: 1, source_commit: dev, source_tree: tree,
    target: 'openwrt-25.12.5-aarch64_generic', package_signatures: 'unsigned',
    firmware_acceptance: 'pending' };
  if (mutation === 'provenance') record.source_tree = 'd'.repeat(40);
  let manifest = '';
  for (const name of names) {
    const data = name === 'install.sh' ? await readFile(join(root, name)) :
      Buffer.from(name === 'CANDIDATE.json' ? JSON.stringify(record) : 'fixture ' + name);
    await writeFile(join(candidate, name), data);
    manifest += sha(data) + '  ' + name + '\n';
  }
  if (mutation === 'duplicate') manifest += manifest.split('\n')[0] + '\n';
  await writeFile(join(candidate, 'SHA256SUMS'), manifest);
  await writeFile(join(directory, 'RELEASE.json'), JSON.stringify({
    main_commit: main, dev_commit: dev, source_tree: tree,
    candidate_manifest_sha256: sha(manifest)
  }));
  if (mutation === 'tamper') await writeFile(join(candidate, names[0]), 'changed bytes');
  if (mutation === 'extra') await writeFile(join(candidate, 'unexpected'), 'extra');
  return spawnSync('python3', ['-B', '-c', verify, root, directory,
    mutation === 'main' ? 'e'.repeat(40) : main, tree], {
    encoding: 'utf8', timeout: 10000
  });
}

test('release preparation accepts verified main candidate', async t => {
  const result = await fixture(t);
  assert.equal(result.status, 0, result.stderr);
});

for (const mutation of ['tamper', 'extra', 'duplicate', 'provenance', 'main']) {
  test('release preparation rejects ' + mutation + ' before signing', async t => {
    const result = await fixture(t, mutation);
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /ValueError/);
  });
}
