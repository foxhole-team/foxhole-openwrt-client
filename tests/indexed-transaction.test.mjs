import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { root } from './helpers.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const roots = ['foxcore-cli', 'foxhole-openwrt-client', 'hysteria'];
const canonical = 'fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1';

function budget() {
  const names = [...roots, 'shared-library', 'kernel', 'libc', 'libgcc1'];
  const packages = names.map(name => ({
    name, version: name === 'shared-library' ? '2-r1' : '1-r1', arch: 'x86_64',
    file: name + '.apk', sha256: hash('archive:' + name),
    depends: roots.includes(name) ? ['shared-library', 'kernel']
      : name === 'kernel' ? ['libc'] : name === 'libc' ? ['libgcc1'] : []
  }));
  return {
    schema: 1, mode: 'flash', architecture: 'x86_64',
    supportedTargets: ['x86/64'], supportedOpenWrt: ['25.12.5'],
    verification: { signatureModel: 'canonical-apk-and-upstream-index-v1', factorySourceSha256: hash('factory') },
    packages, rootPackages: roots,
    repositoryIndexes: [
      { file: 'own.adb', sha256: hash('own'), bytes: 100, role: 'foxhole',
        sourceUrl: 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.0/packages.adb', trustKeyFiles: ['foxhole-openwrt-apk.pem'] },
      { file: 'upstream.adb', sha256: hash('upstream'), bytes: 100, role: 'upstream',
        sourceUrl: 'https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/packages/packages.adb', trustKeyFiles: ['upstream.pem'] }
    ],
    repositoryIndexBytes: 200, trustKeyBytes: 356,
    trustKeys: [{ file: 'foxhole-openwrt-apk.pem', sha256: canonical, bytes: 178 },
      { file: 'upstream.pem', sha256: hash('upstream-key'), bytes: 178 }],
    packageAuthentications: packages.map(p => ({ file: p.file,
      indexFile: roots.includes(p.name) ? 'own.adb' : 'upstream.adb',
      name: p.name, version: p.version, architecture: p.arch, packageIdentity: hash('payload:' + p.name) })),
    filesSha256: { ...Object.fromEntries(packages.map(p => [p.file, p.sha256])),
      'own.adb': hash('own'), 'upstream.adb': hash('upstream'),
      'foxhole-openwrt-apk.pem': canonical, 'upstream.pem': hash('upstream-key') }
  };
}

async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'foxhole-indexed-transaction-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const value = budget(), path = join(dir, 'budget.json');
  await writeFile(path, JSON.stringify(value), { mode: 0o600 });
  async function run(action, values = [], extra = []) {
    const files = [];
    for (let i = 0; i < values.length; i++) {
      const file = join(dir, action + '-' + i + '-' + files.length + '.json');
      await writeFile(file, typeof values[i] === 'string' ? values[i] : JSON.stringify(values[i]), { mode: 0o600 });
      files.push(file);
    }
    const result = spawnSync('ucode', [join(root, 'tools/indexed-install.uc'), action, path, ...files, ...extra], {
      encoding: 'utf8', timeout: 5000, maxBuffer: 1048576
    });
    assert.ifError(result.error);
    return result;
  }
  return { value, run };
}

test('plan selects every authenticated payload identity and keeps only managed roots durable', async t => {
  const { value, run } = await fixture(t);
  const result = await run('plan');
  assert.equal(result.status, 0, result.stderr);
  const rows = result.stdout.trim().split('\n');
  assert.deepEqual(rows.filter(r => r.startsWith('exact ')).sort(),
    value.packageAuthentications.map(p => `exact ${p.name}><X1${p.packageIdentity.slice(0, 40)}`).sort());
  assert.deepEqual(rows.filter(r => r.startsWith('durable ')).sort(), roots.map(n => 'durable ' + n).sort());
});

test('kernel checksum solver closure accepts installed dependencies and rejects empty rc0 result', async t => {
  const { value, run } = await fixture(t);
  const selected = value.packages.filter(p => ['kernel', 'libc', 'libgcc1'].includes(p.name))
    .map(p => ({ name: p.name, version: p.version, arch: p.arch, status: ['installed'] }));
  assert.equal((await run('kernel-query', [selected, ''])).status, 0);
  for (const bad of [[], selected.slice(0, 1), [...selected, selected[0]],
    selected.map(p => p.name === 'kernel' ? { ...p, status: ['installed', 'broken-files'] } : p)]) {
    assert.notEqual((await run('kernel-query', [bad, ''])).status, 0);
  }
  assert.notEqual((await run('kernel-query', [selected, 'ERROR: unable to select packages\n'])).status, 0);
});

test('world preflight preserves unrelated explicit pins and refuses managed pins or owned-name collision', async t => {
  const { run } = await fixture(t), temp = '.foxhole-exact-0123456789abcdef';
  const before = 'kernel=1-r1\nshared-library=2-r1\nunrelated=7-r1\n';
  const ok = await run('world-before', [before], [temp]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(ok.stdout, before);
  for (const bad of [before + 'foxcore-cli=1-r1\n', before + temp + '=20261015.120000\n']) {
    assert.notEqual((await run('world-before', [bad], [temp])).status, 0);
  }
});

test('world completion keeps exact user pins plus bare roots and only the owned temporary constraint', async t => {
  const { run } = await fixture(t), constraint = '.foxhole-exact-0123456789abcdef=20261015.120000';
  const before = 'kernel=1-r1\nunrelated=7-r1\n';
  const durable = before + roots.join('\n') + '\n';
  assert.equal((await run('world-after', [before, durable + constraint + '\n'], [constraint])).status, 0);
  assert.equal((await run('world-after', [before, durable])).status, 0);
  for (const changed of [durable.replace('unrelated=7', 'unrelated=8'), durable + 'shared-library\n',
    durable + constraint + '\n', durable.replace('foxcore-cli\n', 'foxcore-cli=1-r1\n')]) {
    assert.notEqual((await run('world-after', [before, changed])).status, 0);
  }
});

test('temporary meta package is bound to its exact owned name version architecture and healthy status', async t => {
  const { run } = await fixture(t), name = '.foxhole-exact-0123456789abcdef';
  const item = { name, version: '20261015.120000', arch: 'noarch', status: ['installed'] };
  const ok = await run('temporary-created', [[item]], [name]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(ok.stdout, name + '=' + item.version);
  for (const bad of [[], [item, item], [{ ...item, name: '.other' }],
    [{ ...item, version: 'foreign' }], [{ ...item, status: ['installed', 'broken-scripts'] }]]) {
    assert.notEqual((await run('temporary-created', [bad], [name])).status, 0);
  }
});

test('cleanup prediction permits only the exact owned temporary package and rejects dependency purge', async t => {
  const { run } = await fixture(t), constraint = '.foxhole-exact-0123456789abcdef=20261015.120000';
  const line = '(1/1) Purging .foxhole-exact-0123456789abcdef (20261015.120000)\n';
  assert.equal((await run('purge-only', [line + 'OK: 2 MiB in 10 packages\n'], [constraint])).status, 0);
  for (const bad of [line.replace('120000', '120001'), line + '(2/2) Purging shared-library (2-r1)\n', '',
    line + line, 'WARNING: cleanup differs\n' + line]) {
    assert.notEqual((await run('purge-only', [bad], [constraint])).status, 0);
  }
});

test('post-install query rejects broken packages even when names versions and count match', async t => {
  const { value, run } = await fixture(t);
  const selected = value.packages.map(p => ({ name: p.name, version: p.version, arch: p.arch, status: ['installed'] }));
  assert.equal((await run('query-installed', [selected])).status, 0);
  assert.notEqual((await run('query-installed', [selected.map((p, i) => i ? p : { ...p, status: ['installed', 'broken-files'] })])).status, 0);
});
