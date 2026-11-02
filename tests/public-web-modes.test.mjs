import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, readdir, stat, chmod, writeFile, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const source = resolve(dirname(fileURLToPath(import.meta.url)), '../package/foxhole-openwrt-client');

async function tree(path) {
  const result = [];
  for (const item of await readdir(path, { withFileTypes: true })) {
    const name = join(path, item.name);
    assert.ok(item.isDirectory() || item.isFile(), 'public resources must be regular files or directories');
    result.push([name, item.isDirectory()]);
    if (item.isDirectory()) result.push(...await tree(name));
  }
  return result;
}

test('SDK public asset install normalizes private input modes without changing private files', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'foxhole-public-mode-'));
  try {
    const fixture = join(temporary, 'source'), destination = join(temporary, 'root');
    const relative = 'htdocs/luci-static/resources/foxhole';
    const inputs = join(fixture, relative);
    await mkdir(dirname(inputs), { recursive: true });
    await cp(join(source, relative), inputs, { recursive: true });
    for (const [path, directory] of await tree(inputs)) await chmod(path, directory ? 0o700 : 0o600);
    await chmod(inputs, 0o700);
    const privateDirectory = join(destination, 'etc/foxhole');
    await mkdir(privateDirectory, { recursive: true, mode: 0o700 });
    const privateFile = join(privateDirectory, 'fixture.json');
    await writeFile(privateFile, '{"fixture":true}', { mode: 0o600 });
    const publicDirectory = join(destination, 'www/luci-static/resources/foxhole');
    await mkdir(publicDirectory, { recursive: true, mode: 0o755 });

    const makefile = await readFile(join(source, 'Makefile'), 'utf8');
    const start = makefile.indexOf('\t$(CP) ./htdocs/luci-static/resources/foxhole/*');
    assert.ok(start >= 0);
    const end = makefile.indexOf('\t$(INSTALL_DIR)', start);
    assert.ok(end > start);
    const commands = makefile.slice(start, end).replaceAll('$(CP)', 'cp -fpR').replaceAll('$(1)', destination);
    const process = spawnSync('/bin/sh', ['-eu', '-c', commands], { cwd: fixture, encoding: 'utf8' });
    assert.equal(process.status, 0, process.stderr);
    const outputs = await tree(publicDirectory);
    assert.ok(outputs.length > 100, 'exercise the complete resource tree');
    for (const [path, directory] of outputs)
      assert.equal((await stat(path)).mode & 0o777, directory ? 0o755 : 0o644, path);
    assert.equal((await stat(publicDirectory)).mode & 0o777, 0o755);
    for (const [path, directory] of await tree(inputs))
      assert.equal((await stat(path)).mode & 0o777, directory ? 0o700 : 0o600, 'source mode changed');
    assert.equal((await stat(privateDirectory)).mode & 0o777, 0o700);
    assert.equal((await stat(privateFile)).mode & 0o777, 0o600);
    assert.equal(await readFile(privateFile, 'utf8'), '{"fixture":true}');
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
