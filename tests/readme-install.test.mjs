import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { read, root } from './helpers.mjs';

const sha = data => createHash('sha256').update(data).digest('hex');
const manifest = '1'.repeat(64);
const release = 'https://github.com/foxhole-team/foxhole-openwrt-client/' +
  'releases/download/v0.1.0-test';
const shellQuote = value => "'" + value.replaceAll("'", "'\\''") + "'";

async function command() {
  const commands = await Promise.all(['README.md', 'docs/README.ru.md'].map(async path => {
    const blocks = [...(await read(path)).matchAll(/```sh\n([\s\S]*?)\n```/g)]
      .map(match => match[1]).filter(block => block.includes('uclient-fetch'));
    assert.equal(blocks.length, 1, path + ' must contain one installation command');
    assert.equal(blocks[0].split('\n').length, 1, path + ' must use one shell line');
    return blocks[0];
  }));
  assert.equal(commands[0], commands[1], 'README commands must remain identical');
  assert.match(commands[0], /; sh "\$f" /);
  assert.doesNotMatch(commands[0], /\/bin\/(?:ba)?sh/);
  return commands[0];
}

const mock = `
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, relative, isAbsolute } from 'node:path';

const [name, ...args] = process.argv.slice(2);
const root = process.env.MOCK_ROOT;
const sha = data => createHash('sha256').update(data).digest('hex');
function local(path) {
  const part = relative(root, path);
  if (!part || part.startsWith('..') || isAbsolute(part)) throw Error('Outside fixture');
  return path;
}
switch (name) {
  case 'mktemp': {
    if (args.length !== 1 || args[0] !== '/tmp/foxhole-install.XXXXXX')
      throw Error('Unexpected temporary file request');
    const path = join(mkdtempSync(join(root, 'download-')), 'install.sh');
    writeFileSync(path, '', { mode: 0o600 });
    process.stdout.write(path + '\\n');
    break;
  }
  case 'uclient-fetch': {
    if (args.length !== 6 || args.slice(0, 4).join(' ') !== '-q -T 60 -O')
      throw Error('Unexpected download options');
    const path = local(args[4]);
    if (args[5] !== process.env.MOCK_RELEASE + '/install.sh')
      throw Error('Unexpected download URL');
    writeFileSync(join(root, 'download.json'), JSON.stringify(args));
    if (process.env.MOCK_DOWNLOAD === 'failed') process.exit(22);
    const data = readFileSync(process.env.MOCK_INSTALLER);
    writeFileSync(path, process.env.MOCK_DOWNLOAD === 'tampered' ?
      Buffer.concat([data, Buffer.from('\\ncorrupt download\\n')]) : data);
    break;
  }
  case 'sha256sum': {
    if (args.join(' ') !== '-c -') throw Error('Unexpected checksum options');
    const line = readFileSync(0, 'utf8').trimEnd();
    const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
    if (!match || sha(readFileSync(local(match[2]))) !== match[1]) process.exit(1);
    break;
  }
  case 'sh':
    writeFileSync(join(root, 'shell.json'), JSON.stringify({
      args, digest: sha(readFileSync(local(args[0])))
    }));
    break;
  case 'rm':
    if (args.length !== 2 || args[0] !== '-f') throw Error('Unexpected cleanup');
    rmSync(local(args[1]), { force: true });
    break;
  default: throw Error('External commands are unavailable');
}
`;

async function fixture(t, download) {
  const directory = await mkdtemp(join(tmpdir(), 'foxhole-readme-install-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const bin = join(directory, 'bin');
  await mkdir(bin);
  const script = join(directory, 'mock.mjs');
  await writeFile(script, mock);
  const checksum = spawnSync('/bin/sh', ['-c', 'command -v sha256sum'], {
    encoding: 'utf8'
  });
  for (const name of ['mktemp', 'uclient-fetch', 'sha256sum', 'sh', 'rm']) {
    const path = join(bin, name);
    if (name === 'sha256sum' && checksum.status === 0 && checksum.stdout.trim()) {
      await symlink(checksum.stdout.trim(), path);
      continue;
    }
    await writeFile(path, '#!/bin/sh\nexec ' + shellQuote(process.execPath) +
      ' ' + shellQuote(script) + ' ' + shellQuote(name) + ' "$@"\n');
    await chmod(path, 0o755);
  }
  const source = (await command()).replaceAll('RELEASE_TAG', 'v0.1.0-test')
    .replaceAll('MANIFEST_SHA256', manifest);
  const result = spawnSync('/bin/sh', ['-c', source], {
    cwd: directory, encoding: 'utf8', timeout: 10000,
    env: { PATH: bin, MOCK_ROOT: directory, MOCK_DOWNLOAD: download,
      MOCK_RELEASE: release, MOCK_INSTALLER: join(root, 'install.sh') }
  });
  return { directory, result };
}

test('README installation commands match and pin the current installer', async () => {
  const source = await command();
  const hashes = source.match(/\b[a-f0-9]{64}\b/g);
  assert.deepEqual(hashes, [sha(await readFile(join(root, 'install.sh')))]);
});

test('README installation verifies the download before passing release options', async t => {
  const { directory, result } = await fixture(t, 'success');
  assert.equal(result.status, 0, result.stderr);
  const shell = JSON.parse(await readFile(join(directory, 'shell.json'), 'utf8'));
  assert.deepEqual(shell.args.slice(1), [
    '--base-url', release, '--manifest-sha256', manifest, '--apply'
  ]);
  assert.equal(shell.digest, sha(await readFile(join(root, 'install.sh'))));
  await assert.rejects(readFile(shell.args[0]), { code: 'ENOENT' });
});

for (const mode of ['tampered', 'failed']) {
  test('README installation never executes a ' + mode + ' download', async t => {
    const { directory, result } = await fixture(t, mode);
    assert.notEqual(result.status, 0, result.stdout);
    await assert.rejects(readFile(join(directory, 'shell.json')), { code: 'ENOENT' });
    const args = JSON.parse(await readFile(join(directory, 'download.json'), 'utf8'));
    await assert.rejects(readFile(args[4]), { code: 'ENOENT' });
  });
}
