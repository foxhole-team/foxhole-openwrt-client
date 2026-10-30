import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { packageRoot, read } from './helpers.mjs';

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'foxhole-mobile-identity-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const directory = join(root, 'identity');
  const script = join(root, 'create');
  const source = await read(`${packageRoot}/root/usr/libexec/foxhole-mobile-identity`);
  assert.equal(source.split("directory='/etc/foxhole'").length, 2);
  await writeFile(script, source.replace("directory='/etc/foxhole'", `directory='${directory}'`));
  const run = (env = {}) => spawnSync('/bin/sh', [script], {
    encoding: 'utf8', timeout: 15000, env: { ...process.env, ...env }
  });
  const digest = async path => createHash('sha256').update(await readFile(path)).digest('hex');
  return { root, directory, script, run, digest };
}

test('mobile identity retry preserves the same leaf and private key', async t => {
  const { directory, run, digest } = await fixture(t);
  assert.equal(run().status, 0);
  const certificate = join(directory, 'mobile.crt');
  const key = join(directory, 'mobile-identity', 'key.pem');
  const first = [await digest(certificate), await digest(key)];
  assert.equal(run().status, 0);
  assert.deepEqual([await digest(certificate), await digest(key)], first);
  assert.equal((await stat(key)).mode & 0o077, 0);
  assert.equal((await readdir(directory)).some(name => name.startsWith('.mobile-')), false);
});

test('a failed public alias publication retries a complete identity', async t => {
  const { root, directory, run, digest } = await fixture(t);
  const bin = join(root, 'bin');
  await mkdir(bin);
  const marker = join(root, 'failed-once');
  await writeFile(join(bin, 'ln'), `#!/bin/sh
if [ ! -e "$IDENTITY_FAILURE_MARKER" ]; then
  touch "$IDENTITY_FAILURE_MARKER"
  exit 44
fi
exec /usr/bin/ln "$@"
`);
  await chmod(join(bin, 'ln'), 0o755);
  const env = { PATH: `${bin}:${process.env.PATH}`, IDENTITY_FAILURE_MARKER: marker };
  const first = run(env);
  assert.notEqual(first.status, 0);
  const leaf = join(directory, 'mobile-identity', 'cert.pem');
  const original = await digest(leaf);
  assert.equal(run(env).status, 0);
  assert.equal(await digest(join(directory, 'mobile.crt')), original);
});

test('mismatched existing key material is refused without replacement', async t => {
  const { root, directory, run, digest } = await fixture(t);
  assert.equal(run().status, 0);
  const key = join(directory, 'mobile-identity', 'key.pem');
  const generated = spawnSync('openssl', ['genpkey', '-algorithm', 'RSA',
    '-pkeyopt', 'rsa_keygen_bits:2048', '-out', join(root, 'other-key')],
  { encoding: 'utf8', timeout: 15000 });
  assert.equal(generated.status, 0);
  await writeFile(key, await readFile(join(root, 'other-key')));
  const original = await digest(key);
  assert.notEqual(run().status, 0);
  assert.equal(await digest(key), original);
});

test('an unknown partial legacy identity cannot be silently reset', async t => {
  const { directory, run } = await fixture(t);
  await mkdir(directory, { mode: 0o700 });
  const path = join(directory, 'mobile.crt');
  const publicBytes = 'incomplete synthetic public certificate';
  await writeFile(path, publicBytes);
  assert.notEqual(run().status, 0);
  assert.equal(await readFile(path, 'utf8'), publicBytes);
  await assert.rejects(stat(join(directory, 'mobile-identity')), { code: 'ENOENT' });
});
