import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { basename, join, posix } from 'node:path';
import test from 'node:test';
import { root, packageRoot } from './helpers.mjs';

test('declared RPC and runtime sources include their full installed import closure', async () => {
  const makefile = await readFile(join(root, packageRoot, 'Makefile'), 'utf8');
  const body = makefile.match(/define Package\/foxhole-openwrt-client\/install\n([\s\S]*?)\nendef/);
  assert.ok(body, 'package installation declaration missing');
  const installed = new Map();
  for (const line of body[1].replace(/\\\n\s*/g, ' ').split('\n')) {
    const command = line.match(/^\s*\$\(INSTALL_(?:DATA|BIN|CONF)\)\s+(.+)$/);
    if (!command) continue;
    const args = command[1].trim().split(/\s+/);
    const destination = args.pop();
    assert.ok(destination.startsWith('$(1)/'), 'unexpected installation destination');
    for (const source of args) {
      if (!source.startsWith('./root/')) continue;
      const target = destination.endsWith('/')
        ? destination.slice(4) + basename(source) : destination.slice(4);
      assert.ok(!installed.has(target), 'duplicate installed source: ' + target);
      installed.set(target, join(root, packageRoot, source));
    }
  }
  const queue = ['/usr/share/rpcd/ucode/foxhole.uc'];
  for (const [target, source] of installed) {
    if (target.startsWith('/usr/libexec/') &&
        (await readFile(source, 'utf8')).startsWith('#!/usr/bin/ucode')) queue.push(target);
  }
  const seen = new Set();
  while (queue.length) {
    const path = queue.pop();
    if (seen.has(path)) continue;
    seen.add(path);
    assert.ok(installed.has(path), 'module is not installed: ' + path);
    const source = await readFile(installed.get(path), 'utf8');
    for (const match of source.matchAll(/\bfrom\s+'([^']+\.uc)'/g)) {
      const dependency = posix.isAbsolute(match[1])
        ? match[1] : posix.resolve(posix.dirname(path), match[1]);
      assert.ok(dependency.startsWith('/usr/'), 'import escaped package');
      assert.ok(installed.has(dependency), 'module is not installed: ' + dependency);
      await readFile(installed.get(dependency));
      queue.push(dependency);
    }
  }
  assert.ok(seen.has('/usr/share/foxhole/client-observation.uc'));
  assert.ok(seen.has('/usr/share/foxhole/device-model.uc'));
});
