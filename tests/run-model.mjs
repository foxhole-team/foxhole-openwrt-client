import { spawnSync } from 'node:child_process';
import { readFile, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { functionBody } from './helpers.mjs';

const root = await realpath(fileURLToPath(new URL('..', import.meta.url)));
const container = process.env.FOXHOLE_TEST_CONTAINER || 'foxhole-public-model-check';

function command(args, options = {}) {
  const result = spawnSync('docker', args, {
    encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024, ...options
  });
  if (result.error || result.status !== 0) {
    throw new Error(`Docker command failed: ${args[0]}`);
  }
  return result.stdout;
}

try {
  const mounts = JSON.parse(command(['inspect', '--format', '{{json .Mounts}}', container]));
  const mount = mounts.find((item) => item.Destination === '/workspace');
  if (!mount || mount.RW || await realpath(mount.Source) !== root) {
    throw new Error('Model tests require this repository at /workspace read-only');
  }
  for (const path of [
    '/workspace/package/foxhole-openwrt-client/root/www/cgi-bin/foxhole',
    '/workspace/package/foxhole-openwrt-client/root/usr/share/rpcd/ucode/foxhole.uc',
    '/workspace/package/foxhole-openwrt-client/root/usr/libexec/foxhole-runtime',
    '/workspace/package/foxhole-openwrt-client/root/usr/libexec/foxhole-probe'
  ]) {
    const source = await readFile(resolve(root,
      path.replace('/workspace/', '')), 'utf8');
    command(['exec', '-i', container, 'ucode', '-c', '-o', '/dev/null', '-'], {
      input: source.replaceAll("'/usr/share/foxhole/",
        "'/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/")
    });
  }
  const rpc = await readFile(resolve(root,
    'package/foxhole-openwrt-client/root/usr/share/rpcd/ucode/foxhole.uc'), 'utf8');
  const implementations = [
    ['valid_revision', 'value'], ['client_export', 'state, client'],
    ['update_client', 'request']
  ].map(([name, args]) => `function ${name}(${args}) ${functionBody(rpc, name)};`).join('\n');
  const marker = '// RPC implementations are injected without loading system state.';
  const runtimeMarker =
    '// Runtime RPC implementations are injected without services.';
  const runtimeImplementations = [
    ['start_server', 'request'], ['stop_server', 'request'],
    ['save_server', 'request']
  ].map(([name, args]) =>
    `function ${name}(${args}) ${functionBody(rpc, name)};`).join('\n');
  const authMarker =
    '// Authentication uses isolated sessions and storage.';
  const authImplementations = [
    ['new_token', 'user'], ['session', 'request, allow_setup'],
    ['change_pin', 'request'], ['admin_pin', 'request']
  ].map(([name, args]) =>
    `function ${name}(${args}) ${functionBody(rpc, name)};`).join('\n');
  let failed = false;
  for (const path of ['tests/model.uc', 'tests/runtime-model.uc',
    'tests/client-rpc.uc', 'tests/runtime-rpc.uc', 'tests/auth-rpc.uc',
    'tests/inbound-history.uc']) {
    let source = await readFile(resolve(root, path), 'utf8');
    if (path === 'tests/client-rpc.uc') {
      if (source.split(marker).length !== 2) throw new Error('Invalid RPC fixture marker');
      source = source.replace(marker, implementations);
    }
    if (path === 'tests/runtime-rpc.uc') {
      if (source.split(runtimeMarker).length !== 2)
        throw new Error('Invalid runtime RPC fixture marker');
      source = source.replace(runtimeMarker, runtimeImplementations);
    }
    if (path === 'tests/auth-rpc.uc') {
      if (source.split(authMarker).length !== 2)
        throw new Error('Invalid authentication fixture marker');
      source = source.replace(authMarker, authImplementations);
    }
    const result = spawnSync('docker', ['exec', '-i', container, 'ucode', '-'], {
      input: source, encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024
    });
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.error) throw new Error('Model execution failed');
    failed ||= result.status !== 0;
  }
  process.exitCode = failed ? 1 : 0;
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
