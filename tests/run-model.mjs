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
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
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
    '/workspace/package/foxhole-openwrt-client/root/usr/libexec/foxhole-engine-job',
    '/workspace/package/foxhole-openwrt-client/root/usr/libexec/foxhole-update-job',
    '/workspace/package/foxhole-openwrt-client/root/usr/libexec/foxhole-license',
    '/workspace/package/foxhole-openwrt-client/root/usr/libexec/foxhole-probe',
    '/workspace/package/foxhole-openwrt-client/root/usr/libexec/foxhole-inbound',
    '/workspace/tools/register-compact-engines.uc',
    '/workspace/tools/install-plan.uc',
    '/workspace/tools/install-compact-plan.uc',
    '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/client-observation.uc'
  ]) {
    const source = path.endsWith('/client-observation.uc')
      ? `import * as observation from '${path}'; print(type(observation.online_map));`
      : await readFile(resolve(root, path.replace('/workspace/', '')), 'utf8');
    process.stdout.write(`Compile: ${path}\n`);
    command(['exec', '-i', container, 'ucode', '-cdynlink=uci,dynlink=ubus', '-o', '/dev/null', '-'], {
      input: (path.startsWith('/workspace/tools/') ? source.replaceAll("from './", "from '/workspace/tools/") : source).replaceAll("'/usr/share/foxhole/",
        "'/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/")
    });
  }
  const rpc = await readFile(resolve(root,
    'package/foxhole-openwrt-client/root/usr/share/rpcd/ucode/foxhole.uc'), 'utf8');
  const implementations = [
    ['valid_revision', 'value'], ['client_export', 'state, client'],
    ['update_client', 'request'], ['delete_client', 'request']
  ].map(([name, args]) => `function ${name}(${args}) ${functionBody(rpc, name)};`).join('\n');
  const marker = '// RPC implementations are injected without loading system state.';
  const runtimeMarker =
    '// Runtime RPC implementations are injected without services.';
  const runtimeImplementations = [
    ['admit_server', 'raw, engine'],
    ['start_server', 'request'], ['stop_server', 'request'],
    ['save_server', 'request']
  ].map(([name, args]) =>
    `function ${name}(${args}) ${functionBody(rpc, name)};`).join('\n');
  const authMarker =
    '// Authentication uses isolated sessions and storage.';
  const authImplementations = [
    ['license_record', ''], ['license_required', 'auth'],
    ['new_token', 'user, paired'], ['session', 'request, allow_setup'],
    ['change_pin', 'request'], ['admin_pin', 'request'],
    ['pair_create', 'request'], ['pair_unlock', 'request'],
    ['pair_revoke', 'request'], ['unlock', 'request']
  ].map(([name, args]) =>
    `function ${name}(${args}) ${functionBody(rpc, name)};`).join('\n');
  const setupMarker = '// Setup RPC implementations use isolated storage and services.';
  const setupImplementations = [
    ['license_record', ''], ['license_required', 'auth'], ['license_choice', 'auth, acceptance'],
    ['auth_record', 'allow_missing'], ['pin_hash', 'salt, pin'],
    ['equal_secret', 'left, right'], ['check_pin', 'pin'],
    ['new_token', 'user, paired'], ['session', 'request, allow_setup'],
    ['store_pin', 'pin, acceptance'], ['admin_pin', 'request'], ['change_pin', 'request'],
    ['pair_create', 'request'], ['valid_revision', 'value'],
    ['package_status', 'request'], ['setup_reset', 'request']
  ].map(([name, args]) =>
    `function ${name}(${args}) ${functionBody(rpc, name)};`).join('\n');
  command(['exec', container, 'node', '--test', '/workspace/tests/compact-bootstrap-selection-cases.mjs',
    '/workspace/tests/compact-bootstrap-cases.mjs'], { timeout: 120000, maxBuffer: 4194304 });
  let failed = false;
  for (const path of ['tests/model.uc', 'tests/runtime-model.uc',
    'tests/client-rpc.uc', 'tests/runtime-rpc.uc', 'tests/auth-rpc.uc', 'tests/setup-rpc.uc',
    'tests/inbound-history.uc', 'tests/pairing.uc', 'tests/mobile.uc',
    'tests/core-model.uc', 'tests/update-model.uc', 'tests/engine-rpc.uc', 'tests/engine-model.uc', 'tests/core-bootstrap-rpc.uc', 'tests/device-model.uc', 'tests/client-observation.uc', 'tests/handoff.uc', 'tests/private-store.uc', 'tests/install-plan.uc',
    'tests/inbound-process.uc']) {
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
    if (path === 'tests/setup-rpc.uc') {
      if (source.split(setupMarker).length !== 2)
        throw new Error('Invalid setup fixture marker');
      source = source.replace(setupMarker, setupImplementations);
    }
    if (path === 'tests/client-observation.uc') {
      const observationMarker = '// The authenticated observer implementation is injected here.';
      if (source.split(observationMarker).length !== 2)
        throw new Error('Invalid client observation fixture marker');
      source = source.replace(observationMarker,
        `function client_status(request) ${functionBody(rpc, 'client_status').replaceAll('read_online(', 'fixture_read_online(')};`);
      const socketMarker = '// The loopback socket reader is injected without process calls.';
      if (source.split(socketMarker).length !== 2)
        throw new Error('Invalid socket observer fixture marker');
      source = source.replace(socketMarker, [
        ['online_ready', 'connection, flags, deadline'], ['read_online', 'listener, ids']
      ].map(([name, args]) => `function ${name}(${args}) ${functionBody(rpc, name)};`).join('\n'));
      const rebindMarker = '// The unchanged-generation metadata rebind is injected here.';
      const inboundSource = await readFile(resolve(root,
        'package/foxhole-openwrt-client/root/usr/libexec/foxhole-inbound'), 'utf8');
      if (source.split(rebindMarker).length !== 2)
        throw new Error('Invalid observation rebind fixture marker');
      source = source.replace(rebindMarker,
        `function rebind_observations(state, signature, base, clients) ${functionBody(inboundSource, 'rebind_observations')};`);

    }
    if (path === 'tests/core-bootstrap-rpc.uc') {
      const bootstrapMarker = '// Saved native profiles run through the real RPC/runtime bodies.';
      if (source.split(bootstrapMarker).length !== 2)
        throw new Error('Invalid Core bootstrap RPC fixture marker');
      const runtimeSource = await readFile(resolve(root,
        'package/foxhole-openwrt-client/root/usr/libexec/foxhole-runtime'), 'utf8');
      source = source.replace(bootstrapMarker, [
        ...[['admit_server', 'raw, engine'], ['save_server', 'request'],
          ['get_server', 'request'], ['start_server', 'request']].map(([name, args]) =>
          `function ${name}(${args}) ${functionBody(rpc, name)};`),
        `function prepare() ${functionBody(runtimeSource, 'prepare')};`
      ].join('\n'));
    }
    if (path === 'tests/engine-rpc.uc') {
      const service = await readFile(resolve(root,
        'package/foxhole-openwrt-client/root/usr/share/foxhole/engine-service.uc'), 'utf8');
      const engineMarker = '// Actual stop-intent and restart guard are injected here.';
      if (source.split(engineMarker).length !== 2) throw new Error('Invalid engine RPC fixture marker');
      source = source.replace(engineMarker, [
        ['stop_intent', ''], ['start_if_allowed', 'job, action']
      ].map(([name, args]) => `function ${name}(${args}) ${functionBody(service, name)};`).join('\n'));
    }
    if (path === 'tests/inbound-process.uc') {
      const processSource = await readFile(resolve(root,
        'package/foxhole-openwrt-client/root/usr/libexec/foxhole-inbound-revoke'), 'utf8');
      const processMarker = '// The revoke-helper process snapshot is injected below.';
      if (source.split(processMarker).length !== 2) throw new Error('Invalid process fixture marker');
      source = source.replace(processMarker,
        `function snapshot(pid) ${functionBody(processSource, 'snapshot')};`);
    }
    const result = spawnSync('docker', ['exec', '-i', container, 'ucode', '-'], {
      input: source, encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024
    });
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.error) throw new Error('Model execution failed');
    failed ||= result.status !== 0;
  }
  const socketResult = spawnSync('docker', ['exec', container, 'node',
    'tests/client-observation-socket.mjs'], {
    encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024
  });
  if (socketResult.stdout) process.stdout.write(socketResult.stdout);
  if (socketResult.stderr) process.stderr.write(socketResult.stderr);
  if (socketResult.error) throw new Error('Actual socket observer execution failed');
  failed ||= socketResult.status !== 0;
  process.exitCode = failed ? 1 : 0;
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
