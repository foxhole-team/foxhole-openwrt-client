import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { functionBody, packageRoot, read, rpcMethods } from './helpers.mjs';

for (const [recovery, mode, expected, starts] of [
  [10, 'off', 0, false], [10, 'block', 0, false], [10, 'tunnel', 1, false], [0, 'tunnel', 0, true], [1, 'tunnel', 1, false]
]) test(`startup recovery=${recovery} mode=${mode} cannot bypass the tunnel gate`, async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'foxhole-backup-start-'));
  try {
    const source = await read(`${packageRoot}/root/etc/init.d/foxhole-runtime`);
    const body = source.match(/start_service\(\) \{([\s\S]*?)\n\}/)?.[1]; assert.ok(body);
    const recover = join(temporary, 'recover'), controller = join(temporary, 'controller'), log = join(temporary, 'calls');
    await writeFile(recover, `#!/bin/sh\nexit ${recovery}\n`, { mode: 0o700 });
    await writeFile(controller, `#!/bin/sh\nif [ "$1" = mode ]; then echo ${mode}; else echo "$*" >> "$TEST_LOG"; fi\n`, { mode: 0o700 });
    const script = `set -eu\ncontroller='${controller}'\nsupervisor=fixture-supervisor\n` +
      `procd_open_instance(){ echo instance >> "$TEST_LOG"; }\nprocd_set_param(){ :; }\nprocd_close_instance(){ :; }\n` +
      `start_service(){${body.replace('/usr/libexec/foxhole-backup-recover', recover)}\n}\nstart_service\n`;
    const result = spawnSync('/bin/sh', ['-c', script], { encoding: 'utf8', env: { ...process.env, TEST_LOG: log } });
    assert.equal(result.status, expected, result.stderr);
    let calls = ''; try { calls = await readFile(log, 'utf8'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    assert.equal(calls.includes('instance'), starts);
    if (recovery === 10 && mode === 'block') assert.match(calls, /apply blocked/);
    if (recovery === 10 && mode === 'off') assert.match(calls, /cleanup/);
  } finally { await rm(temporary, { recursive: true, force: true }); }
});

test('RPC backup methods, TLS gateway, capability and access scopes are explicit', async () => {
  const methods = await rpcMethods(), rpc = await read(`${packageRoot}/root/usr/share/rpcd/ucode/foxhole.uc`);
  assert.deepEqual(Object.keys(methods['backup.apply'].args), ['token', 'document', 'expectedRevision', 'confirmed', 'requestId']);
  assert.deepEqual(Object.keys(methods['backup.validate'].args), ['token', 'document', 'expectedRevision']);
  const dispatcher = functionBody(rpc, 'call');
  assert.match(dispatcher, /'server\.stop'/); assert.match(dispatcher, /'pin\.change'/); assert.match(dispatcher, /'pair\.revoke'/);
  assert.match(dispatcher, /backup_service\.guard/);
  const handler = functionBody(rpc, 'backup_request');
  assert.match(handler, /queue_backup/); assert.match(handler, /foxhole-backup-job/); assert.doesNotMatch(handler, /restore_backup/);
  assert.match(functionBody(rpc, 'package_status'), /backupSupported: true/);
  const gateway = await read(`${packageRoot}/root/www/cgi-bin/foxhole`);
  for (const method of ['backup.export', 'backup.validate', 'backup.apply', 'backup.status'])
    assert.ok(gateway.slice(gateway.indexOf('pairing.requires_tls')).includes(`'${method}'`));
  const acl = JSON.parse(await read(`${packageRoot}/root/usr/share/rpcd/acl.d/luci-app-foxhole.json`))['luci-app-foxhole'];
  assert.ok(acl.write.ubus.foxhole.includes('backup.apply'));
  for (const method of ['backup.export', 'backup.validate', 'backup.status']) assert.ok(acl.read.ubus.foxhole.includes(method));
});
