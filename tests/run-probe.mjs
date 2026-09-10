import { spawnSync } from 'node:child_process';
import { read, functionBody } from './helpers.mjs';

const container = process.env.FOXHOLE_TEST_CONTAINER || 'foxhole-public-model-check';
const base = 'package/foxhole-openwrt-client/root';
const sampler = await read(`${base}/usr/libexec/foxhole-probe`);
const rpc = await read(`${base}/usr/share/rpcd/ucode/foxhole.uc`);

function execute(source, compile = false) {
  const result = spawnSync('docker', ['exec', '-i', container, 'ucode',
    ...(compile ? ['-c', '-o', '/dev/null'] : []), '-'], {
    input: source, encoding: 'utf8', timeout: 30000
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error || result.status !== 0)
    throw new Error('Focused probe verification failed');
}

for (const source of [sampler, rpc]) execute(source.replaceAll(
  "'/usr/share/foxhole/", `'/workspace/${base}/usr/share/foxhole/`), true);
process.stdout.write('Sampler and RPC ucode compilation passed.\n');

const fixture = await read('tests/probe.uc');
const marker = '// The production sampler is injected with deterministic I/O.';
if (fixture.split(marker).length !== 2) throw new Error('Invalid fixture');
execute(fixture.replace(marker,
  `function collect() ${functionBody(sampler, 'collect')};`));
