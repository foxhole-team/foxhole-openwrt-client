import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const root = process.env.FOXHOLE_MODEL_ROOT || '/workspace';
const digest = 'a'.repeat(64), source = 'e'.repeat(40);
const publicDigest = createHash('sha256').update(readFileSync(root + '/config/foxhole-openwrt-apk.pem')).digest('hex');
const ids = ['anytls', 'http', 'hysteria2', 'naive', 'shadowsocks', 'shadowtls', 'socks', 'trojan', 'tuic', 'vless', 'vmess', 'wireguard'];
const pointer = file => ({ file, sha256: digest });
function module(id, storage) {
  const manifestSha256 = (id === 'vless' ? 'b' : 'c').repeat(64);
  const packageName = `foxcore-engine-${id}-${storage}-${manifestSha256}`;
  const entry = { id, storage: storage.toUpperCase(), version: '1.0.0', architecture: 'x86_64',
    binarySha256: digest, executableSha256: digest, producerSha256: digest, capabilitiesSha256: digest,
    legalProvenanceSha256: digest, manifestSha256, sourceCommit: source,
    binaryBytes: 8192, archiveBytes: 1024, indexBytes: 512, installedBytes: 12288,
    runtimeMemoryBytes: 33554432, reserveBytes: 16777216,
    packageName, packageVersion: '1.0.0-r1', packageSha256: digest, indexSha256: digest,
    packageUrl: `https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.0/${packageName}-1.0.0-r1.apk`,
    indexUrl: 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.0/engines.adb' };
  return { id, storage, entry, producer: pointer(id + '-producer.json'), capabilities: pointer(id + '-caps.json'),
    slotManifest: { file: id + '-slot.json', sha256: manifestSha256 } };
}
function fixture(storage = 'flash') {
  const clients = [module('hysteria2', storage), module('vless', storage)];
  const basePackage = { name: 'foxhole-openwrt-client', file: 'panel.apk', sha256: digest, packageIdentity: digest };
  const server = { name: storage === 'flash' ? 'hysteria' : 'hysteria-server-ram', file: 'server.apk',
    sha256: digest, producerSha256: digest, binarySha256: digest, executableSha256: digest,
    runtimeMemoryBytes: 67108864, securityReceiptSha256: digest,
    ...(storage === 'ram' ? { volatileFile: 'server.bin', binaryBytes: 16384 } : {}) };
  const platform = { id: 'x86-25.12.5', architecture: 'x86_64', supportedTargets: ['x86/64'], supportedOpenWrt: ['25.12.5'],
    basePackage, engineCatalog: pointer('engines.json'), packageUniverse: pointer('universe.json'), clients,
    server: { producer: pointer('server-producer.json'), modes: { [storage]: { name: server.name, file: server.file, sha256: digest } } } };
  const catalog = { schema: 2, kind: 'compact-client-engines-v1', development: false,
    defaultProtocols: ['hysteria2'], allProtocols: ids, platforms: [platform] };
  const packageRecord = (name, file, depends = ['libc']) => ({ name, file, version: '1.0.0-r1', arch: 'x86_64',
    depends, provides: [], archiveBytes: 1024, installedBytes: 12288, sha256: digest });
  const packages = [packageRecord('libc', 'libc.apk', []), packageRecord('kernel', 'kernel.apk'),
    packageRecord(basePackage.name, basePackage.file), ...clients.map(row => packageRecord(row.entry.packageName,
      row.entry.packageUrl.split('/').at(-1))), packageRecord(server.name, server.file)];
  const indexes = [
    { file: 'base.adb', role: 'foxhole', sourceUrl: 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.0/base.adb', trustKeyFiles: ['foxhole-openwrt-apk.pem'], sha256: digest, bytes: 512 },
    { file: 'engines.adb', role: 'foxhole', sourceUrl: clients[0].entry.indexUrl, trustKeyFiles: ['foxhole-openwrt-apk.pem'], sha256: digest, bytes: 512 },
    { file: 'core.adb', role: 'upstream', sourceUrl: 'https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/packages/packages.adb', trustKeyFiles: ['firmware.pem'], sha256: digest, bytes: 512 }
  ];
  const trustKeys = [{ file: 'foxhole-openwrt-apk.pem', sha256: publicDigest, bytes: 512 }, { file: 'firmware.pem', sha256: 'd'.repeat(64), bytes: 512 }];
  const packageAuthentications = packages.map(row => ({ file: row.file, name: row.name, version: row.version, architecture: row.arch,
    packageIdentity: digest, indexFile: ['libc', 'kernel'].includes(row.name) ? 'core.adb' : row.name.startsWith('foxcore-engine-') ? 'engines.adb' : 'base.adb' }));
  const filesSha256 = Object.fromEntries([...packages, ...indexes, ...trustKeys].map(row => [row.file, row.sha256]));
  const universe = { schema: 2, kind: 'compact-package-universe-v1', architecture: platform.architecture,
    supportedTargets: platform.supportedTargets, supportedOpenWrt: platform.supportedOpenWrt,
    verification: { signatureModel: 'canonical-apk-and-upstream-index-v1', signatures: true,
      factorySourceSha256: digest, resolver: 'apk add --simulate --no-network' },
    packages, packageAuthentications, repositoryIndexes: indexes, trustKeys, filesSha256,
    requires: Object.fromEntries(packages.map(row => [row.name, row.depends])), server: { [storage]: server },
    baseRuntimeMemoryBytes: 16777216, flashReserveBytes: 16777216, ramReserveBytes: 16777216,
    memoryEvidence: { schema: 1, type: 'conservative', description: 'Synthetic fixture reserve; no measured runtime claim' } };
  return { catalog, universe, clients, server };
}
function run(value, { protocols = 'vless', server = false, flash = 2 ** 40, ram = 2 ** 40, mutate } = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'foxhole-compact-budget-'));
  try {
    const documents = { 'catalog.json': value.catalog, 'universe.json': value.universe,
      'engines.json': { schema: 1, entries: value.clients.map(row => row.entry) },
      'server-producer.json': { schema: 1, exitCode: 0, target: 'linux-amd64', binarySha256: digest, sourcePatch: { receiptSha256: digest } } };
    for (const client of value.clients) {
      documents[client.producer.file] = { schema: 1, exitCode: 0, target: 'x86_64-unknown-linux-musl',
        binarySha256: digest, sourceCommit: source, sourceSha256: digest, coreVersion: '1.0.0', protocols: [client.id] };
      documents[client.capabilities.file] = { schema_version: 1, router_contract_version: 1, platform: 'linux', core_version: '1.0.0', protocols: [client.id] };
      documents[client.slotManifest.file] = { schema: 1, ...Object.fromEntries(['id', 'storage', 'version', 'architecture',
        'binarySha256', 'executableSha256', 'producerSha256', 'capabilitiesSha256', 'legalProvenanceSha256', 'sourceCommit',
        'binaryBytes', 'runtimeMemoryBytes', 'reserveBytes'].map(key => [key, client.entry[key]])) };
    }
    mutate?.(documents);
    for (const [name, body] of Object.entries(documents)) writeFileSync(join(directory, name), JSON.stringify(body), { mode: 0o600 });
    const result = spawnSync('ucode', [root + '/tools/install-compact-plan.uc', 'budget', join(directory, 'catalog.json'),
      'x86_64', '25.12.5', protocols, '0', 'x86/64', directory, 'auto', String(flash), String(ram), '0', server ? '1' : '0'],
    { encoding: 'utf8', timeout: 5000, maxBuffer: 1048576 });
    assert.equal(result.error, undefined, 'actual ucode must start');
    assert.doesNotMatch(result.stderr, /SyntaxError|ReferenceError|Module not found|No such file/, 'fixture setup must compile');
    return { ...result, value: result.status === 0 ? JSON.parse(result.stdout) : null };
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

test('VLESS-only compact budget includes panel and exact module without Go/HY2 roots or bytes', () => {
  const result = run(fixture()); assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.value.protocols, ['vless']); assert.equal(result.value.includeServer, false);
  assert.equal(result.value.server, null); assert.equal(result.value.rootPackages.length, 2);
  assert.ok(result.value.rootPackages.some(name => name.startsWith('foxcore-engine-vless-')));
  assert.ok(result.value.packages.every(row => !/hysteria|foxcore-cli/.test(row.name)));
  assert.equal(result.value.runtimeMemoryBytes, 50331648);
});
test('two selected clients share dependencies and runtime uses largest client plus base', () => {
  const result = run(fixture(), { protocols: 'hysteria2,vless' }); assert.equal(result.status, 0, result.stderr);
  assert.equal(result.value.packages.filter(row => row.name === 'libc').length, 1);
  assert.equal(result.value.modules.length, 2); assert.equal(result.value.runtimeMemoryBytes, 50331648);
});
test('explicit server intent adds exact server role and its resource cost', () => {
  const result = run(fixture(), { server: true }); assert.equal(result.status, 0, result.stderr);
  assert.equal(result.value.server.name, 'hysteria'); assert.equal(result.value.rootPackages.length, 3);
  assert.equal(result.value.runtimeMemoryBytes, 117440512);
});
test('RAM selection includes only selected volatile binaries and accounts for all staging', () => {
  const result = run(fixture('ram'), { protocols: 'vless', server: true }); assert.equal(result.status, 0, result.stderr);
  assert.equal(result.value.mode, 'ram'); assert.equal(result.value.installedRamBytes, 8192 + 16384);
  assert.deepEqual(result.value.volatile.map(row => row.id), ['vless', 'server']);
  assert.equal(result.value.requiredRamBytes, result.value.stagingBytes + result.value.runtimeMemoryBytes + result.value.ramReserveBytes);
});
test('insufficient actual memory refuses selection instead of dropping chosen protocols', () => {
  const result = run(fixture(), { ram: 1 }); assert.notEqual(result.status, 0); assert.match(result.stderr, /Insufficient/);
});
test('hidden monolithic/Go dependency without explicit server intent is refused', () => {
  const value = fixture(); value.universe.requires['foxhole-openwrt-client'].push('hysteria');
  assert.notEqual(run(value).status, 0);
});
test('unrequested immutable module cannot enter the selected dependency closure', () => {
  const value = fixture(); value.universe.requires['foxhole-openwrt-client'].push(value.clients[0].entry.packageName);
  assert.notEqual(run(value).status, 0);
});
test('wrong signed index package identity for the base is refused', () => {
  const value = fixture(); value.universe.packageAuthentications.find(row => row.name === 'foxhole-openwrt-client').packageIdentity = 'f'.repeat(64);
  assert.notEqual(run(value).status, 0);
});
test('module source, capabilities and slot legal identity are cross-checked separately', () => {
  for (const mutate of [
    docs => { docs['vless-producer.json'].protocols = ['hysteria2']; },
    docs => { docs['vless-caps.json'].platform = 'android'; },
    docs => { docs['vless-slot.json'].legalProvenanceSha256 = 'f'.repeat(64); }
  ]) assert.notEqual(run(fixture(), { mutate }).status, 0);
});
test('a changed engine catalog cannot silently replace the signed selected slot', () => {
  assert.notEqual(run(fixture(), { mutate: docs => { docs['engines.json'].entries[1].packageSha256 = 'f'.repeat(64); } }).status, 0);
});
test('kernel and upstream dependency cannot borrow canonical FoxHole authority', () => {
  const value = fixture(); value.universe.packageAuthentications.find(row => row.name === 'kernel').indexFile = 'base.adb';
  assert.notEqual(run(value).status, 0);
});
test('missing explicit server ABI/mode fails and never downgrades to client-only', () => {
  const value = fixture(); value.catalog.platforms[0].server = null;
  assert.notEqual(run(value, { server: true }).status, 0);
});
