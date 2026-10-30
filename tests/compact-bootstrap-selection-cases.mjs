import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const root = process.env.FOXHOLE_MODEL_ROOT || '/workspace';
const H = 'a'.repeat(64);
const protocols = ['anytls', 'http', 'hysteria2', 'naive', 'shadowsocks', 'shadowtls', 'socks', 'trojan', 'tuic', 'vless', 'vmess', 'wireguard'];
const asset = file => ({ file, sha256: H });
function client(id, storage = 'flash') {
  const manifest = (id === 'vless' ? 'b' : id === 'wireguard' ? 'd' : 'c').repeat(64);
  const name = `foxcore-engine-${id}-${storage}-${manifest}`;
  const entry = { id, storage: storage.toUpperCase(), version: '1.0.0', architecture: 'x86_64', binarySha256: H,
    executableSha256: H, producerSha256: H, capabilitiesSha256: H, legalProvenanceSha256: H,
    manifestSha256: manifest, sourceCommit: 'e'.repeat(40), binaryBytes: 8192, archiveBytes: 1024,
    indexBytes: 512, installedBytes: 12288, runtimeMemoryBytes: 33554432, reserveBytes: 16777216,
    packageName: name, packageVersion: '1.0.0-r1', packageSha256: H, indexSha256: H,
    packageUrl: `https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.0/${name}-1.0.0-r1.apk`,
    indexUrl: 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.0/engines.adb' };
  return { id, storage, entry, producer: asset(id + '-producer.json'),
    capabilities: asset(id + '-capabilities.json'), slotManifest: { file: id + '-slot.json', sha256: manifest } };
}
function compact() {
  return { schema: 2, kind: 'compact-client-engines-v1', development: false,
    defaultProtocols: ['hysteria2'], allProtocols: protocols,
    platforms: [{ id: 'x86-25.12.5', architecture: 'x86_64', supportedTargets: ['x86/64'], supportedOpenWrt: ['25.12.5'],
      basePackage: { name: 'foxhole-openwrt-client', file: 'panel.apk', sha256: H, packageIdentity: H },
      engineCatalog: asset('engine-catalog.json'), packageUniverse: asset('universe.json'),
      clients: [client('hysteria2'), client('vless')],
      server: { producer: asset('server-producer.json'), modes: { flash: { name: 'hysteria', file: 'server.apk', sha256: H } } } }] };
}
function legacy() {
  return { schema: 1, development: false, defaultProtocols: ['hysteria2'], allProtocols: protocols,
    variants: [{ id: 'legacy-hy2', architecture: 'x86_64', supportedTargets: ['x86/64'], supportedOpenWrt: ['25.12.5'],
      protocols: ['hysteria2'], coreProducerFile: 'producer.json', coreProducerSha256: H, coreBinarySha256: H,
      coreSourceSha256: H, capabilitiesFile: 'capabilities.json', capabilitiesSha256: H,
      serverProducerFile: 'legacy-server.json', serverProducerSha256: H,
      modes: { flash: { budgetFile: 'flash.json', budgetSha256: H } } }] };
}
function select(value, requested = '', server = false, architecture = 'x86_64') {
  const temporary = mkdtempSync(join(tmpdir(), 'foxhole-compact-selection-'));
  try {
    const file = join(temporary, 'catalog.json'); writeFileSync(file, JSON.stringify(value), { mode: 0o600 });
    const result = spawnSync('ucode', [root + '/tools/install-plan.uc', 'select', file,
      architecture, '25.12.5', requested, '0', 'x86/64', server ? '1' : '0'],
    { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
    assert.equal(result.error, undefined, 'real ucode must start; a missing tool is not behavior evidence');
    assert.ok(!/SyntaxError|ReferenceError|No such file|Module not found/.test(result.stderr), result.stderr);
    return result;
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}

test('legacy v1 exact HY2 selection still uses its original producer/server contract', () => {
  const result = select(legacy()); assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^producer\.json /m); assert.match(result.stdout, /^legacy-server\.json /m);
});
test('compact VLESS-only selection never inserts HY2 or an unrequested server', () => {
  const result = select(compact(), 'vless'); assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^vless-producer\.json /m);
  assert.doesNotMatch(result.stdout, /hysteria2-producer|server-producer|legacy-server/);
});
test('compact default is one HY2 client module without the incoming server', () => {
  const result = select(compact()); assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^hysteria2-producer\.json /m);
  assert.doesNotMatch(result.stdout, /vless-producer|server-producer/);
});
test('compact selected pair reuses the two single modules without a union producer', () => {
  const result = select(compact(), 'hysteria2,vless'); assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^hysteria2-producer\.json /m); assert.match(result.stdout, /^vless-producer\.json /m);
  assert.doesNotMatch(result.stdout, /server-producer/);
});
test('compact all selects the three released modules without requesting the twelve-id vocabulary', () => {
  const value = compact(); value.platforms[0].clients.push(client('wireguard'));
  const result = select(value, 'all'); assert.equal(result.status, 0, result.stderr);
  for (const id of ['hysteria2', 'vless', 'wireguard']) assert.match(result.stdout, new RegExp('^' + id + '-producer\\.json ', 'm'));
  assert.doesNotMatch(result.stdout, /tuic-producer|server-producer/);
});
test('compact all derives only from the matching firmware platform', () => {
  const value = compact(); value.platforms[0].clients.push(client('wireguard'));
  const other = JSON.parse(JSON.stringify(value.platforms[0]));
  other.id = 'other-firmware'; other.supportedOpenWrt = ['25.12.4']; other.clients = [client('tuic')];
  value.platforms.push(other);
  const result = select(value, 'all'); assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stdout, /tuic-producer|server-producer/);
});
test('compact all refuses modules with no common storage mode', () => {
  const value = compact(); value.platforms[0].clients = [client('hysteria2'), client('vless', 'ram'), client('wireguard')];
  assert.notEqual(select(value, 'all').status, 0);
});
test('compact all support does not ignore an explicitly requested unavailable protocol', () => {
  const value = compact(); value.platforms[0].clients.push(client('wireguard'));
  assert.notEqual(select(value, 'hysteria2,vless,wireguard,tuic').status, 0);
});
test('incoming HY2 server metadata appears only after explicit server intent', () => {
  const result = select(compact(), 'vless', true); assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^server-producer\.json /m); assert.doesNotMatch(result.stdout, /hysteria2-producer/);
});
test('a protocol without a released platform module is refused instead of all fallback', () => {
  assert.notEqual(select(compact(), 'wireguard').status, 0);
});
test('a different architecture cannot borrow the x86 module or budget', () => {
  assert.notEqual(select(compact(), 'vless', false, 'aarch64_generic').status, 0);
});
test('wrong v2 kind cannot downgrade into the legacy variant contract', () => {
  const value = compact(); value.kind = 'legacy'; value.variants = legacy().variants;
  assert.notEqual(select(value, 'vless').status, 0);
});
