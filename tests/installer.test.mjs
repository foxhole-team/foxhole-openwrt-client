import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile, access, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { root, functionBody } from './helpers.mjs';

for (const args of [[], ['--ram'], ['--flash'], ['--development'], ['--ram', '--apply', '--development']]) {
  test('Stable installer refuses unqualified legacy assets before any mutation: ' + args.join(' '), async t => {
    const directory = await mkdtemp(join(tmpdir(), 'foxhole-legacy-refusal-'));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const bin = join(directory, 'bin'), marker = join(directory, 'mutation');
    await mkdir(bin);
    for (const tool of ['apk', 'id', 'uclient-fetch', 'sysupgrade']) {
      await writeFile(join(bin, tool), '#!/bin/sh\ntouch "$TEST_MUTATION"\nexit 88\n', { mode: 0o755 });
    }
    const result = spawnSync('/bin/sh', [join(root, 'install.sh'), '--legacy-hy2', ...args], {
      encoding: 'utf8', timeout: 10000,
      env: { ...process.env, PATH: bin + ':' + process.env.PATH, TEST_MUTATION: marker }
    });
    assert.ifError(result.error);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /not qualified for Stable/);
    await assert.rejects(access(marker), { code: 'ENOENT' });
  });
}


async function compactReleaseModel() {
  const source = await readFile(join(root, 'tools/install-plan-model.uc'), 'utf8');
  const signatures = { compact_reject: '', hash: 'value', name: 'value', number: 'value', version: 'value',
    compact_exact: 'value,fields', compact_asset: 'value', compact_ids: 'requested', compact_release: 'item',
    compact_client: 'value,architecture', compact_selection: 'catalog,architecture,release,requested,development,target,include_server' };
  const code = Object.entries(signatures).map(([name,args]) => `function ${name}(${args}) ${functionBody(source,name)}`).join('\n')
    .replace(/for \(let (\w+), (\w+) in ([^)]+)\)/g, 'for (let [$1,$2] of Object.entries($3))')
    .replace(/for \(let (\w+) in /g, 'for (let $1 of ');
  const bindings = { protocols: ['anytls','http','hysteria2','naive','shadowsocks','shadowtls','socks','trojan','tuic','vless','vmess','wireguard'],
    type: v => v == null ? 'null' : Array.isArray(v) ? 'array' : Number.isInteger(v) ? 'int' : typeof v === 'boolean' ? 'bool' : typeof v,
    match: (v,r) => v.match(r), length: v => Array.isArray(v) || typeof v === 'string' ? v.length : Object.keys(v).length,
    keys: Object.keys, index: (v,x) => v.indexOf(x), push: (v,x) => v.push(x), sort: v => v.sort(),
    split: (v,x) => v.split(x), join: (s,v) => v.join(s), filter: (v,f) => v.filter(f), die: () => { throw Error('rejected'); } };
  return new Function(...Object.keys(bindings),code+';return {compact_selection};')(...Object.values(bindings));
}
function compactReleaseFixture(release = '1.0.3') {
  const hash='a'.repeat(64),pointer=file=>({file,sha256:hash});
  const clients=['hysteria2','vless'].map(id=>{
    const packageName=`foxcore-engine-${id}-flash-${hash}`,base=`https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v${release}/`;
    return {id,storage:'flash',entry:{id,storage:'FLASH',version:'1.0.2',architecture:'x86_64',
      binarySha256:hash,executableSha256:hash,producerSha256:hash,capabilitiesSha256:hash,legalProvenanceSha256:hash,
      manifestSha256:hash,sourceCommit:'b'.repeat(40),binaryBytes:8192,archiveBytes:1024,indexBytes:512,installedBytes:12288,
      runtimeMemoryBytes:33554432,reserveBytes:16777216,packageName,packageVersion:'1.0.2-r1',packageSha256:hash,indexSha256:hash,
      packageUrl:base+packageName+'-1.0.2-r1.apk',indexUrl:base+'engines.adb'},producer:pointer(id+'-producer.json'),
      capabilities:pointer(id+'-caps.json'),slotManifest:pointer(id+'-slot.json')};
  });
  return {schema:2,kind:'compact-client-engines-v1',development:false,defaultProtocols:['hysteria2'],
    allProtocols:['anytls','http','hysteria2','naive','shadowsocks','shadowtls','socks','trojan','tuic','vless','vmess','wireguard'],
    platforms:[{id:'x86-25.12.5',architecture:'x86_64',supportedTargets:['x86/64'],supportedOpenWrt:['25.12.5'],
      basePackage:{name:'foxhole-openwrt-client',file:'panel.apk',sha256:hash,packageIdentity:hash},
      engineCatalog:pointer('engine-catalog.json'),packageUniverse:pointer('universe.json'),clients,server:null}]};
}
function compactReleaseSelect(api,catalog) { return api.compact_selection(catalog,'x86_64','25.12.5','hysteria2',false,'x86/64',false); }
for (const release of ['1.0.2','1.0.3']) test('compact release reference accepts router '+release+' with unchanged Core 1.0.2', async()=>{
  const api=await compactReleaseModel(),catalog=compactReleaseFixture(release),before=JSON.stringify(catalog);
  assert.deepEqual(compactReleaseSelect(api,catalog).protocols,['hysteria2']);assert.equal(JSON.stringify(catalog),before);
});
test('compact release reference rejects mixed releases in one platform',async()=>{
  const api=await compactReleaseModel(),catalog=compactReleaseFixture();
  catalog.platforms[0].clients[1]=compactReleaseFixture('1.0.2').platforms[0].clients[1];
  assert.throws(()=>compactReleaseSelect(api,catalog));
});
test('compact release reference rejects mixed releases in an unselected platform',async()=>{
  const api=await compactReleaseModel(),catalog=compactReleaseFixture(),other=compactReleaseFixture('1.0.2').platforms[0];
  other.id='filogic';other.architecture='aarch64_cortex-a53';other.supportedTargets=['mediatek/filogic'];
  for(const client of other.clients)client.entry.architecture=other.architecture;
  catalog.platforms.push(other);assert.throws(()=>compactReleaseSelect(api,catalog));
});
test('compact release reference rejects foreign, query, leading-zero and inconsistent URLs',async()=>{
  const api=await compactReleaseModel();
  for(const mutate of [e=>e.indexUrl=e.indexUrl.replace('github.com','example.test'),e=>e.indexUrl+='?x=1',
    e=>e.indexUrl=e.indexUrl.replace('/v1.0.3/','/v01.0.3/'),e=>e.packageUrl=e.packageUrl.replace('/v1.0.3/','/v1.0.2/'),
    e=>e.packageUrl=e.packageUrl.replace('-1.0.2-r1.apk','-1.0.3-r1.apk')]){
    const catalog=compactReleaseFixture();mutate(catalog.platforms[0].clients[0].entry);assert.throws(()=>compactReleaseSelect(api,catalog));
  }
});
test('compact release reference retains native Core version validation',async()=>{
  const api=await compactReleaseModel(),catalog=compactReleaseFixture();catalog.platforms[0].clients[0].entry.version='invalid';
  assert.throws(()=>compactReleaseSelect(api,catalog));
});
