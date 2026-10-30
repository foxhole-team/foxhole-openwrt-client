import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { root } from './helpers.mjs';

const check = `
import importlib.util,pathlib,sys
p=pathlib.Path(sys.argv[1])/'tools/indexed-auth.py'
s=importlib.util.spec_from_file_location('indexed',p)
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
name='foxcore-engine-vless-flash-'+'b'*64
packages=[{'file':'engine.apk','name':name,'version':'1.0.0-r1','arch':'x86_64'}]
value={'architecture':'x86_64','supportedTargets':['x86/64'],'supportedOpenWrt':['25.12.5'],
 'verification':{'signatureModel':m.MODEL,'factorySourceSha256':'a'*64},
 'repositoryIndexes':[{'file':'engines.adb','sha256':'b'*64,'bytes':100,'role':'foxhole',
 'sourceUrl':'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.0/engines.adb','trustKeyFiles':['foxhole-openwrt-apk.pem']}],
 'packageAuthentications':[{'file':'engine.apk','indexFile':'engines.adb','name':name,
 'version':'1.0.0-r1','architecture':'x86_64','packageIdentity':'c'*64}],
 'filesSha256':{'engine.apk':'d'*64,'engines.adb':'b'*64,'foxhole-openwrt-apk.pem':m.CANONICAL_PUBLIC_SHA},
 'repositoryIndexBytes':100,'trustKeyBytes':400,
 'trustKeys':[{'file':'foxhole-openwrt-apk.pem','sha256':m.CANONICAL_PUBLIC_SHA,'bytes':400}]}
scenario=sys.argv[2]
owned=frozenset([name])
if scenario=='legacy-default': m.schema(value,packages);sys.exit(0)
if scenario=='foreign-slot': owned=frozenset([name[:-1]+'c'])
if scenario=='upstream-as-owned': owned=frozenset(['kernel'])
if scenario=='duplicate-binding': value['packageAuthentications']*=2
if scenario=='extra-archive': value['filesSha256']['foreign.apk']='f'*64
if scenario=='bad-identity': value['packageAuthentications'][0]['packageIdentity']='invalid'
if scenario=='unbounded-own': owned=frozenset('engine-'+str(i) for i in range(27))
m.schema(value,packages,own_names=owned)
`;
for (const scenario of ['valid-selected-slot', 'legacy-default', 'foreign-slot', 'upstream-as-owned',
  'duplicate-binding', 'extra-archive', 'bad-identity', 'unbounded-own']) {
  test('compact exact index trust boundary: ' + scenario, () => {
    const result = spawnSync('python3', ['-B', '-c', check, root, scenario], { encoding: 'utf8', timeout: 10000 });
    assert.ifError(result.error);
    if (scenario === 'valid-selected-slot') assert.equal(result.status, 0, result.stderr);
    else { assert.notEqual(result.status, 0); assert.match(result.stderr, /ValueError/); }
  });
}
