import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { root } from './helpers.mjs';

const check = `
import importlib.util,pathlib,sys
path=pathlib.Path(sys.argv[1])/'tools/indexed-auth.py'
spec=importlib.util.spec_from_file_location('indexed',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
packages=[{'file':'core.apk','name':'foxcore-cli','version':'1.0.0-r1','arch':'x86_64'}]
value={'architecture':'x86_64','supportedTargets':['x86/64'],'supportedOpenWrt':['25.12.5'],
 'verification':{'signatureModel':module.MODEL,'factorySourceSha256':'a'*64},
 'repositoryIndexes':[{'file':'own.adb','sha256':'b'*64,'bytes':100,'role':'foxhole',
 'sourceUrl':'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.0/packages.adb','trustKeyFiles':['foxhole-openwrt-apk.pem']}],
 'packageAuthentications':[{'file':'core.apk','indexFile':'own.adb','name':'foxcore-cli',
 'version':'1.0.0-r1','architecture':'x86_64','packageIdentity':'c'*64}],
 'filesSha256':{'core.apk':'d'*64,'own.adb':'b'*64,'foxhole-openwrt-apk.pem':module.CANONICAL_PUBLIC_SHA},
 'repositoryIndexBytes':100,'trustKeyBytes':400,
 'trustKeys':[{'file':'foxhole-openwrt-apk.pem','sha256':module.CANONICAL_PUBLIC_SHA,'bytes':400}]}
case=sys.argv[2]
if case=='old-model': value['verification'].pop('signatureModel')
if case=='no-factory': value['verification'].pop('factorySourceSha256')
if case=='boolean-size': value['repositoryIndexes'][0]['bytes']=True
if case=='unindexed': value['packageAuthentications'][0]['indexFile']='other.adb'
if case=='wrong-role': value['repositoryIndexes'][0]['role']='upstream';value['repositoryIndexes'][0]['sourceUrl']='https://downloads.openwrt.org/releases/25.12.5/base/packages.adb'
if case=='unsafe-version': value['packageAuthentications'][0]['version']='../../root'
if case=='duplicate-binding': value['packageAuthentications']*=2
if case=='foreign-extra': value['filesSha256']['other.apk']='f'*64
if case=='missing-key': value['filesSha256'].pop('foxhole-openwrt-apk.pem')
if case=='bad-index-total': value['repositoryIndexBytes']=99
if case=='bad-key-total': value['trustKeyBytes']=399
if case=='unused-key': value['trustKeys'].append({'file':'unused.pem','sha256':'f'*64,'bytes':400})
if case=='boolean-key-bytes': value['trustKeys'][0]['bytes']=True
if case=='secret-url': value['repositoryIndexes'][0]['sourceUrl']='https://user:password@example.test/packages.adb'
if case=='foreign-upstream': value['repositoryIndexes'][0]['role']='upstream'
module.schema(value,packages)
`;

for (const scenario of ['valid', 'old-model', 'no-factory', 'boolean-size',
  'unindexed', 'wrong-role', 'unsafe-version', 'duplicate-binding', 'foreign-extra',
  'missing-key', 'bad-index-total', 'bad-key-total', 'unused-key', 'boolean-key-bytes',
  'secret-url', 'foreign-upstream']) {
  test('indexed package trust schema: ' + scenario, () => {
    const result = spawnSync('python3', ['-B', '-c', check, root, scenario], {
      encoding: 'utf8', timeout: 10000
    });
    assert.ifError(result.error);
    if (scenario === 'valid') assert.equal(result.status, 0, result.stderr);
    else {
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /ValueError/);
    }
  });
}
