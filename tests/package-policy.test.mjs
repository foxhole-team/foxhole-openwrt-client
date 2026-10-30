import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { root } from './helpers.mjs';

const check = `
import importlib.util, pathlib, sys
path=pathlib.Path(sys.argv[1]) / 'tools/package-catalog.py'
spec=importlib.util.spec_from_file_location('catalog',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
value={'schema':1,'type':'conservative','runtimeMemoryBytes':1048576,'description':'Synthetic policy fixture'}
case=sys.argv[2]
if case in ('lab','provisional'): value['provisional']=True
if case=='unreviewed': value['acceptedForRelease']=False
if case=='boolean-schema': value['schema']=True
if case=='boolean-bytes': value['runtimeMemoryBytes']=True
if case=='string-qualification': value['provisional']='false'
if case=='different-runtime': value['runtimeMemoryBytes']=2097152
if case=='no-policy': value=None
module.memory_policy(value,1048576,case=='lab')
`;

for (const scenario of ['reviewed', 'lab', 'provisional', 'unreviewed',
  'boolean-schema', 'boolean-bytes', 'string-qualification', 'different-runtime', 'no-policy']) {
  test('package memory policy: ' + scenario, () => {
    const result = spawnSync('python3', ['-B', '-c', check, root, scenario], {
      encoding: 'utf8', timeout: 10000
    });
    assert.ifError(result.error);
    if (scenario === 'reviewed' || scenario === 'lab') {
      assert.equal(result.status, 0, result.stderr);
    } else {
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /ValueError/);
    }
  });
}

test('empty APK closure cannot establish a verified installation budget', () => {
  const code = `
import importlib.util,pathlib,sys
path=pathlib.Path(sys.argv[1]) / 'tools/package-budget.py'
spec=importlib.util.spec_from_file_location('budget',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
try:
 module.closure('/not-used',[],[],[],'x86_64',None,True)
except ValueError:
 sys.exit(0)
raise AssertionError('empty_closure_admitted')
`;
  const result = spawnSync('python3', ['-B', '-c', code, root], {
    encoding: 'utf8', timeout: 10000
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});
