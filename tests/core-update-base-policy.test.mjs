import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createHash } from 'node:crypto';
import { read, functionBody, packageRoot, plain } from './helpers.mjs';
const source = await read(`${packageRoot}/root/usr/share/foxhole/ram-update-model.uc`);
const body = functionBody(source, 'policy');
const policy = JSON.parse(await read(`${packageRoot}/root/usr/share/foxhole/update-policy.json`));
function receiver(value) {
 const scope = vm.createContext({ type: value => typeof value,
  length: value => value.length, keys: Object.keys, index: (rows, item) => rows.indexOf(item),
  sprintf: (_format, value) => JSON.stringify(value),
  fail: reason => { throw new Error(reason); } });
 vm.runInContext(`function policy(value,wanted,release) ${body}`.replace('for(let key in keys(value))', 'for(let key of keys(value))'), scope);
 return plain(scope.policy(value, policy.packageVersion, policy.releaseTag));
}
test('the one-time BASE migration remains accepted by the unchanged exact-seven-field RAM receiver', () => {
 assert.equal(createHash('sha256').update(body).digest('hex'), '7ee1beb2dd95df782a5ecabd729051f3c20c99c421c4b40ab9091c9c016da8c1');
 assert.equal(Object.keys(policy).length, 7);
 assert.deepEqual(receiver(policy), policy);
});
test('legacy receiver still refuses unknown policy extensions', () => {
 const legacy = { ...policy }; delete legacy.coreFeedAbi;
 assert.throws(() => receiver({ ...legacy, arbitraryAbi: 2 }), /PACKAGE_VERIFICATION_FAILED/);
 assert.throws(() => receiver({ ...legacy, coreFeedAbi: 1 }), /PACKAGE_VERIFICATION_FAILED/);
});
