import assert from 'node:assert/strict';
import test from 'node:test';
import { functionBody, read } from './helpers.mjs';
const source=await read('package/foxhole-openwrt-client/root/usr/share/foxhole/ram-update-service.uc');
function decoder(raw) {
  return new Function('raw','json','fail',`return function(path,maximum) ${functionBody(source,'decode')}`)(raw,JSON.parse,
    reason=>{throw Error('update_'+reason.toLowerCase());});
}
test('RAM status marker reads preserve NO_SPACE rather than blaming a signed package', () => {
  const decode=decoder(()=>{throw Error('update_no_space');});
  assert.throws(()=>decode('/tmp/foxhole-ram-active.json',4096),{message:'update_no_space'});
});
test('RAM status malformed JSON and ownership rejection still fail closed', () => {
  assert.throws(()=>decoder(()=>'{invalid')('x',4096),{message:'update_package_verification_failed'});
  assert.throws(()=>decoder(()=>{throw Error('update_package_verification_failed');})('x',4096),{message:'update_package_verification_failed'});
});
