import * as fs from 'fs';
import * as engines from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/engine-model.uc';

let fixture = json(fs.readfile('/workspace/tests/fixtures/engine-catalog-v1.0.3.json', 262144));
let passed = 0, failed = 0;
const H = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const G = 'gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg';
function equal(a, b) { if (sprintf('%J', a) != sprintf('%J', b)) die('assertion_failed'); };
function test(name, fn) {
 try { fn(); passed++; print('ok ', name, '\n'); }
 catch (error) { failed++; print('not ok ', name, ': ', type(error) == 'string' ? error : error.message, '\n'); }
};
function copy(value) { return json(sprintf('%J', value)); };
function rejects(value) {
 let error = null;
 try { engines.catalog(value); } catch (caught) { error = type(caught) == 'string' ? caught : caught.message; }
 equal(error, 'engine_package_verification_failed');
};
test('published router 1.0.3 catalog accepts all 12 unchanged Core 1.0.2 entries', () => {
 let checked = engines.catalog(fixture);
 equal(length(checked.entries), 12); equal(checked, fixture);
 for (let entry in checked.entries) equal(entry.version, '1.0.2');
});
test('legacy delivery whose tag equals Core version remains valid', () => {
 let value = copy(fixture);
 for (let entry in value.entries) {
  entry.packageUrl = replace(entry.packageUrl, '/v1.0.3/', '/v1.0.2/');
  entry.indexUrl = replace(entry.indexUrl, '/v1.0.3/', '/v1.0.2/');
 }
 equal(engines.catalog(value), value);
});
for (let field in ['packageUrl', 'indexUrl']) {
 test('forged repository in ' + field + ' is refused', () => {
  let value = copy(fixture);
  value.entries[0][field] = replace(value.entries[0][field], '/foxhole-team/foxhole-openwrt-client/', '/foxhole-team/foreign/');
  rejects(value);
 });
 test('plain HTTP in ' + field + ' is refused', () => {
  let value = copy(fixture); value.entries[0][field] = replace(value.entries[0][field], 'https:', 'http:'); rejects(value);
 });
}
test('package and index from different immutable tags are refused', () => {
 let value = copy(fixture); value.entries[0].indexUrl = replace(value.entries[0].indexUrl, '/v1.0.3/', '/v1.0.2/'); rejects(value);
});
for (let tag in ['latest', 'dev', 'v1.0.3/../v1.0.3', 'v1.0.3%2fother', 'v1.0.3?x=1', 'v1.0.3#x']) {
 test('noncanonical tag ' + tag + ' is refused', () => {
  let value = copy(fixture);
  value.entries[0].packageUrl = replace(value.entries[0].packageUrl, '/v1.0.3/', '/' + tag + '/');
  value.entries[0].indexUrl = replace(value.entries[0].indexUrl, '/v1.0.3/', '/' + tag + '/'); rejects(value);
 });
}
test('foreign filename cannot inherit an immutable manifest identity', () => {
 let value = copy(fixture); value.entries[0].packageUrl += '.foreign'; rejects(value);
});
test('changed manifest hash cannot borrow the old package filename', () => {
 let value = copy(fixture); value.entries[0].manifestSha256 = H; rejects(value);
});
for (let field in ['binarySha256', 'executableSha256', 'packageSha256', 'indexSha256']) {
 test('malformed ' + field + ' remains refused', () => {
  let value = copy(fixture); value.entries[0][field] = G; rejects(value);
 });
}
test('unsupported ABI is refused', () => {
 let value = copy(fixture); value.entries[0].architecture = 'armv7'; rejects(value);
});
test('duplicate exact engine coordinates are refused', () => {
 let value = copy(fixture); push(value.entries, copy(value.entries[0])); rejects(value);
});
print('1..', passed + failed, '\n# Engine release origin: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
