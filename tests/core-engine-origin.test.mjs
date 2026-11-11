import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { read, packageRoot, functionBody, plain } from './helpers.mjs';

const source = await read(`${packageRoot}/root/usr/share/foxhole/engine-model.uc`);
const fixture = JSON.parse(await read('tests/fixtures/engine-catalog-v1.0.3.json')).entries[0];
function admit(value) {
 const context = vm.createContext({
  type: value => value === null ? 'null' : Array.isArray(value) ? 'array' :
   typeof value === 'number' && Number.isInteger(value) ? 'int' : typeof value,
  length: value => value.length, keys: Object.keys,
  index: (values, value) => values.indexOf(value), match: (text, expression) => text.match(expression),
  substr: (value, start, count) => count == null ? value.slice(start) : value.slice(start, start + count),
  lc: value => value.toLowerCase(), json: JSON.parse, sprintf: (_format, value) => JSON.stringify(value),
  die: reason => { throw new Error(reason); }
 });
 for (const name of ['IDS', 'ARCHES', 'BASE', 'CORE_BASE', 'ENTRY_FIELDS']) {
  const declaration = source.match(new RegExp(`const ${name} = ([\\s\\S]*?);`));
  if (declaration) vm.runInContext(declaration[0], context);
 }
 for (const [name, args] of [['reject', 'code'], ['copy', 'value'], ['number', 'value,maximum'],
  ['sha', 'value'], ['exact', 'value,fields,code'], ['entry', 'value']]) {
  const body = functionBody(source, name)
   .replaceAll('for (let key in keys(value))', 'for (let key of keys(value))')
   .replace(/for \(let key in (\[[\s\S]*?\])\)/g, 'for (let key of $1)');
  vm.runInContext(`function ${name}(${args}) ${body}`, context);
 }
 return plain(context.entry(value));
}
function core(value = fixture) {
 return { ...value,
  packageUrl: value.packageUrl.replace('/foxhole-openwrt-client/', '/foxhole-core/'),
  indexUrl: value.indexUrl.replace('/foxhole-openwrt-client/', '/foxhole-core/') };
}
test('existing OpenWrt catalog identities remain admitted unchanged', () => {
 assert.deepEqual(admit(fixture), fixture);
});
test('official immutable Core repository is admitted for independent engine delivery', () => {
 assert.deepEqual(admit(core()), core());
});
test('Core origin cannot be generalized to another owner repository or transport', () => {
 for (const change of [value => value.replace('/foxhole-team/', '/foreign/'),
  value => value.replace('/foxhole-core/', '/foxhole-core-foreign/'),
  value => value.replace('https:', 'http:')]) {
  const value = core(); value.packageUrl = change(value.packageUrl); value.indexUrl = change(value.indexUrl);
  assert.throws(() => admit(value), /engine_package_verification_failed/);
 }
});
test('mixed repository or delivery tag is rejected before native fetch', () => {
 assert.throws(() => admit({ ...core(), indexUrl: fixture.indexUrl }), /engine_package_verification_failed/);
 const value = core(); value.indexUrl = value.indexUrl.replace('/v1.0.3/', '/v1.0.4/');
 assert.throws(() => admit(value), /engine_package_verification_failed/);
});
