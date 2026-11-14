import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { read, packageRoot, functionBody, plain } from './helpers.mjs';

const path = `${packageRoot}/root/usr/share/foxhole`;
const native = await read(`${path}/update-native.uc`), source = await read(`${path}/ram-update-model.uc`);
const builtins = {
 type: v => v == null ? 'null' : Array.isArray(v) ? 'array' : typeof v === 'boolean' ? 'bool' : Number.isInteger(v) ? 'int' : typeof v,
 length: v => v?.length ?? Object.keys(v).length, keys: Object.keys, index: (a,v) => a.indexOf(v),
 match: (v,r) => v.match(r), split: (v,s) => v.split(s), replace: (v,a,b) => v.replace(a,b),
 sprintf: (_f,v) => JSON.stringify(v), substr: (v,a,b) => v.substr(a,b)
};
function fixture(os = '25.12.6', board = 'mediatek/filogic', architecture = 'aarch64_cortex-a53') {
 let value = { schema:2, transactionAbi:1, stateAbi:1, supportedOpenWrt:['25.12.5','25.12.6'],
   packageVersion:'1.0.8-r1', releaseTag:'v1.0.8', targets:['x86/64','mediatek/filogic'] };
 const failures = { fail: why => { throw Error(why); } };
 const model = vm.createContext({ ...builtins, digest:{}, updates:failures });
 vm.runInContext(source.replace(/^import .*;\n/gm,'').replace(/^export /gm,'')
   .replace(/for\(let (\w+) in /g,'for(let $1 of '),model);
 const scope = vm.createContext({ ...builtins, guard:failures, ram_updates:model, decode:JSON.parse,
   registry:{ architecture:()=>architecture }, public_raw: name => name === '/etc/openwrt_release'
     ? `DISTRIB_RELEASE='${os}'\nDISTRIB_TARGET='${board}'\n` : JSON.stringify(value) });
 vm.runInContext(`function target() ${functionBody(native,'target')}\nfunction policy(path,version) ${functionBody(native,'policy')}`,scope);
 return { target:()=>scope.target(), policy:()=>scope.policy('/signed-policy','1.0.8-r1'), replace:p=>{value=p;} };
}
test('native admission retains the actual OS identity for both qualified targets',()=>{
 for(const os of ['25.12.5','25.12.6']) for(const [target,architecture] of [['mediatek/filogic','aarch64_cortex-a53'],['x86/64','x86_64']]) {
  const f=fixture(os,target,architecture);assert.deepEqual(plain(f.target()),{release:os,target,architecture});assert.equal(f.policy().schema,2);
 }
});
test('unsupported firmware, target and architecture are refused before candidate acceptance',()=>{
 for(const f of [fixture('25.12.7'),fixture('25.12.50'),fixture('25.12.6','armsr/armv8','aarch64_generic'),
  fixture('25.12.6','x86/64','aarch64_cortex-a53')])assert.throws(()=>f.policy(),/UNSUPPORTED_TARGET/);
});
test('new native reader preserves legacy singleton meaning and refuses missing or mixed claims',()=>{
 const legacy={schema:1,transactionAbi:1,stateAbi:1,osRelease:'25.12.5',targets:['x86/64','mediatek/filogic'],releaseTag:'v1.0.8',packageVersion:'1.0.8-r1'};
 const old=fixture('25.12.5');old.replace(legacy);assert.equal(old.policy().schema,1);
 const current=fixture();current.replace(legacy);assert.throws(()=>current.policy(),/UNSUPPORTED_TARGET/);
 for(const patch of [{schema:2},{osRelease:'25.12.6'},{extra:true},{packageVersion:'1.0.7-r4'}]) {
  old.replace({...legacy,...patch});assert.throws(()=>old.policy(),/UNSUPPORTED_TARGET/);
 }
});

test('RAM descriptor parser keeps an exact OS string and still requires all bank identities',async()=>{
 const link=await read(`${path}/ram-bootstrap-link.uc`), failures={fail:why=>{throw Error(why);}};
 const model=vm.createContext({...builtins,digest:{},updates:failures});
 vm.runInContext(source.replace(/^import .*;\n/gm,'').replace(/^export /gm,'').replace(/for\(let (\w+) in /g,'for(let $1 of '),model);
 const policy=vm.runInContext('({fail,version,sha,integer,compare,signer_sha256})',model);
 const scope=vm.createContext({...builtins,model:policy,push:(a,v)=>a.push(v)});
 for(const name of ['fail','same','exact','url','recovery_overlay','descriptor']) {
  let body=functionBody(link,name).replace(/for\(let (\w+) in /g,'for(let $1 of ')
    .replaceAll('[[:cntrl:]]','[\\u0000-\\u001f\\u007f]');
  const parameters={fail:'reason',same:'a,b',exact:'value,names',url:'value,prefix',recovery_overlay:'value,version,sha,bytes',descriptor:'value'}[name];
  vm.runInContext(`function ${name}(${parameters}) ${body}`,scope);
 }
 const value={schema:1,kind:'foxhole-ram-bootstrap-v1',artifact:{url:'https://example.test/bank.apk',bytes:123,sha256:'a'.repeat(64)},
  version:'1.0.8-r1',baseVersion:'1.0.8-r1',arch:'aarch64_cortex-a53',target:'mediatek/filogic',osRelease:'25.12.6',
  baseSha256:'b'.repeat(64),signerPemSha256:policy.signer_sha256,caFileSha256:null,recoveryOrigin:'https://example.test/recovery/'};
 assert.equal(scope.descriptor(value).osRelease,'25.12.6');
 assert.equal(scope.descriptor({...value,osRelease:'25.12.5'}).osRelease,'25.12.5');
 for(const patch of [{osRelease:'25.12.7'},{osRelease:['25.12.5','25.12.6']},{baseSha256:null},{signerPemSha256:null},
  {target:'x86/64'},{arch:'armv7'}])assert.throws(()=>scope.descriptor({...value,...patch}));
});
