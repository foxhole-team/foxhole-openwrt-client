import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const read=name=>readFileSync(new URL('../tools/'+name,import.meta.url),'utf8');
const source=read('ram-bootstrap-prerequisites-model.uc'),collector=read('ram-bootstrap-prerequisites.uc');
const adapt=s=>s.replace(/^import .*\n/gm,'').replace(/^export /gm,'').replace(/\bfor\s*\(\s*let\s+(\w+)\s+in\s+/g,'for(let $1 of ');
const builtins={die:r=>{throw Error(r);},type:v=>v==null?'null':Array.isArray(v)?'array':Number.isInteger(v)?'int':typeof v,
 length:v=>typeof v=='string'||Array.isArray(v)?v.length:Object.keys(v).length,match:(v,r)=>v.match(r),
 substr:(v,a,n)=>v.substr(a,n),split:(v,p)=>v.split(p),slice:(v,a,z)=>v.slice(a,z),join:(s,a)=>a.join(s),
 push:(a,v)=>a.push(v),pop:a=>a.pop(),filter:(a,f)=>a.filter(f),index:(a,v)=>a.indexOf(v),ord:(v,i)=>v.charCodeAt(i),sprintf:(_f,v)=>JSON.stringify(v)};
const names=[...source.matchAll(/^export function (\w+)/gm)].map(v=>v[1]);
const model=new Function(...Object.keys(builtins),adapt(source)+'\nreturn {'+names.join(',')+'};')(...Object.values(builtins));
const dir=()=>({type:'directory',uid:0,mode:0o755});
const file=()=>({type:'file',uid:0,mode:0o755,nlink:1,size:12});
const hash='a'.repeat(64);

test('absolute ROM aliases stay inside their candidate namespace',()=>{
 const nodes=new Map([['/bin',dir()],['/bin/sh',{type:'link',uid:0,mode:0o777,target:'/bin/busybox'}],['/bin/busybox',file()]]),calls=[];
 const value=model.resolve('/bin/sh',logical=>{calls.push('/rom'+logical);return nodes.get(logical);});
 assert.equal(value.path,'/bin/busybox');assert.deepEqual(value.links,[{path:'/bin/sh',target:'/bin/busybox'}]);
 assert.ok(calls.every(path=>path.startsWith('/rom/')));
 for(const path of ['../../outside','/../../outside'])assert.throws(()=>model.normalize(path,'/'));
});
test('namespace lookup never follows a candidate intermediate absolute symlink',()=>{
 const nodes=new Map([['/rom/usr',{type:'link',uid:0,mode:0o777}],['/outside/lib',dir()]]),calls=[];
 const fs={lstat:path=>{calls.push(path);return nodes.get(path);},readlink:()=>'/outside'};
 const body=collector.match(/^function candidate\([^]*?^};/m)[0];
 const candidate=new Function('fs','paths','fail','split','substr','length',body+';return candidate;')(fs,model,r=>{throw Error(r);},(v,p)=>v.split(p),(v,a)=>v.substr(a),v=>v.length);
 assert.equal(candidate('/rom','/usr/lib/file'),null);assert.deepEqual(calls,['/rom/usr']);
});
test('RAM-only dependencies, escaping/looping links and writable backing fail closed',()=>{
 assert.throws(()=>model.resolve('/lib/only-ram',()=>null));
 for(const row of [{...file(),mode:0o777},{...file(),uid:1},{...file(),nlink:2}])
  assert.throws(()=>model.resolve('/lib/file',p=>p=='/lib'?dir():row));
 assert.throws(()=>model.resolve('/loop',()=>({type:'link',uid:0,mode:0o777,target:'/loop'})));
});
test('persistent file equality requires canonical aliases, bytes and permissions',()=>{
 const value={path:'/bin/busybox',row:file(),links:[]};
 assert.equal(model.same_file(value,structuredClone(value),hash,hash),true);
 for(const other of [{...value,path:'/tmp/busybox'},{...value,row:{...file(),size:13}},{...value,row:{...file(),mode:0o700}},
  {...value,links:[{path:'/bin/x',target:'/tmp/y'}]}])assert.throws(()=>model.same_file(value,other,hash,hash));
 assert.throws(()=>model.same_file(value,value,hash,'b'.repeat(64)));
});
test('only the owned temporary helper input may traverse sticky /tmp',()=>{
 const lookup=p=>p=='/tmp'?{...dir(),mode:0o1777,ownedTemporaryInput:true}:file();
 assert.equal(model.resolve('/tmp/helper',lookup).path,'/tmp/helper');
 assert.throws(()=>model.resolve('/tmp/helper',p=>p=='/tmp'?{...dir(),mode:0o1777}:file()));
});
test('required commands use the approved PATH and skip non-executable candidates',()=>{
 const block=collector.match(/^function require_command\([^]*?^};/m)[0],checked=[];
 const fs={stat:path=>{
  if(path=='/usr/sbin/ubus')return {type:'file',mode:0o644};
  if(path=='/bin/ubus'||path=='/usr/bin/jshn'||path.startsWith('/bin/'))return {type:'file',mode:0o755};
  return null;
 }};
 const requireCommand=new Function('fs','require_file','fail',adapt(block)+';return require_command;')(fs,(path,inspect,required)=>checked.push({path,inspect,required}),r=>{throw Error(r);});
 requireCommand('ubus');requireCommand('jshn');
 assert.ok(checked.some(row=>row.path=='/bin/ubus'&&row.inspect&&row.required));
 assert.ok(checked.some(row=>row.path=='/usr/bin/jshn'&&row.inspect&&row.required));
 assert.ok(!checked.some(row=>row.path=='/usr/sbin/ubus'));
 assert.doesNotMatch(collector,/require_file\('\/usr\/bin\/(ubus|jshn)'/);
});
test('stat CLI is required only by the generic launcher that actually calls it',()=>{
 const universal=collector.match(/^for\(let command in \[([^]*)\]\)require_command\(command\);/m)[1];
 assert.ok(!universal.includes("'stat'"));
 assert.match(collector,/sha256=='c264e9a3[^]*?require_command\('stat'\)/);
 const legacy=readFileSync(new URL('../tests/fixtures/protocol-facts/legacy-hysteria-wrapper.sh',import.meta.url),'utf8');
 assert.doesNotMatch(legacy,/\bstat\s+-c/);
});
function elf(){
 const b=Buffer.alloc(512);b.write('\x7fELF');b[4]=2;b[5]=1;b.writeUInt16LE(3,16);b.writeUInt16LE(183,18);
 b.writeBigUInt64LE(64n,32);b.writeUInt16LE(56,54);b.writeUInt16LE(2,56);
 b.writeUInt32LE(1,64);b.writeBigUInt64LE(512n,64+32);
 b.writeUInt32LE(2,120);b.writeBigUInt64LE(256n,128);b.writeBigUInt64LE(96n,152);
 [[1,0],[1,14],[5,384],[10,64],[0,0]].forEach(([tag,value],i)=>{b.writeBigUInt64LE(BigInt(tag),256+i*16);b.writeBigUInt64LE(BigInt(value),264+i*16);});
 b.write('libuclient.so\0libc.so\0',384);return b;
}
const parse=b=>model.elf_dependencies((o,n)=>b.subarray(o,o+n).toString('latin1'),b.length,183);
test('ELF closure uses bounded dynamic metadata without executing a binary',()=>{
 assert.deepEqual(parse(elf()),['libuclient.so','libc.so']);
 for(const mutate of [b=>b[4]=1,b=>b.writeUInt16LE(62,18),b=>b.writeBigUInt64LE(9000n,32),b=>b.writeBigUInt64LE(29n,256),b=>b.write('../escape\0',384)]){
  const bytes=elf();mutate(bytes);assert.throws(()=>parse(bytes));
 }
});
test('Go admission admits only existing qualified launchers and never invents an autoload/provider change',()=>{
 assert.equal(model.legacy_launcher('73d93ba411aac9e91a6b0bc916d17d3c3bf8d0dbfa9f0a2d9cd74268669ca079'),true);
 assert.equal(model.legacy_launcher(hash),false);assert.match(collector,/runtime\('engine'\)/);
 assert.doesNotMatch(collector,/runtime\('binary'\)|fs\.writefile|fs\.mkdir|fs\.symlink|\bmodprobe\b|\binsmod\b|\breboot\b/);
 const loader=read('ram-bootstrap.uc'),call=loader.indexOf("source+'/ram-bootstrap-prerequisites.uc'");
 assert.ok(call>0&&call<loader.indexOf('owner_namespace(true);',call));
 assert.ok(!loader.match(/const TOOLS=.*prerequisites/));
 assert.doesNotThrow(()=>new Function(adapt(collector)));
});
