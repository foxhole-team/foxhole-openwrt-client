import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
const source=readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/history.uc',import.meta.url),'utf8');
const types=v=>v==null?'null':Array.isArray(v)?'array':Number.isInteger(v)?'int':typeof v==='boolean'?'bool':typeof v;
const bindings={fs:{},store:{},type:types,index:(v,x)=>v.indexOf(x),split:(v,s)=>v.split(s),length:v=>v==null?0:typeof v==='object'&&!Array.isArray(v)?Object.keys(v).length:v.length,
 substr:(s,a,n)=>s.substr(a,n),trim:s=>s.trim(),json:JSON.parse,sprintf:(_,v)=>JSON.stringify(v),
 match:(s,r)=>s.match(r),push:(a,v)=>a.push(v),slice:(a,n,m)=>a.slice(n,m),sort:(a,f)=>a.sort(f),int:Math.trunc,
 min:Math.min,max:Math.max,time:()=>1800000000,die:c=>{throw Error(c);}};
const code=source.replace(/^import .*;$/gm,'').replace(/^export /gm,'')
 .replace(/for \(let (\w+), (\w+) in (\w+)\)/g,'for (let [$1, $2] of Object.entries($3))')
 .replace(/for \(let (\w+) in /g,'for (let $1 of ');
const model=new Function(...Object.keys(bindings),code+';return {compact,scan_rows,scan_rows_fast,stream_index,select_entries};')(...Object.values(bindings));
function reader(raw,size=4096){let offset=0;return count=>{assert.ok(count<=4096);const n=Math.min(count,size);const part=raw.slice(offset,offset+n);offset+=part.length;return part;};}
function selected(raw,now,size){const entries=model.stream_index(reader(raw,size),now);return entries.map(e=>{const row=JSON.parse(raw.slice(e.offset,e.offset+e.bytes));if(row.measurementVersion!==2)row.cpu=null;return row;});}
const now=1800000000000;
test('chunked history selection preserves the exact existing retention contract',()=>{
 const rows=[];for(let i=0;i<9000;i++)rows.push({t:now-i*300000,measurementVersion:2,cpu:i%100,vpnRx:i});
 rows.push({t:now+999999},{t:now-2592000001},{t:now-15001,cpu:99},{t:now-15000,measurementVersion:2});
 const expected=model.compact(structuredClone(rows),now);assert.deepEqual(selected(JSON.stringify(rows),now,37),expected);
});
test('arbitrary chunk boundaries preserve escaped strings, nested JSON and legacy CPU handling',()=>{
 const rows=[{t:now-1200000,label:'quotes \" slash \\ brackets ],{',nested:{x:[1,2]}},{t:now,measurementVersion:2,label:'safe'}];
 for(const size of [1,2,7,4096])assert.deepEqual(selected(JSON.stringify(rows,null,2),now,size),model.compact(structuredClone(rows),now));
});
test('only lightweight descriptors survive indexing, never full row objects',()=>{
 const rows=Array.from({length:8000},(_,i)=>({t:now-i*300000,measurementVersion:2,padding:'x'.repeat(250)}));
 const entries=model.stream_index(reader(JSON.stringify(rows)),now);assert.ok(entries.length>7000);
 for(const e of entries){assert.deepEqual(Object.keys(e).sort(),['bytes','legacy','offset','order','t']);assert.ok(!JSON.stringify(e).includes('padding'));}
});
test('invalid or truncated input refuses to replace existing owner history',()=>{
 for(const raw of ['{}','[','[{"t":1}','[{}] trailing','[{},]','[,{}]','[{"x":"unterminated}]','[true false]'])
  assert.throws(()=>model.stream_index(reader(raw,2),now));
});
test('oversized streams, rows and excessive point counts stop at fixed bounds',()=>{
 assert.throws(()=>model.stream_index(reader('[{"padding":"'+'x'.repeat(65536)+'"}]'),now));
 assert.throws(()=>model.stream_index(reader('['+' '.repeat(6000000)+']'),now));
 assert.throws(()=>model.stream_index(reader('['+Array(18001).fill('{}').join(',')+']'),now));
});
test('duplicate coarse buckets keep last input and equal timestamps remain stable',()=>{
 const rows=[{t:now-999999,a:1},{t:now-999998,a:2},{t:now,a:3},{t:now,a:4}];
 assert.deepEqual(selected(JSON.stringify(rows),now),model.compact(structuredClone(rows),now));
});
test('adding a point retains the same 9000-point cap without parsing retained rows',()=>{
 const entries=Array.from({length:9001},(_,i)=>({t:now-i,order:i,offset:i,bytes:1,legacy:false}));
 const result=model.select_entries(entries,now);assert.equal(result.length,9000);assert.equal(result[0].t,now-8999);assert.equal(result.at(-1).t,now);
});

function indexedFast(raw,size=4096){const rows=[];model.scan_rows_fast(reader(raw,size),(point,offset,bytes,order)=>rows.push({point,offset,bytes,order}));return rows;}
test('fast line reader handles current writer output at every chunk boundary',()=>{
 const rows=[{t:now-1200000,measurementVersion:2,nested:{value:'escaped \" \\ ],{'}},{t:now,measurementVersion:2}];
 const raw='['+rows.map(v=>JSON.stringify(v)).join(',\n')+']';
 for(const size of [1,2,7,4096]){const actual=indexedFast(raw,size);assert.deepEqual(actual.map(v=>v.point),rows);for(const v of actual)assert.deepEqual(JSON.parse(raw.slice(v.offset,v.offset+v.bytes)),v.point);}
});
test('fast line reader accepts empty, whitespace and nested arrays without losing offsets',()=>{
 for(const raw of ['[]',' [\n ]\n','[\n {"t":'+now+',"nested":[1,2]},\n {"t":'+now+'}\n]']){
  const actual=indexedFast(raw,7);assert.deepEqual(actual.map(v=>v.point),JSON.parse(raw));for(const v of actual)assert.deepEqual(JSON.parse(raw.slice(v.offset,v.offset+v.bytes)),v.point);
 }
});
test('legacy single-line or pretty input restarts the exact bounded general scanner',()=>{
 const rows=[{t:now-1200000,measurementVersion:2,nested:{x:[1,2]}},{t:now,measurementVersion:2}];
 for(const raw of [JSON.stringify(rows),JSON.stringify(rows,null,2)]){
  let offset=0,resets=0;const read=n=>{const data=raw.slice(offset,offset+n);offset+=data.length;return data;};
  const entries=model.stream_index(read,now,()=>{offset=0;resets++;return true;});assert.equal(resets,1);
  assert.deepEqual(entries.map(e=>JSON.parse(raw.slice(e.offset,e.offset+e.bytes))),model.compact(structuredClone(rows),now));
 }
});
test('fast input rejects trailing commas, missing delimiters and trailing data',()=>{
 for(const raw of ['[{},\n]','[{},]','[{}\n{}]','[{}]\n{}','[{"t":1},\n','[{},\n,{}]'])assert.throws(()=>indexedFast(raw));
});
