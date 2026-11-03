import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
const source=readFileSync(new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/log-model.uc',import.meta.url),'utf8');
const bindings={type:v=>v==null?'null':Array.isArray(v)?'array':Number.isInteger(v)?'int':typeof v==='boolean'?'bool':typeof v,
 length:v=>typeof v==='string'?Buffer.byteLength(v):v.length,split:(v,s)=>v.split(s),match:(v,r)=>v.match(r),
 index:(v,x)=>v.indexOf(x),push:(v,x)=>v.push(x),shift:v=>v.shift(),substr:(v,a,n)=>v.substr(a,n),int:v=>Math.trunc(Number(v)),min:Math.min,max:Math.max,
 die:()=>{throw Error('invalid_log_data');}};
const code=source.replace(/^export /gm,'').replace(/for \(let (\w+) in /g,'for (let $1 of ');
const model=new Function(...Object.keys(bindings),code+';return {package_events,kernel_events,core_status,runtime_status};')(...Object.values(bindings));
test('package logs retain only fixed lifecycle metadata, never raw secrets',()=>{
 const raw='Mon Nov  2 11:20:30 2026 daemon.warn foxhole: tunnel_exited engine=core stage=running exit_status=137\n'+
  'Mon Nov  2 11:20:31 2026 daemon.warn foxhole: secret token=private-password server=https://private.test\n';
 const rows=model.package_events(raw);assert.equal(rows.length,1);assert.equal(rows[0].exitStatus,137);assert.equal(rows[0].engine,'core');
 assert.ok(!JSON.stringify(rows).includes('private-password'));assert.ok(!JSON.stringify(rows).includes('private.test'));
});
test('package output is bounded and malformed or appended credentials are excluded',()=>{
 const good='Mon Nov  2 11:20:30 2026 daemon.warn foxhole: tunnel_exited engine=hysteria stage=running exit_status=2';
 assert.equal(model.package_events(Array(100).fill(good).join('\n')).length,32);
 assert.equal(model.package_events(good+' token=secret').length,0);assert.throws(()=>model.package_events('x'.repeat(65537)));
});
test('Linux OOM events have monotonic time and whitelisted process names only',()=>{
 const rows=model.kernel_events('[ 67100.123456] Out of memory: Killed process 100 (hysteria) total-vm:123 private details\n'+
  '[ 67101.123456] oom-kill:constraint=NONE,task=private-secret,pid=101,uid=0\n');
 assert.equal(rows[0].event,'oom_killed');assert.equal(rows[0].uptimeSeconds,67100.123456);assert.equal(rows[0].process,'hysteria');
 assert.equal(rows[1].process,'other');assert.ok(!JSON.stringify(rows).includes('private-secret'));
 const history=model.kernel_events('[ 80841.123] foxhole-history invoked oom-killer: redacted\n[ 80861.123] Out of memory: Killed process 2830 (foxhole-history) details');
 assert.deepEqual(history.map(v=>v.process),['foxhole-history','foxhole-history']);
});
test('Core state exposes recorded counters and protocol without private identity/config',()=>{
 const value=model.core_status({schema_version:1,phase:'running',protocol:'vless',bytes_up:20,bytes_down:30,pid:42,config:'secret'});
 assert.deepEqual(value,{available:true,phase:'running',protocol:'vless',bytesUp:20,bytesDown:30});assert.equal(model.core_status(null).available,false);
});
test('runtime error messages are a fixed enum rather than arbitrary exception text',()=>{
 assert.equal(model.runtime_status({phase:'error',error:'tunnel_exited'}).error,'tunnel_exited');
 assert.equal(model.runtime_status({phase:'error',error:'https://user:password@private.test'}).error,null);
});
