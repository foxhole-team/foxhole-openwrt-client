import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {functionBody} from './helpers.mjs';
const root=new URL('../package/foxhole-openwrt-client/root/usr/share/foxhole/',import.meta.url);
const source=name=>readFileSync(new URL(name,root),'utf8');
const adapt=s=>s.replace(/for\(let (\w+) in /g,'for(let $1 of ');
for(const [file,name] of [['engine-service.uc','guard_mutation'],['backup-service.uc','package_jobs_idle'],['core-update-upload.uc','idle'],['ram-update-service.uc','require_idle'],['update-service.uc','engine_busy']]){
 test(`${file} excludes queued/live/recovery SERVER jobs before another native transaction`,()=>{
  let current=null;const reads=[];
  const read=(path,limit)=>{reads.push([path,limit]);return path==='/etc/foxhole/vpn-server-job.json'?current:null;};
  const builtin={read,private_json:read,JOB:'other',job_record:()=>null,
   fail:s=>{throw Error(s);},backup:{guard(){}},backup_service:{guard(){}},core_upload:{busy:()=>false},
   index:(a,x)=>a.indexOf(x),active:v=>v!=null&&!['SUCCEEDED','FAILED','RECOVERY_REQUIRED'].includes(v.state),
   blocked:v=>v!=null&&!['SUCCEEDED','FAILED'].includes(v.state),boot:()=> 'boot',now:()=>1000,principal_current:()=>true};
  const fn=new Function(...Object.keys(builtin),`return function() ${adapt(functionBody(source(file),name))}`)(...Object.values(builtin));
  for(const state of ['QUEUED','DOWNLOADING','INSTALLING','ACTIVATING','RECOVERY_REQUIRED']){
   current={state};if(name==='engine_busy')assert.equal(fn(),true);else assert.throws(fn,/BUSY|backup_busy/);
  }
  for(const state of ['SUCCEEDED','FAILED']){current={state};if(name==='engine_busy')assert.equal(fn(),false);else assert.doesNotThrow(fn);}
  current=null;if(name==='engine_busy')assert.equal(fn(),false);else assert.doesNotThrow(fn);
  assert.ok(reads.some(([path,maximum])=>path==='/etc/foxhole/vpn-server-job.json'&&maximum===2097152));
 });
}
