import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const selector=fileURLToPath(new URL('../native/ram-recovery-fetch/github-release-asset.uc',import.meta.url));
const repo='foxhole-team/foxhole-openwrt-client', api='https://api.github.com/repos/'+repo, web='https://github.com/'+repo;
const name='foxhole-openwrt-client-1.0.8-r2.apk', tag='v1.0.8', stable=web+'/releases/download/'+tag+'/'+name;
function metadata() {
 return {tag_name:tag,draft:false,prerelease:true,id:19,url:api+'/releases/19',html_url:web+'/releases/tag/'+tag,
  assets:[{id:748445468,name,state:'uploaded',size:2461969,digest:'sha256:'+'a'.repeat(64),
   url:api+'/releases/assets/748445468',browser_download_url:stable}]};
}
function check(input) {
 const result=spawnSync('ucode',[selector,tag,name,stable],{input:JSON.stringify(input),encoding:'utf8',timeout:10000,maxBuffer:8192});
 assert.equal(result.error,undefined);return result;
}
test('native release selector accepts one public exact tag asset and rejects inconsistent metadata',()=>{
 const ok=check(metadata());assert.equal(ok.status,0,ok.stderr);assert.equal(ok.stdout,'748445468');
 const changes=[
  v=>{v.tag_name='v1.0.9';},v=>{v.draft=true;},v=>{v.draft=0;},
  v=>{v.url=api+'/releases/20';},v=>{v.html_url=web+'/releases/tag/v1.0.9';},
  v=>{v.assets.push({...v.assets[0]});},v=>{v.assets[0].id='748445468';},
  v=>{v.assets[0].name='other.apk';},v=>{v.assets[0].url=api+'/releases/assets/2';},
  v=>{v.assets[0].browser_download_url=stable+'?mirror';},v=>{v.assets[0].state='open';},
  v=>{v.assets[0].size=0;},v=>{v.assets[0].digest='md5:legacy';},
  v=>{v.note='x'.repeat(262144);}
 ];
 for(const change of changes){const v=metadata();change(v);const result=check(v);assert.notEqual(result.status,0);assert.equal(result.stdout,'');}
});
