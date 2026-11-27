import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

test('release downloads bind the official repository, tag, filename and one authenticated CDN handoff', () => {
 const dir=mkdtempSync(join(tmpdir(),'foxhole-release-fetch-'));
 const header=resolve(new URL('../native/ram-recovery-fetch/https-policy.h',import.meta.url).pathname);
 const release='https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.8/';
 const name='foxhole-openwrt-client-1.0.8-r2.apk', origin=release+name;
 const destination='https://release-assets.githubusercontent.com/github-production-release-asset/1361759440/'
   +'fb9633fe-3965-49d0-a34a-65de4a4c42bc?sig=test&rscd=attachment%3B%20filename%3D'+name;
 try {
  writeFileSync(join(dir,'main.c'), '#include "'+header+'"\nint main(int n,char **v){if(n==5 && (!strcmp(v[1],"hop")||!strcmp(v[1],"next-hop"))) return !foxhole_recovery_hop(!strcmp(v[2],"github"),v[3],v[4],!strcmp(v[1],"next-hop"));return !foxhole_recovery_arguments(n,v); }\n');
  assert.equal(spawnSync('cc',['-std=c99','-Wall','-Werror',join(dir,'main.c'),'-o',join(dir,'check')]).status,0);
  const allowed=(...args)=>spawnSync(join(dir,'check'),args).status===0;
  assert.ok(allowed('--github-release',origin));
  assert.equal(allowed('--github-release','--ca-certificate','/another.pem',origin),false);
  assert.ok(allowed('--github-release',release.replace('v1.0.8','v1.0.9')+'foxhole-ram-bootstrap-bank-1.0.9-r1-aarch64_cortex-a53.apk'));
  assert.ok(allowed('hop','github',origin,destination));
  assert.equal(allowed('next-hop','github',origin,destination),false);
  assert.ok(allowed('https://direct.example/a'));
  assert.ok(allowed('hop','direct','https://direct.example/a','https://direct.example/b'));
  for(const endpoint of [origin, destination, 'https://github.com:443/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.8/'+name])
   assert.equal(allowed(endpoint),false);
  for(const endpoint of [origin.replace('/foxhole-team/','/another/'),origin.replace('/v1.0.8/','/v1.0.9/'),origin+'?token=x',
   origin.replace(name,'other.apk'),destination])
   assert.equal(allowed('--github-release',endpoint),false);
  for(const bad of [destination.replace('https:','http:'),destination.replace('release-assets.','different.'),
   destination.replace('/1361759440/','/1/'),destination.replace(name,'another.apk'),destination+'&rscd=bad',
   destination+'&r%73cd=bad',destination+'&sig=second',destination+'&bad=%xy',destination+'&x=a;b',
   destination.replace('githubusercontent.com/','githubusercontent.com:444/'),destination.replace('fb9633fe','../fb9633fe')])
   assert.equal(allowed('hop','github',origin,bad),false);
  assert.equal(allowed('hop','direct','https://direct.example/a',destination),false);
  assert.equal(allowed('hop','direct','https://direct.example/a','https://direct.example:444/b'),false);
 } finally { rmSync(dir,{recursive:true,force:true}); }
});

test('actual native recovery URL policy permits HTTPS assets and rejects schemes before network dispatch',()=>{
 const header=resolve(new URL('../native/ram-recovery-fetch/https-policy.h',import.meta.url).pathname);
 const cases=[
  ['https://github.com/foxhole-team/repo/releases/download/v1.0.4/bank.apk',0],
  ['https://release-assets.githubusercontent.com/a/b?sp=r&sig=a%2Fb%3D',0],
  ['https://release-assets.githubusercontent.com/a/b?response-content-disposition=attachment%3B%20filename%3Dbank.apk',0],
  ['https://127.0.0.1:4443/bank.apk',1],
  ['http://example.invalid/bank.apk',0],['HTTPS://example.invalid/bank.apk',0],
  ['//example.invalid/bank.apk',0],['/bank.apk',0],['file:///tmp/bank.apk',0],
  ['https://user:password@example.invalid/bank.apk',0],['https://example.invalid@evil.invalid/a',0],
  ['https://example.invalid:0/a',0],['https://example.invalid:65536/a',0],
  ['https://example.invalid/a#fragment',0],['https://example.invalid/a\r\nHost:evil.invalid',0],
  ['https://example.invalid/a b',0],['https://example.invalid/a?x=%00',0],['https://example.invalid/a?x=%09',0],
  ['https://example.invalid/a?x=%0A',0],['https://example.invalid/a?x=%0D',0],['https://example.invalid/a?x=%7F',0],
  ['https://example.invalid\\@evil.invalid/a',0],['https:///a',0],
 ];
 const dir=mkdtempSync(join(tmpdir(),'foxhole-ram-fetch-policy-'));
 try{
  const input=`#include <stdio.h>\n#include ${JSON.stringify(header)}\nint main(int argc,char **argv){return foxhole_recovery_arguments(argc,argv)?0:1;}\n`;
  writeFileSync(join(dir,'policy.c'),input);
  const compile=spawnSync('/usr/bin/cc',['-std=c99','-Wall','-Wextra','-Werror',join(dir,'policy.c'),'-o',join(dir,'policy')],{encoding:'utf8'});
  assert.equal(compile.status,0,compile.stderr);
  for(const [url,accepted] of cases)assert.equal(spawnSync(join(dir,'policy'),[url]).status,accepted?0:1,url);
  assert.equal(spawnSync(join(dir,'policy'),['--ca-certificate','/protected/public-ca.pem','https://example.invalid/a']).status,0);
  for(const args of [['--no-check-certificate','https://example.invalid/a'],['--proxy=on','https://example.invalid/a'],
   ['--header','Authorization: secret','https://example.invalid/a'],['https://example.invalid/a','https://example.invalid/b'],
   ['--ca-certificate','relative-ca.pem','https://example.invalid/a']])assert.equal(spawnSync(join(dir,'policy'),args).status,1);
  const source=readFileSync(new URL('../native/ram-recovery-fetch/uclient-fetch.c',import.meta.url),'utf8');
  const guard=source.indexOf('if (!foxhole_redirect_allowed(cl))');
  assert.ok(guard>0&&guard<source.indexOf('int ret = uclient_http_redirect(cl);'));
  assert.ok(source.indexOf('if (!foxhole_recovery_arguments(argc, argv))')<source.indexOf('ssl_ctx = uclient_new_ssl_context(&ssl_ops);'));
  assert.doesNotMatch(source,/verify = false/);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
