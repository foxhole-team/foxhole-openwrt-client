import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

test('actual native recovery URL policy permits HTTPS assets and rejects schemes before network dispatch',()=>{
 const header=resolve(new URL('../native/ram-recovery-fetch/https-policy.h',import.meta.url).pathname);
 const cases=[
  ['https://github.com/foxhole-team/repo/releases/download/v1.0.4/bank.apk',1],
  ['https://release-assets.githubusercontent.com/a/b?sp=r&sig=a%2Fb%3D',1],
  ['https://release-assets.githubusercontent.com/a/b?response-content-disposition=attachment%3B%20filename%3Dbank.apk',1],
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
