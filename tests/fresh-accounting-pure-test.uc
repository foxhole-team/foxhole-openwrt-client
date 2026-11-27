'use strict';
import * as fs from 'fs';
import * as digest from 'digest';
import * as fresh from '../tools/fresh-install-accounting.uc';

let passed=0;
function assert(value) { if (!value) die('Pure accounting regression failed\n'); passed++; };
function refuses(callback) { let refused=false;try { callback(); } catch (e) { refused=true; } assert(refused); };
let fixtures=json(fs.readfile(ARGV[0],65537));
let raw=fixtures.raw, packages=fixtures.packages, auth=fixtures.authentications, asset=fixtures.asset,p=fixtures.profile;
let state=fresh.snapshot(raw), a=fresh.accounting(state,packages,auth,'flash',asset,p.guardStagingBytes);
assert(state.sha256==digest.sha256(raw));assert(a.fullInstalledBytes==123);assert(a.retainedInstalledBytes==123);assert(a.additionalInstalledBytes==0);
for(let bad in [raw+raw,replace(raw,'P:libc','P:libc\nP:duplicate'),replace(raw,'Q1','Q2'),replace(raw,'f:S','f:Z'),
 replace(raw,'f:S','?:unknown'),substr(raw,0,length(raw)-1),raw+'\x00',replace(raw,'P:libc','P:../libc')])refuses(()=>fresh.snapshot(bad));
for(let flags in ['','Sf','Ss','Sx'])refuses(()=>fresh.accounting(fresh.snapshot(replace(raw,'f:S','f:'+flags)),packages,auth,'flash',asset,p.guardStagingBytes));
for(let changed in [replace(raw,'V:1-r1','V:2-r1'),replace(raw,'A:aarch64_cortex-a53','A:x86_64'),fixtures.otherCid]) {
 assert(fresh.accounting(fresh.snapshot(changed),packages,auth,'flash',asset,p.guardStagingBytes).additionalInstalledBytes==123);
}
refuses(()=>fresh.accounting(fresh.snapshot(replace(raw,'P:libc','P:unrelated')),packages,auth,'flash',asset,p.guardStagingBytes));
refuses(()=>fresh.accounting(state,packages,auth,'ram',asset,p.guardStagingBytes));
let value=fresh.apply(fixtures.budget,state,asset,p);
assert(value.schema==3 && value.mode=='flash');assert(value.installedFlashBytes==123);assert(value.compressedBytes==10);
assert(value.runtimeMemoryBytes==134217728);assert(value.flashReserveBytes==33554432 && value.ramReserveBytes==33554432);
assert(value.requiredFlashBytes==33554432);assert(value.stagingBytes==65+p.guardStagingBytes);
for(let field in ['requiredFlashBytes','stagingBytes','requiredRamBytes']) {
 let changed=json(sprintf('%J',value));changed[field]--;refuses(()=>fresh.validate_budget(changed));
}
let bad=json(sprintf('%J',value));bad.installAccounting.retainedPackages[0].packageIdentity=fixtures.otherIdentity;refuses(()=>fresh.validate_budget(bad));
let duplicate=json(sprintf('%J',value));push(duplicate.installAccounting.retainedPackages,duplicate.installAccounting.retainedPackages[0]);refuses(()=>fresh.validate_budget(duplicate));
let wrong=json(sprintf('%J',p));wrong.requiredMode='auto';refuses(()=>fresh.profile(wrong));
printf('PASS %d pure accounting checks; no native APK or filesystem mutation executed\n',passed);
