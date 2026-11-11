'use strict';

import * as fs from 'fs';
import * as store from './private-store.uc';
import * as model from './ram-update-model.uc';

const ROOT='/tmp/foxhole/ram-updates';
let command_generation=null;
function fail(reason) {model.fail(reason);};
function memory() {
 let found=match(fs.readfile('/proc/meminfo',65537)||'',/\n?MemAvailable:[ \t]+([0-9]+) kB/);
 if(!found)fail('NO_SPACE');return +found[1]*1024;
};
function admit(bytes) {if(!model.integer(bytes)||memory()<bytes+model.reserve_bytes)fail('NO_SPACE');};
function parents(path) {
 for(let part=path;;part=fs.dirname(part)) {
  let info=fs.lstat(part);
  if(info?.type!='directory'||info.uid!=0||(info.mode&0o022)&&!(part=='/tmp'&&(info.mode&0o7777)==0o1777))fail('PACKAGE_VERIFICATION_FAILED');
  if(part=='/')break;
 }
};
function facts(info) {return sprintf('%J',[info?.type,info?.uid,info?.gid,info?.mode,info?.dev,info?.inode,info?.nlink,info?.size,info?.mtime,info?.ctime]);};
function raw(path,maximum,empty) {
 parents(fs.dirname(path));let before=fs.lstat(path);
 if(before?.type!='file'||before.uid!=0||before.nlink!=1||(before.mode&0o022)||before.size<(empty?0:1)||before.size>maximum)
  fail('PACKAGE_VERIFICATION_FAILED');
 admit(2*before.size);let value=fs.readfile(path,maximum+1);
 if(value==null||length(value)!=before.size||facts(before)!=facts(fs.lstat(path)))fail('PACKAGE_VERIFICATION_FAILED');return value;
};
function random() {let raw=fs.readfile('/dev/urandom',16);if(length(raw||'')!=16)fail('ROUTER_UNAVAILABLE');return hexenc(raw);};
export function capture(operation,args,maximum,milliseconds) {
 admit(2*maximum);store.directory(ROOT);let nonce=random(),output=ROOT+'/io-'+nonce;
 model.capture_arguments(output,operation,args);
 let directory='/tmp/foxhole/engine-command-'+nonce+'.io';store.directory(directory);
 if(command_generation==null)command_generation={helper:raw('/usr/libexec/foxhole-ram-update-command',32768,false),
  utility:raw('/usr/share/foxhole/engine-capture.uc',32768,false)};
 store.write(directory+'/helper',command_generation.helper);
 store.write(directory+'/utility.uc',command_generation.utility);
 let code=system(['/bin/sh',directory+'/helper',output,''+maximum,''+milliseconds,operation,...args],milliseconds+5000);
 let clean=!fs.lstat(directory+'/owner.json')&&!fs.lstat(directory+'/stdout')&&!fs.lstat(directory+'/stderr');
 let stdout=null,stderr=null;
 if(fs.lstat(output)&&fs.lstat(output+'.err')) {
  stdout=raw(output,maximum,true);stderr=raw(output+'.err',operation=='probe'?16384:1048576,true);
 }
 if(clean) {
  for(let path in [directory+'/helper',directory+'/utility.uc'])if(!fs.unlink(path))clean=false;
  if(!fs.rmdir(directory))clean=false;
 }
 for(let path in [output,output+'.err'])if(fs.lstat(path)&&!fs.unlink(path))clean=false;
 if(!clean||stdout==null||stderr==null)fail('PACKAGE_VERIFICATION_FAILED');return {code,stdout,stderr};
};
