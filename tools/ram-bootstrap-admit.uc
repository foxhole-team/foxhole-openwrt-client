'use strict';
import * as fs from 'fs';
import * as model from './ram-bootstrap-model.uc';
function fail() {exit(1);};
function parents(path) {
 for(let p=path;;p=fs.dirname(p)) {
  let s=fs.lstat(p);if(s?.type!='directory'||s.uid!=0||(s.mode&0o022)&&!(p=='/tmp'&&(s.mode&0o7777)==0o1777))fail();
  if(p=='/')break;
 }
};
function regular(path,maximum,empty) {
 parents(fs.dirname(path));let s=fs.lstat(path);
 if(s?.type!='file'||s.uid!=0||s.nlink!=1||(s.mode&0o022)||s.size<(empty?0:1)||s.size>maximum)fail();return s;
};
function read(path,maximum) {let s=regular(path,maximum,false),text=fs.readfile(path,maximum+1);if(text==null||length(text)!=s.size)fail();return text;};
let output=ARGV[0],limit=ARGV[1],timeout=ARGV[2],operation=ARGV[3],args=slice(ARGV,4);
if(!match(output||'',/^\/tmp\/foxhole-ram-stage-boot-v1\/io-[a-f0-9]{32}$/)||
 !match(limit||'',/^[0-9]{1,8}$/)||!match(timeout||'',/^[0-9]{1,6}$/)||+limit<1||+timeout<1000||+timeout>180000)fail();
parents(model.stage);if((fs.lstat(model.stage).mode&0o7777)!=0o700)fail();
let descriptor=model.descriptor(json(read('/etc/foxhole/ram-update/boot.json',8192)));
if(operation=='fetch') {
 let artifact=args[0]==descriptor.artifact.url?descriptor.artifact:descriptor.overlay?.artifact;
 if(length(args)!=2||artifact==null||args[0]!=artifact.url||args[1]!=(descriptor.caFileSha256==null?'system':'pinned')||+limit!=artifact.bytes)fail();
 if(args[1]=='pinned')regular(model.trust+'/ca.pem',32768,false);
}else {
 if(+limit>model.maximum_metadata)fail();
 if(operation=='hash') {
  if(length(args))fail();let lines=split(trim(read(model.stage+'/hash-batch.list',32768)),'\n');
  if(length(lines)<1||length(lines)>64)fail();
  for(let path in lines) {
   if(path!='/lib/apk/db/installed'&&path!='/etc/apk/world'&&
    (index(path,model.stage+'/')!=0||!model.relative(substr(path,length(model.stage)+1))))fail();
   regular(path,33554432,true);
  }
 }else if(operation=='query') {
  if(length(args)!=1||args[0]!=descriptor.arch)fail();parents(model.stage+'/root');
 }else if(index(['verify-overlay','dump-overlay','simulate-overlay','install-overlay'],operation)>=0) {
  if(descriptor.overlay==null)fail();regular(model.stage+'/overlay.apk',8388608,false);
  parents(model.trust+'/keys');regular(model.trust+'/keys/signer.pem',32768,false);
  if(operation=='simulate-overlay'||operation=='install-overlay') {
   if(length(args)!=1||args[0]!=descriptor.arch)fail();parents(model.stage+'/root/.foxhole-apk-cache');
   if((fs.lstat(model.stage+'/root/.foxhole-apk-cache').mode&0o7777)!=0o700)fail();
  }else if(length(args))fail();
 }else if(index(['verify','dump','extract'],operation)>=0) {
  if(length(args))fail();regular(model.stage+'/bank.apk',model.maximum_archive,false);
  if(operation!='dump') {parents(model.trust+'/keys');regular(model.trust+'/keys/signer.pem',32768,false);}
  if(operation=='extract')parents(model.stage+'/payload');
 }else fail();
}
