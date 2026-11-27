'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as fresh from './fresh-install-accounting.uc';

function reject() { die('Stock firmware package or file state differs from the verified factory image\n'); };
function plain(path) {
 if (type(path) != 'string' || !length(path) || length(path) > 1024 || !match(path,/^[!-~]+$/)) reject();
 for (let part in split(path,'/')) if (!part || part == '.' || part == '..' || index(part,'\\') >= 0) reject();
 return path;
};
function identity(s) {
 return s && sprintf('%J',[s.type,s.mode,s.uid,s.gid,s.dev,s.inode,s.nlink,s.size,s.mtime,s.ctime]);
};
function content(path, limit, allow_empty) {
 let s=fs.lstat(path);
 if (s?.type != 'file' || s.uid != 0 || s.nlink != 1 || (s.mode & 0o022) ||
     s.size < (allow_empty ? 0 : 1) || s.size > limit) reject();
 let f=fs.open(path,'r'), held=f ? fs.stat('/proc/self/fd/'+f.fileno()) : null;
 if (!f || identity(s) != identity(held)) reject();
 let raw=f.read(s.size+1);
 if (s.size == 0 && raw == null) raw='';
 if (type(raw) != 'string' || length(raw) != s.size || identity(held) != identity(fs.lstat(path))) reject();
 f.close();
 return raw;
};
function owned_paths(raw, selected) {
 let result={}, all={};
 for (let record in split(trim(raw),'\n\n')) {
  let name=null, parent=null, paths={};
  for (let line in split(record,'\n')) {
   let tag=substr(line,0,2), value=substr(line,2);
   if (tag == 'P:') { if (name) reject(); name=value; }
   else if (tag == 'F:') parent=value ? plain(value) : '';
   else if (tag == 'R:') {
    if (parent == null || index(value,'/') >= 0) reject();
    let path=plain(parent ? parent+'/'+value : value);
    if (all[path]) reject();
    all[path]=true; paths[path]=true;
   }
  }
  if (!name) reject();
  if (selected[name]) result[name]={paths,record:digest.sha256(record)};
 }
 return result;
};
function matches(path, expected, state) {
 let s=fs.lstat('/'+path), policy=expected.policy || 'immutable';
 if (!s) { if (policy == 'first-boot-script') return; reject(); }
 let kind={R:'file',D:'directory',S:'link'}[expected.type];
 if (!kind || s.type != kind || s.uid != expected.uid || s.gid != expected.gid) reject();
 if (policy == 'configuration') {
  if (s.type != 'file' || ((s.mode & 0o7777) & ~expected.mode)) reject();
  state[path]=sprintf('%d:%d:%d:%s',s.uid,s.gid,s.mode,digest.sha256(content('/'+path,1048576,true)));
 } else {
  if (index(['first-boot-script','immutable'],policy)<0 || (s.mode & 0o7777) != expected.mode) reject();
  if (kind == 'file' && (s.size != expected.bytes || !match(expected.sha256||'',/^[a-f0-9]{64}$/) ||
      digest.sha256(content('/'+path,16777216,true)) != expected.sha256)) reject();
  if (kind == 'link' && fs.readlink('/'+path) != expected.target) reject();
 }
};
function record_config(path, state, budget, depth) {
 plain(path);
 if (depth > 8 || length(keys(state)) >= 512 || index(path,'etc/') != 0) reject();
 let s=fs.lstat('/'+path);
 if (!s) return;
 if (s.uid != 0 || (s.mode & 0o022)) reject();
 if (s.type == 'directory') {
  state[path]=sprintf('dir:%d:%d:%d',s.uid,s.gid,s.mode);
  let names=fs.lsdir('/'+path);
  if (type(names) != 'array' || length(names) > 256) reject();
  for (let name in names) record_config(path+'/'+name,state,budget,depth+1);
 } else {
  if (s.type != 'file' || s.size > 1048576 || budget.bytes+s.size>4194304) reject();
  if (!state[path]) budget.bytes+=s.size;
  state[path]=sprintf('%d:%d:%d:%s',s.uid,s.gid,s.mode,digest.sha256(content('/'+path,1048576,true)));
 }
};
let witness_raw=content(ARGV[0],1048576,false), expected=ARGV[1], release=ARGV[2], mode=ARGV[3];
if (!match(expected||'',/^[a-f0-9]{64}$/) || digest.sha256(witness_raw)!=expected) reject();
let w=json(witness_raw), boards={
 '25.12.5':['cudy,wr3000-v1','ram','be876cf5335ab757874cd19f806b01f2271d8c20a1a0e68f1680019346c4408a'],
 '25.12.6':['cudy,wr3000s-v1','flash','81a4c12e02d5e81ac9b14d8b7c82ad2a0dcce60af6176049946bad912e478011']
}, board=boards[release];
if (!board || w?.schema!=1 || w.kind!='stock-installed-files-v1' || w.release!=release || w.board!=board[0] ||
    w.storageMode!=mode || mode!=board[1] || w.imageSha256!=board[2] || w.target!='mediatek/filogic' ||
    w.architecture!='aarch64_cortex-a53' || w.protocol!='hysteria2' ||
    w.primaryFingerprint!='8A8BC12F46B836C0F9CDB36F1D53D1877742E911' ||
    w.signingFingerprint!='92C561DE55AE6552F3C736B82B0151090606D1D9' ||
    trim(content('/tmp/sysinfo/board_name',128,false))!=board[0] ||
    digest.sha256(content('/etc/openwrt_release',16384,false))!=w.openWrtReleaseSha256) reject();
if (type(w.packages)!='object' || !length(keys(w.packages)) || length(keys(w.packages))>256 ||
    type(w.directories)!='object' || length(keys(w.directories))>2048 ||
    type(w.closurePackages)!='array' || !length(w.closurePackages) || length(w.closurePackages)>512) reject();
let db=content('/lib/apk/db/installed',1048576,false), installed=fresh.snapshot(db), files=owned_paths(db,w.packages);
let expected_names={};
for (let n in w.closurePackages) {
 if (!match(n||'',/^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$/) || expected_names[n]) reject();
 expected_names[n]=true;
 if (installed.packages[n] && !w.packages[n]) reject();
}
let current={}, cfg={}, immutable={}, count=0, budget={bytes:0};
for (let path in sort(keys(w.directories))) matches(plain(path),w.directories[path],current);
for (let name in sort(keys(w.packages))) {
 if (!expected_names[name] && !(name=='dnsmasq' && expected_names['dnsmasq-full'])) reject();
 let want=w.packages[name], have=installed.packages[name], record=files[name], owned=record?.paths;
 if (have?.version!=want.version || have.architecture!=want.architecture || have.flags!='S' ||
     want.flags!='S' || have.nativeCid160!=want.cid || record?.record!=want.databaseRecordSha256 ||
     type(want.files)!='object' || type(owned)!='object' ||
     length(keys(want.files))!=length(keys(owned))) reject();
 for (let path in keys(want.files)) {
  if (!owned[path] || ++count>8192) reject();
  matches(plain(path),want.files[path],current);
  if (want.files[path].policy=='immutable' || (want.files[path].policy=='first-boot-script' && fs.lstat('/'+path)))
   immutable[path]=true;
 }
 for (let path in want.configurationFiles) cfg[plain(path)]=true;
 for (let path in want.configurationDirectories) cfg[plain(path)]=true;
}
for (let path in sort(keys(cfg))) record_config(path,current,budget,0);
let audit=content(ARGV[4],1048576,true);
for (let line in split(audit,'\n')) {
 if (!line) continue;
 let row=match(line,/^[A-Za-z+-] (.+)$/);
 if (!row || immutable[row[1]] || w.directories[row[1]]) reject();
}
let rows=[];for (let path in sort(keys(current))) push(rows,[path,current[path]]);
if (digest.sha256(content('/lib/apk/db/installed',1048576,false))!=installed.sha256) reject();
print(sprintf('%J\n',{schema:1,kind:'stock-package-observation-v1',boardName:w.board,storageMode:mode,
 witnessSha256:expected,installedDbSha256:installed.sha256,configSha256:digest.sha256(sprintf('%J',rows)),
 packages:length(keys(w.packages)),packageFiles:count}));
