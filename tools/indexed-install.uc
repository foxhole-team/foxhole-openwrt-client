'use strict';

import * as fs from 'fs';
import { authentication, read } from './install-plan-model.uc';

function reject() { die('Indexed package authentication failed\n'); };
function metadata(path) {
 let info = fs.lstat(path);
 if (info?.type != 'file' || info.size > 67108864) reject();
 let raw = fs.readfile(path, 67108865);
 if (raw == null || length(raw) != info.size) reject();
 return json(raw);
};

function text(path) {
 let info=fs.lstat(path);
 if (info?.type!='file' || info.size>65536) reject();
 let raw=fs.readfile(path,65537);
 if (raw==null || length(raw)!=info.size) reject();
 return raw;
};
function world(path) {
 let raw=text(path), rows=length(trim(raw)) ? split(trim(raw),'\n') : [], seen={};
 for (let row in rows) {
  if (!match(row,/^[A-Za-z0-9_.+-]+[^ \t\r\n]*$/) || seen[row]) reject();
  seen[row]=true;
 }
 return {raw,rows};
};
function temporary(value, constraint) {
 let pattern=constraint ? /^\.foxhole-exact-[a-f0-9]{16}=[0-9]{8}\.[0-9]{6}$/ : /^\.foxhole-exact-[a-f0-9]{16}$/;
 if (type(value)!='string' || !match(value,pattern)) reject();
 return value;
};

let action = ARGV[0], value = authentication(read(ARGV[1]));
if (action == 'plan') {
 for (let item in value.repositoryIndexes) {
  for (let key in item.trustKeyFiles)
   printf('key %s %s %s %s\n', item.file, item.role, key, value.filesSha256[key]);
  printf('index %s %s\n', item.file, item.role);
 }
 for (let item in value.packageAuthentications)
  printf('package %s %s %s %s\n', item.file, item.indexFile, item.name, item.version);
 let names = {};
 for (let item in value.packages) {
  if (names[item.name]) reject();
  names[item.name] = item.version;
 }
 if (type(value.rootPackages) != 'array' || !length(value.rootPackages)) reject();
 let seen = {};
 for (let item in value.rootPackages) {
  if (!names[item] || seen[item]) reject();
  seen[item] = true;
  let identity = null;
  for (let binding in value.packageAuthentications) {
   if (binding.name != item) continue;
   if (identity != null || binding.version != names[item] ||
       type(binding.packageIdentity) != 'string' || !match(binding.packageIdentity, /^[a-f0-9]{64}$/)) reject();
   identity = binding.packageIdentity;
  }
  if (identity == null) reject();
  printf('root %s><X1%s\n', item, substr(identity, 0, 40));
  printf('durable %s\n', item);
 }
 for (let binding in value.packageAuthentications)
  printf('exact %s><X1%s\n',binding.name,substr(binding.packageIdentity,0,40));
} else if (action == 'index') {
 let indexFile = ARGV[2], dump = metadata(ARGV[3]), found = false;
 for (let item in value.repositoryIndexes) if (item.file == indexFile) found = true;
 if (!found || type(dump.packages) != 'array' || !length(dump.packages) ||
     length(dump.packages) > 50000 ||
     (dump['pkgname-spec'] != null && dump['pkgname-spec'] != '${name}-${version}.apk')) reject();
 for (let binding in value.packageAuthentications) {
  if (binding.indexFile != indexFile) continue;
  let match = null;
  for (let item in dump.packages) {
   if (item.name != binding.name || item.version != binding.version || item.arch != binding.architecture) continue;
   if (match != null) reject();
   match = item;
  }
  let record = null;
  for (let item in value.packages) if (item.file == binding.file) record = item;
  if (match == null || !record || match.hashes != binding.packageIdentity ||
      match['file-size'] != record.archiveBytes || match['installed-size'] != record.installedBytes) reject();
 }
} else if (action == 'query' || action == 'query-installed') {
 let selected = metadata(ARGV[2]), expected = {};
 if (type(selected) != 'array' || length(selected) != length(value.packages)) reject();
 for (let item in value.packages) {
  if (expected[item.name]) reject();
  expected[item.name] = item;
 }
 for (let item in selected) {
  let record = expected[item.name];
  if (!record || item.version != record.version || item.arch != record.arch ||
      (action=='query-installed' && sprintf('%J',item.status)!=sprintf('%J',['installed']))) reject();
  delete expected[item.name];
 }
 if (length(keys(expected))) reject();
} else if (action=='kernel-query') {
 let packages={}, required={}, pending=['kernel'];
 for (let p in value.packages) {
  if (packages[p.name]) reject();
  packages[p.name]=p;
 }
 for (let i=0; i<length(pending); i++) {
  if (i>=length(value.packages)) reject();
  let name=pending[i], p=packages[name];
  if (!p || type(p.depends)!='array' || length(p.depends)>256) reject();
  required[name]=p;
  for (let dependency in p.depends) {
   if (type(dependency)!='string' || !match(dependency,/^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$/) || !packages[dependency]) reject();
   if (index(pending,dependency)<0) push(pending,dependency);
  }
 }
 if (text(ARGV[3])!='') reject();
 let selected=metadata(ARGV[2]), seen={}, count=0;
 if (type(selected)!='array' || !length(selected) || length(selected)!=length(keys(required))) reject();
 for (let p in selected) {
  let expected=required[p.name];
  if (!expected || seen[p.name] || p.version!=expected.version || p.arch!=expected.arch || sprintf('%J',p.status)!=sprintf('%J',['installed'])) reject();
  seen[p.name]=true;
  if (p.name=='kernel') count++;
 }
 if (count!=1 || length(keys(seen))!=length(keys(required))) reject();
} else if (action=='world-before') {
 let before=world(ARGV[2]), pending=temporary(ARGV[3],false), names={};
 for (let row in before.rows) {
  let name=match(row,/^([A-Za-z0-9_.+-]+)/)[1];
  if (names[name] || name==pending || (index(value.rootPackages,name)>=0 && row!=name)) reject();
  names[name]=true;
 }
 print(before.raw);
} else if (action=='world-after') {
 let before=world(ARGV[2]), after=world(ARGV[3]), expected={};
 for (let row in before.rows) expected[row]=true;
 for (let name in value.rootPackages) expected[name]=true;
 if (ARGV[4]!=null) expected[temporary(ARGV[4],true)]=true;
 if (length(after.rows)!=length(keys(expected))) reject();
 for (let row in after.rows) {
  if (!expected[row]) reject();
  delete expected[row];
 }
 if (length(keys(expected))) reject();
} else if (action=='temporary-created') {
 let selected=metadata(ARGV[2]), name=temporary(ARGV[3],false);
 if (type(selected)!='array' || length(selected)!=1 || selected[0].name!=name ||
     type(selected[0].version)!='string' || !match(selected[0].version,/^[0-9]{8}\.[0-9]{6}$/) ||
     selected[0].arch!='noarch' || sprintf('%J',selected[0].status)!=sprintf('%J',['installed'])) reject();
 print(name+'='+selected[0].version);
} else if (action=='purge-only') {
 let constraint=temporary(ARGV[3],true), parts=split(constraint,'='), count=0;
 let expected='(1/1) Purging '+parts[0]+' ('+parts[1]+')';
 for (let row in split(trim(text(ARGV[2])),'\n')) {
  if (row==expected) count++;
  else if (!match(row,/^OK: [0-9.]+ (B|KiB|MiB|GiB) in [0-9]+ packages$/)) reject();
 }
 if (count!=1) reject();
} else if (action == 'fetch') {
 let files = fs.lsdir(ARGV[2]), expected = {};
 if (type(files) != 'array' || length(files) != length(value.packages)) reject();
 for (let item in value.packages) expected[item.name + '-' + item.version + '.apk'] = item;
 for (let file in files) {
  let item = expected[file], info = fs.lstat(ARGV[2] + '/' + file);
  if (!item || info?.type != 'file' || info.size != item.archiveBytes) reject();
  printf('%s %s %d\n', file, item.sha256, item.archiveBytes);
  delete expected[file];
 }
 if (length(keys(expected))) reject();
} else if (action == 'installed') {
 function owned(path) {
  let parts = split(path, '/'), parent = '';
  for (let i = 1; i < length(parts) - 1; i++) {
   parent += '/' + parts[i];
   let info = fs.lstat(parent);
   if (info?.type != 'directory' || info.uid != 0 ||
       ((info.mode & 022) && !(parent == '/tmp' && (info.mode & 07777) == 01777))) reject();
  }
  let info = fs.lstat(path);
  if (info?.type != 'file' || info.uid != 0 || info.nlink != 1 ||
      (info.mode & 022) || info.size > 536870912) reject();
  return path;
 };
 printf('file %s %s\n', owned('/usr/share/foxhole/core-producer.json'), value.coreProducerSha256);
 printf('file %s %s\n', owned('/usr/share/foxhole/hysteria-producer.json'), value.serverProducerSha256);
 let core = '/usr/bin/foxcore-cli', server = '/usr/bin/hysteria';
 if (value.mode == 'ram') {
  core = '/tmp/foxhole-core-binary/' + value.volatileBinary.sha256 + '/foxcore-cli';
  server = '/tmp/foxhole-hysteria-server-binary/' + value.volatileDependencies[0].sha256 + '/hysteria';
  for (let root in ['/tmp/foxhole-core-binary','/tmp/foxhole-hysteria-server-binary']) {
   let info = fs.lstat(root);
   if (info?.type != 'directory' || info.uid != 0 || (info.mode & 0777) != 0700) reject();
  }
  for (let path in [core, server]) {
   let directory = replace(path, /\/[^/]+$/, ''), info = fs.lstat(directory);
   if (info?.type != 'directory' || info.uid != 0 || (info.mode & 0777) != 0700) reject();
  }
 }
 printf('file %s %s\n', owned(core), value.corePackage.binarySha256);
 printf('file %s %s\n', owned(server), value.serverPackage.binarySha256);
 printf('capabilities %s %s\n', core, value.capabilitiesSha256);
} else reject();
