'use strict';

import * as fs from 'fs';
import * as digest from 'digest';
import * as engines from './engine-model.uc';
import * as packages from './package-operations.uc';
import * as registry from './engine-registry.uc';
import * as store from './private-store.uc';
import * as native from './update-native.uc';
import * as guard from './update-model.uc';
import * as model from './core-update-model.uc';
import * as capture from './update-capture.uc';
import * as ram_model from './ram-update-model.uc';

const ORIGIN='https://github.com/foxhole-team/foxhole-core/releases/download/';
const CACHE='/etc/foxhole/update-cache';
const CURRENT=CACHE+'/core-current.json';
const HIGHEST=CACHE+'/core-highest.json';
function capacity(bytes) {
 let raw=fs.readfile('/proc/meminfo',65536);
 let found=match(raw||'',/\n?MemAvailable:[ \t]+([0-9]+) kB/);
 if(!found || +found[1]*1024<bytes)guard.fail('NO_SPACE');
};

export function current() {
 let raw=store.read(CURRENT,8192);
 return raw?model.reference(native.decode(raw)):null;
};
export function highest() {
 let raw=store.read(HIGHEST,8192);
 return raw?model.reference(native.decode(raw)):null;
};
export function remember(reference) {
 let value=model.reference(reference),before=highest();
 if(before && (value.sequence<before.sequence ||
  native.compare(before.coreVersion,value.coreVersion)=='>'))
  guard.fail('DOWNGRADE_REJECTED');
 if(before?.sequence==value.sequence &&
  before.bodySha256!=value.bodySha256)
  guard.fail('VERSION_IDENTITY_CONFLICT');
 store.directory(CACHE);store.write(HIGHEST,sprintf('%J',value));
 if(sprintf('%J',highest())!=sprintf('%J',value))
  guard.fail('PACKAGE_VERIFICATION_FAILED');
};
export function latest(directory) {
 capacity(20971520);
 let path=directory+'/core-release-hint.json';store.target(path);
 if(fs.lstat(path) ||
  system(['/usr/libexec/foxhole-core-update-hint',path],25000)!=0)
  guard.fail('RELEASE_UNAVAILABLE');
 return guard.release_tag(native.decode(native.public_raw(path,1048576)));
};
export function network_unreachable() {
 let result=capture.capture('probe',[ram_model.core_release_api],32,6000);
 return ram_model.network_unreachable(result.code,result.stderr);
};
function metadata_asset(url,maximum,provided,index) {
 if(provided==null)return native.fetch(url,maximum);
 let path=index?provided.index:provided.archive;
 let role=index?'catalog-index':'catalog-apk';
 if(type(path)!='string' ||
  !match(path,/^\/tmp\/foxhole\/core-uploads\/update-upload-[a-f0-9]{32}\/assets\/catalog-(index|apk)$/) ||
  substr(path,length(path)-length(role))!=role)
  guard.fail('PACKAGE_VERIFICATION_FAILED');
 native.public_raw(path,maximum);return path;
};
export function verify_catalog(tag,directory,keys,active_version,previous,provided) {
 if(!match(tag||'',/^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$/))
  guard.fail('RELEASE_UNAVAILABLE');
 store.directory(directory);
 let index=metadata_asset(ORIGIN+tag+'/core-catalog.adb',1048576,provided,true);
 packages.apk(['--keys-dir',keys,'verify',index]);
 let rows=native.decode(packages.apk(['adbdump','--format','json',index])).packages;
 if(type(rows)!='array' || length(rows)!=1)guard.fail('PACKAGE_VERIFICATION_FAILED');
 let row=rows[0],version=substr(tag,1);
 if(row.name!='foxcore-update-catalog' || row.arch!='noarch' ||
  type(row.version)!='string' ||
  !match(row.version,/^[0-9]+\.[0-9]+\.[0-9]+-r[1-9][0-9]{0,5}$/) ||
  substr(row.version,0,length(version)+2)!=version+'-r' ||
  type(row['file-size'])!='int' || row['file-size']<1 ||
  row['file-size']>1048576 || !match(row.hashes||'',/^[a-f0-9]{64}$/))
  guard.fail('PACKAGE_VERIFICATION_FAILED');
 let filename='foxcore-update-catalog-'+row.version+'.apk';
 capacity(18874368+4*row['file-size']+4*fs.lstat(index).size);
 let archive=metadata_asset(ORIGIN+tag+'/'+filename,row['file-size'],provided,false);
 if(fs.lstat(archive)?.size!=row['file-size'])guard.fail('PACKAGE_VERIFICATION_FAILED');
 packages.apk(['--keys-dir',keys,'verify',archive]);
 let document=native.decode(packages.apk(['adbdump','--format','json',archive]));
 let body=model.metadata_layout(document,row.version);
 store.directory(directory+'/root');store.directory(directory+'/fetched');
 if(system(['/bin/cp',index,directory+'/core-catalog.adb'],3000)!=0 ||
  system(['/bin/cp',archive,directory+'/'+filename],5000)!=0)
  guard.fail('PACKAGE_VERIFICATION_FAILED');
 store.write(directory+'/repositories',directory+'/core-catalog.adb\n');
 let target=native.target();
 let common=['--root',directory+'/root','--arch',target.architecture,
  '--no-network','--no-cache','--repositories-file',directory+'/repositories',
  '--keys-dir',keys];
 packages.apk([...common,'add','--initdb']);
 packages.apk([...common,'fetch','--output',directory+'/fetched',row.name]);
 let archive_sha=registry.hash_file(archive);
 if(registry.hash_file(directory+'/fetched/'+filename)!=archive_sha)
  guard.fail('PACKAGE_VERIFICATION_FAILED');
 store.directory(directory+'/extracted');
 packages.apk(['--keys-dir',keys,'extract','--no-chown',
  '--destination',directory+'/extracted',archive]);
 let path=directory+'/extracted/'+body.path;
 let raw=native.public_raw(path,262144);
 if(length(raw)!=body.bytes || digest.sha256(raw)!=body.sha256)
  guard.fail('PACKAGE_VERIFICATION_FAILED');
 let value=native.decode(raw);
 let compared=model.comparison_inputs(value);
 value.catalog=engines.catalog(value.catalog);
 let context={...target,osRelease:target.release,nowUnixMs:time()*1000,
  baseComparison:native.compare(active_version,compared.minimumBaseVersion),
  coreComparison:previous?native.compare(previous.coreVersion,compared.coreVersion):'<'};
 value=model.feed(value,context,previous?{sequence:previous.sequence,
  sha256:previous.bodySha256}:null,body.sha256);
 let reference=model.reference({schema:1,sequence:value.sequence,
  coreVersion:value.coreVersion,packageVersion:row.version,
  bodySha256:body.sha256,bodyBytes:body.bytes,
  archiveSha256:archive_sha,archiveBytes:row['file-size'],
  indexSha256:registry.hash_file(index),indexBytes:fs.lstat(index).size});
 native.cache_asset(archive,reference.archiveSha256,reference.archiveBytes);
 native.cache_asset(index,reference.indexSha256,reference.indexBytes);
 native.cache_asset(path,reference.bodySha256,reference.bodyBytes);
 native.prepare_keys(CACHE+'/core-verifier');
 return {reference,feed:value};
};
export function publish(reference) {
 let checked=model.reference(reference);store.directory(CACHE);
 store.write(CURRENT,sprintf('%J',checked));
 if(sprintf('%J',current())!=sprintf('%J',checked))
  guard.fail('PACKAGE_VERIFICATION_FAILED');
};
export function restore(reference) {
 if(reference!=null)return publish(reference);
 let path=fs.lstat(CURRENT);
 if(path && (!store.file_metadata(path) || !fs.unlink(CURRENT)))
  guard.fail('RECOVERY_REQUIRED');
};
