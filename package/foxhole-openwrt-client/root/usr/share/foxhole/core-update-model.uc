'use strict';

export const FEED_ABI = 1;

function fail(reason) { die('update_' + reason); };
function integer(value) {
 return type(value)=='int' && value>=0 && value<=9007199254740991;
};
function sha(value) {
 return type(value)=='string' && match(value,/^[a-f0-9]{64}$/)!=null;
};
function exact(value, fields) {
 if(type(value)!='object' || value==null || length(keys(value))!=length(fields))
  fail('package_verification_failed');
 let names=keys(value);
 for(let i=0;i<length(names);i++)
  if(index(fields,names[i])<0)fail('package_verification_failed');
};
function version(value) {
 return type(value)=='string' &&
  match(value,/^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$/)!=null;
};
function source(value) {
 exact(value,['producerCommit','publisherCommit','publisherTree',
  'sourceContentSha256','sourceManifestSha256','signatureReceiptSha256',
  'contentJoinReceiptSha256']);
 let commits=['producerCommit','publisherCommit','publisherTree'];
 for(let i=0;i<length(commits);i++)
  if(type(value[commits[i]])!='string' ||
   !match(value[commits[i]],/^[a-f0-9]{40}$/))
   fail('package_verification_failed');
 let receipts=['sourceContentSha256','sourceManifestSha256',
  'signatureReceiptSha256','contentJoinReceiptSha256'];
 for(let i=0;i<length(receipts);i++)
  if(!sha(value[receipts[i]]))fail('package_verification_failed');
};
export function comparison_inputs(value) {
 if(!version(value?.coreVersion) ||
  type(value.compatibility?.minimumBaseVersion)!='string' ||
  !match(value.compatibility.minimumBaseVersion,
   /^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}-r[1-9][0-9]{0,5}$/))
  fail('package_verification_failed');
 return {coreVersion:value.coreVersion,
  minimumBaseVersion:value.compatibility.minimumBaseVersion};
};
function admit_feed(value, context, previous, body_sha256, fresh) {
 exact(value,['schema','feedAbi','channel','sequence','coreVersion',
  'releaseTag','publishedAtUnixMs','expiresAtUnixMs','compatibility',
  'source','catalog']);
 if(type(value.schema)!='int' || value.schema!=1 ||
  type(value.feedAbi)!='int' || value.feedAbi!=FEED_ABI || value.channel!='stable' ||
  !integer(value.sequence) || value.sequence<1 || value.sequence>0x7ffffffe ||
  !version(value.coreVersion) || value.releaseTag!='v'+value.coreVersion ||
  !sha(body_sha256))fail('package_verification_failed');
 exact(value.compatibility,['stateAbi','transactionAbi',
  'routerContractVersion','osRelease','targets','minimumBaseVersion']);
 let compatibility=value.compatibility;
 if(type(compatibility.stateAbi)!='int' || compatibility.stateAbi!=1 ||
  type(compatibility.transactionAbi)!='int' || compatibility.transactionAbi!=1 ||
  type(compatibility.routerContractVersion)!='int' || compatibility.routerContractVersion!=1 ||
  index(['25.12.5','25.12.6'],compatibility.osRelease)<0 ||
  sprintf('%J',compatibility.targets)!=
   sprintf('%J',['x86/64','mediatek/filogic']) ||
  type(compatibility.minimumBaseVersion)!='string' ||
  !match(compatibility.minimumBaseVersion,
   /^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}-r[1-9][0-9]{0,5}$/))
  fail('unsupported_target');
 if(context.osRelease!=compatibility.osRelease ||
  !((context.target=='x86/64' && context.architecture=='x86_64') ||
    (context.target=='mediatek/filogic' &&
     context.architecture=='aarch64_cortex-a53')) ||
  index(['=','>'],context.baseComparison)<0)fail('unsupported_target');
 if(index(['<','='],context.coreComparison)<0)fail('downgrade_rejected');
 if(!integer(value.publishedAtUnixMs) || !integer(value.expiresAtUnixMs) ||
  value.publishedAtUnixMs<1577836800000 ||
  value.expiresAtUnixMs<=value.publishedAtUnixMs)
  fail('release_unavailable');
 if(fresh && (!integer(context.nowUnixMs) ||
  context.nowUnixMs<1577836800000 ||
  value.publishedAtUnixMs>context.nowUnixMs+300000 ||
  value.expiresAtUnixMs<=context.nowUnixMs))fail('release_unavailable');
 if(previous!=null) {
  exact(previous,['sequence','sha256']);
  if(!integer(previous.sequence) || !sha(previous.sha256))
   fail('recovery_required');
  if(value.sequence<previous.sequence)fail('downgrade_rejected');
  if(value.sequence==previous.sequence && previous.sha256!=body_sha256)
   fail('version_identity_conflict');
 }
 source(value.source);
 exact(value.catalog,['schema','entries']);
 if(value.catalog.schema!=1 || type(value.catalog.entries)!='array' ||
  length(value.catalog.entries)<1 || length(value.catalog.entries)>72)
  fail('package_verification_failed');
 for(let i=0;i<length(value.catalog.entries);i++) {
  let entry=value.catalog.entries[i];
  if(entry?.version!=value.coreVersion ||
   entry.sourceCommit!=value.source.producerCommit)
   fail('package_verification_failed');
 }
 return json(sprintf('%J',value));
};
export function feed(value, context, previous, body_sha256) {
 return admit_feed(value,context,previous,body_sha256,true);
};
export function reference(value) {
 exact(value,['schema','sequence','coreVersion','packageVersion',
  'bodySha256','bodyBytes','archiveSha256','archiveBytes',
  'indexSha256','indexBytes']);
 if(value.schema!=1 || !integer(value.sequence) || value.sequence<1 ||
  value.sequence>0x7ffffffe || !version(value.coreVersion) ||
  type(value.packageVersion)!='string' ||
  !match(value.packageVersion,
   /^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}-r[1-9][0-9]{0,5}$/) ||
  substr(value.packageVersion,0,length(value.coreVersion)+2)!=
   value.coreVersion+'-r')fail('package_verification_failed');
 let names=['body','archive','index'];
 for(let i=0;i<length(names);i++) {
  let name=names[i];
  if(!sha(value[name+'Sha256']) || !integer(value[name+'Bytes']) ||
   value[name+'Bytes']<1 ||
   value[name+'Bytes']>(name=='body'?262144:1048576))
   fail('package_verification_failed');
 }
 return json(sprintf('%J',value));
};

export function cached_feed(value, context, installed) {
 let checked=reference(installed);
 if(value.sequence!=checked.sequence ||
  value.coreVersion!=checked.coreVersion)fail('version_identity_conflict');
 // Expiry limits discovery, not installed offline use.
 return admit_feed(value,context,{sequence:checked.sequence,
  sha256:checked.bodySha256},checked.bodySha256,false);
};

export function metadata_layout(document, package_version) {
 let info=document?.info;
 if(info?.name!='foxcore-update-catalog' || info.version!=package_version ||
  info.arch!='noarch' || !integer(info['installed-size']) ||
  info['installed-size']<1 || info['installed-size']>524288 ||
  length(document.scripts||{}) || length(document.triggers||[]) ||
  length(info.provides||[]) || length(info.replaces||[]) ||
  length(info['install-if']||[]) || length(info.recommends||[]) ||
  (length(info.depends||[]) &&
   sprintf('%J',info.depends)!=sprintf('%J',['libc'])) ||
  type(document.paths)!='array' || length(document.paths)>12)
  fail('package_verification_failed');
 let allowed=['usr/share/foxhole-core-catalog/core-update.json',
  'lib/apk/packages/foxcore-update-catalog.list'];
 let parents=['','usr','usr/share','usr/share/foxhole-core-catalog',
  'lib','lib/apk','lib/apk/packages'];
 let seen={},directories={},body=null;
 for(let i=0;i<length(document.paths);i++) {
  let folder=document.paths[i],directory=folder.name||'';
  if(index(parents,directory)<0 || directories[directory] ||
   folder.acl?.mode!=0o755 ||
   index(['root','0'],folder.acl?.user)<0 ||
   index(['root','0'],folder.acl?.group)<0 ||
   length(folder.acl?.xattrs||[]) || type(folder.files||[])!='array')
   fail('package_verification_failed');
  directories[directory]=true;
  for(let j=0;j<length(folder.files||[]);j++) {
   let file=folder.files[j],path=directory+'/'+file.name;
   if(index(allowed,path)<0 || seen[path] || file.target!=null ||
    file.acl?.mode!=0o644 || index(['root','0'],file.acl?.user)<0 ||
    index(['root','0'],file.acl?.group)<0 || length(file.acl?.xattrs||[]) ||
    !integer(file.size) || file.size<1 || !sha(file.hash) ||
    file.size>(path==allowed[0]?262144:16384))
    fail('package_verification_failed');
   seen[path]=true;
   if(path==allowed[0])body={path,sha256:file.hash,bytes:file.size};
  }
 }
 if(body==null)fail('package_verification_failed');
 return body;
};

export function module_changes(previous, catalog, architecture, comparisons) {
 if(type(previous)!='array' || length(previous)>3 ||
  type(catalog?.entries)!='array')fail('package_verification_failed');
 let artifacts=[],changes=[],seen={};
 for(let i=0;i<length(previous);i++) {
  let old=previous[i],next=null;
  if(index(['vless','hysteria2','wireguard'],old.id)<0 || seen[old.id])
   fail('package_verification_failed');
  seen[old.id]=true;
  for(let j=0;j<length(catalog.entries);j++) {
   let item=catalog.entries[j];
   if(item.id==old.id && item.storage==old.storage &&
    item.architecture==architecture) {
    if(next!=null)fail('package_verification_failed');
    next=item;
   }
  }
  if(next==null)fail('unsupported_target');
  let comparison=comparisons[old.id];
  if(index(['<','=','>'],comparison?.core)<0 ||
   index(['<','=','>'],comparison?.package)<0)
   fail('package_verification_failed');
  if(comparison.core=='>' || comparison.package=='>')
   fail('downgrade_rejected');
  if(comparison.package=='=') {
   if(old.manifestSha256!=next.manifestSha256 ||
    old.binarySha256!=next.binarySha256 || comparison.core!='=')
    fail('version_identity_conflict');
   continue;
  }
  if(comparison.core=='=' && old.binarySha256!=next.binarySha256)
   fail('version_identity_conflict');
  push(artifacts,next);
  push(changes,{id:next.id,storage:next.storage,
   fromVersion:old.packageVersion,toVersion:next.packageVersion});
 }
 return {artifacts:json(sprintf('%J',artifacts)),changes};
};

export function cohort_asset_id(value) {
 return value=='catalog-index' || value=='catalog-apk' ||
  type(value)=='string' && match(value,/^asset-[a-f0-9]{64}$/)!=null;
};
function request_fields(value, names) {
 if(type(value)!='object' || value==null)fail('invalid_request');
 let fields=keys(value);
 for(let i=0;i<length(fields);i++)
  if(fields[i]!='token' && index(names,fields[i])<0)
   fail('invalid_request');
 for(let i=0;i<length(names);i++)
  if(value[names[i]]==null)fail('invalid_request');
 if(value.cohortKind!='CORE')fail('invalid_request');
};
export function cohort_begin(value) {
 request_fields(value,['cohortKind','assetId','uploadId','expectedRevision',
  'requestId','releaseTag','version','fileSha256','fileBytes']);
 if(!cohort_asset_id(value.assetId) || !integer(value.expectedRevision) ||
  type(value.requestId)!='string' ||
  !match(value.requestId,/^[a-f0-9]{32}$/) || !version(value.version) ||
  value.releaseTag!='v'+value.version || !sha(value.fileSha256) ||
  !integer(value.fileBytes) || value.fileBytes<1 ||
  value.fileBytes>(value.assetId=='catalog-index'||value.assetId=='catalog-apk'?
   1048576:134217728) || type(value.uploadId)!='string' ||
  value.uploadId!='' && !match(value.uploadId,/^update-upload-[a-f0-9]{32}$/) ||
  value.assetId!='catalog-index' && value.uploadId=='')fail('invalid_request');
 return value;
};
export function cohort_action(value, chunk) {
 request_fields(value,chunk?
  ['cohortKind','assetId','uploadId','offset','dataBase64','chunkSha256']:
  ['cohortKind','assetId','uploadId']);
 if(!cohort_asset_id(value.assetId) || type(value.uploadId)!='string' ||
  !match(value.uploadId,/^update-upload-[a-f0-9]{32}$/))
  fail('invalid_request');
 return value;
};
