import * as update from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/update-model.uc';

let passed = 0, failed = 0;
function equal(a, b) { if (sprintf('%J', a) != sprintf('%J', b)) die('update_test_assertion'); };
function rejects(fn, reason) {
	let caught = null; try { fn(); } catch (e) { caught = type(e) == 'string' ? e : e.message; }
	equal(caught, 'update_' + lc(reason));
};
function test(name, fn) {
	try { fn(); passed++; print('ok ', name, '\n'); }
	catch (e) { failed++; print('not ok ', name, ': ', type(e) == 'string' ? e : e.message, '\n'); }
};
function copy(v) { return json(sprintf('%J', v)); };
const H = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

test('automatic policy defaults off and is due only once per24h', () => {
	let p = update.policy(null); equal(p.enabled, false); equal(update.due(p, 1577836801000, false), false);
	p.enabled = true; equal(update.due(p, 1577836801000, false), true);
	p.lastAttemptAtUnixMs = 1577836801000; equal(update.due(p, 1577923200999, false), false);
	equal(update.due(p, 1577923201000, false), true); equal(update.due(p, 1577923201000, true), false);
	equal(update.due(p, 1577836800999, false), false);
});
test('corrupt policy cannot silently enable or reset its cadence', () => {
	for (let p in [{enabled:'true'}, {schema:1,revision:-1,enabled:true},
		{schema:1,revision:0,enabled:true,lastAttemptAtUnixMs:-1}])
		rejects(() => update.policy(p), 'RECOVERY_REQUIRED');
});
test('BASE replacement is the only admitted same-name version change', () => {
	let before = {os:{name:'os',version:'1',arch:'x86_64'},
		'foxhole-openwrt-client':{name:'foxhole-openwrt-client',version:'1-r1',arch:'noarch'}};
	let after = copy(before); after['foxhole-openwrt-client'].version='2-r1';
	equal(update.package_delta(before, after, [{name:'foxhole-openwrt-client',version:'2-r1',arch:'noarch'}]), true);
	after.os.version='2'; rejects(() => update.package_delta(before, after,
		[{name:'foxhole-openwrt-client',version:'2-r1',arch:'noarch'}]), 'PACKAGE_VERIFICATION_FAILED');
});
test('unselected server or OS changes and removals are rejected', () => {
	let before = {hysteria:{name:'hysteria',version:'2',arch:'x86_64'}};
	for (let after in [{}, {hysteria:{name:'hysteria',version:'3',arch:'x86_64'}},
		{...before, unselected:{name:'unselected',version:'1',arch:'x86_64'}}])
		rejects(() => update.package_delta(before, after, []), 'PACKAGE_VERIFICATION_FAILED');
});
test('selected content-addressed additions retain every old rollback slot', () => {
	let before = {old:{name:'old',version:'1',arch:'x86_64'}},
		row = {name:'new',version:'2',arch:'x86_64'};
	equal(update.package_delta(before, {...before,new:row}, [row]), true);
	rejects(() => update.package_delta(before, {new:row}, [row]), 'PACKAGE_VERIFICATION_FAILED');
});
test('duplicate or non-BASE replacement allowances fail closed', () => {
	let row = {name:'new',version:'2',arch:'x86_64'};
	rejects(() => update.package_delta({}, {new:row}, [row,row]), 'PACKAGE_VERIFICATION_FAILED');
	rejects(() => update.package_delta({new:{...row,version:'1'}}, {new:row}, [row]), 'PACKAGE_VERIFICATION_FAILED');
});
test('only a semantic native upgrade admits a different identity', () => {
	equal(update.version_admit('<', H, B), true); equal(update.version_admit('=', H, H), false);
	rejects(() => update.version_admit('>', H, B), 'DOWNGRADE_REJECTED');
	rejects(() => update.version_admit('=', H, B), 'VERSION_IDENTITY_CONFLICT');
	rejects(() => update.version_admit('garbage', H, B), 'PACKAGE_VERIFICATION_FAILED');
});
test('release hint accepts only bounded stable tag and cannot inject a URL', () => {
	equal(update.release_tag({tag_name:'v1.0.1',draft:false,prerelease:false}), 'v1.0.1');
	for (let tag in ['latest','v1.0.1/../../x','https://evil/v1.0.1','v1.0.1-rc1'])
		rejects(() => update.release_tag({tag_name:tag,draft:false,prerelease:false}), 'RELEASE_UNAVAILABLE');
});
test('BASE namespace cannot overwrite pairing configuration, keys or OS', () => {
	for (let path in ['etc/foxhole/auth.json','etc/foxhole/state.json','etc/shadow',
		'usr/bin/apk','usr/libexec/foxhole-engine-command-v3','usr/libexec/foxhole-other2','usr/libexec/foxhole/../../evil','www/../etc/shadow'])
		equal(update.base_path(path), false);
	for (let path in ['usr/share/foxhole/update-model.uc','usr/libexec/foxhole-update-job','usr/libexec/foxhole-engine-command-v2',
		'www/luci-static/resources/foxhole/update-panel.js','etc/config/foxhole'])
		equal(update.base_path(path), true);
});
test('automatic admission rechecks current permanent policy and revision', () => {
	let p=update.policy(null); p.enabled=true; p.revision=2;
	equal(update.auto_authorized({automatic:true,policyRevision:2},p),true);
	p.enabled=false; equal(update.auto_authorized({automatic:true,policyRevision:2},p),false);
	p.enabled=true; p.revision=3; equal(update.auto_authorized({automatic:true,policyRevision:2},p),false);
});
test('canonical native BASE noarch layout is accepted and all is rejected', () => {
 let paths = ['usr/share/foxhole/update-policy.json','usr/share/foxhole/engine-catalog.json',
  'usr/share/foxhole/update-service.uc','usr/libexec/foxhole-update-job','usr/libexec/foxhole-engine-command-v2','usr/share/foxhole/engine-capture.uc','www/foxhole.html',
  'usr/share/rpcd/ucode/foxhole.uc','etc/config/foxhole','lib/apk/packages/foxhole-openwrt-client.list'];
 let folders = {};
 for(let path in paths){let parts=split(path,'/'),name=pop(parts),folder=join('/',parts);
  if(!folders[folder])folders[folder]={name:folder,acl:{user:'root',group:'root',mode:0o755},files:[]};
  push(folders[folder].files,{name,acl:{user:'root',group:'root',mode:0o644},size:1,hash:H});
 }
 let document={info:{name:'foxhole-openwrt-client',version:'1.0.0-r3',arch:'noarch','installed-size':32768},
  paths:[{acl:{user:'root',group:'root',mode:0o755}},...map(keys(folders),key=>folders[key])]};
 equal(length(keys(update.base_layout(document,'1.0.0-r3'))),10);
 document.info.provides=['foxhole-openwrt-client-any'];
 let config=filter(document.paths,row=>row.name=='etc/config')[0].files[0];
 for(let mode in [0o600,0o644,0o755]){
  config.acl.mode=mode;equal(length(keys(update.base_layout(document,'1.0.0-r3'))),10);
 }
 config.acl.mode=0o600;
 for(let provided in [['other-any'],['foxhole-openwrt-client-any=1.0.0-r3'],
  ['foxhole-openwrt-client-any','foxhole-openwrt-client-any'],
  ['foxhole-openwrt-client-any','other-any'],'foxhole-openwrt-client-any',false]){
  let wrong=copy(document);wrong.info.provides=provided;
  rejects(()=>update.base_layout(wrong,'1.0.0-r3'),'PACKAGE_VERIFICATION_FAILED');
 }
 for(let mode in [0o640,0o666]){
  let wrong=copy(document);filter(wrong.paths,row=>row.name=='etc/config')[0].files[0].acl.mode=mode;
  rejects(()=>update.base_layout(wrong,'1.0.0-r3'),'PACKAGE_VERIFICATION_FAILED');
 }
 let private_other=copy(document);
 filter(private_other.paths,row=>row.name=='usr/share/foxhole')[0].files[0].acl.mode=0o600;
 rejects(()=>update.base_layout(private_other,'1.0.0-r3'),'PACKAGE_VERIFICATION_FAILED');
 for(let path in ['lib/apk/packages/foxhole-openwrt-client.conffiles',
  'lib/apk/packages/foxhole-openwrt-client.conffiles_static',
  'lib/upgrade/keep.d/foxhole-openwrt-client'])equal(update.base_path(path),true);
 for(let path in ['lib/apk/packages/other.conffiles',
  'lib/apk/packages/foxhole-openwrt-client.conffiles_extra',
  'lib/apk/packages/foxhole-openwrt-client.conffiles_static.extra',
  'lib/upgrade/keep.d/other','lib/upgrade/keep.d/foxhole-openwrt-client.extra',
  'lib/upgrade/keep.d/../foxhole-openwrt-client'])equal(update.base_path(path),false);

 for(let unexpected in ['foxhole-engine-command-v3','foxhole-other2']){let wrong=copy(document);let folder=filter(wrong.paths,row=>row.name=='usr/libexec')[0];let file=filter(folder.files,row=>row.name=='foxhole-engine-command-v2')[0];file.name=unexpected;rejects(()=>update.base_layout(wrong,'1.0.0-r3'),'PACKAGE_VERIFICATION_FAILED');}
 for(let arch in ['all','x86_64','aarch64_cortex-a53']){let wrong=copy(document);wrong.info.arch=arch;
  rejects(()=>update.base_layout(wrong,'1.0.0-r3'),'PACKAGE_VERIFICATION_FAILED');}
});
print('Update model cases: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
