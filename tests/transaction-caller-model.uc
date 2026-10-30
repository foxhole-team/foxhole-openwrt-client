import * as native from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/update-native.uc';
import * as digest from 'digest';
let passed=0,failed=0;
function equal(a,b){if(sprintf('%J',a)!=sprintf('%J',b))die('caller_assertion');};
function segment(value,a,b){let out=[];for(let i=a;i<b;i++)push(out,value[i]);return out;};
function rejects(fn){let caught=false;try{fn();}catch(_){caught=true;}equal(caught,true);};
function test(name,fn){try{fn();passed++;print('ok ',name,'\n');}catch(e){failed++;print('not ok ',name,': ',type(e)=='string'?e:e.message,'\n');}};
const A='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const B='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const C='cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
const NAME='foxcore-engine-vless-flash-'+A;
const OLD='foxhole-openwrt-client\nbusybox\n';
function record(){return {schema:1,abi:1,oldBase:{version:'0.0.1-r1',nativeId:A,archive:'/etc/foxhole/update-cache/job-update-job-'+substr(A,0,32)+'/assets/foxhole-openwrt-client-0.0.1-r1.apk'},
 newBase:{version:'0.0.2-r1',nativeId:B,archive:'/etc/foxhole/update-cache/job-update-job-'+substr(A,0,32)+'/assets/foxhole-openwrt-client-0.0.2-r1.apk'},oldCas:'sha256-160:'+substr(A,0,40),newCas:'sha256-160:'+substr(B,0,40),
 beforeSha256:A,afterSha256:B,keys:'/etc/foxhole/update-cache/job-update-job-'+substr(A,0,32)+'/keys',
 repositories:'/etc/foxhole/update-cache/job-update-job-'+substr(A,0,32)+'/repositories',modules:[]};};
test('world preserves original BASE and unrelated entry order',()=>{
 let value=native.world_plan(OLD,[NAME]);equal(value.beforeRaw,OLD);equal(value.afterRaw,OLD+NAME+'\n');
 equal(value.beforeSha256,digest.sha256(OLD));equal(value.afterSha256,digest.sha256(OLD+NAME+'\n'));
});
test('zero-module transaction preserves exact world bytes',()=>{let value=native.world_plan(OLD,[]);equal(value.beforeRaw,value.afterRaw);equal(value.beforeSha256,value.afterSha256);});
test('pinned BASE, noncanonical world and duplicate roots are refused',()=>{
 for(let raw in ['foxhole-openwrt-client=0.0.1-r1\nbusybox\n',' foxhole-openwrt-client\n','foxhole-openwrt-client\n\n','foxhole-openwrt-client\nbusybox','foxhole-openwrt-client\nbusybox\nbusybox\n'])rejects(()=>native.world_plan(raw,[]));
 rejects(()=>native.world_plan(OLD,[NAME,NAME]));rejects(()=>native.world_plan(OLD,['base-files']));
});
test('installed CAS is explicitly typed and never full32 stored identity',()=>{equal(native.native_cas(A),'sha256-160:'+substr(A,0,40));rejects(()=>native.native_cas(substr(A,0,40)));});
test('apply zero-module exact prefix and six header args',()=>{
 let tx=record(),args=native.native_args(tx,false,A);equal(segment(args,0,9),['--root','/','--no-network','--no-cache','--keys-dir',tx.keys,'--repositories-file',tx.repositories,'foxhole-apply']);
 equal(segment(args,9,length(args)),['foxhole-openwrt-client=0.0.2-r1','0.0.1-r1',A,tx.oldCas,B,tx.newBase.archive]);
});
test('recover exact ten headers and persisted approved hashes',()=>{
 let tx=record(),args=native.native_args(tx,true,B);equal(segment(args,8,11),['foxhole-recover','foxhole-openwrt-client=0.0.1-r1','foxhole-openwrt-client=0.0.2-r1']);
 equal(segment(args,11,length(args)),[B,A,tx.oldCas,tx.newCas,A,tx.oldBase.archive,B,tx.newBase.archive]);rejects(()=>native.native_args(tx,true,C));rejects(()=>native.native_args(tx,false,B));
});
test('three exact module tuples append without changing BASE headers',()=>{
 let tx=record();for(let id in ['vless','hysteria2','wireguard'])push(tx.modules,{name:'foxcore-engine-'+id+'-ram-'+C,version:'1.0.0-r1',nativeId:C,archive:'/etc/foxhole/update-cache/'+C});
 equal(length(native.native_args(tx,false,A)),24);equal(length(native.native_args(tx,true,B)),28);
 tx.modules[1].name=tx.modules[0].name;rejects(()=>native.native_args(tx,false,A));
});
test('postchecks reject unrelated identity drift and missing approved module',()=>{
 let tx=record(),before={'foxhole-openwrt-client':{name:'foxhole-openwrt-client',version:'0.0.1-r1',arch:'noarch',cas:tx.oldCas,flags:'S'},busybox:{name:'busybox',version:'1',arch:'x86_64',cas:'sha1:'+substr(C,0,40),flags:''}};
 let after=json(sprintf('%J',before));after['foxhole-openwrt-client'].version='0.0.2-r1';after['foxhole-openwrt-client'].cas=tx.newCas;
 native.assert_identities(before,after,tx,false);after.busybox.version='2';rejects(()=>native.assert_identities(before,after,tx,false));
 tx.modules=[{name:NAME,version:'1.0.1-r1',arch:'x86_64',nativeId:C,payloadFiles:[]}];rejects(()=>native.assert_identities(before,before,tx,false));
 native.assert_identities(before,before,tx,true);
});
print('Native caller model cases: ',passed,' passed, ',failed,' failed\n');if(failed)exit(1);
