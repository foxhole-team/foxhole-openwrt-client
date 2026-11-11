import * as fs from 'fs';
import * as core from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/core-update-model.uc';
import * as ram from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/ram-update-model.uc';
import * as update from '/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/update-model.uc';

let passed=0,failed=0;
function equal(a,b) {if(sprintf('%J',a)!=sprintf('%J',b))die('core_update_model_assertion');};
function copy(value) {return json(sprintf('%J',value));};
function rejects(fn) {let caught=false;try{fn();}catch(_){caught=true;}equal(caught,true);};
function test(name,fn) {
 try{fn();passed++;print('ok ',name,'\n');}
 catch(error){failed++;print('not ok ',name,': ',type(error)=='string'?error:error.message,'\n');}
};
const H='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const C='cccccccccccccccccccccccccccccccccccccccc';
const stamp=1793000000000;
let policy=json(fs.readfile('/workspace/package/foxhole-openwrt-client/root/usr/share/foxhole/update-policy.json',8192));
function feed() {
 return {schema:1,feedAbi:1,channel:'stable',sequence:1,coreVersion:'1.0.4',releaseTag:'v1.0.4',
  publishedAtUnixMs:stamp-1000,expiresAtUnixMs:stamp+86400000,
  compatibility:{stateAbi:1,transactionAbi:1,routerContractVersion:1,osRelease:'25.12.5',
   targets:['x86/64','mediatek/filogic'],minimumBaseVersion:'1.0.6-r1'},
  source:{producerCommit:C,publisherCommit:C,publisherTree:C,sourceContentSha256:H,
   sourceManifestSha256:H,signatureReceiptSha256:H,contentJoinReceiptSha256:H},
  catalog:{schema:1,entries:[{id:'vless',storage:'FLASH',architecture:'x86_64',version:'1.0.4',sourceCommit:C}]}};
};
let context={nowUnixMs:stamp,osRelease:'25.12.5',target:'x86/64',architecture:'x86_64',baseComparison:'=',coreComparison:'<'};
test('legacy exact7 BASE receiver admits migration and rejects extensions',()=>{
 equal(length(keys(policy)),7);equal(ram.policy(policy,policy.packageVersion,policy.releaseTag),policy);
 let extended={...policy,coreFeedAbi:1};rejects(()=>ram.policy(extended,policy.packageVersion,policy.releaseTag));
});
test('compiled signed feed ABI rejects unknown and coercible types',()=>{
 equal(type(core.FEED_ABI),'int');equal(core.FEED_ABI,1);equal(core.feed(feed(),context,null,H).feedAbi,1);
 for(let value in [2,'1',null]) {let candidate=feed();candidate.feedAbi=value;rejects(()=>core.feed(candidate,context,null,H));}
});
test('consumer state transaction and router ABIs remain typed and closed',()=>{
 for(let name in ['stateAbi','transactionAbi','routerContractVersion'])
  for(let value in [2,'1']) {let candidate=feed();candidate.compatibility[name]=value;rejects(()=>core.feed(candidate,context,null,H));}
});
test('sequence replay and changed same-sequence content remain refused',()=>{
 rejects(()=>core.feed(feed(),context,{sequence:2,sha256:H},H));
 rejects(()=>core.feed(feed(),context,{sequence:1,sha256:'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'},H));
});
test('fresh bootstrap eligibility never overwrites configured or legacy policy',()=>{
 let auth={changed:false,bootstrapBootId:'synthetic-boot',bootstrapExpiresUptimeMs:10000};
 let state={schema:1,revision:0,activeServerId:null,countries:[],devices:[],sites:[],servers:[],clients:[]};
 let pairs={schema:1,devices:[]};equal(update.fresh_setup(auth,state,pairs,false),true);
 equal(update.fresh_setup(auth,state,pairs,true),false);delete auth.bootstrapBootId;
 equal(update.fresh_setup(auth,state,pairs,false),false);equal(update.policy(null).enabled,false);
});
print('Core update native model: ',passed,' passed, ',failed,' failed\n');exit(failed?1:0);
