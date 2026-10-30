import * as plan from '/workspace/tools/install-plan-model.uc';

const hash = sprintf('%064d', 0);
const ownAuthority = 'fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1';
const upstreamAuthority = '27d61d827d64ccf2f46dce5f52aec6279404d4a00686dafb22f52f3b4ee675f8';
const variant = { id: 'x86-hy2', architecture: 'x86_64', supportedOpenWrt: ['25.12.5'],
 supportedTargets: ['x86/64'], protocols: ['hysteria2'], coreProducerFile: 'producer.json',
 coreProducerSha256: hash, coreBinarySha256: hash, coreSourceSha256: hash,
 capabilitiesFile: 'capabilities.json', capabilitiesSha256: hash,
 serverProducerFile: 'server-producer.json', serverProducerSha256: hash,
 modes: { flash: { budgetFile: 'flash.json', budgetSha256: hash } } };
const catalog = { schema: 1, development: false, defaultProtocols: ['hysteria2'],
 allProtocols: ['anytls','http','hysteria2','naive','shadowsocks','shadowtls','socks','trojan','tuic','vless','vmess','wireguard'],
 variants: [variant] };
function fixture() {
 return { schema: 1, architecture: 'x86_64', mode: 'flash', protocols: ['hysteria2'],
  supportedOpenWrt: ['25.12.5'], supportedTargets: ['x86/64'], coreProducerSha256: hash,
  capabilitiesSha256: hash, serverProducerSha256: hash,
  verification: { signatures: true, resolver: 'apk add --simulate --no-network',
   signatureModel:'canonical-apk-and-upstream-index-v1',factorySourceSha256:hash },
  packages: [{name:'foxcore-cli',file:'core.apk',version:'1.0.0-r1',arch:'x86_64',sha256:hash,archiveBytes:512,installedBytes:2048},
   {name:'hysteria',file:'server.apk',version:'2.12.2-r4',arch:'x86_64',sha256:hash,archiveBytes:512,installedBytes:2048},
   {name:'foxhole-openwrt-client',file:'panel.apk',version:'1.0.0-r1',arch:'x86_64',sha256:hash,archiveBytes:512,installedBytes:2048},
   {name:'kernel',file:'kernel.apk',version:'6.12-r1',arch:'x86_64',sha256:hash,archiveBytes:512,installedBytes:2048}],
  repositoryIndexes:[{file:'own.adb',sha256:hash,bytes:100,role:'foxhole',
   sourceUrl:'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.0/packages.adb',trustKeyFiles:['foxhole-openwrt-apk.pem']},
   {file:'upstream.adb',sha256:hash,bytes:200,role:'upstream',
    sourceUrl:'https://downloads.openwrt.org/releases/25.12.5/packages/x86_64/base/packages.adb',trustKeyFiles:['upstream.pem']}],
  trustKeys:[{file:'foxhole-openwrt-apk.pem',sha256:ownAuthority,bytes:400},{file:'upstream.pem',sha256:upstreamAuthority,bytes:400}],
  repositoryIndexBytes:300,trustKeyBytes:800,
  packageAuthentications:[{file:'core.apk',indexFile:'own.adb',name:'foxcore-cli',version:'1.0.0-r1',architecture:'x86_64',packageIdentity:hash},
   {file:'server.apk',indexFile:'own.adb',name:'hysteria',version:'2.12.2-r4',architecture:'x86_64',packageIdentity:hash},
   {file:'panel.apk',indexFile:'own.adb',name:'foxhole-openwrt-client',version:'1.0.0-r1',architecture:'x86_64',packageIdentity:hash},
   {file:'kernel.apk',indexFile:'upstream.adb',name:'kernel',version:'6.12-r1',architecture:'x86_64',packageIdentity:hash}],
  filesSha256: {'core.apk':hash,'server.apk':hash,'panel.apk':hash,'kernel.apk':hash,'own.adb':hash,'upstream.adb':hash,
   'foxhole-openwrt-apk.pem':ownAuthority,'upstream.pem':upstreamAuthority}, platformPackages:{kernel:'6.12-r1'},
  rootPackages:['foxcore-cli','foxhole-openwrt-client','hysteria'],
  corePackage:{file:'core.apk',sha256:hash,binarySha256:hash,producerSha256:hash,payloadVerified:true},
  serverPackage:{file:'server.apk',sha256:hash,binarySha256:hash,producerSha256:hash,payloadVerified:true},
  compressedBytes:2048, installedFlashBytes:8192, installedRamBytes:0,
  dependencyInstalledBytes:2048, stagingBytes:13688, flashReserveBytes:1024, ramReserveBytes:1024,
  runtimeMemoryBytes:4096, requiredFlashBytes:9216, requiredRamBytes:18808,
  memoryEvidence:{schema:1,type:'conservative',runtimeMemoryBytes:4096,description:'Synthetic policy fixture'} };
};
let passed = 0;
function equal(value, expected) { if (sprintf('%J',value) != sprintf('%J',expected)) die('assertion'); };
function rejects(fn) { let rejected = false; try { fn(); } catch (_) { rejected = true; } equal(rejected,true); };
function test(name, fn) { fn(); passed++; print('ok ',name,'\n'); };
test('default is exact HY2 variant on the exact firmware target', () => {
 equal(plan.selection(catalog,'x86_64','25.12.5','',false,'x86/64').id,'x86-hy2');
 rejects(() => plan.selection(catalog,'x86_64','25.12.4','',false,'x86/64'));
 rejects(() => plan.selection(catalog,'x86_64','25.12.5','',false,'other/board'));
 rejects(() => plan.selection(catalog,'x86_64','25.12.5','vless',false,'x86/64'));
 rejects(() => plan.selection(catalog,'x86_64','25.12.5','all',false,'x86/64'));
});
test('empty, mismatched and negative package budgets are refused', () => {
 let value=fixture(); value.packages=[]; rejects(() => plan.budget(value,variant,'flash',false));
 value=fixture(); value.installedFlashBytes=-1; rejects(() => plan.budget(value,variant,'flash',false));
 value=fixture(); value.filesSha256={}; rejects(() => plan.budget(value,variant,'flash',false));
 value=fixture(); value.platformPackages.kernel='other'; rejects(() => plan.budget(value,variant,'flash',false));
});
test('complete memory includes working set, staging, reserve and backup', () => {
 let value=plan.budget(fixture(),variant,'flash',false);
 equal(plan.fits(value,9216,18808,0),true);
 equal(plan.fits(value,9215,18808,0),false);
 equal(plan.fits(value,9216,18807,0),false);
 equal(plan.fits(value,9216,18808,1),false);
 value=fixture(); value.requiredRamBytes=6144; rejects(() => plan.budget(value,variant,'flash',false));
});
test('unsigned development receipts cannot become production budgets', () => {
 let value=fixture(); value.verification.signatures=false;
 rejects(() => plan.budget(value,variant,'flash',false));
 rejects(() => plan.budget(value,variant,'flash',true));
});
test('original index and key bytes are complete and role-bound', () => {
 let value=fixture(); value.trustKeyBytes=799; rejects(() => plan.budget(value,variant,'flash',false));
 value=fixture(); value.repositoryIndexes[1].trustKeyFiles=['foxhole-openwrt-apk.pem']; rejects(() => plan.budget(value,variant,'flash',false));
 value=fixture(); value.packageAuthentications[3].indexFile='own.adb'; rejects(() => plan.budget(value,variant,'flash',false));
 value=fixture(); value.stagingBytes=13687; value.requiredRamBytes=18807;
 rejects(() => plan.budget(value,variant,'flash',false));
});
test('RAM accounts for both native Core and incoming server payloads', () => {
 let value=fixture(); value.mode='ram';
 value.packages[0].name='foxcore-cli-ram';value.packageAuthentications[0].name='foxcore-cli-ram';
 value.packages[1].name='hysteria-server-ram';value.packageAuthentications[1].name='hysteria-server-ram';
 value.rootPackages=['foxcore-cli-ram','foxhole-openwrt-client','hysteria-server-ram'];
 value.volatileBinary={file:'core.bin',bytes:1024,sha256:hash};
 value.volatileDependencies=[{file:'server.bin',bytes:2048,sha256:hash,
  producerFile:variant.serverProducerFile,producerSha256:hash}];
 value.installedRamBytes=3072; value.stagingBytes+=3072; value.requiredRamBytes+=3072;
 equal(plan.budget(value,variant,'ram',false).installedRamBytes,3072);
 value.installedRamBytes=1024; rejects(() => plan.budget(value,variant,'ram',false));
 value.installedRamBytes=3072; value.volatileDependencies[0].file='core.bin';
 rejects(() => plan.budget(value,variant,'ram',false));
});
test('installed native evidence must bind exact packages and producers', () => {
 let value=fixture(); value.corePackage.producerSha256='other'; rejects(() => plan.budget(value,variant,'flash',false));
 value=fixture();value.serverPackage.file='core.apk'; rejects(() => plan.budget(value,variant,'flash',false));
 value=fixture();value.corePackage=null; rejects(() => plan.budget(value,variant,'flash',false));
});

const actualKernel = {"name":"kernel","version":"6.12.94~a7bc15f451f9652701ba04af9cfb0b95-r1","arch":"x86_64","depends":["libc"],"status":["installed"]};
const installedExpected = { kernel: { version: actualKernel.version, arch: 'x86_64' } };
test('actual stock installed kernel JSON preserves the exact ABI', () => {
 equal(plan.installedPackages([actualKernel],installedExpected),true);
});
test('installed query refuses wrong version, architecture and duplicate rows', () => {
 let value=json(sprintf('%J',actualKernel));value.version='6.12.94-r1';
 equal(plan.installedPackages([value],installedExpected),false);
 value=json(sprintf('%J',actualKernel));value.arch='other';
 equal(plan.installedPackages([value],installedExpected),false);
 equal(plan.installedPackages([actualKernel,actualKernel],installedExpected),false);
});
test('installed query refuses missing, malformed or broken installed status', () => {
 equal(plan.installedPackages([],installedExpected),false);
 equal(plan.installedPackages({},installedExpected),false);
 let value=json(sprintf('%J',actualKernel));delete value.status;
 equal(plan.installedPackages([value],installedExpected),false);
 value=json(sprintf('%J',actualKernel));value.status=['installed','broken-files'];
 equal(plan.installedPackages([value],installedExpected),false);
 value=json(sprintf('%J',actualKernel));value.status=['available'];
 equal(plan.installedPackages([value],installedExpected),false);
});
test('installed dependency evidence must include the exact kernel constraint', () => {
 let row={name:'kmod-tun',version:'6.12.94-r1',arch:'x86_64',status:['installed'],depends:['kernel='+actualKernel.version]};
 let expected={'kmod-tun':{version:row.version,arch:row.arch,dependency:'kernel='+actualKernel.version}};
 equal(plan.installedPackages([row],expected),true);
 row.depends=[];equal(plan.installedPackages([row],expected),false);
 row.depends=['kernel=other'];equal(plan.installedPackages([row],expected),false);
 row.depends='kernel='+actualKernel.version;equal(plan.installedPackages([row],expected),false);
});
print('Installation-plan source fixtures: ',passed,'; no actual APK acceptance implied\n');
