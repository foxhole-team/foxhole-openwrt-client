"""Run the WHOLE production runtime apply path with closed synthetic I/O imports."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,shutil,tempfile
ROOT=Path(__file__).resolve().parents[1]
RUNTIME=ROOT/'package/foxhole-openwrt-client/root/usr/libexec/foxhole-runtime'
ADAPTER=ROOT/'package/foxhole-openwrt-client/root/usr/share/foxhole/core-adapter.uc'
CORE=ROOT/'package/foxhole-openwrt-client/root/usr/share/foxhole/core-model.uc'
OUT=None
U=None
CASES=[
 ('fast_policy',{'policyDelay':0},True),
 ('actual_5640ms_policy',{'policyDelay':5640},True),
 ('near_expiry_initial_proof',{'policyDelay':2,'initialAge':4989},True),
 ('final_checks_5000ms',{'policyDelay':5640,'finalKernelDelay':5000},False),
 ('final_owner_5000ms',{'policyDelay':5640,'finalOwnerDelay':5000},False),
 ('post_probe_owner_lost',{'policyDelay':5640,'mutation':'owner_lost'},False),
 ('post_probe_generation_changed',{'policyDelay':5640,'mutation':'generation'},False),
 ('post_probe_state_changed',{'policyDelay':5640,'mutation':'state'},False),
 ('post_probe_server_config_changed',{'policyDelay':5640,'mutation':'state_config'},False),
 ('post_probe_config_changed',{'policyDelay':5640,'mutation':'config'},False),
 ('post_probe_kernel_changed',{'policyDelay':5640,'mutation':'kernel'},False),
 ('synthetic_selection_cleared_during_probe',{'policyDelay':5640,'mutation':'selection_cleared'},False),
 ('authenticated_probe_failure_saved_consent',{'policyDelay':5640,'mutation':'probe_failure'},False),
 ('initial_wrong_generation',{'policyDelay':0,'initialMutation':'generation'},False),
 ('initial_future_proof',{'policyDelay':0,'initialMutation':'future'},False),
 ('initial_unvalidated_proof',{'policyDelay':0,'initialMutation':'unvalidated'},False),
 ('initial_expired_proof',{'policyDelay':0,'initialAge':4991},False),
]
STATE=r'''import * as digest from 'digest';
export const memory={clock:100000,files:{},commands:[],probes:0,owners:0,kernels:0,exitCode:0,connectedPublications:[],policyDelay:0,finalKernelDelay:0,finalOwnerDelay:0,mutation:null,initialMutation:null,initialAge:0,key:'1111111111111111',kernel:'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',stopped:false};
export function setup(options){
 for(let k,v in options)memory[k]=v;
 let state={activeServerId:'fixture-server',settings:{localRules:false,localScope:'LAN',killSwitch:true},devices:[],sites:[],countries:[],servers:[{id:'fixture-server',engine:'core',config:'fixture-config-with-saved-TLS-consent'}]};
 memory.files['/etc/foxhole/state.json']=sprintf('%J',state);
 memory.files['/tmp/foxhole/core.json']=state.servers[0].config;
 memory.files['/tmp/foxhole/core-state.json']='{"phase":"running","pid":123,"process_start":99,"ifindex":7,"tun_fd":3,"generation":12345}';
 let proof={generation_key:memory.key,serverId:'fixture-server',checkedUptimeMs:memory.clock-memory.initialAge,bootId:'fixture-boot',configIdentity:digest.sha256(state.servers[0].config),validated:true};
 if(memory.initialMutation=='generation')proof.generation_key='2222222222222222';
 if(memory.initialMutation=='future')proof.checkedUptimeMs=memory.clock+1;
 if(memory.initialMutation=='unvalidated')proof.validated=false;
 memory.files['/tmp/foxhole/core-proof.json']=sprintf('%J',proof);
};
'''
MOCKS={
'fixture-fs.uc':r'''import { memory } from './fixture-state.uc';
export function stat(path){
 if(path in memory.files)return {type:'file',size:length(memory.files[path])};
 if(index(['/sys/class/net/foxhole0','/sys/class/net/br-lan'],path)>=0)return {type:'directory'};
 if(path=='/fixture/foxcore-cli')return {type:'file'};
 if(path=='/proc/123/exe')return {type:'file',dev:{major:1,minor:2},inode:3};
 return null;
};
export function readfile(path,limit){
 if(path=='/proc/sys/kernel/random/boot_id')return 'fixture-boot';
 if(path=='/proc/uptime')return sprintf('%d.%03d 0.0',int(memory.clock/1000),memory.clock%1000);
 if(path=='/sys/class/net/foxhole0/ifindex')return '7\n';
 if(path=='/dev/urandom'&&limit==12)return 'abcdefghijkl';
 if(path=='/etc/passwd')return 'dnsmasq:x:453:453:fixture:/var:/bin/false\n';
 if(path in memory.files)return memory.files[path];
 die('fixture_refused_real_read');
};
export function writefile(path,value){
 if(path=='/proc/sys/net/ipv4/conf/foxhole0/rp_filter')return length(value);
 if(path=='/var/run/foxhole.dnsmasq.new'){memory.files[path]=value;return length(value);}
 die('fixture_refused_real_write');
};
export function chmod(path,mode){if(path!='/var/run/foxhole.dnsmasq.new'||mode!=0o640)die('fixture_bad_chmod');return true;};
export function rename(from,to){if(from!='/var/run/foxhole.dnsmasq.new'||to!='/var/run/foxhole.dnsmasq')die('fixture_bad_rename');memory.files[to]=memory.files[from];delete memory.files[from];return true;};
export function open(path,mode){if(path!='/tmp/foxhole/core-probe.lock'||mode!='a+')die('fixture_bad_lock');return {lock:kind=>true,close:()=>true};};
export function unlink(path){if(!(path in memory.files))return false;delete memory.files[path];return true;};
''',
'fixture-store.uc':r'''import { memory } from './fixture-state.uc';
export function directory(path){if(path!='/tmp/foxhole'&&path!='/tmp/foxhole/countries')die('fixture_bad_directory');};
export function read(path,limit){if(!(path in memory.files))return null;return memory.files[path];};
export function write(path,value){
 if(index(['/tmp/foxhole/policy.nft','/tmp/foxhole/core-policy.json','/tmp/foxhole/core-proof.json','/tmp/foxhole/runtime.json'],path)<0)die('fixture_bad_store_write');
 memory.files[path]=value;
 if(path=='/tmp/foxhole/runtime.json'){
  let s=json(value);if(s.connected){let proof=json(memory.files['/tmp/foxhole/core-proof.json']);push(memory.connectedPublications,{age:memory.clock-proof.checkedUptimeMs,probes:memory.probes});}
 }
};
''',
'fixture-registry.uc':r'''export function current_binary(){return '/fixture/foxcore-cli';};''',
'fixture-system.uc':r'''import { memory } from './fixture-state.uc';
export function system(argv,timeout){
 if(type(argv)=='array'&&length(argv)==3&&argv[0]=='/bin/sh'&&argv[1]=='-c'){
  let cmd=argv[2],capture=match(cmd,/ >([^ ]+) 2>\/dev\/null$/);if(!capture||!match(capture[1],/^\/tmp\/foxhole\/(receipt|kernel)-[a-f0-9]{24}$/))die('fixture_bad_native_capture');
  let value;
  if(index(cmd,'/fixture/foxcore-cli owner --state ')>=0){
   if(timeout!=3000)die('fixture_owner_timeout');memory.owners++;if(memory.probes)memory.clock+=memory.finalOwnerDelay;value=memory.stopped?null:{owned:true,generation_key:memory.key};
  }else if(index(cmd,'/fixture/foxcore-cli probe --state ')>=0){
   if(timeout!=43000)die('fixture_probe_timeout');memory.probes++;if(memory.probes>1)die('fixture_probe_retry_or_fallback');memory.clock+=10;
   let saved=json(memory.files['/etc/foxhole/state.json']);
   if(memory.mutation=='owner_lost'||memory.mutation=='selection_cleared')memory.stopped=true;
   if(memory.mutation=='selection_cleared'){saved.activeServerId=null;memory.files['/etc/foxhole/state.json']=sprintf('%J',saved);}
   if(memory.mutation=='generation')memory.key='2222222222222222';
   if(memory.mutation=='state'){saved.settings.killSwitch=false;memory.files['/etc/foxhole/state.json']=sprintf('%J',saved);}
   if(memory.mutation=='state_config'){saved.servers[0].config='changed-server-config';memory.files['/etc/foxhole/state.json']=sprintf('%J',saved);}
   if(memory.mutation=='config')memory.files['/tmp/foxhole/core.json']='changed-during-authenticated-probe';
   if(memory.mutation=='kernel')memory.kernel='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
   value={validated:memory.mutation!='probe_failure'&&memory.mutation!='selection_cleared',generation_key:memory.key};
  }else{
   if(timeout!=3000)die('fixture_kernel_timeout');
   if(index(cmd,'/usr/libexec/ip-full -j -4 route get ')>=0){memory.kernels++;if(memory.kernels>1)memory.clock+=memory.finalKernelDelay;value=[{dev:'foxhole0',type:'unicast'}];}
   else if(index(cmd,'/usr/libexec/ip-full -j -6 route get ')>=0)value=[{dev:'foxhole0',type:'unicast'}];
   else if(index(cmd,'/usr/sbin/nft -j list chain inet foxhole ')>=0)value={nftables:[{rule:{expr:[{fixturePolicy:memory.kernel}]}}]};
   else die('fixture_foreign_kernel_command');
  }
  memory.files[capture[1]]=sprintf('%J',value);return 0;
 }
 if(type(argv)!='array'||index(['/usr/sbin/nft','/usr/libexec/ip-full','/usr/libexec/foxhole-dnsmasq'],argv[0])<0)die('fixture_refused_real_system');
 push(memory.commands,{argv,timeout});
 if(argv[0]=='/usr/sbin/nft'&&argv[1]=='-f'){memory.clock+=memory.policyDelay;memory.policyDelay=0;}
 if(argv[0]=='/usr/libexec/ip-full'&&argv[1]=='delete-fixture-rule')return 1;
 return 0;
};
export function exit(code){memory.exitCode=code;};
''',
'fixture-model.uc':r'''export function validate_state(state){return state;};''',
'fixture-runtime.uc':r'''export function active_server(state){return filter(state.servers,s=>s.id==state.activeServerId)[0];};
export function constants(){return {tunName:'foxhole0'};};
export function nft_config(state,options){return 'fixture-nft';};
export function dnsmasq_config(sites){return 'fixture-dns';};
export function route_commands(connected){return {delete4:['delete-fixture-rule'],delete6:['delete-fixture-rule'],route4:['fixture-route4'],route6:['fixture-route6'],rule4:['fixture-rule4'],rule6:['fixture-rule6']};};
''',
'fixture-uci.uc':r'''export function cursor(){return {get:(a,b,c)=>c=='lan_devices'?['br-lan']:'1',unload:()=>true};};''',
'fixture-ubus.uc':r'''export function connect(){die('fixture_unexpected_ubus');};''',
}
def transformed(raw,root):
 text=raw.decode();replacements={
  "from 'fs'":"from '"+str(root/'fixture-fs.uc')+"'",
  "from 'ubus'":"from '"+str(root/'fixture-ubus.uc')+"'",
  "from 'uci'":"from '"+str(root/'fixture-uci.uc')+"'",
  "from '/usr/share/foxhole/model.uc'":"from '"+str(root/'fixture-model.uc')+"'",
  "from '/usr/share/foxhole/runtime-model.uc'":"from '"+str(root/'fixture-runtime.uc')+"'",
  "from '/usr/share/foxhole/core-model.uc'":"from '"+str(root/'core-model.actual.uc')+"'",
  "from '/usr/share/foxhole/core-adapter.uc'":"from '"+str(root/'adapter.actual.uc')+"'",
  "from '/usr/share/foxhole/private-store.uc'":"from '"+str(root/'fixture-store.uc')+"'"}
 for before,after in replacements.items():assert text.count(before)==1;text=text.replace(before,after)
 insertion="\nimport { system, exit } from '"+str(root/'fixture-system.uc')+"';\nimport { memory, setup } from '"+str(root/'fixture-state.uc')+"';\nsetup("+json.dumps(CURRENT_OPTIONS,separators=(',',':'))+");\n"
 anchor="import * as digest from 'digest';";assert text.count(anchor)==1;text=text.replace(anchor,anchor+insertion)
 reverse=text.replace(insertion,'')
 for before,after in replacements.items():reverse=reverse.replace(after,before)
 assert reverse.encode()==raw
 return text+"\nprintf('%J',{exitCode:memory.exitCode,clock:memory.clock,probes:memory.probes,kernels:memory.kernels,connected:memory.connectedPublications,status:memory.files['/tmp/foxhole/runtime.json'],state:memory.files['/etc/foxhole/state.json']});\n"
def run_cases():
 global CURRENT_OPTIONS
 os.umask(0o077)
 results=[]
 for variant,name in(('GREEN','current-source'),):
  raw=RUNTIME.read_bytes()
  for case,options,expect_connected in CASES:
   root=OUT/(variant+'-'+case);root.mkdir(mode=0o700)
   for n,text in {'fixture-state.uc':STATE,**MOCKS}.items():(root/n).write_text(text)
   (root/'core-model.actual.uc').write_bytes(CORE.read_bytes());CURRENT_OPTIONS=options
   adapter_raw=ADAPTER.read_bytes();adapter_text=adapter_raw.decode();adapter_replacements={"from 'fs'":"from '"+str(root/'fixture-fs.uc')+"'","from './core-model.uc'":"from '"+str(root/'core-model.actual.uc')+"'","from './private-store.uc'":"from '"+str(root/'fixture-store.uc')+"'","from './engine-registry.uc'":"from '"+str(root/'fixture-registry.uc')+"'"}
   for a,z in adapter_replacements.items():assert adapter_text.count(a)==1;adapter_text=adapter_text.replace(a,z)
   adapter_insert="\nimport { system } from '"+str(root/'fixture-system.uc')+"';\n";adapter_text=adapter_text.replace("import * as digest from 'digest';","import * as digest from 'digest';"+adapter_insert);reverse=adapter_text.replace(adapter_insert,'')
   for a,z in adapter_replacements.items():reverse=reverse.replace(z,a)
   assert reverse.encode()==adapter_raw;(root/'adapter.actual.uc').write_text(adapter_text)
   code=transformed(raw,root);(root/'whole-runtime.fixture.uc').write_text(code)
   q=subprocess.run([U,'-e',code,'--','apply','connected'],capture_output=True,timeout=10)
   (root/'stdout.bin').write_bytes(q.stdout);(root/'stderr.bin').write_bytes(q.stderr)
   if q.returncode!=0:
    (OUT/'first-command-failure.stdout.bin').write_bytes(q.stdout);(OUT/'first-command-failure.stderr.bin').write_bytes(q.stderr)
    (OUT/'first-command-failure.json').write_text(json.dumps({'schema':1,'variant':variant,'case':case,'returncode':q.returncode,'stdoutBytes':len(q.stdout),'stderrBytes':len(q.stderr),'stdoutSha256':hashlib.sha256(q.stdout).hexdigest(),'stderrSha256':hashlib.sha256(q.stderr).hexdigest(),'rawSavedBeforeAssertion':True})+'\n')
   assert q.returncode==0,'Whole-runtime native fixture failed: '+q.stderr[:8192].decode(errors='replace')
   value=json.loads(q.stdout);status=json.loads(value['status']);state=json.loads(value['state'])
   connected=value['exitCode']==0 and status['connected']is True
   passed=connected==expect_connected
   if expect_connected:passed=passed and len(value['connected'])==1 and value['connected'][0]['age']<=4990 and (variant=='RED'or value['probes']==1)
   elif options.get('initialMutation')or options.get('initialAge',0)>4990:passed=passed and value['probes']==0
   else:passed=passed and value['probes']<=1 and not value['connected']
   if options.get('mutation')not in('state','selection_cleared'):passed=passed and state['settings']['killSwitch']is True
   if options.get('mutation')!='state_config':passed=passed and state['servers'][0]['config']=='fixture-config-with-saved-TLS-consent'
   results.append({'variant':variant,'case':case,'passed':passed,'runtimeExitCode':value['exitCode'],'probes':value['probes'],'connectedPublications':value['connected'],'stdoutSha256':hashlib.sha256(q.stdout).hexdigest(),'stderrSha256':hashlib.sha256(q.stderr).hexdigest()})
 failed=[r for r in results if not r['passed']]
 print('Native runtime publication cases: '+str(len(results)-len(failed))+' passed, '+str(len(failed))+' failed')
 for row in failed:print(json.dumps(row),file=sys.stderr)
 return 1 if failed else 0

def main():
 global U,OUT
 U=shutil.which('ucode')
 if U is None:raise SystemExit('Required native ucode unavailable')
 for path in (RUNTIME,ADAPTER,CORE):assert path.is_file()and not path.is_symlink()and 0<path.stat().st_size<=262144
 with tempfile.TemporaryDirectory(prefix='foxhole-runtime-publication-native-')as directory:
  OUT=Path(directory);return run_cases()
if __name__=='__main__':raise SystemExit(main())
