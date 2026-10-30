"""Exercise the complete real adapter's private caches through its public APIs."""
from pathlib import Path
import hashlib,json,os,subprocess,shutil,tempfile,sys
ROOT=Path(__file__).resolve().parents[1]
ADAPTER=ROOT/'package/foxhole-openwrt-client/root/usr/share/foxhole/core-adapter.uc'
CORE=ROOT/'package/foxhole-openwrt-client/root/usr/share/foxhole/core-model.uc'
OUT=None
U=None
STATE=r'''export const memory={clock:100000,files:{},ownerCalls:0,probeCalls:0,kernelCalls:0,owned:true,kernel:'old',mutation:null};
memory.files['/tmp/foxhole/core-state.json']='{"phase":"running","pid":123,"process_start":99,"ifindex":7,"tun_fd":3,"generation":12345}';
'''
MOCKS={
'fixture-fs.uc':r'''import { memory } from './fixture-state.uc';
export function stat(path){
 if(path=='/fixture/foxcore-cli')return {type:'file'};
 if(path=='/proc/123/exe')return {type:'file',dev:{major:1,minor:2},inode:3};
 die('cache_fixture_refused_stat');
};
export function readfile(path,limit){
 if(path=='/proc/uptime')return sprintf('%d.%03d 0.0',int(memory.clock/1000),memory.clock%1000);
 if(path=='/sys/class/net/foxhole0/ifindex')return '7\n';
 if(path=='/dev/urandom'&&limit==12)return 'abcdefghijkl';
 die('cache_fixture_refused_read');
};
export function unlink(path){if(!match(path,/^\/tmp\/foxhole\/(receipt|kernel)-[a-f0-9]{24}$/))die('cache_fixture_refused_unlink');delete memory.files[path];return true;};
''',
'fixture-store.uc':r'''import { memory } from './fixture-state.uc';
export function directory(path){if(path!='/tmp/foxhole')die('cache_fixture_bad_directory');};
export function read(path,limit){return memory.files[path]||null;};
''',
'fixture-registry.uc':r'''export function current_binary(){return '/fixture/foxcore-cli';};''',
'fixture-system.uc':r'''import { memory } from './fixture-state.uc';
export function system(argv,timeout){
 if(type(argv)!='array'||length(argv)!=3||argv[0]!='/bin/sh'||argv[1]!='-c')die('cache_fixture_refused_system');
 let cmd=argv[2],m=match(cmd,/ >([^ ]+) 2>\/dev\/null$/);if(!m||!match(m[1],/^\/tmp\/foxhole\/(receipt|kernel)-[a-f0-9]{24}$/))die('cache_fixture_bad_capture');
 let result;
 if(index(cmd,'/fixture/foxcore-cli owner --state ')>=0){
  if(timeout!=3000)die('cache_fixture_owner_timeout');memory.ownerCalls++;result={owned:memory.owned,generation_key:'1111111111111111'};
 }else if(index(cmd,'/fixture/foxcore-cli probe --state ')>=0){
  if(timeout!=43000)die('cache_fixture_probe_timeout');memory.probeCalls++;memory.clock+=10;
  if(memory.mutation=='owner'||memory.mutation=='failed')memory.owned=false;
  if(memory.mutation=='kernel'||memory.mutation=='failed')memory.kernel='changed';
  result={validated:memory.mutation!='failed',generation_key:'1111111111111111'};
 }else{
  if(timeout!=3000)die('cache_fixture_kernel_timeout');memory.kernelCalls++;
  if(index(cmd,'/usr/libexec/ip-full -j -4 route get ')>=0||index(cmd,'/usr/libexec/ip-full -j -6 route get ')>=0)result=[{dev:'foxhole0',type:'unicast'}];
  else if(index(cmd,'/usr/sbin/nft -j list chain inet foxhole ')>=0)result={nftables:[{rule:{expr:[{fixturePolicy:memory.kernel}]}}]};
  else die('cache_fixture_foreign_kernel_command');
 }
 memory.files[m[1]]=sprintf('%J',result);return 0;
};
''',
}
def transform(raw,root):
 text=raw.decode();replacements={"from 'fs'":"from '"+str(root/'fixture-fs.uc')+"'","from './core-model.uc'":"from '"+str(root/'core-model.actual.uc')+"'","from './private-store.uc'":"from '"+str(root/'fixture-store.uc')+"'","from './engine-registry.uc'":"from '"+str(root/'fixture-registry.uc')+"'"}
 for a,b in replacements.items():assert text.count(a)==1;text=text.replace(a,b)
 insertion="\nimport { system } from '"+str(root/'fixture-system.uc')+"';\n";anchor="import * as digest from 'digest';";assert text.count(anchor)==1;text=text.replace(anchor,anchor+insertion)
 rev=text.replace(insertion,'')
 for a,b in replacements.items():rev=rev.replace(b,a)
 assert rev.encode()==raw;return text
def run_cases():
 os.umask(0o077);rows=[]
 for variant,name in(('GREEN','current-source'),):
  for case in('stable','owner','kernel','failed','TTL_unchanged'):
   root=OUT/(variant+'-cache-'+case);root.mkdir(mode=0o700)
   for n,text in {'fixture-state.uc':STATE,**MOCKS}.items():(root/n).write_text(text)
   (root/'core-model.actual.uc').write_bytes(CORE.read_bytes());raw=ADAPTER.read_bytes();(root/'adapter.actual.uc').write_text(transform(raw,root))
   code="import * as a from '"+str(root/'adapter.actual.uc')+"';import {memory} from '"+str(root/'fixture-state.uc')+"';\n"
   code+="let o1=a.receipt('owner'),o2=a.receipt('owner');let k1=a.kernel_policy('1111111111111111','state'),k2=a.kernel_policy('1111111111111111','state');let warm={owners:memory.ownerCalls,kernels:memory.kernelCalls};\n"
   if case=='TTL_unchanged':
    code+="memory.clock+=240;a.receipt('owner');let ownerWithin=memory.ownerCalls;memory.clock+=20;a.receipt('owner');let ownerExpired=memory.ownerCalls;memory.clock=100990;a.kernel_policy('1111111111111111','state');let kernelWithin=memory.kernelCalls;memory.clock=101010;a.kernel_policy('1111111111111111','state');printf('%J',{warm,ownerWithin,ownerExpired,kernelWithin,kernelExpired:memory.kernelCalls});"
   else:
    code+="memory.mutation='"+case+"';let probe=a.receipt('probe');let afterOwner=a.receipt('owner');let afterKernel=a.kernel_policy('1111111111111111','state');printf('%J',{warm,probe,afterOwner,sameKernel:afterKernel==k1,ownerCalls:memory.ownerCalls,kernelCalls:memory.kernelCalls,probeCalls:memory.probeCalls});"
   q=subprocess.run([U,'-e',code],capture_output=True,timeout=10);(root/'stdout.bin').write_bytes(q.stdout);(root/'stderr.bin').write_bytes(q.stderr)
   if q.returncode!=0:
    (OUT/'first-cache-command-failure.stdout.bin').write_bytes(q.stdout);(OUT/'first-cache-command-failure.stderr.bin').write_bytes(q.stderr);(OUT/'first-cache-command-failure.json').write_text(json.dumps({'variant':variant,'case':case,'returncode':q.returncode,'rawSavedBeforeAssertion':True})+'\n')
   assert q.returncode==0,'Real-adapter native fixture failed: '+q.stderr[:8192].decode(errors='replace')
   v=json.loads(q.stdout);warm=v['warm']=={'owners':1,'kernels':7}
   if case=='TTL_unchanged':passed=warm and (v['ownerWithin'],v['ownerExpired'],v['kernelWithin'],v['kernelExpired'])==(1,2,7,14)
   else:passed=warm and v['ownerCalls']==2 and v['kernelCalls']==14 and v['probeCalls']==1 and v['afterOwner']['owned']==(case not in('owner','failed'))and v['sameKernel']==(case not in('kernel','failed'))and v['probe']['validated']==(case!='failed')
   rows.append({'variant':variant,'case':case,'passed':passed,'observation':v,'stdoutSha256':hashlib.sha256(q.stdout).hexdigest(),'stderrSha256':hashlib.sha256(q.stderr).hexdigest()})
 failed=[r for r in rows if not r['passed']]
 print('Native adapter probe cache cases: '+str(len(rows)-len(failed))+' passed, '+str(len(failed))+' failed')
 for row in failed:print(json.dumps(row),file=sys.stderr)
 return 1 if failed else 0

def main():
 global U,OUT
 U=shutil.which('ucode')
 if U is None:raise SystemExit('Required native ucode unavailable')
 for path in (ADAPTER,CORE):assert path.is_file()and not path.is_symlink()and 0<path.stat().st_size<=262144
 with tempfile.TemporaryDirectory(prefix='foxhole-adapter-probe-cache-native-')as directory:
  OUT=Path(directory);return run_cases()
if __name__=='__main__':raise SystemExit(main())
