// RAM-stage variant of engine-capture.uc: path/limits and command admission only.
'use strict';
import * as fs from 'fs';
import * as digest from 'digest';
const mode=ARGV[0], roles=['stdout','stderr','timer','native'];
function fail(){exit(mode=='poll'?20:1);};
function process(pid){
 if(!match(''+pid,/^[1-9][0-9]{0,6}$/)||+pid<2)fail();
 let text=fs.readfile('/proc/'+pid+'/stat',8192),found=match(text||'',/^([0-9]+) \(.*\) (.*)$/);
 if(!found)return null;
 let fields=split(trim(found[2]),/ +/),info=fs.stat('/proc/'+pid),command=fs.readfile('/proc/'+pid+'/cmdline',524289);
 if(!info||command==null)return null;
 if(+found[1]!=+pid||length(fields)<20||info.uid!=0||length(command)>524288)fail();
 return {pid:+pid,parent:+fields[1],state:fields[0],start:fields[19],hash:digest.sha256(command),command};
};
function unpack(value){let m=match(value||'',/^([1-9][0-9]{0,6}):([0-9]+):([a-f0-9]{64})$/);if(!m)fail();return {pid:+m[1],start:m[2],hash:m[3]};};
function main_live(owner){let expected=unpack(owner),current=process(expected.pid);return current&&current.start==expected.start&&current.hash==expected.hash&&current.state!='Z';};
function ram_directory(path){
 if(!match(path||'',/^\/tmp\/foxhole-ram[.-][A-Za-z0-9_.-]{6,80}$/))fail();
 let tmp=fs.lstat('/tmp'),s=fs.lstat(path);
 if(tmp?.type!='directory'||tmp.uid!=0||(tmp.mode&0o022)&&((tmp.mode&0o7777)!=0o1777)||
  s?.type!='directory'||s.uid!=0||(s.mode&0o7777)!=0o700)fail();
};
function private_stage(path){
 if(!match(path||'',/^\/tmp\/foxhole-ram[.-][A-Za-z0-9_.-]{6,80}\/native-[a-f0-9]{24}\.io$/))fail();
 ram_directory(fs.dirname(path));
 let parent=fs.lstat(fs.dirname(path)),value=fs.lstat(path);
 if(parent?.type!='directory'||parent.uid!=0||(parent.mode&0o7777)!=0o700||value?.type!='directory'||value.uid!=0||(value.mode&0o7777)!=0o700)fail();
};
function read(path,maximum){let info=fs.lstat(path);if(info?.type!='file'||info.uid!=0||info.nlink!=1||(info.mode&0o7777)!=0o600||info.size<1||info.size>maximum)fail();let raw=fs.readfile(path,maximum+1);if(raw==null||length(raw)!=info.size)fail();return raw;};
function write(path,raw){let f=fs.open(path,'wxe',0o600);if(!f||f.write(raw)!=length(raw)||f.flush()!=true)fail();f.close();};
function state(path,owner){private_stage(path);let value=json(read(path+'/owner.json',4096));if(value.owner!=owner)fail();return value;};
function replace_state(path,value){write(path+'/owner.new',sprintf('%J',value));if(!fs.rename(path+'/owner.new',path+'/owner.json'))fail();};
function prefix(path,role,owner){if(index(roles,role)<0)fail();return '/bin/sh\x00'+path+'/helper\x00--owned-child\x00'+path+'\x00'+role+'\x00'+owner+'\x00';};
function initial(value,path,role,owner){return value&&value.parent==unpack(owner).pid&&(index(value.command,prefix(path,role,owner))==0||value.hash==unpack(owner).hash);};
function pending_marker(info){return info?.type=='file'&&info.uid==0&&info.nlink==1&&(info.mode&0o7777)==0o600&&info.size==0;};
function child(path,role,owner,pid){
 state(path,owner);if(index(roles,role)<0)fail();let record=path+'/'+role+'.owner.json',current=process(pid);
 if(!current||current.state=='Z')return null;
 let marker=fs.lstat(record);
 if(marker&&marker.size>0){
  let value=json(read(record,4096));if(value.owner!=owner||value.role!=role||value.pid!=+pid)fail();
  if(current.start!=value.start)return null;
  // Prove the generation before exec; RAM launchers may exec again.
  if(current.parent!=unpack(owner).pid)fail();return {pid:+pid,start:value.start};
 }
 if(marker&&!pending_marker(marker))fail();
 if(!initial(current,path,role,owner))fail();return {pid:+pid,start:current.start};
};
function child_live(value,parent){let current=process(value.pid);if(!current||current.start!=value.start||current.state=='Z')return false;if(current.parent!=parent)fail();return true;};
function signal_child(value,parent,number){if(!child_live(value,parent))return;if(system(['/bin/sh','-c','kill -'+number+' "$1"','owned-capture',''+value.pid],100)!=0&&child_live(value,parent))fail();};

function protected_parents(path){
 if(!match(path||'',/^\/[A-Za-z0-9_.~+:\/-]+$/)||match(path,/\/(\.|\.\.)(\/|$)/))fail();
 for(let p=path;;p=fs.dirname(p)){
  let s=fs.lstat(p);
  if(s?.type!='directory'||s.uid!=0||(s.mode&0o022)&&!(p=='/tmp'&&(s.mode&0o7777)==0o1777))fail();
  if(p=='/')break;
 }
};
function public_raw(path,maximum){
 protected_parents(fs.dirname(path));let a=fs.lstat(path);
 if(a?.type!='file'||a.uid!=0||a.nlink!=1||(a.mode&0o022)||a.size<1||a.size>maximum)fail();
 let raw=fs.readfile(path,maximum+1),b=fs.lstat(path);
 if(raw==null||length(raw)!=a.size||
  sprintf('%J',[a.type,a.uid,a.gid,a.mode,a.dev,a.inode,a.nlink,a.size,a.mtime,a.ctime])!=
  sprintf('%J',[b?.type,b?.uid,b?.gid,b?.mode,b?.dev,b?.inode,b?.nlink,b?.size,b?.mtime,b?.ctime]))fail();return raw;
};
function log_role(value){return index(['signature','index-dump','init','selected','simulate','apply','installed'],value)>=0;};
function deadline(value){if(!match(value||'',/^[0-9]+$/)||+value<1000||+value>180000)fail();};
function constraints(args){
 if(length(args)<2||length(args)>129)fail();
 for(let arg in args)if(!match(arg,/^([A-Za-z0-9][A-Za-z0-9_.+-]{0,127}><X1[a-f0-9]{40}|foxhole-openwrt-client=[0-9]+\.[0-9]+\.[0-9]+-r[1-9][0-9]{0,5})$/))fail();
};
function admit_command(stage,args){
 ram_directory(stage);if(length(args)<2||length(args)>160||args[0]!='/usr/bin/apk')fail();
 let size=0;for(let arg in args){if(type(arg)!='string'||length(arg)>512||match(arg,/[[:cntrl:]]/))fail();size+=length(arg);}
 if(size>65536)fail();
 let options={},at=1;
 for(;at<length(args)&&substr(args[at],0,2)=='--';at++){
  let arg=args[at];if(options[arg]!=null)fail();
  if(index(['--root','--arch','--keys-dir','--repositories-file'],arg)>=0){
   if(++at>=length(args))fail();options[arg]=args[at];
  }else if(index(['--no-network','--no-cache','--scripts=no','--commit-hooks=no','--logfile=no'],arg)>=0)options[arg]=true;
  else fail();
 }
 if(options['--no-network']!=true||options['--no-cache']!=true||at>=length(args))fail();
 let command=args[at++],rest=slice(args,at);
 if(options['--root']==null){
  for(let key in keys(options))if(index(['--no-network','--no-cache','--keys-dir'],key)<0)fail();
  let input=null;
  if(command=='verify'&&length(rest)==1){
   let keydir=options['--keys-dir'];
   if(type(keydir)!='string'||index(keydir,stage+'/repositories/')!=0||!match(keydir,/\/keys$/))fail();
   protected_parents(keydir);input=rest[0];
  }else if(command=='adbdump'&&length(rest)==3&&rest[0]=='--format'&&rest[1]=='json'&&options['--keys-dir']==null)input=rest[2];
  else fail();
  let parts=split(input||'','/'),leaf=parts[length(parts)-1];
  if(length(leaf)>255||index(input||'',stage+'/repositories/')!=0||!match(input,/\/(packages\.adb|[A-Za-z0-9][A-Za-z0-9_.~+:-]{0,254}\.apk)$/))fail();
  public_raw(input,8388608);return;
 }
 if(options['--root']!=stage+'/root'||index(['x86_64','aarch64_cortex-a53'],options['--arch'])<0||
  options['--keys-dir']!=stage+'/keys'||options['--repositories-file']!=stage+'/repositories.list'||
  options['--logfile=no']!=true)fail();
 protected_parents(stage+'/root');protected_parents(stage+'/keys');public_raw(stage+'/repositories.list',65536);
 if(command=='add'){
  if(options['--scripts=no']!=true||options['--commit-hooks=no']!=true||length(keys(options))!=9)fail();
  if(length(rest)==1&&rest[0]=='--initdb')return;
  if(rest[0]=='--simulate')rest=slice(rest,1);
  constraints(rest);return;
 }
 if(command!='query'||options['--scripts=no']!=null||options['--commit-hooks=no']!=null||length(keys(options))!=7)fail();
 let selected=['--from','repositories','--recursive','--fields','name,version,arch,installed-size','--format','json'];
 let installed=['--from','installed','--installed','--all-matches','--fields','name,version,arch,installed-size,status','--format','json','*'];
 if(sprintf('%J',rest)==sprintf('%J',installed))return;
 if(sprintf('%J',slice(rest,0,length(selected)))!=sprintf('%J',selected))fail();constraints(slice(rest,length(selected)));
};
if(mode=='lock'){
 let stage=ARGV[1];ram_directory(stage);let path=stage+'/native-capture.lock',s=fs.lstat(path);
 if(!s){write(path,'');s=fs.lstat(path);}
 if(s?.type!='file'||s.uid!=0||s.nlink!=1||(s.mode&0o7777)!=0o600||s.size!=0)fail();exit(0);
}
if(mode=='setup'){
 let stage=ARGV[1],log=ARGV[2],milliseconds=ARGV[3],helper=ARGV[4],utility=ARGV[5];
 ram_directory(stage);if(!log_role(log))fail();deadline(milliseconds);admit_command(stage,slice(ARGV,6));
 let raw_helper=public_raw(helper,32768),raw_utility=public_raw(utility,32768);
 for(let extension in ['.stdout','.stderr']){
  let path=stage+'/'+log+extension,s=fs.lstat(path),maximum=log=='index-dump'&&extension=='.stdout'?16777216:1048576;
  if(s){if(s.type!='file'||s.uid!=0||s.nlink!=1||(s.mode&0o7777)!=0o600||s.size>maximum||!fs.unlink(path))fail();}
 }
 let random=fs.readfile('/dev/urandom',12);if(length(random||'')!=12)fail();
 let path=stage+'/native-'+hexenc(random)+'.io';if(fs.lstat(path)||!fs.mkdir(path,0o700))fail();
 write(path+'/helper',raw_helper);write(path+'/utility.uc',raw_utility);print(path);exit(0);
}
if(mode=='arguments'){
 let path=ARGV[1],stage=fs.dirname(path),output=ARGV[2],error=ARGV[3],milliseconds=ARGV[4];private_stage(path);deadline(milliseconds);
 let found=match(output||'',/\/([a-z-]+)\.stdout$/),log=found?found[1]:null;
 if(!log_role(log)||output!=stage+'/'+log+'.stdout'||error!=stage+'/'+log+'.stderr'||fs.lstat(output)||fs.lstat(error))fail();
 admit_command(stage,slice(ARGV,5));exit(0);
}

if(mode=='owner'){
 let self=+match(fs.readfile('/proc/self/stat',8192),/^([0-9]+) /)[1],mine=process(self),value=process(ARGV[1]);if(!value||mine.parent!=value.pid)fail();print(value.pid+':'+value.start+':'+value.hash);exit(0);
}
if(mode=='prepare'){
 let path=ARGV[1],owner=ARGV[2];private_stage(path);if(!main_live(owner)||fs.lstat(path+'/owner.json')||fs.lstat(path+'/stdout')||fs.lstat(path+'/stderr'))fail();
 for(let name in ['helper','utility.uc'])read(path+'/'+name,32768);write(path+'/owner.json',sprintf('%J',{owner,pipes:{}}));exit(0);
}
if(mode=='makepipe'){
 let path=ARGV[1],owner=ARGV[2],name=ARGV[3],value=state(path,owner);if(index(['stdout','stderr'],name)<0||value.pipes[name]!=null||fs.lstat(path+'/'+name))fail();
 // Reserve the absent path before mkfifo to own partial failures.
 value.pipes[name]={reserved:true,identity:null};replace_state(path,value);
 let code=system(['mkfifo','-m','600',path+'/'+name],1000),info=fs.lstat(path+'/'+name);
 if(info?.type!='fifo'||info.uid!=0||info.nlink!=1||(info.mode&0o7777)!=0o600)fail();
 value.pipes[name].identity={inode:info.inode,dev:info.dev};replace_state(path,value);if(code!=0)fail();exit(0);
}
if(mode=='register'){
 let path=ARGV[1],role=ARGV[2],owner=ARGV[3],pid=+ARGV[4];state(path,owner);
 let self=+match(fs.readfile('/proc/self/stat',8192),/^([0-9]+) /)[1],mine=process(self),value=process(pid);
 if(!main_live(owner)||mine.parent!=pid||!initial(value,path,role,owner))fail();
 write(path+'/'+role+'.owner.json',sprintf('%J',{owner,role,pid,start:value.start,birthCommandSha256:value.hash,registeredBeforeBlockingOrExec:true}));exit(0);
}
if(mode=='ready'){
 let path=ARGV[1],role=ARGV[2],owner=ARGV[3],pid=+ARGV[4],record_path=path+'/'+role+'.owner.json';
 for(let attempt=0;attempt<4;attempt++){
  state(path,owner);let value=process(pid),marker=fs.lstat(record_path);
  if(marker&&marker.size>0){
   if(role=='native'){
    let record=json(read(record_path,4096)),parent=unpack(owner).pid;
    if(record.owner!=owner||record.role!=role||type(record.pid)!='int'||record.pid!=pid||type(record.start)!='string'||!match(record.start,/^[0-9]{1,20}$/)||type(record.birthCommandSha256)!='string'||!match(record.birthCommandSha256,/^[a-f0-9]{64}$/)||type(record.registeredBeforeBlockingOrExec)!='bool'||record.registeredBeforeBlockingOrExec!=true)fail();
    if(value&&(value.start!=record.start||value.parent!=parent))fail();
    let present=fs.stat('/proc/'+pid),current=process(pid);
    if(!current){
     if(!present&&!fs.stat('/proc/'+pid))exit(0);
     if(sleep(50)!=true)fail();continue;
    }
    if(current.start!=record.start||current.parent!=parent)fail();exit(0);
   }
   if(!value||value.state=='Z'||!child(path,role,owner,pid))fail();exit(0);
  }
  if(!value||value.state=='Z')fail();if(marker&&!pending_marker(marker))fail();if(!initial(value,path,role,owner))fail();if(sleep(50)!=true)fail();
 }fail();
}
if(mode=='poll'){
 let path=ARGV[1],role=ARGV[2],owner=ARGV[3],pid=+ARGV[4];state(path,owner);
 if(index(['native','stdout','stderr'],role)<0||!match(''+pid,/^[1-9][0-9]{0,6}$/)||pid<2||!main_live(owner))fail();
 let record=json(read(path+'/'+role+'.owner.json',4096));
 if(record.owner!=owner||record.role!=role||record.pid!=pid||!match(record.start||'',/^[0-9]{1,20}$/))fail();
 let current=process(pid);
 if(!current){if(fs.stat('/proc/'+pid))fail();exit(0);}
 if(current.start!=record.start||current.parent!=unpack(owner).pid)fail();
 exit(current.state=='Z'?0:10);
}
if(mode=='stop'){
 let path=ARGV[1],role=ARGV[2],owner=ARGV[3],pid=+ARGV[4],value=child(path,role,owner,pid);if(!value)exit(0);let parent=unpack(owner).pid;
 signal_child(value,parent,'TERM');for(let i=0;i<4;i++){if(!child_live(value,parent))exit(0);if(sleep(50)!=true)fail();}
 signal_child(value,parent,'KILL');for(let i=0;i<4;i++){if(!child_live(value,parent))exit(0);if(sleep(50)!=true)fail();}if(child_live(value,parent))fail();exit(0);
}
if(mode=='drain'){
 let path=ARGV[1],maximum=+ARGV[2];if(!match(''+maximum,/^[0-9]+$/)||maximum<1||maximum>16777216||substr(path,length(path)-7)=='/stderr'&&maximum>1048576)fail();
 let info=fs.lstat(path);if(info?.type!='fifo'||info.uid!=0||info.nlink!=1||(info.mode&0o7777)!=0o600)fail();private_stage(fs.dirname(path));
 let input=fs.open(path,'re'),output=fs.fdopen(1,'w'),left=maximum,result=0;if(!input||!output)fail();
 while(true){let want=left<4096?left+1:4096,raw=input.read(want);if(raw==null){result=1;break;}let n=length(raw);if(n==0)break;
  let keep=n<left?n:left;if(keep&&output.write(substr(raw,0,keep))!=keep){result=1;break;}left-=keep;if(n>keep){result=1;break;}}
 if(output.flush()!=true)result=1;input.close();output.close();exit(result);
}
if(mode=='watch'){
 let path=ARGV[1],owner=ARGV[2],milliseconds=+ARGV[3];state(path,owner);if(!match(''+milliseconds,/^[0-9]+$/)||milliseconds<1000||milliseconds>180000||sleep(milliseconds)!=true)fail();
 if(!main_live(owner))exit(0);write(path+'/timeout','1');let value=unpack(owner);
 if(system(['/bin/sh','-c','kill -TERM "$1"','owned-capture',''+value.pid],100)!=0&&main_live(owner))fail();exit(0);
}
if(mode=='timedout'){let path=ARGV[1],owner=ARGV[2];state(path,owner);exit(fs.lstat(path+'/timeout')&&read(path+'/timeout',1)=='1'?0:1);}
if(mode=='clean'){
 let path=ARGV[1],owner=ARGV[2];private_stage(path);if(!fs.lstat(path+'/owner.json'))exit(0);let value=state(path,owner);
 for(let name in ['stdout','stderr']){let p=path+'/'+name,info=fs.lstat(p);if(!info)continue;let reserved=value.pipes[name];
  if(!reserved?.reserved||info.type!='fifo'||info.uid!=0||info.nlink!=1||(info.mode&0o7777)!=0o600||reserved.identity!=null&&sprintf('%J',{inode:info.inode,dev:info.dev})!=sprintf('%J',reserved.identity))fail();if(!fs.unlink(p))fail();}
 for(let role in roles){let p=path+'/'+role+'.owner.json',info=fs.lstat(p);if(!info)continue;if(pending_marker(info)){if(!fs.unlink(p))fail();continue;}let record=json(read(p,4096));if(record.owner!=owner||record.role!=role)fail();if(child(path,role,owner,record.pid))fail();if(!fs.unlink(p))fail();}
 if(fs.lstat(path+'/timeout')){if(read(path+'/timeout',1)!='1'||!fs.unlink(path+'/timeout'))fail();}
 if(fs.lstat(path+'/owner.new')){read(path+'/owner.new',4096);if(!fs.unlink(path+'/owner.new'))fail();}
 if(!fs.unlink(path+'/owner.json'))fail();exit(0);
}
fail();
