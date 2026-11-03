'use strict';
function fail(reason) {die('RAM_RECOVERY_PREREQUISITE: '+reason+'\n');};
export function normalize(path,base) {
 if(type(path)!='string'||!length(path)||length(path)>512||!match(path,/^[A-Za-z0-9_+.,@=:\/-]+$/))fail('unsafe path');
 let parts=substr(path,0,1)=='/'?[]:split(base||'/','/'),result=[];
 for(let item in parts)if(length(item))push(result,item);
 for(let item in split(path,'/')) {
  if(!length(item)||item=='.')continue;
  if(item=='..') {if(!length(result))fail('path escapes namespace');pop(result);}
  else push(result,item);
 }
 return '/'+join('/',result);
};
export function resolve(path,lookup) {
 let wanted=normalize(path),links=[],seen={};
 for(let hop=0;hop<40;hop++) {
  let pieces=split(substr(wanted,1),'/'),at='',restart=false;
  for(let index=0;index<length(pieces);index++) {
   at+='/'+pieces[index];let row=lookup(at);
   if(!row)fail('missing '+at);
   if(row.uid!=0||(row.type!='link'&&(row.mode&0o022)&&!(at=='/tmp'&&row.ownedTemporaryInput==true&&(row.mode&0o7777)==0o1777)))fail('unprotected '+at);
   if(row.type=='link') {
    if(seen[at])fail('symlink loop');seen[at]=true;
    push(links,{path:at,target:row.target});
    let parent=join('/',slice(split(at,'/'),0,-1))||'/';
    wanted=normalize(row.target,parent)+(index+1<length(pieces)?'/'+join('/',slice(pieces,index+1)):'');
    restart=true;break;
   }
   if(index+1<length(pieces)) {if(row.type!='directory')fail('non-directory '+at);}
   else {if(row.type!='file'||row.nlink!=1||row.size<1||row.size>67108864)fail('non-regular '+at);return {path:at,row,links};}
  }
  if(!restart)break;
 }
 fail('symlink resolution limit');
};
export function same_file(current,persistent,current_hash,persistent_hash) {
 if(current.path!=persistent.path||sprintf('%J',current.links)!=sprintf('%J',persistent.links)||
  current.row.size!=persistent.row.size||(current.row.mode&0o7777)!=(persistent.row.mode&0o7777)||
  !match(current_hash||'',/^[a-f0-9]{64}$/)||current_hash!=persistent_hash)fail('persistent bytes differ');
 return true;
};
function integer(raw,offset,count) {
 if(offset<0||offset+count>length(raw))fail('ELF range');let value=0,scale=1;
 for(let i=0;i<count;i++){value+=ord(raw,offset+i)*scale;scale*=256;}
 if(value>9007199254740991)fail('ELF integer');return value;
};
export function elf_dependencies(read,size,machine) {
 let header=read(0,64);
 if(substr(header,0,4)!='\x7fELF')return null;
 if(ord(header,4)!=2||ord(header,5)!=1||integer(header,18,2)!=machine)fail('unsupported ELF ABI');
 let kind=integer(header,16,2);if(kind==1)return [];
 if(kind!=2&&kind!=3)fail('unsupported ELF type');
 let offset=integer(header,32,8),width=integer(header,54,2),count=integer(header,56,2);
 if(width!=56||count<1||count>64||offset+width*count>size)fail('ELF program headers');
 let table=read(offset,width*count),loads=[],dynamic=null,needed=[];
 for(let i=0;i<count;i++) {
  let at=i*width,type=integer(table,at,4),file=integer(table,at+8,8),bytes=integer(table,at+32,8);
  if(file+bytes>size)fail('ELF segment range');
  if(type==1)push(loads,{offset:file,address:integer(table,at+16,8),bytes});
  if(type==2){if(dynamic||bytes>65536)fail('ELF dynamic size');dynamic={offset:file,bytes};}
  if(type==3){let path=split(read(file,bytes),'\x00')[0];push(needed,normalize(path));}
 }
 if(!dynamic)return needed;
 let raw=read(dynamic.offset,dynamic.bytes),strings=null,maximum=0,indexes=[];
 for(let at=0;at+16<=length(raw);at+=16) {
  let tag=integer(raw,at,8),value=integer(raw,at+8,8);if(tag==0)break;
  if(tag==1)push(indexes,value);if(tag==5)strings=value;if(tag==10)maximum=value;
  if(tag==15||tag==29)fail('custom ELF library path');
 }
 if(!length(indexes))return needed;
 if(strings==null||maximum<1||maximum>262144)fail('ELF string table');
 let mappings=filter(loads,row=>strings>=row.address&&strings+maximum<=row.address+row.bytes);
 if(length(mappings)!=1)fail('ELF string mapping');
 let names=read(mappings[0].offset+strings-mappings[0].address,maximum);
 for(let at in indexes) {
  if(at>=maximum)fail('ELF needed range');let name=split(substr(names,at),'\x00')[0];
  if(!match(name,/^[A-Za-z0-9_+.-]{1,96}$/)||match(name,/\.\./))fail('unsafe ELF dependency');
  push(needed,name);
 }
 return needed;
};
export function legacy_launcher(hash) {
 return index(['73d93ba411aac9e91a6b0bc916d17d3c3bf8d0dbfa9f0a2d9cd74268669ca079',
  'c264e9a3b6f9bbfa5bd842c91101ffefc848da2f3f616d855150d1a379850286'],hash)>=0;
};
