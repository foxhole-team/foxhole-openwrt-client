'use strict';

function fail() { die('lan_unavailable'); };
function device(value) {
 return type(value)=='string' && match(value,/^[A-Za-z0-9_.:-]{1,32}$/)!=null;
};
function upstream(status) {
 if(index(['wan','wan6','loopback','pppoe'],status.interface)>=0)return true;
 let routes=status.route||[];
 if(type(routes)!='array'||length(routes)>128)fail();
 for(let i=0;i<length(routes);i++) {
  let row=routes[i];
  if(row.mask==0&&index(['0.0.0.0','::'],row.target)>=0)return true;
 }
 return false;
};
function private_address(value) {
 let bytes=type(value)=='string'?iptoarr(value):null;
 if(length(bytes||[])!=4)return null;
 if(bytes[0]==10||bytes[0]==172&&bytes[1]>=16&&bytes[1]<=31||bytes[0]==192&&bytes[1]==168)
  return arrtoip(bytes);
 return null;
};

export function listeners(statuses,configured) {
 if(type(statuses)!='array'||length(statuses)>64)fail();
 let selected=[];
 if(configured==null) {
  for(let i=0;i<length(statuses);i++) {
   let status=statuses[i];
   if(status?.interface=='lan'&&status.up==true&&device(status.l3_device)&&index(selected,status.l3_device)<0)
    push(selected,status.l3_device);
  }
 } else {
  if(type(configured)!='array'||!length(configured)||length(configured)>8)fail();
  for(let i=0;i<length(configured);i++) {
   if(!device(configured[i])||index(selected,configured[i])>=0)fail();
   push(selected,configured[i]);
  }
 }
 if(!length(selected)||length(selected)>8)fail();
 let result=[],seen=[];
 for(let i=0;i<length(statuses);i++) {
  let status=statuses[i];
  if(status?.up!=true||index(selected,status.l3_device)<0)continue;
  if(upstream(status))fail();
  let addresses=status['ipv4-address']||[];
  if(type(addresses)!='array'||length(addresses)>16)fail();
  for(let j=0;j<length(addresses);j++) {
   let address=private_address(addresses[j]?.address);
   if(address==null)continue;
   let key=status.l3_device+' '+address;
   if(index(seen,key)>=0)continue;
   if(length(result)>=16)fail();
   push(seen,key);push(result,{address,device:status.l3_device});
  }
 }
 if(!length(result))fail();
 return result;
};

export function firewall_elements(bindings) {
 let values=[];
 for(let i=0;i<length(bindings);i++) {
  let row=bindings[i];
  if(!device(row.device)||private_address(row.address)!=row.address)fail();
  push(values,'"'+row.device+'" . '+row.address);
 }
 return join(', ',values);
};

export function socket_addresses(bindings) {
 let result=[];
 for(let i=0;i<length(bindings);i++) {
  let row=bindings[i];
  if(!device(row.device)||private_address(row.address)!=row.address)fail();
  if(index(result,row.address)<0)push(result,row.address);
 }
 return result;
};

export function firewall_set(bindings) {
 let elements=firewall_elements(bindings);
 return 'set foxhole_mobile_endpoints { type ifname . ipv4_addr;'+
  (length(elements)?' elements = { '+elements+' };':'')+' }\n';
};

export function parse_firewall_set(raw) {
 if(type(raw)!='string'||!length(raw)||length(raw)>4096)fail();
 if(raw==firewall_set([]))return [];
 let prefix='set foxhole_mobile_endpoints { type ifname . ipv4_addr; elements = { ',suffix=' }; }\n';
 if(substr(raw,0,length(prefix))!=prefix||substr(raw,-length(suffix))!=suffix)fail();
 let parts=split(substr(raw,length(prefix),length(raw)-length(prefix)-length(suffix)),', '),result=[],seen=[],devices=[];
 if(!length(parts)||length(parts)>16)fail();
 for(let i=0;i<length(parts);i++) {
  let found=match(parts[i],/^"([A-Za-z0-9_.:-]{1,32})" \. ([0-9.]{7,15})$/);
  if(!found||private_address(found[2])!=found[2]||index(seen,parts[i])>=0)fail();
  if(index(devices,found[1])<0)push(devices,found[1]);
  if(length(devices)>8)fail();
  push(seen,parts[i]);push(result,{device:found[1],address:found[2]});
 }
 if(firewall_set(result)!=raw)fail();
 return result;
};

export function api_accept_rule() {
 return 'iifname . ip daddr @foxhole_mobile_endpoints tcp dport 8443 accept comment "FoxHole mobile API"\n';
};

function exact_shape(value,expected) {
 if(expected==null)return value==null;
 if(type(value)!=type(expected))return false;
 if(type(expected)=='array') {
  if(length(value)!=length(expected))return false;
  for(let i=0;i<length(expected);i++)if(!exact_shape(value[i],expected[i]))return false;
 } else if(type(expected)=='object') {
  let actual=keys(value),wanted=keys(expected);
  if(length(actual)!=length(wanted))return false;
  for(let i=0;i<length(wanted);i++)
   if(index(actual,wanted[i])<0||!exact_shape(value[wanted[i]],expected[wanted[i]]))return false;
 } else return value==expected;
 return true;
};

export function api_accept_present(document) {
 let entries=document?.nftables;
 if(type(entries)!='array'||length(entries)>4096)fail();
 let expected=[{match:{op:'==',left:{concat:[{meta:{key:'iifname'}},{payload:{protocol:'ip',field:'daddr'}}]},
  right:'@foxhole_mobile_endpoints'}},{match:{op:'==',left:{payload:{protocol:'tcp',field:'dport'}},right:8443}},{accept:null}];
 let count=0;
 for(let i=0;i<length(entries);i++) {
  if(type(entries[i])!='object')fail();
  let rule=entries[i].rule;
  if(rule?.comment!='FoxHole mobile API')continue;
  count++;
  if(count!=1||rule.family!='inet'||rule.table!='fw4'||rule.chain!='input'||!exact_shape(rule.expr,expected))fail();
 }
 return count==1;
};

// Reading a file may update atime without changing its identity or contents.
export function file_identity(info) {
 return sprintf('%J',[info?.type,info?.uid,info?.gid,info?.dev,info?.inode,
  info?.nlink,info?.size,info?.mode,info?.mtime,info?.ctime]);
};
