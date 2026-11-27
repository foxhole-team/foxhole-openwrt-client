'use strict';
import * as digest from 'digest';
import * as engines from './engine-model.uc';

const NAME='foxhole-openwrt-client';
function refuse(code){die(code);};
function snapshot(io){
 let host=io.host(),ram=io.ram(),mode=ram!=null?'RAM':host!=null?'FLASH':'ABSENT';
 let starts=mode=='RAM'?io.startups():[];
 if(length(starts)>1)refuse('AMBIGUOUS_STARTUP');
 if(mode=='FLASH'&&!engines.purge_only(io.simulation(),[NAME],{[NAME]:host}))refuse('PACKAGE_CHANGES');
 let v={mode,version:ram?.version??host?.version??null,hostVersion:host?.version??null};
 let identity=[io.boot(),v,ram?.identity,starts,io.world(),io.database()];
 return {plan:{...v,token:digest.sha256(sprintf('%J',identity))},starts};
};
export function plan(io){return snapshot(io).plan;};
export function apply(io,token,choice){
 if(choice!='FLASH'&&choice!='RAM')refuse('UNCONFIRMED');
 io.guard();
 let current=snapshot(io),p=current.plan;
 if(p.mode!=choice)refuse(p.mode=='ABSENT'?'STALE':'UNCONFIRMED');
 if(p.token!=token)refuse('STALE');
 if(choice=='RAM'){
  let starts=current.starts;
  if(length(starts))io.disableStartup(starts[0]);
  io.afterDisable();
  if(length(io.startups()))refuse('VERIFY_FAILED');
  return {status:'REBOOT_REQUIRED',hostVersion:p.hostVersion};
 }
 io.flashGuard();
 let before=io.retained();
 if(plan(io).token!=token)refuse('STALE');
 io.removeFlash();
 if(io.host()!=null||!io.sameRetained(before))refuse('VERIFY_FAILED');
 return {status:io.finishFlash()?'REMOVED':'REMOVED_RELOAD_REQUIRED'};
};
