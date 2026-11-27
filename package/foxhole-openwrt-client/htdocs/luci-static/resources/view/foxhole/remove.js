'use strict';
'require rpc';
'require request';
'require ui';
'require view';
'require foxhole.loader as pixelLoader';

const getPlan = rpc.declare({ object:'foxhole.admin', method:'remove_package_plan', params:[], reject:true, nobatch:true });
const applyPlan = rpc.declare({ object:'foxhole.admin', method:'remove_package_apply', params:['planSha256','confirmMode'], reject:true });
const supported = ['en','ru','de','es','fr','ja','zh','ar'];
const version = value => typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.~+-]{0,159}$/.test(value);
const loadLocale = name => request.get(L.resource('foxhole/locales/' + name + '.json'), {timeout:5000}).then(response => {
 if (!response.ok) throw new Error('locale');
 return response.json();
});

async function readPlan() {
 let timer;
 try {
  // Native mount verification may take tens of seconds on a RAM installation.
  const timeout = Math.max(35000, ((Number(L.env?.rpctimeout) || 20) + 5) * 1000);
  return await Promise.race([getPlan(), new Promise(resolve => {
   timer = setTimeout(() => resolve({error:'UNAVAILABLE'}), timeout);
  })]);
 } catch (_) { return {error:'UNAVAILABLE'}; }
 finally { clearTimeout(timer); }
}

return view.extend({
 load: function() {
  pixelLoader.mount();
  const lang = String(document.documentElement.lang || 'en').toLowerCase().split(/[-_]/)[0];
  const plan = readPlan();
  return loadLocale(supported.includes(lang) ? lang : 'en').catch(() => null).then(dictionary => [dictionary, plan]);
 },
 render: function(data) {
  if (!data[0]) return E('div',{class:'cbi-map'},[E('h2',{},[_('Uninstall FoxHole')]),
   E('p',{role:'status'},[_('Unable to load translations.')]),
   E('a',{class:'cbi-button',href:L.url('admin','services','foxhole','remove')},[_('Retry')])]);
  const t = key => data[0][key] || key, content = E('div'), status = E('p', {role:'status','aria-live':'polite'});
  const message = error => t(({BUSY:'error.engine_busy',STALE:'error.update_stale_plan',UNAUTHORIZED:'error.unauthorized',
   PACKAGE_CHANGES:'remove.other_packages',UNVERIFIED:'remove.unverified',AMBIGUOUS_STARTUP:'remove.unverified'})[error] || 'remove.failed');
  let pending = false;
  const retry = text => {
   status.className='';status.textContent=text;
   const refresh=E('button',{type:'button',class:'cbi-button'},t('remove.retry'));
   content.replaceChildren(refresh);
   refresh.addEventListener('click',async()=>{
    if(pending)return;pending=true;refresh.disabled=true;
    status.className='foxhole-loading';status.textContent=t('updates.state_checking');
    try {draw(await readPlan());}
    catch (_) {retry(t('remove.failed'));}
    finally {pending=false;}
   });
  };
  const draw = plan => {
   content.replaceChildren();status.className='';status.textContent='';
   if (plan?.error) { retry(message(plan.error)); return; }
   if (plan?.mode === 'ABSENT') { status.textContent=t('remove.absent'); return; }
   if (!['RAM','FLASH'].includes(plan?.mode) || !/^[a-f0-9]{64}$/.test(plan.token) || !version(plan.version) ||
       (plan.hostVersion != null && !version(plan.hostVersion))) {
    retry(message('UNVERIFIED'));return;
   }
   const note = t(plan.mode==='RAM'?'remove.ram':'remove.flash'), hybrid=plan.mode==='RAM' && typeof plan.hostVersion==='string';
   const details = () => [E('p',{},[E('strong',{},[plan.mode+' · '+plan.version])]),E('p',{},note),
    ...(hybrid ? [E('p',{},[t('remove.mixed')+' ('+plan.hostVersion+')'])] : [])];
   content.append(...details());
   const button=E('button',{type:'button',class:'cbi-button cbi-button-negative'},t('remove.title'));
   button.disabled=L.hasViewPermission()!==true;
   button.addEventListener('click',()=>{
    if(pending||button.disabled)return;
    let confirming=true;
    const cancel=E('button',{type:'button',class:'cbi-button'},t('action.back'));
    const confirm=E('button',{type:'button',class:'cbi-button cbi-button-negative'},t('action.confirm'));
    cancel.addEventListener('click',()=>{confirming=false;ui.hideModal();});
    confirm.addEventListener('click',async()=>{
     if(!confirming||pending||L.hasViewPermission()!==true)return;
     confirming=false;pending=true;button.disabled=true;confirm.disabled=true;cancel.disabled=true;
     try {
      const result=await applyPlan(plan.token,plan.mode);
      if(result?.status==='REMOVED'&&plan.mode==='FLASH'){content.replaceChildren();status.textContent=t('remove.done');}
      else if(result?.status==='REBOOT_REQUIRED'&&plan.mode==='RAM'||result?.status==='REMOVED_RELOAD_REQUIRED'&&plan.mode==='FLASH'){
       content.replaceChildren(E('p',{},t(plan.mode==='RAM'?'remove.reboot':'remove.done')),E('a',{class:'cbi-button',href:L.url('admin','system','reboot')},t('remove.restart')));
       status.textContent=hybrid?t('remove.mixed'):'';
      } else {
       const warning=message(result?.error);draw(await readPlan());status.textContent=warning;
      }
     } catch (_) {retry(t('remove.failed'));}
     finally {pending=false;ui.hideModal();}
    });
    ui.showModal(t('remove.confirm_title'),[...details(),E('div',{class:'right'},[cancel,' ',confirm])]);
   });
   content.append(button);
  };
  status.className='foxhole-loading';
  status.textContent = t('updates.state_checking');
  Promise.resolve(data[1]).then(draw, () => retry(t('remove.failed')));
  return E('div',{class:'cbi-map'},[E('h2',{},t('remove.title')),content,status]);
 },
 handleSaveApply:null,handleSave:null,handleReset:null
});
