import assert from 'node:assert/strict';

export async function checkSettingsHelp(browser, origin) {
 const results=[];
 for (const mobile of [false,true]) {
  const page=await browser.newPage({viewport:{width:mobile?390:1280,height:850},isMobile:mobile,hasTouch:mobile,reducedMotion:'reduce'});
  try {
   const state={schema:1,revision:1,settings:{language:'ru',theme:mobile?'light':'dark',vpnServerEnabled:true},countries:[],devices:[],sites:[],servers:[],
    clients:[{id:'demo-client',name:'Demo',deviceType:'smartphone'}]};
   const updates={schema:1,supported:true,routerId:'a'.repeat(64),revision:3,busy:false,availability:'AVAILABLE',currentVersion:'1.0.9-r2',
    availableVersion:'1.0.10-r1',lastCheckedAtUnixMs:Date.now(),failureReason:null,installedModules:[],activeOwnJob:null,lastOwnJob:null,activeAutomaticJob:null,
    autoUpdate:{enabled:false,intervalSeconds:86400,lastAttemptAtUnixMs:null,nextCheckAtUnixMs:null,suspendedReason:null}};
   const calls=[], delayed=new Map();
   const hold=action=>{
    let release; delayed.set(action,new Promise(done=>{release=done;}));
    return ()=>{delayed.delete(action);release();};
   };
   await page.route('**/cgi-bin/foxhole',async route=>{
    const {action,payload}=route.request().postDataJSON();calls.push({action,id:payload?.id});
    if(delayed.has(action))await delayed.get(action);
    return route.fulfill({json:action==='unlock'?{token:'fixture',state}:action==='updates.status'?updates:action==='telemetry'?{available:true}:
     action==='pair.list'?{devices:[{id:'pair-'+'a'.repeat(32),name:'Demo',created:1}]}:
     action==='client.get'?{id:'demo-client',name:'Demo',export:{name:'Demo',config:'fixture'}}:action==='device.list'?{devices:[]}:state});
   });
   await page.goto(origin+'/luci-static/resources/foxhole/shell.html');
   await page.locator('#pin-input').fill('123456');
   await page.locator('#app-shell').waitFor();
   assert.equal(await page.locator('.topbar [data-action="open-help"]').count(),0);
   const logo=await page.locator('.brand img').boundingBox();
   assert.equal(logo.width,mobile?26:30);
   assert.equal(await page.locator('.pin-brand').textContent(),'FOXHOLE OPENWRT');
   assert.equal(await page.locator('.brand > span').textContent(),'FOXHOLE OPENWRT');
   const brand = await page.locator('.brand .brand-platform').evaluate(n=>getComputedStyle(n).color);
   assert.equal(brand, mobile ? 'rgb(85, 85, 85)' : 'rgb(179, 179, 179)');
   assert.equal(await page.locator('.pin-brand .brand-platform').evaluate(n=>getComputedStyle(n).color),brand);
   const openSettings=()=>page.locator('[data-action="open-settings"]').click();
   const back=()=>page.locator('dialog[open] [data-action="modal-back"]').click();
   const close=()=>page.locator('dialog[open] [data-action="modal-close"]').click();
   await openSettings();
   const entry=page.locator('dialog[open] [data-settings-help-entry]');
   const bounds=await entry.evaluate(e=>({w:e.offsetWidth,h:e.offsetHeight,right:e.getBoundingClientRect().right,
    end:e.closest('header').getBoundingClientRect().right}));
   assert.ok(bounds.w>=44 && bounds.h>=44 && bounds.end-bounds.right<22);
   assert.equal(await entry.locator('use').getAttribute('href'),'#icon-question');
   assert.equal(await entry.evaluate(e=>getComputedStyle(e).borderTopWidth),'0px');
   assert.equal((await entry.locator('svg').boundingBox()).width,24);
   const normalToggle = await page.locator('#local-rules').evaluate(e=>e.closest('.setting-row').getBoundingClientRect().height);
   await page.getByText('Блокировка при потере VPN соединения',{exact:true}).waitFor();
   await entry.click();
   const topic=page.locator('dialog [data-help-topic="profiles"]');
   const summary=topic.locator('summary');
   const open=()=>topic.evaluate(d=>d.open);
   const column=await topic.evaluate(d=>({width:d.getBoundingClientRect().width,
    total:d.parentElement.getBoundingClientRect().width,count:getComputedStyle(d.parentElement).gridTemplateColumns.split(' ').length}));
   assert.ok(column.count===1 && Math.abs(column.width-column.total)<1);
   assert.equal(await open(),false);
   if(mobile){
    await summary.tap();assert.equal(await open(),true);
    await summary.tap();assert.equal(await open(),false);
   }else{
    await summary.hover();assert.equal(await open(),true);
    await topic.locator('.help-topic-content').hover();assert.equal(await open(),true);
    const outside=page.locator('dialog .modal-header');
    await outside.hover();
    await page.waitForFunction(()=>!document.querySelector('details[data-help-topic="profiles"]').open);
    await summary.hover();await summary.click();await outside.hover();
    assert.equal(await open(),true,'Click pins the hover preview');
    await summary.click();assert.equal(await open(),false);
   }
   await summary.focus();await page.keyboard.press('Enter');assert.equal(await open(),true);
   await page.keyboard.press('Space');assert.equal(await open(),false);
   await back();assert.ok(await entry.evaluate(e=>document.activeElement===e));
   await page.locator('dialog [data-action="open-about"]').click();
   assert.equal(await entry.isVisible(),false);
   assert.equal(await page.locator('dialog [data-i18n="about.description"]').count(),0);
   await back();
   for(const available of [true,false]){
    if(!available){updates.availability='CURRENT';updates.availableVersion=updates.currentVersion;}
    await page.locator('dialog [data-action="open-updates"]').click();
    await page.locator('dialog .'+(available?'download-mark':'success-mark')).waitFor();
    const primary=page.locator('.modal-footer [data-update-primary]');
    assert.equal(await primary.getAttribute('data-action'),available?'update-install':'update-check');
    assert.equal(await primary.evaluate(e=>getComputedStyle(e).borderTopColor===getComputedStyle(e).color),true);
    assert.equal(await page.locator('[data-update-detail] button').count(),0);
    const toggleHeight = await page.locator('[data-update-detail] .setting-row').evaluate(e=>e.getBoundingClientRect().height);
    assert.ok(Math.abs(toggleHeight-normalToggle)<2);
    const marks=page.locator('dialog .update-versions .is-update-available');
    assert.equal(await marks.count(),available?2:0);
    if(available){
     assert.deepEqual(await marks.allTextContents(),['Доступная версия','1.0.10-r1']);
     const colors=await marks.evaluateAll(nodes=>nodes.map(e=>getComputedStyle(e).color));
     const iconColor=await page.locator('dialog .download-mark').evaluate(e=>getComputedStyle(e).color);
     assert.equal(colors[0],mobile?'rgb(18, 95, 159)':'rgb(114, 185, 255)');
     assert.deepEqual(colors,[iconColor,iconColor]);
     await page.getByText('Требуется обновление ПО',{exact:true}).waitFor();
    }else assert.equal(await page.getByText('Требуется обновление ПО',{exact:true}).count(),0);
    await back();
   }
   await close();
   const boundsOfModal=()=>page.locator('dialog[open]').evaluate(d=>[
    d.offsetHeight,d.querySelector('.modal-stage').clientHeight,d.querySelector('.modal-footer').offsetHeight]);
   const pairsDone=hold('pair.list');
   await page.locator('[data-paired-phone-button]').click();
   const pairStatus=page.locator('[data-pairing-status]');
   await pairStatus.waitFor();assert.equal(await pairStatus.textContent(),'Загрузка');
   assert.equal(await pairStatus.evaluate(p=>p.classList.contains('foxhole-loading')),true);
   assert.equal(await page.locator('[data-pairing-list]').isVisible(),false);
   const listBounds=await boundsOfModal();pairsDone();
   await page.locator('[data-pairing-list] tbody tr').waitFor();
   assert.deepEqual(await boundsOfModal(),listBounds);
   await close();
   await page.locator('[data-action="open-client-control"]').click();
   const profile=page.getByRole('button',{name:'Открыть профиль'});
   assert.equal(await profile.locator('use').getAttribute('href'),'#icon-eye');
   const profileDone=hold('client.get');await profile.click();
   await page.locator('[data-client-pending]').waitFor();
   assert.equal(await page.locator('[data-client-pending]').textContent(),'Загрузка');
   assert.equal(await page.locator('[data-client-form]').isVisible(),false);
   assert.equal(await page.locator('[data-client-result]').isVisible(),false);
   assert.equal(await page.locator('dialog [data-action="delete-client"]').isDisabled(),true);
   const profileBounds=await boundsOfModal();profileDone();
   await page.locator('[data-client-result]').waitFor();
   assert.deepEqual(await boundsOfModal(),profileBounds);
   assert.equal(await page.locator('[data-client-pending]').isVisible(),false);
   assert.deepEqual(calls.filter(row=>row.action.startsWith('client.')),[{action:'client.get',id:'demo-client'}]);
   results.push({device:mobile?'touch/mobile':'mouse/desktop',logoWidth:logo.width,helpColumns:column.count,headerHitArea:[bounds.w,bounds.h]});
  }finally{await page.close();}
 }
 return results;
}
