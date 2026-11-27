import assert from 'node:assert/strict';

export async function checkSettingsLayout(browser, origin, responseCases) {
 const results = [];
 for (const width of [390, 1024]) {
  const page = await browser.newPage({ viewport: { width, height: 850 }, reducedMotion: 'reduce' });
  try {
   const state = { schema:1, revision:1, countries:[], devices:[], sites:[], servers:[], clients:[], settings:{language:'ru',theme:'dark'} };
   let releaseCapability;
   const capabilityGate = new Promise(resolve => { releaseCapability = resolve; });
   let holdCapability = false;
   await page.route('**/cgi-bin/foxhole', async r => {
    const {action,payload} = r.request().postDataJSON();
    if(action==='package.status'){
     assert.deepEqual(payload,{});
     if (holdCapability) await capabilityGate;
     return r.fulfill({json:{schema:1,product:'foxhole',installed:true,storage:'RAM',version:'1.0.9-r2',installedModules:[],
      backupSupported:width >= 960,homeServerEnabled:true,routerInfo:{schema:1,firmwareVersion:'OpenWrt 25.12.5',model:'Cudy WR3000 v1',lanAddress:'192.0.2.1'}}});
    }
    return r.fulfill({json: action==='unlock'?{token:'fixture',state}:action==='state'?state:action==='device.list'?{devices:[]}:{}});
   });
   await page.goto(origin+'/luci-static/resources/foxhole/shell.html');
   await page.locator('#pin-input').fill('123456');
   await page.waitForSelector('#pin-gate[hidden]',{state:'attached'});
   holdCapability = true;
   await page.locator('[data-action="open-settings"]').click();
   await page.waitForSelector('dialog.view-settings-home[open]');
   await page.evaluate(()=>document.fonts.ready);
   const backup = page.locator('dialog[open] [data-backup-entry]');
   const geometry = () => backup.evaluate(row => {
    const next = row.nextElementSibling;
    return [row.offsetTop, row.offsetHeight, next.offsetTop, row.parentElement.offsetHeight];
   });
   assert.ok(await backup.isVisible(), 'Backup row is present before the reply');
   assert.ok(await backup.isDisabled());
   const before = await geometry();
   releaseCapability();
   await backup.evaluate(row => row.getAttribute('aria-busy') === 'true'
     ? new Promise(resolve => {
        const observer = new MutationObserver(() => {
         if (!row.hasAttribute('aria-busy')) { observer.disconnect(); resolve(); }
        });
        observer.observe(row, {attributes: true});
       }) : undefined);
   assert.deepEqual(await geometry(), before, 'Backup capability shifted the settings layout');
   assert.equal(await backup.isEnabled(), width >= 960);
   const home = await page.locator('dialog[open] .settings-list').evaluate(grid=>{
    const about=grid.querySelector('[data-action="open-about"]'), local=grid.querySelector('#local-rules').closest('.setting-row');
    const box=grid.getBoundingClientRect(), item=about.getBoundingClientRect();
    return {columns:getComputedStyle(grid).gridTemplateColumns.split(' ').length,border:parseFloat(getComputedStyle(local).borderTopWidth),
     aboutSpan:item.width/box.width,aboutLeft:(item.left-box.left)/box.width};
   });
   await page.locator('dialog [data-action="open-about"]').click();
   await page.waitForFunction(()=>document.querySelector('dialog[open] [data-about-version]')?.textContent==='1.0.9-r2');
   for(const [field,expected] of Object.entries({storage:'RAM',model:'Cudy WR3000 v1',firmware:'OpenWrt 25.12.5',address:'192.0.2.1'}))
    assert.equal(await page.locator('dialog[open] [data-about-'+field+']').textContent(),expected);
   await page.locator('dialog[open] [data-action="modal-close"]').click();
   await page.locator('[data-action="open-settings"]').click();
   await page.locator('dialog.view-settings-home [data-settings-help-entry]').click();
   const help=page.locator('dialog[open] [data-help-content]');
   await help.waitFor();
   const columns=await help.evaluate(el=>getComputedStyle(el).gridTemplateColumns.split(' ').length);
   assert.equal(columns,1,'help uses a single full-width column at '+width);
   await page.locator('dialog[open] [data-action="modal-close"]').click();
   await page.locator('[data-action="open-settings"]').click();
   await page.locator('dialog [data-action="open-interface-settings"]').click();
   await page.waitForSelector('dialog.view-interface-settings[open]');
   const trigger=page.locator('dialog .font-picker-trigger');await trigger.click();
   const menu=page.locator('.font-picker-menu:visible');await menu.waitFor();
   const fonts=await menu.evaluate(el=>{
    const m=el.getBoundingClientRect();return [...el.querySelectorAll('button > span')].map(s=>{
     const r=document.createRange();r.selectNodeContents(s);const lines=[...r.getClientRects()];
     return {text:s.textContent,lineCount:lines.length,contained:lines.every(q=>q.left>=m.left-1&&q.right<=m.right+1&&q.top>=m.top-1&&q.bottom<=m.bottom+1),
      menuWidth:m.width,textWidth:r.getBoundingClientRect().width};
    });
   });
   const interfaceRows = await page.evaluate(settingsGeometry);
   results.push({width,home,fonts,interfaceRows});
  } finally { await page.close(); }
 }
 assertSettingsResponses(responseCases ?? await checkSettingsResponses(browser, origin));
 return results;
}

export function assertSettingsLayout(results) {
 for(const {width,home,fonts,interfaceRows} of results){
  const wide=width>=960;
  assert.equal(home.columns,wide?2:1);
  assert.equal(home.border,wide?0:1,'first row separators: '+width);
  if(wide){assert.ok(home.aboutSpan < .51 && home.aboutLeft >= .5,'About belongs to the right column');}
  else assert.ok(home.aboutSpan > .98,'About uses the mobile column');
  assert.deepEqual(fonts.map(f=>f.text),['Tiny5','JetBrains Mono']);
  for(const row of interfaceRows) assert.ok(Math.abs(row.iconError) <= 2 && row.controlError <= 1, row.key);
  for(const font of fonts){assert.equal(font.lineCount,1,font.text+' wraps unnecessarily');assert.ok(font.contained,font.text+' is clipped');}
 }
}

function settingsGeometry() {
 const grid = document.querySelector('dialog[open] .settings-list');
 const ctx = document.createElement('canvas').getContext('2d');
 return [...grid.children].map(row => {
  const label = row.querySelector('.setting-copy strong');
  const title = label.querySelector('[data-i18n]') || label;
  const text = title.firstChild, range = document.createRange();
  range.setStart(text, 0); range.setEnd(text, 1);
  const first = range.getBoundingClientRect(), style = getComputedStyle(label);
  ctx.font = style.fontWeight + ' ' + style.fontSize + ' ' + style.fontFamily;
  const ink = ctx.measureText(text.textContent.trim().split(/\s+/)[0]);
  const textCenter = first.top + ink.fontBoundingBoxAscent + (ink.actualBoundingBoxDescent - ink.actualBoundingBoxAscent) / 2;
  const glyph = row.querySelector('.setting-icon use'), drawn = glyph.getBBox(), matrix = glyph.getScreenCTM();
  const iconCenter = new DOMPoint(drawn.x + drawn.width / 2, drawn.y + drawn.height / 2).matrixTransform(matrix).y;
  const rect = row.getBoundingClientRect(), control = row.lastElementChild.getBoundingClientRect();
  return { key: title.dataset.i18n, x: rect.x, y: rect.y, w: rect.width, h: rect.height,
   first: first.y, iconError: Math.round((iconCenter - textCenter) * 100) / 100,
   controlError: Math.abs((control.top + control.bottom - rect.top - rect.bottom) / 2) };
 });
}

function deferred() {
 let resolve;
 const promise = new Promise(done => { resolve = done; });
 return { promise, resolve };
}

function updateFixture(state) {
 if (state === 'MALFORMED') return {schema:1, supported:true};
 if (state === 'ERROR') return {_foxhole_error:'unavailable'};
 const value = {schema:1, supported:true, revision:3, routerId:'a'.repeat(64), busy:state==='BUSY',
  currentVersion:'1.0.9-r2', availableVersion:'1.0.9-r2', availability:state==='BUSY'?'CURRENT':state,
  lastCheckedAtUnixMs:1700000000000, failureReason:null, installedModules:[],
  autoUpdate:{enabled:false,intervalSeconds:86400,lastAttemptAtUnixMs:null,nextCheckAtUnixMs:null,suspendedReason:null},
  activeOwnJob:null,lastOwnJob:null,activeAutomaticJob:null};
 if (state === 'AVAILABLE') value.availableVersion = '1.0.10-r1';
 if (state === 'UNSUPPORTED') Object.assign(value, {supported:false,currentVersion:null,availableVersion:null,failureReason:'UNSUPPORTED_TARGET'});
 if (state === 'NOT_CHECKED') Object.assign(value, {availableVersion:null,lastCheckedAtUnixMs:null});
 if (state === 'CHECK_FAILED') Object.assign(value, {availableVersion:null,failureReason:'RELEASE_UNAVAILABLE'});
 return value;
}

export async function checkSettingsResponses(browser, origin) {
 const results = [];
 for (const {width,scale,language} of [
  {width:320,scale:1,language:'ru'}, {width:320,scale:2,language:'fr'},
  {width:1024,scale:1,language:'ru'}, {width:1024,scale:2,language:'ru'}, {width:1024,scale:2,language:'fr'},
 ]) {
  const page = await browser.newPage({viewport:{width,height:900},reducedMotion:'reduce'});
  let current = null, cachedAvailable = false;
  const state = {schema:1,revision:1,settings:{language,theme:scale===1?'dark':'light',vpnServerEnabled:scale===1},
   devices:[],servers:[],clients:[],sites:[],countries:[]};
  try {
   await page.route('**/cgi-bin/foxhole', async route => {
    const {action,payload} = route.request().postDataJSON();
    if (action === 'unlock') return route.fulfill({json:{token:'settings-geometry',state}});
    if (action === 'package.status') assert.deepEqual(payload,{});
    if (action === 'updates.status') assert.equal(payload.token,'settings-geometry');
    if (current && ['package.status','updates.status'].includes(action)) {
     const task = current[action];
     task.started.resolve();
     await task.release.promise;
     return route.fulfill({json:task.reply});
    }
    return route.fulfill({json:action==='state'?state:action==='device.list'?{devices:[]}:{}});
   });
   const bootstrap = page.waitForResponse(r=>r.request().method()==='POST' && r.request().postDataJSON()?.action==='package.status');
   await page.goto(origin+'/luci-static/resources/foxhole/shell.html');
   await page.locator('#pin-input').fill('123456');
   await bootstrap;
   await page.locator('#app-shell').waitFor();
   await page.evaluate(async scale => { document.documentElement.style.fontSize = 16*scale+'px'; await document.fonts.ready; },scale);
   for (const availability of ['CURRENT','AVAILABLE','NOT_CHECKED','UNSUPPORTED','CHECK_FAILED','BUSY','MALFORMED','ERROR']) {
    for (const supported of [true,false]) for (const backupFirst of [true,false]) {
     const backupReply = {schema:1,product:'foxhole',installed:true,backupSupported:supported};
     if (!supported && availability==='MALFORMED') Object.assign(backupReply,{product:'invalid',backupSupported:true});
     if (!supported && availability==='ERROR') Object.assign(backupReply,{_foxhole_error:'unavailable'});
     current = Object.fromEntries(Object.entries({'package.status':backupReply,'updates.status':updateFixture(availability)})
      .map(([action,reply])=>[action,{reply,started:deferred(),release:deferred()}]));
     await page.locator('[data-action="open-settings"]').click();
     await Promise.all(Object.values(current).map(task=>task.started.promise));
     await page.evaluate(async () => {
      await document.fonts.ready;
      await Promise.allSettled(document.querySelector('dialog[open]').getAnimations({subtree:true})
       .filter(a=>Number.isFinite(a.effect.getComputedTiming().endTime)).map(a=>a.finished));
      await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));
     });
     const grid = page.locator('#settings-form'), backup = grid.locator('[data-backup-entry]'), badge = grid.locator('[data-update-summary]');
     const before = await page.evaluate(settingsGeometry), moved = [];
     let authorization = await backup.isDisabled(), summary = (await badge.isVisible()) === cachedAvailable;
     assert.equal(await backup.evaluate(row => getComputedStyle(row).opacity), '1', 'Backup label is readable before the reply');
     assert.equal(await badge.evaluate(node => node.parentElement.getAttribute('aria-busy')), 'true');
     assert.equal(await grid.getByRole('button',{name:/Есть обновление|Mise à jour disponible/}).count(), cachedAvailable ? 1 : 0, 'Sizing labels must not announce an unverified status');
     const order = backupFirst?['package.status','updates.status']:['updates.status','package.status'];
     for (const action of order) {
      const response = page.waitForResponse(r=>r.request().method()==='POST' && r.request().postDataJSON()?.action===action);
      current[action].release.resolve(); await (await response).finished();
      await page.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));
      const after = await page.evaluate(settingsGeometry);
      assert.deepEqual(after.map(r=>r.key),before.map(r=>r.key));
      for (const [index,row] of after.entries()) {
       if (['x','y','w','h','first'].some(k=>Math.abs(row[k]-before[index][k])>.5)) moved.push({key:row.key,after:action,
        y:row.y-before[index].y,h:row.h-before[index].h,first:row.first-before[index].first});
      }
      if (action==='package.status') authorization &&= (await backup.isEnabled())===supported;
      else {
       assert.equal(await badge.evaluate(node => node.parentElement.hasAttribute('aria-busy')), false);
       const expected = availability==='AVAILABLE' ? (language==='ru'?'Есть обновление':'Mise à jour disponible') : null;
       summary &&= expected ? (await badge.isVisible() && await badge.textContent()===expected) : !await badge.isVisible();
       if (!backupFirst) authorization &&= await backup.isDisabled();
      }
     }
     results.push({width,scale,language,availability,backupFirst,supported,moved,authorization,summary,
      worstIcon:Math.max(...before.map(r=>Math.abs(r.iconError))),icons:before.map(({key,iconError})=>[key,iconError]),
      controlError:Math.max(...before.map(r=>r.controlError))});
     cachedAvailable = availability === 'AVAILABLE';
     current=null;
     await page.locator('dialog[open] [data-action="modal-close"]').click();
     await page.locator('dialog[open]').waitFor({state:'hidden'});
    }
   }
  } finally { if (current) for (const step of Object.values(current)) step.release.resolve(); await page.close(); }
 }
 return results;
}

export function assertSettingsResponses(results) {
 for (const value of results) {
  const scenario = [value.width, value.scale, value.language, value.availability, value.supported, value.backupFirst].join('/');
  assert.deepEqual(value.moved, [], 'Asynchronous response shifted settings: ' + scenario);
  assert.ok(value.authorization && value.summary, 'Invalid capability or update state: ' + scenario);
  // The visible ink varies slightly with accents and descenders in each label.
  assert.ok(value.worstIcon <= 1.25 * value.scale + .1, 'Leading icon misses its first line: ' + scenario + ' ' + JSON.stringify(value.icons));
  assert.ok(value.controlError <= 1, 'Trailing control moved off center: ' + scenario);
 }
}
