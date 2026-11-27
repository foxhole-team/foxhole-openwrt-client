import assert from 'node:assert/strict';

// Pass the stock release's luci.js; only router reads are replaced with local fixtures.
export async function runLuCIEntryChecks(browser, origin, luciSource) {
  const page = await browser.newPage({viewport:{width:1000,height:800},reducedMotion:'reduce'});
  const base = '/cgi-bin/luci/admin/services/foxhole/';
  try {
    await page.route('**/cgi-bin/luci/admin/services/foxhole/*', r=>r.fulfill({contentType:'text/html',
      body:'<html lang="ru"><head><title>LuCI</title></head><body><div id="view"></div></body></html>'}));
    async function visit(name) {
      await page.goto(origin + base + name);
      await page.addScriptTag({content:luciSource});
      await page.evaluate(async name=>{
        const L=window.L=Object.create(window.LuCI.prototype);
        L.loaded=true;
        L.resource=(...parts)=>L.path('/luci-static/resources',parts);
        L.url=(...parts)=>L.path('/cgi-bin/luci',parts);
        L.hasViewPermission=()=>window.fixtureWritable!==false;
        window.E=L.dom.create.bind(L.dom);
        window._=s=>s;
        const calls=window.fixtureCalls=[];
        const rpc={declare:spec=>async(...args)=>{
          calls.push(spec.method);
          if(spec.method==='remove_package_plan') return await new Promise(resolve=>{window.planReady=resolve;});
          if(spec.method==='remove_package_apply') throw new Error('Unexpected removal');
          if(spec.method==='unlock')return {token:'fixture',state:{schema:1,revision:1,settings:{language:'ru'},
            servers:[],clients:[],sites:[],devices:[],countries:[]}};
          if(spec.method==='updates.status')return {schema:1,supported:true,routerId:'a'.repeat(64),revision:3,busy:false,
            currentVersion:'1.0.9-r2',availableVersion:'1.0.9-r2',availability:'CURRENT',lastCheckedAtUnixMs:Date.now(),
            failureReason:null,installedModules:[],activeOwnJob:null,lastOwnJob:null,activeAutomaticJob:null,
            autoUpdate:{enabled:false,intervalSeconds:86400,lastAttemptAtUnixMs:null,nextCheckAtUnixMs:null,suspendedReason:null}};
          if(spec.method==='telemetry')return {available:false};
          return {};
        }};
        const ui={showModal:(title,children)=>{const dlg=document.createElement('dialog');dlg.append(E('h3',{},[title]),...children);document.body.append(dlg);dlg.showModal();},
          hideModal:()=>document.querySelector('dialog')?.remove()};
        const source=await fetch('/luci-static/resources/view/foxhole/'+(name==='panel'?'client':name)+'.js').then(r=>r.text());
        const loaderSource=await fetch(L.resource('foxhole/loader.js')).then(r=>r.text());
        const Loader=Function('baseclass','E','L',loaderSource)(L.Class,window.E,L);
        const Type=Function('view','rpc','request','ui','E','L','pixelLoader',source)(L.view,rpc,L.Request,ui,window.E,L,new Loader());
        // The stock View creates its loading surface, calls load/render and mounts the result.
        new Type();
      },name);
    }
    await visit('panel');
    const frame=page.frameLocator('iframe');
    await frame.locator('#pin-input').waitFor();
    assert.match(await page.locator('iframe').getAttribute('src'),/^\/luci-static\/resources\/foxhole\/shell\.html\?v=[\w.-]+$/);
    assert.match(await page.locator('[rel=manifest]').getAttribute('href'),/^\/luci-static\/resources\/foxhole\/manifest\.json\?v=[\w.-]+$/);
    await frame.locator('#pin-input').evaluate(input=>new Promise((resolve,reject)=>{
      if(document.activeElement===input)return resolve();
      const t=setTimeout(()=>reject(new Error('PIN did not receive focus')),1500);
      input.addEventListener('focus',()=>{clearTimeout(t);resolve();},{once:true});
    }));
    await page.keyboard.type('123456');
    await frame.locator('#app-shell').waitFor();
    await frame.locator('[data-telemetry-notice]').waitFor();
    assert.equal(await frame.locator('[data-toast]').isVisible(),false);
    await frame.locator('[data-action="open-settings"]').click();
    await frame.locator('dialog[open] [data-action="open-updates"]').click();
    await frame.locator('dialog[open] .success-mark').waitFor();
    assert.equal(await frame.locator('dialog [data-update-detail] .download-mark').count(),0);
    for (const writable of [false,true]) {
      await visit('remove');
      await page.locator('#view .cbi-map h2').waitFor();
      assert.equal(await page.locator('#view .spinning').count(),0);
      await page.evaluate(writable=>{
        window.fixtureWritable=writable;
        window.planReady({mode:'RAM',token:'f'.repeat(64),version:'1.0.9-r2'});
      },writable);
      const button=page.locator('#view .cbi-button-negative');
      await button.waitFor();
      assert.equal(await button.isEnabled(),writable);
      if(writable) {
        await button.click();await page.locator('dialog[open]').waitFor();
        await page.locator('dialog .cbi-button:not(.cbi-button-negative)').click();
        assert.equal(await page.locator('dialog[open]').count(),0);
      }
      assert.deepEqual(await page.evaluate(()=>window.fixtureCalls),['remove_package_plan']);
    }
  } finally { await page.close(); }
}
