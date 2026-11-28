import assert from 'node:assert/strict';

export async function checkRouterSettingsReview(browser, origin) {
  const measurements = [];
  for (const width of [390, 1024]) {
    const page = await browser.newPage({ viewport: { width, height: 900 }, reducedMotion: 'reduce' });
    try {
      const state = { schema: 1, revision: 1, settings: { language: 'ru', theme: 'dark' },
        servers: [], devices: [], clients: [], sites: [], countries: [] };
      const routerId = 'a'.repeat(64), catalogSha256 = 'b'.repeat(64);
      const job = { automatic: true, operation: 'APPLY', state: 'DOWNLOADING',
        step: 'DOWNLOADING_PACKAGE', progressPercent: 36, failureReason: null };
      const updates = { schema: 1, supported: true, routerId, revision: 3, busy: false,
        currentVersion: '1.0.9-r2', availableVersion: '1.0.9-r2', availability: 'CURRENT',
        lastCheckedAtUnixMs: 1795219200000, failureReason: null, installedModules: [],
        autoUpdate: { enabled: true, intervalSeconds: 86400, lastAttemptAtUnixMs: null, nextCheckAtUnixMs: null, suspendedReason: null },
        activeOwnJob: null, lastOwnJob: null, activeAutomaticJob: null };
      let ready;
      const gate = new Promise(resolve => { ready = resolve; });
      let selected = null;
      await page.route('**/cgi-bin/foxhole', async route => {
        const { action, payload } = route.request().postDataJSON();
        let reply = {};
        if (action === 'unlock') reply = { token: 'fixture-review', state };
        if (action === 'state') reply = state;
        if (action === 'device.list') reply = { devices: [] };
        if (action === 'updates.status') reply = updates;
        if (action === 'engines.status') {
          await gate;
          reply = { schema: 1, revision: 3, busy: false, routerId, catalogSha256, managementSupported: true,
            entries: [
              { id: 'hysteria2', availability: 'AVAILABLE', installed: false },
              { id: 'vless', availability: 'AVAILABLE', installed: true, active: false, storage: 'RAM', updateAvailable: false, binarySha256: 'e'.repeat(64) },
              { id: 'wireguard', availability: 'AVAILABLE', installed: true, active: true, storage: 'FLASH', updateAvailable: false, binarySha256: 'f'.repeat(64) },
            ] };
        }
        if (action === 'engines.plan') {
          selected = payload;
          reply = { _foxhole_error: 'engine_stale_plan' };
        }
        await route.fulfill({ json: reply });
      });
      await page.goto(origin+'/luci-static/resources/foxhole/shell.html');
      await page.locator('#pin-input').fill('123456');
      await page.locator('#app-shell').waitFor();
      const footer = page.locator('.app-footer');
      const foot = await footer.evaluate(el => {
        const shell = document.querySelector('#app-shell'), box = el.getBoundingClientRect();
        return { text: el.textContent, year: new Date().getFullYear(), spaceAfter: Math.abs(box.bottom + shell.scrollTop - shell.scrollHeight),
          screenBottom: shell.clientHeight, scrollHeight: shell.scrollHeight };
      });
      assert.ok(foot.text.includes(String(foot.year)) && foot.text.includes('Все права защищены.'));
      assert.ok(foot.spaceAfter < 2, JSON.stringify(foot));
      const open = async (name) => { await page.locator('[data-action="open-'+name+'"]:visible').click(); await page.locator('dialog.view-'+name+'[open]').waitFor(); };
      const back = async () => { await page.locator('dialog [data-modal-close]').click(); await page.locator('dialog.view-settings-home[open]').waitFor(); };
      await page.locator('[data-action="open-settings"]').click();
      await open('engines');
      await page.locator('[data-engine-analysis]').waitFor();
      assert.match(await page.locator('[data-engine-analysis]').innerText(), /Анализ установленного ядра/);
      assert.equal(await page.locator('[data-engine-list]').isVisible(), false);
      ready();
      await page.locator('.engine-actions button').first().waitFor();
      assert.equal(await page.locator('[data-engine-analysis]').isVisible(), false);
      const vless = page.locator('.engine-row').filter({ has: page.locator('[data-id="vless"]') });
      assert.match(await vless.innerText(), /Установлен/);
      assert.equal(await vless.locator('button').count(), 2);
      const reinstall = vless.getByRole('button', { name: /Переустановить/ });
      assert.equal(await reinstall.innerText(), '');
      assert.ok(await vless.getByRole('button',{ name:/Удалить/ }).isEnabled());
      assert.ok(await page.locator('[data-id="wireguard"][data-operation="REMOVE"]').isDisabled());
      await reinstall.click();
      await page.waitForFunction(() => !document.querySelector('[data-operation="REINSTALL"]')?.disabled);
      assert.equal(selected.operation, 'REINSTALL'); assert.deepEqual(selected.engineIds, ['vless']); assert.equal(selected.storage, 'RAM');
      await back(); await open('updates');
      await page.locator('dialog .success-mark').waitFor();
      assert.match(await page.locator('[data-update-detail]').innerText(), /Установлена последняя версия приложения/);
      assert.equal(await page.locator('[data-update-detail] button').count(), 0);
      assert.equal(await page.locator('.modal-footer [data-action="update-check"]').count(), 1);
      assert.equal(await page.locator('[data-update-detail] progress').count(), 0);
      assert.ok(await page.locator('[data-update-detail] input[type=checkbox]').isChecked());
      await back(); updates.busy = true; updates.activeAutomaticJob = job;
      await open('updates'); const bar = page.locator('[data-update-detail] progress'); await bar.waitFor();
      assert.equal(await bar.getAttribute('value'),'36');
      job.state = 'VERIFYING'; job.step = 'VERIFYING_PACKAGE';
      await bar.waitFor({ state:'detached' });
      assert.equal(await page.locator('dialog .success-mark').count(),0);
      measurements.push({ width, footer:foot, checkedStates:['CURRENT','DOWNLOADING','VERIFYING'] });
    } finally { await page.close(); }
  }
  return measurements;
}

export async function checkEditorActions(browser, origin) {
  for (const width of [320, 1024]) {
    const page = await browser.newPage({ viewport: { width, height: 850 }, reducedMotion: 'reduce' });
    const server = { id: 'server-demo', name: 'Original', protocol: 'hysteria2', country: 'NO', metrics: {} };
    const state = { schema: 1, revision: 1, settings: { language: 'ru', theme: 'dark' },
      countries: [], devices: [], sites: [], clients: [], servers: [server] };
    const writes = [], tests = [];
    try {
      await page.route('**/cgi-bin/foxhole', async route => {
        const {action, payload} = route.request().postDataJSON();
        let reply = {};
        if (action === 'unlock') reply = payload.pin === '123456' ? {token: 'fixture', state} : {_foxhole_error: 'invalid_pin'};
        if (action === 'state') reply = state;
        if (action === 'server.get') reply = {...server, config: 'hy2://fixture@node.example.invalid:443/'};
        if (action === 'server.save') { writes.push(action); server.name = payload.name; state.revision++; reply = state; }
        if (action === 'routing.test') { tests.push(payload.sites); reply = {valid: true}; }
        if (action === 'settings') { writes.push(action); state.sites = payload.sites; state.revision++; reply = state; }
        await route.fulfill({json: reply});
      });
      await page.goto(origin + '/luci-static/resources/foxhole/shell.html');
      const pin = page.locator('#pin-input');
      await page.waitForFunction(() => !document.querySelector('#pin-input').disabled);
      const colors = () => page.evaluate(() => ['.pin-brand', '.pin-brand b', '.pin-dots span'].map(query => {
        const style = getComputedStyle(document.querySelector(query));
        return query.endsWith('span') ? style.borderTopColor : style.color;
      }));
      const original = await colors();
      await pin.fill('000000');
      await page.locator('#pin-gate.pin-rejected').waitFor();
      await page.waitForFunction(before => {
        const dots = document.querySelectorAll('.pin-gate.pin-rejected [data-pin-dot]');
        return dots.length === 6 && [...dots].every(dot => getComputedStyle(dot).borderTopColor !== before);
      }, original[2]);
      const rejected = await colors();
      assert.deepEqual(rejected.slice(0, 2), original.slice(0, 2));
      assert.notEqual(rejected[2], original[2]);
      assert.equal(await pin.getAttribute('aria-invalid'), 'true');
      await pin.fill('1');
      assert.equal(await pin.getAttribute('aria-invalid'), null);
      await pin.fill('123456');
      const action = name => page.locator('[data-action="' + name + '"]:visible').first();
      const footer = page.locator('dialog[open] .modal-footer');
      const pair = async (first, second) => {
        await footer.getByRole('button', {name: first, exact: true}).waitFor();
        const buttons = footer.getByRole('button');
        assert.deepEqual(await buttons.allTextContents(), [first, second]);
        const [a,b] = await Promise.all([buttons.nth(0).boundingBox(),buttons.nth(1).boundingBox()]);
        assert.ok(a && b && Math.abs(a.y-b.y)<1 && Math.abs(a.width-b.width)<=1);
        await page.waitForFunction(() => {
          const el = document.querySelector('dialog[open] .modal-footer');
          return el && getComputedStyle(el).backgroundColor === 'rgba(0, 0, 0, 0)';
        }, null, {timeout: 2000});
      };
      await action('open-server-control').click();
      await action('edit-server').click();
      await pair('Отмена', 'Сохранить');
      await page.locator('[data-server-name]').fill('Discard');
      await action('cancel-server-edit').click();
      await action('edit-server').click();
      assert.equal(await page.locator('[data-server-name]').inputValue(), 'Original');
      assert.deepEqual(writes, []);
      await page.locator('[data-server-name]').fill('Saved');
      await action('save-server').click();
      await page.locator('dialog[open]').waitFor({state: 'hidden'});
      assert.equal(server.name, 'Saved');
      await action('open-add').click();
      await action('open-exceptions').click();
      await pair('Тест', 'Сохранить');
      await page.locator('[data-site-input]').fill('example.org');
      await action('add-site').click();
      await action('test-rules').click();
      await page.getByText('Правила маршрутизации прошли проверку', {exact: true}).waitFor();
      assert.deepEqual(writes, ['server.save']);
      assert.equal(tests[0][0].pattern, 'example.org');
      await action('save-rules').click();
      await page.locator('dialog[open]').waitFor({state: 'hidden'});
      assert.deepEqual(writes, ['server.save','settings']);
      assert.deepEqual(state.sites, tests[0]);
    } finally { await page.close(); }
  }
}
