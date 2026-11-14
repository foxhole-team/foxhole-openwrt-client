// Run with an existing Playwright browser:
// runMobileUiChecks(browser, baseURL).
export async function runUpdateBadgeUiChecks(browser, baseURL) {
  const context = await browser.newContext({ viewport: { width: 320, height: 844 } });
  try {
    const page = await context.newPage();
    const state = { schema: 1, revision: 1, settings: { language: 'ru', theme: 'dark' },
      countries: [], devices: [], sites: [], servers: [], clients: [] };
    const status = { schema: 1, supported: true, routerId: 'a'.repeat(64), revision: 2,
      currentVersion: '1.0.6-r1', availableVersion: '1.0.7-r1', availability: 'AVAILABLE',
      lastCheckedAtUnixMs: 2000000000000, failureReason: null, busy: false,
      autoUpdate: { enabled: false, intervalSeconds: 86400, lastAttemptAtUnixMs: null,
        nextCheckAtUnixMs: null, suspendedReason: null }, installedModules: [],
      activeOwnJob: null, lastOwnJob: null, activeAutomaticJob: null };
    await page.route('**/cgi-bin/foxhole', route => {
      const action = route.request().postDataJSON().action;
      return route.fulfill({ json: action === 'unlock' ? { token: 'ui-fixture', state }
        : action === 'updates.status' ? status : action === 'device.list' ? { devices: [] } : {} });
    });
    await page.goto(`${baseURL}/luci-static/resources/foxhole/shell.html`);
    await page.locator('#pin-input').fill('123456');
    await page.waitForSelector('#pin-gate[hidden]', { state: 'attached' });
    await page.locator('[data-action="open-settings"]').click();
    await page.waitForSelector('dialog.view-settings-home[open]');
    await page.locator('[data-update-summary]').waitFor({ state: 'visible' });
    await page.evaluate(() => document.fonts.ready);
    const results = [];
    for (const width of [320, 390, 1280]) {
      await page.setViewportSize({ width, height: 844 });
      for (const scale of [1, 2]) {
        const count = await page.evaluate(async ({ status, scale }) => {
          const { UpdatePanel } = await import('./update-panel.js');
          const title = document.querySelector('[data-action="open-updates"] [data-i18n="updates.title"]');
          const badge = document.querySelector('[data-update-summary]');
          document.documentElement.style.fontSize = `${16 * scale}px`;
          let count = 0;
          for (const language of ['ru', 'en', 'de', 'fr', 'es', 'ja', 'zh', 'ar']) {
            const strings = await fetch(`./locales/${language}.json`).then(r => r.json());
            document.documentElement.dir = language === 'ar' ? 'rtl' : 'ltr';
            title.textContent = strings['updates.title'];
            for (const availability of ['AVAILABLE', 'CURRENT', 'NOT_CHECKED', 'CHECK_FAILED']) {
              const value = { ...status, availability,
                availableVersion: availability === 'CURRENT' ? status.currentVersion
                  : availability === 'AVAILABLE' ? status.availableVersion : null,
                failureReason: availability === 'CHECK_FAILED' ? 'RELEASE_UNAVAILABLE' : null };
              const panel = new UpdatePanel({ call: async () => value, text: key => strings[key], scope: () => 1 });
              await panel.summary();
              const visible = ['AVAILABLE', 'CURRENT'].includes(availability);
              const check = (ok, reason) => { if (!ok) throw new Error(`${language}/${availability}/${scale}: ${reason}`); };
              check(badge.hidden !== visible, 'incorrect badge visibility');
              if (visible) {
                const b = badge.getBoundingClientRect(), c = badge.closest('.setting-copy').getBoundingClientRect();
                const row = badge.closest('button').getBoundingClientRect();
                const range = document.createRange();
                range.setStart(title.firstChild, title.textContent.length - 1);
                range.setEnd(title.firstChild, title.textContent.length);
                const last = range.getBoundingClientRect();
                check(b.left >= c.left - .5 && b.right <= c.right + .5
                  && b.top >= row.top && b.bottom <= row.bottom, 'badge overlaps row bounds');
                if (scale === 1) {
                  check(b.top < last.top && b.bottom >= last.top, 'badge detached from the final title line');
                  check(language === 'ar' ? b.right <= last.left + .5 : b.left >= last.right - .5,
                    'badge overlaps title');
                } else {
                  range.selectNodeContents(title);
                  for (const text of range.getClientRects())
                    check(b.top >= text.bottom - 2 || b.bottom <= text.top + 2
                      || b.left >= text.right - .5 || b.right <= text.left + .5,
                    'badge overlaps enlarged title');
                }
              }
              count++;
            }
          }
          return count;
        }, { status, scale });
        results.push({ width, scale, cases: count });
      }
    }
    return results;
  } finally { await context.close(); }
}

export async function runMobileUiChecks(browser, baseURL, screenshots = '.') {
  const check = (value, message) => { if (!value) throw new Error(message); };
  const fixtures = language => {
    const now = Date.now();
    const history = Array.from({ length: 96 }, (_, i) => ({ t: now - 86400000 + i * 900000,
      cpu: 10 + i % 55, ram: 40 + i % 15, wanRx: i * 10000000, wanTx: i * 2000000, wanLatency: 18 + i % 12 }));
    const state = { schema: 1, revision: 1, settings: { language, theme: 'dark', darkCharts: false },
      countries: [], devices: [], sites: [], servers: [], clients: [] };
    return action => action === 'unlock' ? { token: 'ui-fixture', state }
      : action === 'telemetry' ? { available: true, history, sample: { time: now, cpu: 22, ram: 48,
        wan: { device: 'wan', rx: 960000000, tx: 192000000, address: '192.0.2.1' }, latency: { wan: 24 } } }
      : action === 'device.list' ? { devices: [] } : {};
  };
  const cases = [
    ...[375, 390, 430].map(width => ({ label: `desktop-${width}`, width })),
    { label: 'iphone-375', width: 375, mobile: 'iphone' },
    { label: 'iphone-390', width: 390, mobile: 'iphone' },
    { label: 'android-430', width: 430, mobile: 'android' },
    { label: 'android-ar-390', width: 390, mobile: 'android', language: 'ar' },
    { label: 'desktop-1280', width: 1280 }
  ];
  const report = [];
  for (const scenario of cases) {
    const language = scenario.language || 'ru', width = scenario.width, height = 844;
    const context = await browser.newContext({ viewport: { width, height }, deviceScaleFactor: scenario.mobile ? 3 : 1,
      isMobile: !!scenario.mobile, hasTouch: !!scenario.mobile,
      ...(scenario.mobile ? { userAgent: scenario.mobile === 'iphone'
        ? 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1'
        : 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36' } : {}) });
    try {
      const page = await context.newPage(), errors = [];
      page.on('pageerror', error => errors.push(error.message));
      const reply = fixtures(language);
      await page.route('**/cgi-bin/foxhole', route => route.fulfill({ json: reply(route.request().postDataJSON().action) }));
      await page.goto(`${baseURL}/luci-static/resources/foxhole/shell.html`);
      await page.locator('#pin-input').fill('123456');
      await page.waitForSelector('#pin-gate[hidden]', { state: 'attached' });
      await page.waitForFunction(() => document.querySelector('[data-chart-card="wrt"]').classList.contains('has-data'));
      check(await page.title() === 'FoxHole OpenWRT', 'Browser title');
      const dimensions = await page.evaluate(() => ({ viewport: innerWidth,
        overflow: document.documentElement.scrollWidth > innerWidth || document.body.scrollWidth > innerWidth,
        cards: [...document.querySelectorAll('[data-chart-card]')].map(e => e.getBoundingClientRect().toJSON()),
        canvas: [...document.querySelectorAll('[data-chart]')].map(e => ({ css: e.clientWidth, pixels: e.width })),
        app: document.querySelector('#app-shell').getBoundingClientRect().toJSON() }));
      check(!dimensions.overflow, `${scenario.label}: page overflow`);
      if (width <= 540) {
        check(dimensions.cards[0].left === 0 && dimensions.cards[0].width === width, `${scenario.label}: wasted chart width`);
        check(dimensions.cards[1].top > dimensions.cards[0].bottom, `${scenario.label}: charts remain cramped`);
      }
      check(dimensions.canvas.every(e => Math.abs(e.pixels - e.css * (scenario.mobile ? 3 : 1)) <= 1), 'Canvas backing scale');
      for (const period of ['24h', '7d', '30d']) {
        await page.locator('[data-period]').selectOption(period);
        check(await page.locator('[data-chart-card="wrt"]').evaluate(e => e.classList.contains('has-data')), 'Period lost valid data');
      }
      await page.locator('[data-period]').selectOption('24h');
      if (['iphone-390', 'android-430', 'desktop-1280'].includes(scenario.label))
        await page.screenshot({ path: `${screenshots}/foxhole-${scenario.label}-dashboard.png` });
      await page.locator('[data-action="open-settings"]').click();
      await page.waitForSelector('dialog.view-settings-home[open]');
      await page.locator('dialog').evaluate(e => Promise.all(e.getAnimations().map(a => a.finished.catch(() => {}))));
      const modalGeometry = async () => page.locator('dialog[open]').evaluate(e => ({
        rect: e.getBoundingClientRect().toJSON(), stage: e.querySelector('.modal-stage').getBoundingClientRect().toJSON(),
        footer: e.querySelector('.modal-footer').getBoundingClientRect().toJSON(),
        scrollHeight: e.querySelector('.modal-stage').scrollHeight,
        clientHeight: e.querySelector('.modal-stage').clientHeight,
        horizontalOverflow: e.scrollWidth > e.clientWidth }));
      const settings = await modalGeometry();
      check(!settings.horizontalOverflow, 'Settings horizontal overflow');
      check(settings.rect.top >= 0 && settings.rect.bottom <= height + 1, 'Settings outside viewport');
      if (width <= 720) check(settings.rect.left === 0 && settings.rect.width === width, 'Mobile modal side gutters');
      const helpEntry = page.locator('dialog [data-action="open-help"]:visible');
      check(await helpEntry.count() === 1, 'Settings must expose one visible Help entry');
      await helpEntry.click();
      await page.waitForSelector('dialog.view-help[open]');
      check(await page.locator('dialog details[data-help-topic]').count() === 11, 'Help topics missing');
      await page.locator('dialog details[data-help-topic="diagnostics"] summary').click();
      await page.locator('dialog [data-action="modal-back"]').click();
      await page.waitForSelector('dialog.view-settings-home[open]');
      await page.locator('dialog [data-action="open-updates"]').click();
      await page.waitForSelector('dialog.view-updates[open]');
      await page.locator('dialog .modal-footer [data-action="open-help"]').click();
      await page.waitForSelector('dialog.view-help[open]');
      const selectedHelp = page.locator('dialog details[data-help-topic="updates"]');
      check(await selectedHelp.evaluate(e => e.open && document.activeElement === e.querySelector('summary')),
        'Context Help must open and focus its topic');
      check(await page.locator('dialog details[data-help-topic="diagnostics"]').evaluate(e => e.open),
        'Help lost disclosure state after navigation');
      await page.locator('dialog [data-action="modal-back"]').click();
      await page.waitForSelector('dialog.view-updates[open]');
      await page.locator('dialog [data-action="modal-back"]').click();
      await page.waitForSelector('dialog.view-settings-home[open]');
      await page.locator('dialog [data-action="open-exceptions"]').click();
      await page.waitForSelector('dialog.view-exceptions[open]');
      const exceptions = await modalGeometry();
      check(exceptions.footer.bottom <= height + 1 && !exceptions.horizontalOverflow, 'Exception footer clipped');
      await page.locator('dialog .modal-stage').evaluate(e => { e.scrollTop = e.scrollHeight; });
      check(await page.locator('dialog .modal-stage').evaluate(e => e.scrollTop > 0 || e.scrollHeight <= e.clientHeight), 'Modal cannot scroll');
      await page.locator('dialog [data-action="modal-back"]').click();
      await page.waitForSelector('dialog.view-settings-home[open]');
      await page.locator('dialog [data-action="open-interface-settings"]').click();
      await page.waitForSelector('dialog.view-interface-settings[open]');
      await page.locator('dialog [data-setting-picker]').first().locator('[data-popup-trigger]').click();
      const popup = page.locator('[data-popup-menu]:visible').first();
      await popup.waitFor();
      const popupRect = await popup.boundingBox();
      check(popupRect.x >= 0 && popupRect.x + popupRect.width <= width + 1, 'Settings popup exceeds viewport');
      await page.keyboard.press('Escape');
      await page.locator('dialog [data-action="modal-close"]').click();
      await page.waitForSelector('dialog:not([open])', { state: 'attached' });
      check(!await page.locator('#app-shell').evaluate(e => e.inert), 'Background remains inert after modal');
      if (['iphone-390', 'android-430'].includes(scenario.label)) {
        await page.locator('[data-action="open-settings"]').click();
        await page.waitForSelector('dialog.view-settings-home[open]');
        await page.screenshot({ path: `${screenshots}/foxhole-${scenario.label}-settings.png` });
      }
      check(errors.length === 0, `${scenario.label}: ${errors.join('; ')}`);
      report.push({ scenario: scenario.label, viewport: `${width}x${height}`, cardWidth: dimensions.cards[0].width,
        canvasWidth: dimensions.canvas[0].css, modalWidth: settings.rect.width,
        modalBottom: settings.rect.bottom, exceptionsScrollable: exceptions.scrollHeight > exceptions.clientHeight,
        popupWidth: popupRect.width, errors });
    } finally { await context.close(); }
  }
  return report;
}

export async function runPwaUiChecks(browser, baseURL) {
  const check = (value, message) => { if (!value) throw new Error(message); };
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  try {
    const page = await context.newPage();
    const shellURL = `${baseURL}/luci-static/resources/foxhole/shell.html`;
    const entries = [];
    for (const entry of [shellURL, `${baseURL}/foxhole.html`]) {
      await page.goto(entry);
      const metadata = await page.evaluate(async () => {
        const link = document.querySelector('link[rel="manifest"]'), response = await fetch(link.href);
        const manifest = await response.json();
        const urls = { start: new URL(manifest.start_url, response.url).href,
          scope: new URL(manifest.scope, response.url).href, id: new URL(manifest.id, response.url).href };
        const images = [];
        for (const [url, size] of [...manifest.icons.map(icon => [new URL(icon.src, response.url).href, icon.sizes]),
          [document.querySelector('link[rel="apple-touch-icon"]').href, '180x180'],
          [document.querySelector('link[rel="icon"]').href, '32x32']]) {
          const response = await fetch(url), blob = await response.blob(), image = await createImageBitmap(blob);
          images.push({ url, size, actual: `${image.width}x${image.height}`, type: response.headers.get('content-type'), ok: response.ok });
          image.close();
        }
        return { title: document.title, app: document.querySelector('meta[name="application-name"]').content,
          apple: document.querySelector('meta[name="apple-mobile-web-app-title"]').content,
          manifest, urls, type: response.headers.get('content-type'), images };
      });
      check([metadata.title, metadata.app, metadata.apple, metadata.manifest.name, metadata.manifest.short_name].every(value => value === 'FoxHole OpenWRT'), 'PWA name differs');
      check(metadata.urls.start === shellURL && metadata.urls.id === shellURL, 'PWA launches wrong entry');
      check(metadata.urls.scope === `${baseURL}/luci-static/resources/foxhole/`, 'PWA scope exceeds panel directory');
      check(/application\/(?:manifest\+)?json/.test(metadata.type), 'Manifest MIME');
      check(metadata.images.every(image => image.ok && image.type.includes('image/png') && image.actual === image.size), 'Icon MIME/dimensions');
      const launch = await context.request.get(metadata.urls.start);
      check(launch.ok() && launch.headers()['content-type'].includes('text/html'), 'PWA start URL unavailable');
      entries.push({ entry, ...metadata });
    }
    // Execute the actual LuCI view in a padded host and exercise
    // its real iframe relay.
    await page.goto(`${baseURL}/cgi-bin/luci/admin/services/foxhole`);
    const host = await page.evaluate(async () => {
      const source = await (await fetch('/luci-static/resources/view/foxhole/client.js')).text();
      const E = (tag, attributes = {}, children = []) => {
        const node = document.createElement(tag);
        for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
        node.append(...children); return node;
      };
      const rpc = { declare: config => async () => config.method === 'unlock'
        ? { token: 'fixture', state: { schema: 1, revision: 1, settings: { language: 'ru' }, countries: [], devices: [], sites: [], servers: [], clients: [] } }
        : config.method === 'telemetry' ? { available: true, history: [], sample: { time: Date.now(), cpu: 25, ram: 40 } } : {} };
      const view = new Function('view', 'rpc', 'E', 'L', source)({ extend: value => value }, rpc, E,
        { resource: path => `/luci-static/resources/${path}` });
      document.querySelector('main').append(view.render());
      window.fixtureLuciView = view;
      const frame = document.querySelector('iframe').getBoundingClientRect();
      return { title: document.title, left: frame.left, width: frame.width,
        manifest: document.querySelector('link[rel="manifest"]').href,
        apple: document.querySelector('link[rel="apple-touch-icon"]').href };
    });
    check(host.title === 'FoxHole OpenWRT' && host.left === 0 && host.width === 390, 'LuCI mobile frame keeps outer gutters');
    check(host.manifest === `${baseURL}/luci-static/resources/foxhole/manifest.json?v=1.0.6`, 'LuCI manifest points at admin path');
    const frame = page.frameLocator('iframe');
    await frame.locator('#pin-prompt:not(:empty)').waitFor();
    await frame.locator('#pin-input').fill('123456');
    await frame.locator('#app-shell:not([hidden])').waitFor();
    const restored = await page.evaluate(() => {
      window.fixtureLuciView.remove();
      return { title: document.title, manifest: !!document.querySelector('link[rel="manifest"]'),
        icon: document.querySelector('link[rel="icon"]').getAttribute('href') };
    });
    check(restored.title === 'LuCI original' && !restored.manifest && restored.icon === '/luci-original.png', 'LuCI metadata cleanup');
    return { entries, host, restored };
  } finally { await context.close(); }
}

export async function runChartDataUiChecks(browser, baseURL) {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  try {
    const page = await context.newPage();
    await page.goto(`${baseURL}/luci-static/resources/foxhole/shell.html`);
    return await page.evaluate(async () => {
      const { Charts } = await import('./charts.js?v=1.0.6');
      const end = Date.now(), report = [];
      for (const mode of ['nonzero', 'zero', 'invalid', 'gapped']) {
        const card = document.createElement('div'); card.className = 'chart-card'; card.dataset.chartCard = 'fixture'; card.style.width = '360px';
        const frame = document.createElement('div'); frame.className = 'chart-frame';
        const canvas = document.createElement('canvas'); frame.append(canvas); card.append(frame); document.body.append(card);
        const ctx = canvas.getContext('2d'), moves = [], lines = [];
        const moveTo = ctx.moveTo.bind(ctx), lineTo = ctx.lineTo.bind(ctx);
        ctx.moveTo = (x, y) => { if (ctx.strokeStyle === '#00ff00') moves.push([x, y]); moveTo(x, y); };
        ctx.lineTo = (x, y) => { if (ctx.strokeStyle === '#00ff00') lines.push([x, y]); lineTo(x, y); };
        const history = Array.from({ length: 12 }, (_, i) => ({
          t: end - 840000 + i * 45000 + (mode === 'gapped' && i >= 8 ? 180000 : 0),
          cpu: mode === 'invalid' || mode === 'gapped' && i === 4 ? 'invalid' : mode === 'zero' ? 0 : 10 + i * 5,
          ram: null
        }));
        const charts = Object.assign(Object.create(Charts.prototype), { samples: [], historyRevision: null,
          maintenanceAt: 0, period: '24h', draw() {}, updateMeta() {} });
        charts.update({ history });
        charts.render(canvas, 'wrt', end, { label: '#777777', grid: '#333333', color: ['#00ff00', '#0000ff'], mono: ['#00ff00', '#0000ff'] });
        const pixels = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
        let colored = 0;
        for (let i = 0; i < pixels.length; i += 4) if (pixels[i + 1] > 80 && pixels[i] < 40 && pixels[i + 2] < 40) colored++;
        const expectedMoves = mode === 'invalid' ? 0 : mode === 'gapped' ? 3 : 1;
        const expectedLines = mode === 'invalid' ? 0 : mode === 'gapped' ? 8 : 11;
        if (moves.length !== expectedMoves || lines.length !== expectedLines) throw new Error(`${mode}: false continuity or gaps`);
        if (mode === 'invalid' ? colored !== 0 : colored === 0) throw new Error(`${mode}: real canvas pixels missing or invented`);
        if (card.classList.contains('has-data') !== (mode !== 'invalid')) throw new Error(`${mode}: wrong empty state`);
        if (mode === 'zero' && ![...moves, ...lines].every(point => point[1] === canvas.clientHeight - 19)) throw new Error('Zero values are not on baseline');
        report.push({ mode, moves: moves.length, lines: lines.length, coloredPixels: colored,
          hasData: card.classList.contains('has-data') });
        card.remove();
      }
      return report;
    });
  } finally { await context.close(); }
}

export async function runKeyboardUiChecks(browser, baseURL) {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  try {
    const page = await context.newPage();
    await page.route('**/cgi-bin/foxhole', route => route.fulfill({ json: route.request().postDataJSON().action === 'unlock'
      ? { token: 'fixture', state: { schema: 1, revision: 1, settings: { language: 'ru' }, countries: [], devices: [], sites: [], servers: [], clients: [] } }
      : { available: true, sample: { time: Date.now(), cpu: 20, ram: 40 }, history: [] } }));
    await page.goto(`${baseURL}/luci-static/resources/foxhole/shell.html`);
    await page.locator('#pin-input').fill('123456');
    await page.locator('#app-shell:not([hidden])').waitFor();
    await page.locator('[data-action="open-add"]').click();
    await page.locator('dialog [data-action="add-server"]').click();
    await page.locator('dialog textarea').focus();
    const keyboard = await page.evaluate(() => {
      Object.defineProperty(window.visualViewport, 'height', { configurable: true, get: () => 350 });
      Object.defineProperty(window.visualViewport, 'offsetTop', { configurable: true, get: () => 100 });
      window.visualViewport.dispatchEvent(new Event('resize'));
      const e = document.querySelector('dialog'), rect = e.getBoundingClientRect();
      return { top: rect.top, bottom: rect.bottom, height: rect.height,
        footerBottom: e.querySelector('.modal-footer').getBoundingClientRect().bottom,
        keyboard: document.documentElement.classList.contains('has-visual-keyboard') };
    });
    if (!keyboard.keyboard || keyboard.top < 100 || keyboard.bottom > 450 || keyboard.footerBottom > 450)
      throw new Error('Keyboard hides dialog actions');
    await page.evaluate(() => {
      delete window.visualViewport.height; delete window.visualViewport.offsetTop;
      window.visualViewport.dispatchEvent(new Event('resize'));
    });
    await page.setViewportSize({ width: 430, height: 360 });
    const landscape = await page.locator('dialog').evaluate(e => ({ top: e.getBoundingClientRect().top,
      bottom: e.getBoundingClientRect().bottom, stage: e.querySelector('.modal-stage').clientHeight,
      scroll: e.querySelector('.modal-stage').scrollHeight }));
    if (landscape.top < 0 || landscape.bottom > 360 || landscape.stage <= 0 || landscape.scroll <= landscape.stage)
      throw new Error('Landscape modal cannot scroll within viewport');
    return { keyboard, landscape };
  } finally { await context.close(); }
}
