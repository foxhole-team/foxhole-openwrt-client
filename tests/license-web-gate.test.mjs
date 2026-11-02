import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { packageRoot, panelRoot, read } from './helpers.mjs';

// Full original Android author text, with only the router product-name adapter.
const original = {
  en: 'a7050b99ff0953919a62e31742a7d038cbd8d3c01c1156875b3a5789ffbaa8d5',
  ru: '354619423e2aba1d979d7e5bce5dfdd7bb4b65b3eb10ee8fbb26d944fb4d84bc',
  de: '69ead2eaeebf7fcb166f9a9f550c9a66bdf65b953c46f37dbe3f967c4e5a9f7b',
  fr: '32c9063008274a1b833894163dd6df57343dc8fb6272c332bef38f805f637322',
  es: 'b01a3f261f05549d0c491e9ed40a3c1088c34c439a17d21e1c6f3ce5ad12693c',
  ja: 'a80ec7eb59d579520a5419ef6ac96b6442e097acf76137d66cb1b1bebf657b03',
  zh: 'f48129ffbc3a4e5b544591588efd6251d8b7d9a5b42a60e015de7cd73b203597'
};
test('web and installed CLI retain all five original clauses in all seven locales', async () => {
  const document = JSON.parse(await read(`${packageRoot}/root/usr/share/foxhole/license-agreement.json`));
  assert.equal(document.schema, 1); assert.equal(document.version, 1);
  for (const [language, expected] of Object.entries(original)) {
    const locale = JSON.parse(await read(`${panelRoot}/locales/${language}.json`));
    assert.equal(locale['license.body'], document.locales[language].body);
    assert.equal(createHash('sha256').update(locale['license.body']).digest('hex'), expected, language);
    assert.equal([...locale['license.body'].matchAll(/(?:^|\n\n)[1-5]\. /g)].length, 5, language);
  }
});
test('first-run text is expanded and scrollable with an unchecked acceptance checkbox at the bottom', async () => {
  const shell = await read(`${panelRoot}/shell.html`), css = await read(`${panelRoot}/app.css`);
  const template = shell.match(/<template id="tpl-pin-change"[\s\S]*?<\/template>/)?.[0];assert.ok(template);
  assert.doesNotMatch(template, /<details|<summary/);
  assert.match(template, /license-agreement-scroll[^>]*role="region"[^>]*tabindex="0"/);
  assert.match(template, /data-i18n="license\.body"/);
  const checkbox = template.match(/<input[^>]+data-license-accept[^>]*>/)?.[0];assert.ok(checkbox);
  assert.match(checkbox, /type="checkbox"/);assert.doesNotMatch(checkbox, /\bchecked\b/);
  assert.ok(template.indexOf('data-license-accept') > template.indexOf('data-repeat-pin'));
  assert.match(css, /\.license-agreement-scroll\s*\{[^}]*overflow:\s*auto/);
  assert.match(css, /\.license-agreement-body\s*\{[^}]*white-space:\s*pre-wrap/);
});
