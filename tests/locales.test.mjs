import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import { panelRoot, read, root } from './helpers.mjs';

const en = JSON.parse(await read(`${panelRoot}/locales/en.json`));
const languages = ['ru', 'en', 'ja', 'de', 'fr', 'es', 'zh'];
const locales = Object.fromEntries(await Promise.all(languages.map(async language =>
  [language, JSON.parse(await read(`${panelRoot}/locales/${language}.json`))])));
const ru = locales.ru;
const keys = (value) => Object.keys(value).sort();
const placeholders = (value) => [...value.matchAll(/\{([a-zA-Z][a-zA-Z0-9_]*)\}/g)]
  .map((match) => match[1]).sort();

test('all supported locale files are shipped', async () => {
  assert.deepEqual((await readdir(resolve(root, panelRoot, 'locales'))).sort(), languages.map(language => `${language}.json`).sort());
});

test('locale keys and interpolation parameters remain identical', () => {
  for (const [language, dictionary] of Object.entries(locales)) {
    assert.deepEqual(keys(dictionary), keys(en), language);
    for (const key of keys(en)) {
      assert.equal(typeof dictionary[key], 'string', `${language}:${key}`);
      assert.ok(dictionary[key].trim(), `${language}:${key}`);
      assert.deepEqual(placeholders(dictionary[key]), placeholders(en[key]), `${language}:${key}`);
    }
  }
});

test('literal UI translation references are present', async () => {
  const app = await read(`${panelRoot}/app.js`);
  const shell = await read(`${panelRoot}/shell.html`);
  const used = [
    ...[...app.matchAll(/\bt\(['"]([^'"]+)['"]/g)].map((match) => match[1]),
    ...[...shell.matchAll(/data-i18n(?:-[a-z-]+)?="([^"]+)"/g)].map((match) => match[1])
  ];
  assert.ok(used.length > 80);
  for (const key of used) assert.ok(Object.hasOwn(en, key), key);
  for (const type of ['servers', 'clients']) {
    for (const suffix of ['title', 'empty_title']) {
      assert.ok(Object.hasOwn(en, `${type}.${suffix}`));
    }
  }
});

test('runtime and configuration status is localized', () => {
  for (const key of ['dashboard.runtime_connected',
    'dashboard.runtime_disconnected', 'server.test_valid',
    'server.connecting', 'server.connected_notice', 'settings.saved']) {
    assert.ok(en[key] && ru[key], key);
  }
  assert.match(en['dashboard.runtime_connected'], /routing is active/i);
  assert.match(en['dashboard.runtime_disconnected'], /not enforced/i);
});

test('UI copy contains no emoji or text-shaped option icons', () => {
  const text = JSON.stringify(locales);
  assert.doesNotMatch(text, /[\p{Extended_Pictographic}\p{Regional_Indicator}]/u);
  assert.doesNotMatch(text, /[◎▣]/u);
});

test('local country flags and Tabler icons are packaged', async () => {
  const flags = await readdir(resolve(root, panelRoot, 'assets/flags'));
  const icons = await readdir(resolve(root, panelRoot, 'assets/tabler'));
  assert.ok(flags.length >= 249);
  for (const name of ['gb.svg', 'no.svg', 'ru.svg', 'us.svg'])
    assert.ok(flags.includes(name), name);
  for (const name of ['devices.svg', 'eye.svg', 'moon.svg', 'sun.svg',
    'trash.svg', 'world.svg']) assert.ok(icons.includes(name), name);
});

test('language picker, normalization and backend accept every shipped locale', async () => {
  const shell = await read(`${panelRoot}/shell.html`);
  const app = await read(`${panelRoot}/app.js`);
  const frontend = await read(`${panelRoot}/frontend-model.js`);
  const backend = await read('package/foxhole-openwrt-client/root/usr/share/foxhole/model.uc');
  for (const language of languages) {
    assert.ok(shell.includes(`<option value="${language}"`), language);
    assert.ok(shell.includes(`data-value="${language}"`), language);
    assert.ok(app.includes(`'${language}'`), language);
    assert.ok(frontend.includes(`'${language}'`), language);
    assert.ok(backend.includes(`'${language}'`), language);
  }
});
