import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import { panelRoot, read, root } from './helpers.mjs';

const en = JSON.parse(await read(`${panelRoot}/locales/en.json`));
const ru = JSON.parse(await read(`${panelRoot}/locales/ru.json`));
const keys = (value) => Object.keys(value).sort();
const placeholders = (value) => [...value.matchAll(/\{([a-zA-Z][a-zA-Z0-9_]*)\}/g)]
  .map((match) => match[1]).sort();

test('only English and Russian locale files are shipped', async () => {
  assert.deepEqual((await readdir(resolve(root, panelRoot, 'locales'))).sort(), ['en.json', 'ru.json']);
});

test('locale keys and interpolation parameters remain identical', () => {
  assert.deepEqual(keys(ru), keys(en));
  for (const key of keys(en)) {
    assert.equal(typeof en[key], 'string', key);
    assert.equal(typeof ru[key], 'string', key);
    assert.ok(en[key].trim() && ru[key].trim(), key);
    assert.deepEqual(placeholders(ru[key]), placeholders(en[key]), key);
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
  const text = JSON.stringify({ en, ru });
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
