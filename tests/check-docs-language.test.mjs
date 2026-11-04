import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const checker = await readFile(new URL('../tools/check-docs.mjs', import.meta.url));
const languageBar = '<p align="center">\n' +
  '  <strong>English</strong> · ' +
  '<a href="docs/README.ru.md">Русский</a>\n</p>';
const languageBadge = '[![Русский](https://img.shields.io/badge/language-Russian-blue)](docs/README.ru.md)';
const languages = ['ru', 'de', 'fr', 'es', 'ja', 'zh', 'ar'];
const plainLanguageRow = (nested = false) => {
  const names = ['English', 'Русский', 'Deutsch', 'Français', 'Español', '日本語', '简体中文', 'العربية'];
  const files = ['README.md', 'README.ru.md', 'README.de.md', 'README.fr.md', 'README.es.md', 'README.ja.md', 'README.zh.md', 'README.ar.md'];
  return names.map((name, i) => `[${name}](${nested ? (i === 0 ? '../README.md' : files[i]) : (i === 0 ? files[i] : `docs/${files[i]}`)})`).join(' · ');
};

async function check(readme, security = '# Security\n', documents = {}) {
  const root = await mkdtemp(join(tmpdir(), 'foxhole-doc-language-'));
  try {
    for (const directory of ['tools', 'docs', 'examples'])
      await mkdir(join(root, directory));
    await writeFile(join(root, 'tools/check-docs.mjs'), checker);
    for (const [name, body] of Object.entries({
      'README.md': readme, 'SECURITY.md': security,
      'CHANGELOG.md': '# Changes\n',
      'THIRD_PARTY_NOTICES.md': '# Notices\n',
      'examples/README.md': '# Examples\n',
      'docs/README.ru.md': '# Документация\n',
      ...Object.fromEntries(languages.filter(locale => locale !== 'ru').map(locale => [`docs/README.${locale}.md`, '# Documentation\n'])),
      ...documents
    })) await writeFile(join(root, name), body);
    const result = spawnSync(process.execPath,
      [join(root, 'tools/check-docs.mjs')], {
        encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024
      });
    assert.equal(result.error, undefined);
    return result;
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('exact English README language bar is allowed', async () => {
  const result = await check('# Product\n\n' + languageBar + '\n');
  assert.equal(result.status, 0, result.stderr);
});

test('Russian prose outside the exact bar is rejected', async () => {
  const result = await check(languageBar + '\nРусский текст\n');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Russian prose belongs/);
});

test('a different Russian selector target is rejected', async () => {
  const result = await check(languageBar.replace('README.ru.md', 'README.md'));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Russian prose belongs/);
});

test('the same bar in a different document is rejected', async () => {
  const result = await check('# Product\n', languageBar);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Russian prose belongs/);
});

test('a duplicate language bar cannot hide Russian text', async () => {
  const result = await check(languageBar + '\n' + languageBar);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Russian prose belongs/);
});

test('the complete approved eight-language plain row is allowed in root README', async () => {
  const result = await check('# Product\n\n' + plainLanguageRow() + '\n');
  assert.equal(result.status, 0, result.stderr);
});

for (const locale of languages) test(`the exact nested plain row is allowed in README.${locale}`, async () => {
  const result = await check('# Product\n', '# Security\n', {
    [`docs/README.${locale}.md`]: '# Documentation\n\n' + plainLanguageRow(true) + '\n'
  });
  assert.equal(result.status, 0, result.stderr);
});

test('plain navigation does not exempt adjacent Russian prose', async () => {
  const result = await check(plainLanguageRow() + '\nРусский текст\n');
  assert.equal(result.status, 1); assert.match(result.stderr, /Russian prose belongs/);
});

test('a valid local target in the wrong plain selector is rejected', async () => {
  const result = await check(plainLanguageRow().replace('docs/README.ru.md', 'README.md'));
  assert.equal(result.status, 1); assert.match(result.stderr, /invalid or duplicate language selector/);
});

test('a wrong target is rejected even in Russian README', async () => {
  const result = await check('# Product\n', '# Security\n', {
    'docs/README.ru.md': plainLanguageRow(true).replace('[English](../README.md)', '[English](README.ru.md)')
  });
  assert.equal(result.status, 1); assert.match(result.stderr, /invalid or duplicate language selector/);
});

test('a plain row missing Arabic is rejected', async () => {
  const result = await check(plainLanguageRow().replace(' · [العربية](docs/README.ar.md)', ''));
  assert.equal(result.status, 1); assert.match(result.stderr, /invalid or duplicate language selector/);
});

test('plain navigation is rejected outside the known README paths', async () => {
  const result = await check('# Product\n', plainLanguageRow());
  assert.equal(result.status, 1); assert.match(result.stderr, /invalid or duplicate language selector/);
});

test('non-Russian roadmap links do not need a Russian prose exception', async () => {
  const result = await check('# Product\n', '# Security\n', {
    'ROADMAP.md': '# Roadmap\n',
    'docs/ROADMAP.ar.md': '# خارطة الطريق\n[English](../ROADMAP.md) · [العربية](README.ar.md)\n'
  });
  assert.equal(result.status, 0, result.stderr);
});

test('a duplicate plain row is rejected even in Russian README', async () => {
  const result = await check('# Product\n', '# Security\n', {
    'docs/README.ru.md': plainLanguageRow(true) + '\n' + plainLanguageRow(true)
  });
  assert.equal(result.status, 1); assert.match(result.stderr, /invalid or duplicate language selector/);
});

for (const old of [languageBar, languageBadge]) test(`mixed plain and legacy ${old === languageBar ? 'bar' : 'badge'} selectors are rejected`, async () => {
  const result = await check(plainLanguageRow() + '\n' + old);
  assert.equal(result.status, 1); assert.match(result.stderr, /invalid or duplicate language selector/);
});

test('the legacy Russian badge is still allowed', async () => {
  const result = await check('# Product\n' + languageBadge);
  assert.equal(result.status, 0, result.stderr);
});

test('plain navigation still checks local links', async () => {
  const result = await check(plainLanguageRow() + '\n[Missing](missing.md)\n');
  assert.equal(result.status, 1); assert.match(result.stderr, /Broken local link/);
});

test('plain navigation still checks shell syntax', async () => {
  const result = await check(plainLanguageRow() + '\n```sh\nif then\n```\n');
  assert.equal(result.status, 1); assert.match(result.stderr, /Invalid shell example/);
});


test('owner Russian release notes are allowed in the exact root changelog', async () => {
  const result = await check('# Product\n', '# Security\n', { 'CHANGELOG.md': '# Изменения\n\n- Исправлена установка пакета.\n' });
  assert.equal(result.status, 0, result.stderr);
});

test('the changelog language exception does not apply to a nested path', async () => {
  const result = await check('# Product\n', '# Security\n', { 'docs/CHANGELOG.md': '# Изменения\n' });
  assert.equal(result.status, 1); assert.match(result.stderr, /Russian prose belongs/);
});

test('Russian changelog still rejects broken local links', async () => {
  const result = await check('# Product\n', '# Security\n', { 'CHANGELOG.md': '# Изменения\n[Ссылка](missing.md)\n' });
  assert.equal(result.status, 1); assert.match(result.stderr, /Broken local link/);
});

test('Russian changelog still rejects an unclosed code fence', async () => {
  const result = await check('# Product\n', '# Security\n', { 'CHANGELOG.md': '# Изменения\n```sh\necho safe\n' });
  assert.equal(result.status, 1); assert.match(result.stderr, /Unclosed code fence/);
});

test('Russian changelog still rejects invalid shell syntax', async () => {
  const result = await check('# Product\n', '# Security\n', { 'CHANGELOG.md': '# Изменения\n```sh\nif then\n```\n' });
  assert.equal(result.status, 1); assert.match(result.stderr, /Invalid shell example/);
});
