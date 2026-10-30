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

async function check(readme, security = '# Security\n') {
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
      'docs/README.ru.md': '# Документация\n'
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
