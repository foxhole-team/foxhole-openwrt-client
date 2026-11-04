import { spawnSync } from 'node:child_process';
import { readdir, readFile, stat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const paths = ['README.md', 'SECURITY.md', 'CHANGELOG.md',
  'THIRD_PARTY_NOTICES.md', 'examples/README.md',
  ...(await readdir(resolve(root, 'docs')))
    .filter(name => name.endsWith('.md')).map(name => `docs/${name}`)];
let links = 0, shells = 0;

try {
  for (const path of paths) {
    const source = await readFile(resolve(root, path), 'utf8');
    if (source.match(/^```/gm)?.length % 2 === 1)
      throw new Error(`Unclosed code fence: ${path}`);
    const languageBar = '<p align="center">\n' +
      '  <strong>English</strong> · ' +
      '<a href="docs/README.ru.md">Русский</a>\n</p>';
    const knownReadme = path === 'README.md' || /^docs\/README\.(?:ru|de|es|fr|ja|zh|ar)\.md$/.test(path);
    const languageNames = ['English', 'Русский', 'Deutsch', 'Français', 'Español', '日本語', '简体中文', 'العربية'];
    const languageFiles = ['README.md', 'README.ru.md', 'README.de.md', 'README.fr.md', 'README.es.md', 'README.ja.md', 'README.zh.md', 'README.ar.md'];
    const plainLanguageRow = languageNames.map((name, i) => {
      const target = path === 'README.md' ? (i === 0 ? languageFiles[i] : `docs/${languageFiles[i]}`) :
        (i === 0 ? '../README.md' : languageFiles[i]);
      return `[${name}](${target})`;
    }).join(' · ');
    const plainRows = source.split('\n').filter(line =>
      line.includes('[Русский](') && languageNames.filter(name => line.includes(`[${name}](`)).length > 1);
    const badges = [...source.matchAll(/^\[!\[Русский\]\(https:\/\/img\.shields\.io\/badge\/[^)\r\n]+\)\]\(([^)\r\n]+)\)$/gm)];
    const bars = [...source.matchAll(/<p align="center">\n  <strong>English<\/strong> · <a href="[^"]+">Русский<\/a>\n<\/p>/g)];
    const selectors = plainRows.length + badges.length + bars.length;
    if (plainRows.some(line => !knownReadme || line !== plainLanguageRow) ||
        badges.some(match => !knownReadme || match[1] !== (path === 'README.md' ? 'docs/README.ru.md' : 'README.ru.md')) ||
        bars.some(match => path !== 'README.md' || match[0] !== languageBar) ||
        selectors > 1)
      throw new Error(`Russian prose belongs in CHANGELOG.md or docs/README.ru.md (invalid or duplicate language selector): ${path}`);
    let prose = path === 'README.md' ? source.replace(languageBar, '') : source;
    if (knownReadme && plainRows.length === 1) prose = prose.replace(plainLanguageRow, '');
    if (knownReadme && badges.length === 1) prose = prose.replace(badges[0][0], '');
    if (!['docs/README.ru.md', 'CHANGELOG.md'].includes(path) && /[А-Яа-яЁё]/.test(
      prose.replace(/<[^>]+>/g, '')))
      throw new Error(`Russian prose belongs in CHANGELOG.md or docs/README.ru.md: ${path}`);
    for (const match of source.matchAll(/\]\(([^\s)]+)\)|(?:href|src)="([^"]+)"/g)) {
      const target = match[1] || match[2];
      if (/^(?:https?:|mailto:|#)/.test(target)) continue;
      const relative = decodeURIComponent(target.split('#')[0]);
      await stat(resolve(root, dirname(path), relative)).catch(() => {
        throw new Error(`Broken local link: ${path} -> ${target}`);
      });
      links += 1;
    }
    for (const [, code] of source.matchAll(/^```sh\n([\s\S]*?)^```/gm)) {
      const result = spawnSync('/bin/sh', ['-n'], {
        input: code, encoding: 'utf8', timeout: 5000
      });
      if (result.error || result.status !== 0)
        throw new Error(`Invalid shell example: ${path}`);
      shells += 1;
    }
  }
  process.stdout.write(`Documentation: ${paths.length} files, ${links} local links, ${shells} shell examples.\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
