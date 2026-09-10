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
    if (path !== 'docs/README.ru.md' && /[А-Яа-яЁё]/.test(
      source.replace(/<[^>]+>/g, '')))
      throw new Error(`Russian prose belongs in docs/README.ru.md: ${path}`);
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
