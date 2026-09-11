import { constants } from 'node:fs';
import { createPublicKey } from 'node:crypto';
import { chmod, lstat, mkdir, open, readdir, realpath, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const publicFiles = ['LICENSE', 'THIRD_PARTY_NOTICES.md',
  'README.md', 'CHANGELOG.md', 'SECURITY.md', '.gitattributes', '.gitignore',
  'install.sh', 'package.json', 'package-lock.json'];
export const publicDirectories = ['package', 'LICENSES', 'media', 'docs', 'config',
  'examples', '.github', 'tests', 'tools'];
const root = fileURLToPath(new URL('..', import.meta.url));
const oldBrand = new RegExp(['dae', 'mon'].join(''), 'i');
const privateName = ['priv', 'vpn', 'vps'].join('_');
const prohibitedNames = /(?:^|\/)(?:\.git|\.DS_Store|node_modules|creds|certs|secrets|artifacts|backups|dist|__pycache__)(?:\/|$)|(?:^|\/)\.env(?:\.|$)|\.(?:key|pem|p12|pfx|crt|cer|ipk|apk|tar|gz|zip|log|pyc)$/i;
const binaryExtensions = /\.(?:png|gif|ttf|woff2?|ico)$/i;

function fail(code) {
  throw new Error(code);
}

function inside(parent, child) {
  const path = relative(parent, child);
  return path === '' || (!path.startsWith(`..${sep}`) && path !== '..' && !isAbsolute(path));
}

export function validatePublicFile(path, data) {
  const apkKey = path === 'config/foxhole-openwrt-apk.pem';
  if (path.split('/').includes('AGENTS.md') || oldBrand.test(path) || path.includes(privateName) ||
    (prohibitedNames.test(path) && !apkKey)) {
    fail('Public export contains a prohibited path');
  }
  const text = data.toString('utf8');
  if (oldBrand.test(text) || text.includes(privateName) ||
    /\/(?:Users|Volumes)\//.test(text)) {
    fail('Public export contains a private identifier');
  }
  if (/-----BEGIN (?:[A-Z ]*PRIVATE KEY|CERTIFICATE)-----/.test(text)) {
    fail('Public export contains credential material');
  }
  if (apkKey) {
    if (!/^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PUBLIC KEY-----\n$/.test(text))
      fail('Invalid public APK key');
    const key = createPublicKey(data);
    if (key.asymmetricKeyType !== 'ec' ||
      key.asymmetricKeyDetails.namedCurve !== 'prime256v1')
      fail('Public APK key must use P-256');
  }
  if (binaryExtensions.test(path)) return;
  if (data.includes(0)) fail('Public export contains an unexpected binary file');
}

async function readRegular(path, expected) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const current = await handle.stat();
    if (!current.isFile() || current.ino !== expected.ino || current.dev !== expected.dev) {
      fail('Public export source changed during inspection');
    }
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

export async function collectPublic(source = root) {
  const sourcePath = resolve(source);
  const sourceInfo = await lstat(sourcePath);
  if (sourceInfo.isSymbolicLink() || !sourceInfo.isDirectory()) {
    fail('Public export source must be a regular directory');
  }
  const entries = [];
  async function visit(path, directory = false) {
    const absolute = join(sourcePath, path);
    const info = await lstat(absolute);
    if (info.isSymbolicLink()) fail('Public export refuses symbolic links');
    if (info.isDirectory()) {
      if (!directory) fail('Public export expected a regular file');
      validatePublicFile(path, Buffer.alloc(0));
      for (const name of (await readdir(absolute)).sort()) {
        if (name === 'AGENTS.md') continue;
        await visit(`${path}/${name}`, true);
      }
      return;
    }
    if (!info.isFile()) fail('Public export refuses special files');
    const data = await readRegular(absolute, info);
    validatePublicFile(path, data);
    entries.push({ path, data, mode: info.mode & 0o111 ? 0o755 : 0o644 });
  }
  for (const path of publicFiles) await visit(path);
  for (const path of publicDirectories) {
    if (!(await lstat(join(sourcePath, path))).isDirectory()) {
      fail('Public export expected a source directory');
    }
    await visit(path, true);
  }
  return entries.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
}

export async function exportPublic({ source = root, destination }) {
  if (!destination) fail('A new destination directory is required');
  const sourcePath = await realpath(source);
  const requested = resolve(destination);
  const parent = await realpath(dirname(requested));
  const target = join(parent, relative(dirname(requested), requested));
  if (inside(sourcePath, target)) fail('Public export must be outside the source repository');
  const entries = await collectPublic(source);
  await mkdir(target, { mode: 0o755 });
  for (const entry of entries) {
    const path = join(target, entry.path);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, entry.data, { flag: 'wx', mode: entry.mode });
    await chmod(path, entry.mode);
  }
  return { destination: target, files: entries.map((entry) => entry.path) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) fail('Usage: node tools/public-export.mjs NEW_DIRECTORY');
    if (process.argv[2] === '--list') {
      const entries = await collectPublic();
      process.stdout.write(JSON.stringify(entries.map(({ path, mode }) => ({ path, mode }))));
    } else {
      const result = await exportPublic({ destination: process.argv[2] });
      process.stdout.write(`Exported ${result.files.length} public files. No Git state was changed.\n`);
    }
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
