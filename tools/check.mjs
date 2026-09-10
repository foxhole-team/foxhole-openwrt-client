import { spawnSync } from 'node:child_process';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { collectPublic, exportPublic } from './public-export.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const model = process.argv.includes('--model');
const flags = process.argv.slice(2).filter((item) => item !== '--model');

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root, encoding: 'utf8', timeout: 60000,
    maxBuffer: 4 * 1024 * 1024, ...options
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error || result.status !== 0) throw new Error(`Check failed: ${command}`);
}

async function files(directory) {
  const result = [];
  for (const entry of await readdir(join(root, directory), { withFileTypes: true })) {
    const path = `${directory}/${entry.name}`;
    if (entry.isDirectory()) result.push(...await files(path));
    else if (entry.isFile()) result.push(path);
    else throw new Error('Validation refuses non-regular source files');
  }
  return result;
}

try {
  if (flags.length) throw new Error('Usage: node tools/check.mjs [--model]');
  const publicSource = await collectPublic(root);
  const paths = [...new Set([
    ...publicSource.map((entry) => entry.path),
    ...await files('tests'), ...await files('tools')
  ])].sort();
  let syntax = 0;
  for (const path of paths) {
    if (!/\.(?:js|mjs|json|uc|sh)$/.test(path) && basename(path) !== 'Makefile' &&
      !path.includes('/usr/libexec/') && !path.includes('/etc/init.d/') &&
      !path.includes('/uci-defaults/')) continue;
    const source = await readFile(resolve(root, path), 'utf8');
    if (/\.json$/.test(path)) JSON.parse(source);
    else if (path.includes('/resources/view/')) new vm.Script(`(function() {${source}\n})`);
    else if (/\.(?:js|mjs)$/.test(path)) run(process.execPath, ['--check', path]);
    else if (source.startsWith('#!/bin/sh')) run('/bin/sh', ['-n', path]);
    if (!/\.json$/.test(path)) {
      source.split('\n').forEach((line, index) => {
        const comment = line.trimStart();
        if (/^(?:\/\/|\/\*|\*(?!\/)|#(?!\!))/.test(comment) &&
          [...comment].length > 66) throw new Error(`Comment exceeds 66 characters: ${path}:${index + 1}`);
      });
    }
    syntax += 1;
  }
  process.stdout.write(`Syntax and comment checks: ${syntax} source files.\n`);
  run(process.execPath, ['tools/check-docs.mjs']);
  const tests = paths.filter((path) => path.startsWith('tests/') && path.endsWith('.test.mjs'));
  run(process.execPath, ['--test', ...tests]);
  const gitleaks = spawnSync('gitleaks', ['version'], { encoding: 'utf8' });
  if (gitleaks.error || gitleaks.status !== 0) throw new Error('gitleaks is required for public sanitization');
  const temporary = await mkdtemp(join(tmpdir(), 'foxhole-public-check-'));
  try {
    const result = await exportPublic({ source: root, destination: join(temporary, 'snapshot') });
    const scan = spawnSync('gitleaks', ['dir', '--redact=100', '--no-banner',
      '--log-level', 'error', result.destination], { encoding: 'utf8', timeout: 60000 });
    if (scan.error || scan.status !== 0) throw new Error('Public snapshot secret scan failed; output withheld');
    process.stdout.write(`Public allowlist and secret scan: ${result.files.length} files.\n`);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
  if (model) {
    run(process.execPath, ['tests/run-model.mjs']);
    run(process.execPath, ['tests/run-probe.mjs']);
  }
  else process.stdout.write('Ucode model execution not requested; add --model to run it.\n');
  process.stdout.write('Checks passed. No router configuration was changed.\n');
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
