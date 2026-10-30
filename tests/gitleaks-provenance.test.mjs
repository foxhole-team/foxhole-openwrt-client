import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { root } from './helpers.mjs';

const paths = ['package/hysteria/patches/100-network-security.patch',
  'package/hysteria/combined-source.patch', 'package/hysteria/security-source.json'];
const knownDigest = 'e80ddc841facfc37db93de8e727865c784c44bef525df8d286de7d8ff653bcad';

for (const scenario of ['public-context', 'network-patch-secret',
  'combined-patch-secret', 'inventory-secret', 'unknown-inventory-digest',
  'known-digest-other-path', 'unknown-module-checksum', 'other-default-rule']) {
  test('Public checksum classification keeps detection: ' + scenario, async t => {
    const directory = await mkdtemp(join(tmpdir(), 'foxhole-scanner-regression-'));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const snapshot = join(directory, 'snapshot');
    await mkdir(snapshot);
    const content = new Map();
    for (const path of paths) content.set(path, await readFile(join(root, path), 'utf8'));
    const generated = createHash('sha256').update('generated scanner fixture').digest('hex');
    if (scenario === 'network-patch-secret') content.set(paths[0], content.get(paths[0]) + '\n+api_key = "' + generated + '"\n');
    if (scenario === 'combined-patch-secret') content.set(paths[1], content.get(paths[1]) + '\n+api_key = "' + generated + '"\n');
    if (scenario === 'inventory-secret') {
      const record = JSON.parse(content.get(paths[2]));
      record.api_key = generated;
      content.set(paths[2], JSON.stringify(record));
    }
    if (scenario === 'unknown-inventory-digest') content.set(paths[2], content.get(paths[2]).replaceAll(knownDigest, generated));
    if (scenario === 'known-digest-other-path') content.set('other.txt', 'api_key = "' + knownDigest + '"\n');
    if (scenario === 'unknown-module-checksum') {
      const original = content.get(paths[0]).split('\n')[72].split('h1:')[1].trim();
      const generatedSum = createHash('sha256').update('unknown module fixture').digest('base64');
      content.set(paths[0], content.get(paths[0]).replace(original, generatedSum));
    }
    if (scenario === 'other-default-rule') content.set(paths[0], content.get(paths[0]) + '\n' + 'gh' + 'p_' + generated.slice(0, 36) + '\n');
    for (const [path, data] of content) {
      await mkdir(dirname(join(snapshot, path)), { recursive: true });
      await writeFile(join(snapshot, path), data);
    }
    const report = join(directory, 'report.json');
    const result = spawnSync('gitleaks', ['dir', '--redact=100', '--no-banner',
      '--log-level', 'error', '--config', join(root, '.gitleaks.toml'),
      '--report-format=json', '--report-path', report, snapshot], {
      encoding: 'utf8', timeout: 10000, maxBuffer: 1024 * 1024
    });
    assert.ifError(result.error);
    const findings = JSON.parse(await readFile(report, 'utf8'));
    if (scenario === 'public-context') {
      assert.equal(result.status, 0);
      assert.equal(findings.length, 0);
    } else {
      assert.equal(result.status, 1);
      assert.ok(findings.length > 0);
      const rule = scenario === 'other-default-rule' ? 'github-pat' : 'generic-api-key';
      assert.ok(findings.some(value => value.RuleID === rule));
    }
  });
}
