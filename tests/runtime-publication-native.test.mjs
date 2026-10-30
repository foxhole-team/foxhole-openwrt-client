import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
for (const [script, expected] of [
  ['runtime-publication-native.py', /Native runtime publication cases: 17 passed, 0 failed/],
  ['core-adapter-probe-cache-native.py', /Native adapter probe cache cases: 5 passed, 0 failed/],
]) {
  test(`whole production native regression: ${script}`, () => {
    const result = spawnSync('python3', ['-B', `tests/${script}`], {
      cwd: root, encoding: 'utf8', timeout: 20000, maxBuffer: 1024 * 1024,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
    });
    assert.equal(result.error, undefined, 'Required Python/native ucode fixture must execute');
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, expected);
  });
}
