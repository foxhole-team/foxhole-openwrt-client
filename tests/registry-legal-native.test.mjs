import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
test('whole registry keeps archive and source-content legal identities strict', () => {
  const result = spawnSync('python3', ['-B', 'tests/registry-legal-native.py'], {
    cwd: root, encoding: 'utf8', timeout: 20000, maxBuffer: 1024 * 1024,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
  });
  assert.equal(result.error, undefined, 'Required Python/native ucode fixture must execute');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /Native registry legal cases: 8 passed, 0 failed/);
});
