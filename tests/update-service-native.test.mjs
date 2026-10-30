import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('actual package update service enforces authorization, CAS, shared busy and status-only recovery', () => {
  const result = spawnSync('python3', ['-B', 'tests/update-service-native.py'], {
    encoding: 'utf8', timeout: 30000, maxBuffer: 1048576
  });
  assert.equal(result.error, undefined, 'Required native ucode fixture must execute');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /Update service cases: 25 passed, 0 failed/);
});
