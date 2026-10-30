import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

test('sixteen original-text legal delivery contract fixtures', () => {
  const result = spawnSync('python3', ['-B', 'tests/engine-legal-test.py'], {
    encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stderr, /Ran 16 tests/);
  assert.match(result.stderr, /\nOK\s*$/);
});
