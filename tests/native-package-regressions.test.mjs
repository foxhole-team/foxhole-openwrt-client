import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: root, encoding: 'utf8', timeout: 30000,
    maxBuffer: 2 * 1024 * 1024,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' }
  });
  assert.equal(result.error, undefined, 'Required test tool must execute');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  return result.stdout + result.stderr;
}

test('native catalog root and unique-index Python regressions', () => {
  assert.match(run('python3', [
    '-B', 'tests/test-build-engine-catalog-root.py'
  ]), /Ran 12 tests[\s\S]*OK/);
});

test('global artifact universe includes every anchored archive', () => {
  assert.match(run('python3', [
    '-B', 'tests/test_compact_engine_artifacts.py'
  ]), /Ran 4 tests[\s\S]*OK/);
});

test('actual ucode strict root layout regressions', () => {
  assert.match(run('ucode', [
    'tests/test-engine-package-layout-root.uc'
  ]), /Native layout cases: 11 passed, 0 failed/);
});

test('compact indexed signatures keep exact native trust roles', () => {
  assert.match(run('python3', [
    '-B', 'tests/test_compact_indexed_signatures.py'
  ]), /Ran 10 tests[\s\S]*OK/);
});

test('public router certificate aliases keep exact identity guards', () => {
  assert.match(run('python3', [
    '-B', 'tests/test_router_certificate_role.py'
  ]), /Public certificate role cases: 16 passed, 0 failed/);
});

test('registry architecture uses the strict APK architecture file without invoking apk', () => {
  assert.match(run('python3', [
    '-B', 'tests/test_registry_architecture.py'
  ]), /Registry architecture cases: 15 passed, 0 failed/);
});

test('prebuilt Hysteria packaging does not require a Go helper or compiler', () => {
  assert.match(run('python3', [
    '-B', 'tests/test_hysteria_prebuilt_make.py'
  ]), /Ran 5 tests[\s\S]*OK/);
});
