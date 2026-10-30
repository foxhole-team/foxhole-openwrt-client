#!/usr/bin/env python3
"""Native ucode tests of actual APK helper and installed parser; all I/O mocked."""
import argparse
from pathlib import Path
import subprocess
import sys

FIXTURE = r'''
'use strict';
let calls, reply, native_error, passed = 0, failed = 0;
function reset() {
 calls = []; native_error = false;
 reply = '[{"name":"base-files","version":"1-r1","arch":"x86_64","status":["installed"]}]';
};
let registry = { capture: (argv, maximum, timeout) => {
 push(calls, { argv, maximum, timeout });
 // Match the stock package's canonical fixed path. No real process/PATH lookup.
 if (argv[0] != '/usr/bin/apk') die('fixture_missing_native_apk_path_127');
 if (native_error) die('engine_package_verification_failed');
 return reply;
} };
/* ACTUAL_FAIL */
/* ACTUAL_HELPER_AND_PARSER */
function equal(actual, expected) {
 if (sprintf('%J', actual) != sprintf('%J', expected)) die('apk_native_assertion');
};
function refuses(fn, reason) {
 let found = null;
 try { fn(); } catch (error) { found = type(error) == 'string' ? error : error.message; }
 equal(found, reason || 'engine_package_verification_failed');
};
function test(name, fn) {
 reset();
 try { fn(); passed++; print('ok ', name, '\n'); }
 catch (error) { failed++; print('not ok ', name, ': ', sprintf('%J', error), '\n'); }
};
test('stock fixed executable retains complete native installed query argv and bounds', () => {
 equal(installed(), { 'base-files': { name: 'base-files', version: '1-r1', arch: 'x86_64' } });
 equal(calls, [{ argv: ['/usr/bin/apk', '--no-network', '--repositories-file', '/dev/null',
  'query', '--from', 'installed', '--all-matches', '--format', 'json', '--fields',
  'name,version,arch,status', '*'], maximum: 8388608, timeout: 30000 }]);
});
test('helper keeps caller argv, native maximum and explicit transaction timeout', () => {
 let args = ['--keys-dir', '/tmp/owned/keys', 'verify', '/tmp/owned/a.apk', '/tmp/owned/i.adb'];
 apk(args, 120000);
 equal(calls, [{ argv: ['/usr/bin/apk', ...args], maximum: 8388608, timeout: 120000 }]);
 equal(args, ['--keys-dir', '/tmp/owned/keys', 'verify', '/tmp/owned/a.apk', '/tmp/owned/i.adb']);
});
test('native command failure is not interpreted as successful installed data', () => {
 native_error = true; refuses(() => installed()); equal(length(calls), 1);
});
test('malformed native JSON is rejected', () => { reply = 'not-json'; refuses(() => installed()); });
test('non-array native JSON is rejected', () => { reply = '{}'; refuses(() => installed()); });
test('missing native status is rejected', () => {
 reply = '[{"name":"base-files","version":"1-r1","arch":"x86_64"}]'; refuses(() => installed());
});
test('broken native status is rejected', () => {
 reply = '[{"name":"base-files","version":"1-r1","arch":"x86_64","status":["installed","broken"]}]'; refuses(() => installed());
});
test('duplicate installed package names are rejected', () => {
 let row = { name: 'duplicate', version: '1-r1', arch: 'x86_64', status: ['installed'] };
 reply = sprintf('%J', [row, row]); refuses(() => installed());
});
test('non-string package name is rejected', () => {
 reply = '[{"name":42,"version":"1-r1","arch":"x86_64","status":["installed"]}]'; refuses(() => installed());
});
test('4097 installed entries exceed the unchanged bound', () => {
 let rows = [];
 for (let n = 0; n < 4097; n++) push(rows, { name: 'p' + n, version: '1', arch: 'x86_64', status: ['installed'] });
 reply = sprintf('%J', rows); refuses(() => installed());
});
test('explicit recovery tolerance retains its original limited behavior', () => {
 reply = '[{"name":"recover-owned","version":"1-r1","arch":"x86_64","status":["broken"]}]';
 equal(installed(['recover-owned']), { 'recover-owned': { name: 'recover-owned', version: '1-r1', arch: 'x86_64' } });
});
print('Engine native APK helper cases: ', passed, ' passed, ', failed, ' failed\n');
exit(failed ? 1 : 0);
'''


def fixture(source):
    fail = source[source.index('function fail(reason)'):source.index('function read(path, limit)')]
    helper = source[source.index('function apk(argv, timeout)'):source.index('\nfunction candidate(')]
    assert FIXTURE.count('/* ACTUAL_FAIL */') == FIXTURE.count('/* ACTUAL_HELPER_AND_PARSER */') == 1
    return FIXTURE.replace('/* ACTUAL_FAIL */', fail).replace('/* ACTUAL_HELPER_AND_PARSER */', helper)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1] /
        'package/foxhole-openwrt-client/root/usr/share/foxhole/engine-service.uc')
    args = parser.parse_args()
    result = subprocess.run(['ucode', '-'], input=fixture(args.source.read_text()).encode(),
        capture_output=True, timeout=15, check=False)
    assert len(result.stdout) + len(result.stderr) <= 1048576
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
