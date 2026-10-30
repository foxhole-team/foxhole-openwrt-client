"""Synthetic shell-boundary regression; genuine APK trust is a separate probe."""
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'tools/install-compact.sh'
if (__name__ == '__main__' and len(sys.argv) > 1
        and not sys.argv[1].startswith('-') and sys.argv[1].endswith('.sh')):
    SCRIPT = Path(sys.argv.pop(1))
SOURCE = SCRIPT.read_text()
START = SOURCE.index(': > "$stage/repositories.list"\n')
END = SOURCE.index('\nset --\n', START)
BLOCK = SOURCE[START:END]
VERIFY_START = SOURCE.index('verify() {\n')
VERIFY_END = SOURCE.index('\n}\n', VERIFY_START) + 3
VERIFY = SOURCE[VERIFY_START:VERIFY_END]


class SignatureBoundary(unittest.TestCase):
    def run_case(self, case, packages=('ca-bundle', 'foxhole-openwrt-client', 'foxcore-engine-selected-abc')):
        with tempfile.TemporaryDirectory(prefix='compact-signature-') as directory:
            root = Path(directory)
            stage = root / 'stage'
            stage.mkdir(mode=0o700)
            for index in ('own.adb', 'upstream.adb'):
                folder = stage / 'repositories' / index / 'keys'
                folder.mkdir(parents=True)
                (stage / index).write_text('Synthetic signed index fixture')
            (stage / 'indexed-install.uc').write_text('Fixture path, not executed')
            (stage / 'install-compact-plan.uc').write_text('Fixture path, not executed')
            (stage / 'compact-budget.json').write_text('{}')
            for name in packages:
                (stage / (name + '.apk')).write_text('Synthetic archive: ' + name)
            payload = stage / (packages[0] + '.apk')
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            (stage / 'SHA256SUMS').write_text(digest + '  ' + payload.name + '\n')
            if case == 'tampered-archive':
                payload.write_text('Changed archive, original SHA retained')
            lines = ['index own.adb foxhole', 'index upstream.adb upstream']
            for name in packages:
                owned = name != 'ca-bundle'
                index = 'own.adb' if owned else 'upstream.adb'
                lines.append('package ' + name + '.apk ' + index + ' ' + name + ' 1-r1')
                if owned:
                    lines.append('durable ' + name)
            if case == 'duplicate-root':
                lines.append('durable ' + packages[0])
            (stage / 'indexed.list').write_text('\n'.join(lines) + '\n')
            trace = root / 'trace'
            setup = 'set -eu\nstage=' + shlex.quote(str(stage)) + '\nbudget_file=compact-budget.json\n'
            setup += 'trace=' + shlex.quote(str(trace)) + '\ncase_name=' + shlex.quote(case) + '\n'
            setup += r'''
apk() {
 printf 'apk %s\n' "$*" >> "$trace"
 for last do :; done
 case "$*" in
  *--allow-untrusted*) return 99 ;;
 esac
 case "$last" in
  */upstream.adb) [ "$case_name" != bad-upstream-index ] || return 31 ;;
  */own.adb) [ "$case_name" != bad-canonical-index ] || return 32 ;;
  */ca-bundle.apk) printf 'UNTRUSTED signature\n'; return 1 ;;
  */foxhole-openwrt-client.apk) [ "$case_name" != missing-panel-signature ] || return 33 ;;
  */foxcore-engine-selected-abc.apk) [ "$case_name" != missing-module-signature ] || return 34 ;;
  */hysteria.apk) [ "$case_name" != missing-server-signature ] || return 35 ;;
 esac
 case "$1" in adbdump) printf '{}\n' ;; esac
 return 0
}
ucode() {
 printf 'ucode %s\n' "$*" >> "$trace"
 if [ "$1" = -e ]; then
  for last do :; done
  [ "$last" = foxcore-engine-selected-abc ] && return 0
  return 2
 fi
 [ "$case_name" != wrong-index-identity ] || [ "$2" != index ] || return 36
 return 0
}
'''
            setup += VERIFY + '\nverify ' + shlex.quote(payload.name) + '\n'
            if case == 'classifier-read-error':
                setup += 'awk() { return 54; }\n'
            result = subprocess.run(['/bin/sh', '-c', setup + BLOCK + '\nprintf complete\\n'],
                capture_output=True, timeout=10, env=dict(os.environ), check=False)
            log = trace.read_text() if trace.exists() else ''
            self.assertNotIn('--allow-untrusted', log)
            return result, log

    def test_upstream_index_authenticated_archive_does_not_require_individual_signature(self):
        result, log = self.run_case('valid')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('verify ', log)
        self.assertNotIn('verify ' + 'ca-bundle.apk', log)
        self.assertFalse(any(' verify ' in line and line.endswith('/ca-bundle.apk') for line in log.splitlines()))
        self.assertTrue(any(' verify ' in line and line.endswith('/foxhole-openwrt-client.apk') for line in log.splitlines()))
        self.assertTrue(any(' verify ' in line and line.endswith('/foxcore-engine-selected-abc.apk') for line in log.splitlines()))

    def test_invalid_upstream_index_still_fails(self):
        result, log = self.run_case('bad-upstream-index', ('ca-bundle',))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any('/ca-bundle.apk' in line for line in log.splitlines()))

    def test_invalid_canonical_index_still_fails(self):
        result, _ = self.run_case('bad-canonical-index', ('foxhole-openwrt-client',))
        self.assertNotEqual(result.returncode, 0)

    def test_wrong_signed_index_package_identity_still_fails(self):
        result, _ = self.run_case('wrong-index-identity', ('ca-bundle',))
        self.assertNotEqual(result.returncode, 0)

    def test_changed_archive_fails_original_sha_before_signature_dispatch(self):
        result, log = self.run_case('tampered-archive', ('ca-bundle',))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(log, '')

    def test_missing_panel_individual_signature_still_fails(self):
        result, _ = self.run_case('missing-panel-signature', ('foxhole-openwrt-client',))
        self.assertNotEqual(result.returncode, 0)

    def test_missing_exact_selected_module_signature_still_fails(self):
        result, _ = self.run_case('missing-module-signature', ('foxcore-engine-selected-abc',))
        self.assertNotEqual(result.returncode, 0)

    def test_explicit_server_signature_still_required(self):
        result, _ = self.run_case('missing-server-signature', ('hysteria',))
        self.assertNotEqual(result.returncode, 0)

    def test_duplicate_exact_root_is_not_an_individual_signature_bypass(self):
        result, _ = self.run_case('duplicate-root', ('foxcore-engine-selected-abc',))
        self.assertNotEqual(result.returncode, 0)

    def test_classifier_read_failure_is_not_an_upstream_decision(self):
        result, _ = self.run_case('classifier-read-error', ('foxcore-engine-selected-abc',))
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
