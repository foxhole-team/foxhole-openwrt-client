"""Actual GNU make selection/validation boundaries; no Go compiler or SDK build."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HysteriaPrebuiltMakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which('make') is None:
            raise RuntimeError('Required GNU make unavailable; this is a setup failure')
        for name in ('package/hysteria/Makefile', 'tools/check-hysteria-package-input.py', 'tools/hysteria_provenance.py'):
            if not (ROOT/name).is_file():
                raise RuntimeError('Actual test source missing: '+name)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='hys-prebuilt-make-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.sdk = self.root/'sdk'
        self.package = self.root/'source/package/hysteria'
        self.package.mkdir(parents=True)
        shutil.copyfile(ROOT/'package/hysteria/Makefile', self.package/'Makefile')
        tools = self.root/'source/tools'; tools.mkdir()
        for name in ('check-hysteria-package-input.py', 'hysteria_provenance.py'):
            shutil.copyfile(ROOT/'tools'/name, tools/name)
        (self.sdk/'include').mkdir(parents=True)
        (self.sdk/'rules.mk').write_text(
            'INCLUDE_DIR:=$(TOPDIR)/include\nBUILD_DIR:=$(TOPDIR)/build\n'
            'STAGING_DIR_HOSTPKG:=$(TOPDIR)/hostpkg\nARCH:=aarch64\n'
            'INSTALL_DIR:=install -d -m0755\nCP:=cp -fpR\n')
        # Expose actual recipe values and its actual Prepare operation; no
        # prebuilt/source selection logic is reimplemented in this fixture.
        (self.sdk/'include/package.mk').write_text(
            'define BuildPackage\n.PHONY: probe prepare-probe\nprobe:\n'
            "\t@printf '%s\\n' 'DEPENDS=$$(PKG_BUILD_DEPENDS)' "
            "'COMPILE_EMPTY=$$(if $$(strip $$(value Build/Compile)),0,1)' "
            "'GO_HELPER=$$(GO_HELPER_SEEN)' 'TOOLCHAIN=$$(HYSTERIA_TOOLCHAIN)' 'RSTRIP=$$(RSTRIP)'\n"
            'prepare-probe:\n\t$$(Build/Prepare)\nendef\n')
        self.go_log = self.root/'go-invocations.txt'
        self.spy = self.root/'go-spy.py'
        self.spy.write_text(
            'from pathlib import Path\nimport sys\n'
            "assert sys.argv[1:]==['env','GOVERSION'], 'Unexpected compiler invocation'\n"
            f"Path({str(self.go_log)!r}).write_text('env GOVERSION\\n')\n"
            "print('go1.26.fixture')\n")

    def helper(self):
        path = self.sdk/'feeds/packages/lang/golang/golang-package.mk'
        path.parent.mkdir(parents=True)
        path.write_text('GO_HELPER_SEEN:=1\n')

    def run_make(self, target='probe', *, prebuilt=False, spy=False):
        args = ['make', '--no-print-directory', '-C', str(self.package), 'TOPDIR='+str(self.sdk)]
        if prebuilt:
            args += ['HYSTERIA_PACKAGE_INPUT='+str(self.root/'invalid-prebuilt')]
        if spy:
            args += ['FOXHOLE_GO='+sys.executable+' '+str(self.spy)]
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        # Prevent the caller's unrelated build flags from choosing a different
        # branch; these two variables are supplied only by this case's argv.
        for name in ('HYSTERIA_PACKAGE_INPUT', 'FOXHOLE_GO', 'MAKEFLAGS', 'MFLAGS'):
            env.pop(name, None)
        return subprocess.run([*args, target], env=env, capture_output=True, text=True, timeout=10)

    def metadata(self, result):
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)

    def test_prebuilt_selection_parses_without_any_go_helper_or_host_dependency(self):
        values = self.metadata(self.run_make(prebuilt=True))
        self.assertEqual(values['DEPENDS'], '')
        self.assertEqual(values['COMPILE_EMPTY'], '1')
        self.assertEqual(values['GO_HELPER'], '')
        self.assertEqual(values['TOOLCHAIN'], '')
        self.assertEqual(values['RSTRIP'], ':')
        self.assertFalse(self.go_log.exists())

    def test_prebuilt_selection_does_not_read_an_available_go_helper_or_probe_go(self):
        self.helper()
        values = self.metadata(self.run_make(prebuilt=True, spy=True))
        self.assertEqual(values['GO_HELPER'], '')
        self.assertEqual(values['TOOLCHAIN'], '')
        self.assertEqual(values['DEPENDS'], '')
        self.assertEqual(values['COMPILE_EMPTY'], '1')
        self.assertFalse(self.go_log.exists())

    def test_invalid_prebuilt_still_runs_the_real_validator_before_copy(self):
        result = self.run_make('prepare-probe', prebuilt=True, spy=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Regular server producer inputs required', result.stderr)
        self.assertFalse((self.sdk/'build/hysteria-app-v2.12.2').exists())
        self.assertFalse(self.go_log.exists())

    def test_normal_source_build_still_requires_the_go_helper(self):
        result = self.run_make()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('golang-package.mk', result.stderr)

    def test_normal_source_build_keeps_its_dependencies_compile_and_toolchain_probe(self):
        self.helper()
        values = self.metadata(self.run_make())
        self.assertEqual(values['DEPENDS'], 'golang/host')
        self.assertEqual(values['GO_HELPER'], '1')
        self.assertEqual(values['COMPILE_EMPTY'], '0')
        values = self.metadata(self.run_make(spy=True))
        self.assertEqual(values['DEPENDS'], '')
        self.assertEqual(values['GO_HELPER'], '1')
        self.assertEqual(values['COMPILE_EMPTY'], '0')
        self.assertEqual(values['TOOLCHAIN'], 'go1.26.fixture')
        self.assertEqual(self.go_log.read_text(), 'env GOVERSION\n')


if __name__ == '__main__':
    unittest.main()
