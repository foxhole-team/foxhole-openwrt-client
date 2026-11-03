"""Check real GNU make expansion of engine identity defaults without SDK build targets."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = ROOT / 'package/foxcore-engine/Makefile'
MANIFEST = 'a' * 64


class EnginePackageReleaseTests(unittest.TestCase):
    def expand(self, storage):
        source = MAKEFILE.read_text().split('include $(INCLUDE_DIR)/package.mk', 1)[0]
        # Evaluate the actual identity assignments; SDK target includes are outside this check.
        source = '\n'.join(line for line in source.splitlines() if not line.startswith('include '))
        source += '\n.PHONY: report\nreport:\n\t@printf "%s|%s|%s\\n" "$(PKG_VERSION)" "$(PKG_RELEASE)" "$(PKG_NAME)"\n'
        make = shutil.which('make')
        self.assertIsNotNone(make, 'GNU make is required for the metadata check')
        with tempfile.TemporaryDirectory(prefix='engine-release-') as directory:
            fixture = Path(directory) / 'Makefile'
            fixture.write_text(source)
            result = subprocess.run([make, '--no-print-directory', '-rR', '-f', str(fixture), 'report',
                'FOXCORE_ENGINE_STORAGE=' + storage, 'FOXCORE_ENGINE_ID=hysteria2',
                'FOXCORE_ENGINE_MANIFEST_SHA256=' + MANIFEST], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            return result.stdout.decode().strip().split('|')

    def test_ram_defaults_to_r2_with_unchanged_core_version(self):
        self.assertEqual(self.expand('RAM'), ['1.0.2', '2', 'foxcore-engine-hysteria2-ram-' + MANIFEST])

    def test_flash_keeps_r1_with_unchanged_core_version(self):
        self.assertEqual(self.expand('FLASH'), ['1.0.2', '1', 'foxcore-engine-hysteria2-flash-' + MANIFEST])

    def test_runtime_dependency_contract_does_not_require_host_base_db_version(self):
        block = MAKEFILE.read_text().split('define Package/$(PKG_NAME)\n', 1)[1].split('\nendef', 1)[0]
        self.assertEqual(re.findall(r'^\s*DEPENDS:=(.+)$', block, re.M), ['@(aarch64||x86_64)'])


if __name__ == '__main__':
    unittest.main()
