import json
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / 'package/foxhole-openwrt-client/root/usr/share/foxhole'
VERSION = (ROOT / 'config/release-version.txt').read_text().strip()
spec = importlib.util.spec_from_file_location('base_binding', ROOT / 'tools/bind-base-release.py')
binder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binder)


class BaseVariantTests(unittest.TestCase):
    def run_writer(self, role, revision, out):
        return subprocess.run([sys.executable, str(ROOT / 'tools/install-base-policies.py'),
                               '--role', role, '--version', VERSION, '--revision', str(revision),
                               '--source', str(SOURCES), '--output', str(out)],
                              capture_output=True)

    def test_older_flash_reads_only_modern_primary_and_older_ram_reads_legacy_primary(self):
        with tempfile.TemporaryDirectory() as temp:
            for role, revision in [('flash', 1), ('managed-ram', 2)]:
                out = Path(temp) / role
                out.mkdir()
                result = self.run_writer(role, revision, out)
                self.assertEqual(result.returncode, 0, result.stderr)
                primary = json.loads((out / 'update-policy.json').read_bytes())
                self.assertEqual(primary['releaseTag'], 'v' + VERSION)
                self.assertEqual(primary['packageVersion'], VERSION + '-r' + str(revision))
                companion = out / 'update-policy-v2.json'
                if role == 'flash':
                    self.assertEqual(primary['schema'], 2)
                    self.assertEqual(primary['supportedOpenWrt'], ['25.12.5','25.12.6'])
                    self.assertFalse(companion.exists())
                else:
                    self.assertEqual(primary['schema'], 1)
                    self.assertEqual(primary['osRelease'], '25.12.5')
                    modern = json.loads(companion.read_bytes())
                    self.assertEqual(modern['packageVersion'], primary['packageVersion'])
                    self.assertEqual(modern['supportedOpenWrt'], ['25.12.5','25.12.6'])
                self.assertEqual(self.run_writer(role, revision, out).returncode, 0)

    def test_mixed_revision_or_existing_other_variant_stops_without_overwriting(self):
        with tempfile.TemporaryDirectory() as work:
            out = Path(work)
            self.assertNotEqual(self.run_writer('flash', 2, out).returncode, 0)
            self.assertEqual(list(out.iterdir()), [])
            self.assertEqual(self.run_writer('managed-ram', 2, out).returncode, 0)
            original = {p.name: p.read_bytes() for p in out.iterdir()}
            self.assertNotEqual(self.run_writer('flash', 1, out).returncode, 0)
            self.assertEqual(original, {p.name: p.read_bytes() for p in out.iterdir()})


    def test_catalog_binding_uses_the_distinct_index_and_preserves_unrelated_packages(self):
        old = dict(name=binder.NAME, file='old.apk', version='1.0.8-r2', sha256='a'*64,
                   arch='noarch', depends=['libc'], provides=[])
        new = {**old, 'file':binder.NAME+'-1.0.9-r2.apk', 'version':'1.0.9-r2', 'sha256':'c'*64}
        unrelated = {'name':'libc', 'file':'libc.apk'}
        u = dict(packages=[old,unrelated], packageAuthentications=[dict(name=binder.NAME,file='old.apk',indexFile='base.adb')],
                 repositoryIndexes=[dict(file='base.adb',role='foxhole',sha256='b'*64)],
                 filesSha256={'old.apk':'a'*64,'base.adb':'b'*64,'libc.apk':'f'*64})
        p = {'basePackage':{'file':'old.apk'}}
        role = dict(metadata=new,packageIdentity='d'*64,indexFile='base-ram.adb',indexSha256='e'*64,indexBytes=400)
        with self.assertRaises(ValueError):
            binder.bind_platform(p,u,{**role,'metadata':{**new,'depends':['changed']}},'1.0.9')
        binder.bind_platform(p,u,role,'1.0.9')
        self.assertEqual(p['basePackage']['packageIdentity'],'d'*64)
        self.assertEqual(u['repositoryIndexes'][0]['file'],'base-ram.adb')
        self.assertTrue(u['repositoryIndexes'][0]['sourceUrl'].endswith('/v1.0.9/base-ram.adb'))
        self.assertEqual(u['packages'][1],unrelated)
        self.assertEqual(u['filesSha256']['libc.apk'],'f'*64)
        self.assertNotIn('old.apk',u['filesSha256'])


if __name__ == '__main__':
    unittest.main()
