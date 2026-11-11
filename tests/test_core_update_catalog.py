import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'tools' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load('build-core-update-catalog')
engines = load('build-engine-catalog')


class CoreUpdateCatalogTest(unittest.TestCase):
    def catalog(self):
        value = json.loads((ROOT / 'tests/fixtures/engine-catalog-v1.0.3.json').read_bytes())
        for row in value['entries']:
            for name in ['packageUrl', 'indexUrl']:
                row[name] = row[name].replace('/foxhole-openwrt-client/', '/foxhole-core/').replace('/v1.0.3/', '/v1.0.2/')
        return value

    def test_verified_catalog_requires_exact_source_and_closed_core_origin(self):
        value = self.catalog()
        source = {'producerCommit': value['entries'][0]['sourceCommit']}
        self.assertEqual(value, builder.validate_catalog(value, '1.0.2', source))
        for field, replacement in [('indexUrl', 'http://foreign.invalid/engines.adb'),
                                   ('sourceCommit', 'a' * 40), ('reserveBytes', 1), ('binaryBytes', 67108865)]:
            changed = copy.deepcopy(value)
            changed['entries'][0][field] = replacement
            with self.assertRaises(ValueError):
                builder.validate_catalog(changed, '1.0.2', source)

    def test_duplicate_and_extra_catalog_fields_are_refused(self):
        value = self.catalog()
        source = {'producerCommit': value['entries'][0]['sourceCommit']}
        changed = copy.deepcopy(value)
        changed['entries'].append(changed['entries'][0])
        with self.assertRaises(ValueError):
            builder.validate_catalog(changed, '1.0.2', source)
        changed = copy.deepcopy(value)
        changed['entries'][0]['executablePath'] = '/arbitrary'
        with self.assertRaises(ValueError):
            builder.validate_catalog(changed, '1.0.2', source)

    def signed_input(self, directory):
        manifest, joined = b'{"synthetic":"source manifest"}\n', b'{"synthetic":"content join"}\n'
        envelope = {'schema': 1, 'kind': 'foxhole-signed-source-content-join-v1',
                    'producerCommit': 'a' * 40, 'publisherCommit': 'b' * 40, 'publisherTree': 'c' * 40,
                    'sourceContentSha256': 'd' * 64, 'sourceManifestSha256': builder.sha(manifest),
                    'contentJoinReceiptSha256': builder.sha(joined)}
        for name, data in [('source-manifest.json', manifest), ('content-join.json', joined),
                           ('source-envelope.json', json.dumps(envelope).encode()),
                           ('source-envelope.json.asc', b'synthetic unit-test signature')]:
            (directory / name).write_bytes(data)
        return envelope

    def test_source_attestation_calls_pinned_gpgv_before_returning(self):
        with tempfile.TemporaryDirectory() as work:
            directory = Path(work)
            envelope = self.signed_input(directory)
            calls = []
            def runner(argv, **kwargs):
                calls.append((argv, kwargs))
                return subprocess.CompletedProcess(argv, 0, b'', b'')
            value = builder.verify_source(directory, runner)
            self.assertEqual(['gpg', 'gpgv'], [row[0][0] for row in calls])
            self.assertEqual(envelope['producerCommit'], value['producerCommit'])
            self.assertEqual(hashlib.sha256(b'synthetic unit-test signature').hexdigest(), value['signatureReceiptSha256'])
            self.assertTrue(all(row[1]['check'] and row[1]['timeout'] == 20 for row in calls))

    def test_missing_signature_changed_join_and_gpgv_failure_cannot_publish(self):
        with tempfile.TemporaryDirectory() as work:
            directory = Path(work)
            self.signed_input(directory)
            def refused(argv, **kwargs):
                raise subprocess.CalledProcessError(1, argv)
            with self.assertRaises(subprocess.CalledProcessError):
                builder.verify_source(directory, refused)
            (directory / 'content-join.json').write_text('changed')
            with self.assertRaises(ValueError):
                builder.verify_source(directory, lambda *_args, **_kwargs: self.fail('native verification must not run'))
            self.signed_input(directory)
            (directory / 'source-envelope.json.asc').unlink()
            with self.assertRaises(ValueError):
                builder.verify_source(directory)

    def test_source_attestation_bytes_survive_process_hash_seeds(self):
        script = '''import importlib.util,json,subprocess,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('fixture',sys.argv[1])
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
directory=Path(sys.argv[2])
fixture.CoreUpdateCatalogTest().signed_input(directory)
def runner(argv,**kwargs):
 return subprocess.CompletedProcess(argv,0,b'',b'')
print(json.dumps(fixture.builder.verify_source(directory,runner)))
'''
        with tempfile.TemporaryDirectory() as work:
            outputs = [subprocess.check_output(
                [sys.executable, '-B', '-c', script, str(Path(__file__)), work],
                env=dict(os.environ, PYTHONHASHSEED=seed), timeout=30)
                for seed in ['1', '2']]
        self.assertEqual(outputs[0], outputs[1])

    def test_release_repository_enum_keeps_old_urls_and_exact_core_tag(self):
        self.assertIn('/foxhole-openwrt-client/', engines.release_base_url('1.0.2', '1.0.4'))
        self.assertEqual('https://github.com/foxhole-team/foxhole-core/releases/download/v1.0.4/',
                         engines.release_base_url('1.0.4', delivery_repository='core'))
        for repository in ['foreign', 'https://foreign.invalid/']:
            with self.assertRaises(ValueError):
                engines.release_base_url('1.0.4', delivery_repository=repository)
        with self.assertRaises(ValueError):
            engines.release_base_url('1.0.4', '1.0.5', 'core')


if __name__ == '__main__':
    unittest.main()
