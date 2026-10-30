import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('engine_legal', Path(__file__).parents[1] / 'tools/engine-legal.py')
legal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legal)


class EngineLegalContractTest(unittest.TestCase):
    def fixture(self, root):
        producer = {'sourceCommit': 'a' * 40, 'sourceSha256': 'b' * 64,
                    'target': 'x86_64-unknown-linux-musl', 'binarySha256': 'c' * 64,
                    'filesSha256': {'LICENSE': 'd' * 64, 'THIRD_PARTY_NOTICES.md': 'e' * 64}}
        files = {}
        for name in legal.TEXTS:
            raw = ('SYNTHETIC CONTRACT FIXTURE ONLY: ' + name + '\n').encode()
            path = root / name; path.write_bytes(raw); path.chmod(0o600)
            files[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
        value = {'schema': 1, 'coreCommit': producer['sourceCommit'],
                 'sourceArchiveSha256': producer['sourceSha256'], 'target': producer['target'],
                 'protocols': ['vless'], 'producerSha256': 'f' * 64,
                 'binarySha256': producer['binarySha256'], 'originalCoreNotices': producer['filesSha256'],
                 'files': files, 'authorities': {key: '1' * 64 for key in legal.AUTHORITY_KEYS}}
        return producer, value

    def validate(self, root, producer, value):
        raw = (json.dumps(value) + '\n').encode()
        path = root / 'LEGAL-PROVENANCE.json'; path.write_bytes(raw); path.chmod(0o600)
        return legal.validate(root, hashlib.sha256(raw).hexdigest(), producer, 'f' * 64, 'vless')

    def test_exact_original_text_contract_is_accepted_without_claiming_real_licenses(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture(root)
            self.assertEqual(self.validate(root, producer, value)['protocols'], ['vless'])

    def test_wrong_producer_or_source_or_target_is_refused(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture(root)
            for key in ('coreCommit', 'sourceArchiveSha256', 'target', 'producerSha256', 'binarySha256'):
                changed = copy.deepcopy(value); changed[key] = 'wrong'
                with self.subTest(key=key), self.assertRaises(ValueError): self.validate(root, producer, changed)

    def test_changed_original_text_bytes_are_refused(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture(root)
            (root / legal.TEXTS[0]).write_bytes(b'changed original text')
            with self.assertRaises(ValueError): self.validate(root, producer, value)

    def test_spdx_only_or_missing_text_delivery_is_refused(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture(root)
            value['files'] = {'SPDX': {'sha256': 'a' * 64, 'bytes': 1}}
            with self.assertRaises(ValueError): self.validate(root, producer, value)

    def test_authorities_must_be_exact_hashes_without_hostpaths(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture(root)
            for changed in ({}, {**value['authorities'], 'privatePath': '/synthetic/private'},
                            {**value['authorities'], 'cargoCaptureSha256': '/synthetic/private'}):
                candidate = copy.deepcopy(value); candidate['authorities'] = changed
                with self.assertRaises(ValueError): self.validate(root, producer, candidate)

    def test_original_core_notice_pair_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture(root)
            value['originalCoreNotices']['LICENSE'] = '0' * 64
            with self.assertRaises(ValueError): self.validate(root, {**producer, 'filesSha256': {'LICENSE': 'd' * 64, 'THIRD_PARTY_NOTICES.md': 'e' * 64}}, value)

    def test_symlink_or_writable_legal_text_is_refused(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture(root)
            path = root / legal.TEXTS[0]
            path.chmod(0o666)
            with self.assertRaises(ValueError): self.validate(root, producer, value)
            path.chmod(0o600); moved = root / 'original'; path.rename(moved); path.symlink_to(moved)
            with self.assertRaises(ValueError): self.validate(root, producer, value)

    def test_boolean_size_and_extra_files_record_are_refused(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture(root)
            value['files'][legal.TEXTS[0]]['bytes'] = True
            with self.assertRaises(ValueError): self.validate(root, producer, value)


    def fixture_v2(self, root):
        producer, value = self.fixture(root)
        del value['sourceArchiveSha256']
        value.update(schema=2, sourceContentSha256=producer['sourceSha256'],
                     sourceManifestSha256='2' * 64,
                     sourceAuthority={'commit': producer['sourceCommit'], 'tree': '3' * 40,
                                      'signatureReceiptSha256': '4' * 64,
                                      'sourceBankReceiptSha256': '5' * 64})
        return producer, value

    def test_source2_content_and_signed_source_references_are_accepted(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture_v2(root)
            self.assertEqual(self.validate(root, producer, value)['schema'], 2)

    def test_source2_has_no_archive_alias_or_unknown_fields(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture_v2(root)
            for key in ('sourceArchiveSha256', 'privatePath'):
                changed = copy.deepcopy(value); changed[key] = producer['sourceSha256']
                with self.subTest(key=key), self.assertRaises(ValueError): self.validate(root, producer, changed)

    def test_source2_content_commit_and_actual_producer_join_are_exact(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture_v2(root)
            for key in ('sourceContentSha256', 'coreCommit', 'producerSha256', 'target', 'protocols', 'binarySha256'):
                changed = copy.deepcopy(value); changed[key] = 'wrong'
                with self.subTest(key=key), self.assertRaises(ValueError): self.validate(root, producer, changed)

    def test_source2_manifest_and_authority_cannot_be_missing_or_booleans(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture_v2(root)
            for bad in ('wrong', True, None):
                changed = copy.deepcopy(value); changed['sourceManifestSha256'] = bad
                with self.subTest(manifest=bad), self.assertRaises(ValueError): self.validate(root, producer, changed)
            for bad in ({}, True, {'ownerSignatureValidated': True}):
                changed = copy.deepcopy(value); changed['sourceAuthority'] = bad
                with self.subTest(authority=bad), self.assertRaises(ValueError): self.validate(root, producer, changed)

    def test_source2_authority_commit_tree_and_receipt_references_are_exact(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture_v2(root)
            for key in value['sourceAuthority']:
                changed = copy.deepcopy(value); changed['sourceAuthority'][key] = 'wrong'
                with self.subTest(key=key), self.assertRaises(ValueError): self.validate(root, producer, changed)
            changed = copy.deepcopy(value); changed['sourceAuthority']['ownerSignatureValidated'] = True
            with self.assertRaises(ValueError): self.validate(root, producer, changed)

    def test_source2_retains_original_text_and_six_authority_guards(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture_v2(root)
            changed = copy.deepcopy(value); del changed['authorities'][next(iter(legal.AUTHORITY_KEYS))]
            with self.assertRaises(ValueError): self.validate(root, producer, changed)
            (root / legal.TEXTS[1]).write_bytes(b'changed')
            with self.assertRaises(ValueError): self.validate(root, producer, value)

    def test_source2_cannot_change_original_core_notice_pair(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture_v2(root)
            changed = copy.deepcopy(value); changed['originalCoreNotices'] = {}
            with self.assertRaises(ValueError): self.validate(root, producer, changed)

    def test_legacy_schema_cannot_smuggle_source2_fields(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); producer, value = self.fixture(root)
            value['sourceContentSha256'] = producer['sourceSha256']
            with self.assertRaises(ValueError): self.validate(root, producer, value)


if __name__ == '__main__':
    unittest.main()
