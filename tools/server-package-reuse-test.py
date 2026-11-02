#!/usr/bin/env python3
"""Focused safety cases for the incoming-server reuse planner."""
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('server_reuse', Path(__file__).with_name('server-package-reuse.py'))
REUSE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REUSE)


class ServerReuseTest(unittest.TestCase):
    def test_ram_wrapper_records_real_url_and_requires_new_binding(self):
        sha = 'a' * 64
        lines = [f'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.0/hysteria-{sha}.bin', sha, '1234', '1073741824']
        value = REUSE.ram_binding(lines, {'binarySha256': sha, 'binaryBytes': 1234}, None, None)
        self.assertEqual(value['currentReserveBytes'], 1073741824)
        self.assertTrue(value['wrapperRebuildRequired'])
        self.assertIsNone(value['desiredURL'])
        value = REUSE.ram_binding(lines, {'binarySha256': sha, 'binaryBytes': 1234},
                                  'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1.0.1', 67108864)
        self.assertTrue(value['wrapperRebuildRequired'])
        self.assertEqual(value['desiredReserveBytes'], 67108864)

    def test_ram_bytes_and_positive_reserve_are_not_optional(self):
        sha = 'a' * 64
        for lines in [['https://example.invalid/file', 'b' * 64, '1234', '1'],
                      ['https://example.invalid/file', sha, '1235', '1'],
                      ['https://example.invalid/file', sha, '1234', '0']]:
            with self.assertRaises(ValueError):
                REUSE.ram_binding(lines, {'binarySha256': sha, 'binaryBytes': 1234}, None, None)

    def test_release_url_refuses_credentials_queries_and_other_hosts(self):
        for url in ['http://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1',
                    'https://fixture@github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1',
                    'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v1?fixture=1',
                    'https://example.invalid/releases/download/v1']:
            with self.assertRaises(ValueError):
                REUSE.release_base(url)

    def test_protected_reader_refuses_links_empty_and_changed_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'fixture.json'; path.write_text('{}')
            REUSE.checked(path, 1024, hashlib.sha256(b'{}').hexdigest())
            with self.assertRaises(ValueError):
                REUSE.checked(path, 1024, 'a' * 64)
            link = root / 'link.json'; link.symlink_to(path)
            with self.assertRaises(ValueError):
                REUSE.checked(link, 1024)
            empty = root / 'empty'; empty.write_bytes(b'')
            with self.assertRaises(ValueError):
                REUSE.checked(empty, 1024)

    def test_security_never_calls_old_or_incomplete_inventory_clean(self):
        now = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'scan.json'
            def check(generated, complete):
                value = {'generatedAt': generated, 'complete': complete, 'inventoryComplete': True,
                         'coverage': 'fixture current tips', 'source': {'repository': 'fixture/local_security'}, 'findings': []}
                path.write_text(json.dumps(value))
                return REUSE.security_status(path, hashlib.sha256(path.read_bytes()).hexdigest(), 'fixture/local_security', now)
            self.assertEqual(check('2026-10-23T00:38:21Z', False)['admission'], 'UNKNOWN_STALE')
            self.assertEqual(check('2026-11-01T00:00:00Z', False)['admission'], 'UNKNOWN_INCOMPLETE')
            self.assertEqual(check('2026-11-01T00:00:00Z', True)['admission'], 'APPLICABILITY_REVIEW_REQUIRED')
            self.assertFalse(check('2026-11-01T00:00:00Z', True)['shippingAdmitted'])


    def test_private_finding_text_is_not_returned_by_security_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'scan.json'
            path.write_text(json.dumps({'generatedAt': '2026-11-01T00:00:00Z', 'complete': False,
                'inventoryComplete': True, 'coverage': 'fixture', 'source': {'repository': 'fixture/local_security'},
                'findings': [{'severity': 'HIGH', 'version': 'go1.26.10', 'description': 'fixture-private-value'}]}))
            value = REUSE.security_status(path, hashlib.sha256(path.read_bytes()).hexdigest(),
                                          'fixture/local_security', dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc))
            self.assertEqual(len(value['exactCoordinateCandidateHashes']), 1)
            self.assertNotIn('fixture-private-value', json.dumps(value))
            self.assertFalse(value['shippingAdmitted'])


if __name__ == '__main__':
    unittest.main()
