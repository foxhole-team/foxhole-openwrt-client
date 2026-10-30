#!/usr/bin/env python3
"""Finite actual-native APK root compatibility and payload-safety regressions."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('engine_catalog', Path(__file__).resolve().parents[1] / 'tools/build-engine-catalog.py')
CATALOG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CATALOG)
DOCUMENT = json.loads('{\n  "info": {\n    "name": "foxcore-engine-hysteria2-flash-5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d",\n    "version": "1.0.0-r1",\n    "hashes": "c51512efbed414ff7a3dcc972ed6be18b34190bf",\n    "description": "One verified protocol producer in a versioned immutable slot. It has no init scripts, service hooks or replacement of another engine.",\n    "arch": "x86_64",\n    "license": "GPL-3.0-or-later",\n    "origin": "/source/package/foxcore-engine",\n    "maintainer": "FoxHole Team",\n    "installed-size": 12525362,\n    "depends": [\n      "libc"\n    ]\n  },\n  "paths": [\n    {\n      "acl": {\n        "mode": 493,\n        "user": "root",\n        "group": "root"\n      }\n    },\n    {\n      "name": "lib",\n      "acl": {\n        "mode": 493,\n        "user": "root",\n        "group": "root"\n      }\n    },\n    {\n      "name": "lib/apk",\n      "acl": {\n        "mode": 493,\n        "user": "root",\n        "group": "root"\n      }\n    },\n    {\n      "name": "lib/apk/packages",\n      "acl": {\n        "mode": 493,\n        "user": "root",\n        "group": "root"\n      },\n      "files": [\n        {\n          "name": "foxcore-engine-hysteria2-flash-5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d.list",\n          "acl": {\n            "mode": 420,\n            "user": "root",\n            "group": "root"\n          },\n          "size": 1152,\n          "mtime": 1792120747,\n          "hash": "3df17b5572a37575b496c14610dfdfd1b8ff2ba1680f2c6dcd8f59330a52325b"\n        }\n      ]\n    },\n    {\n      "name": "usr",\n      "acl": {\n        "mode": 493,\n        "user": "root",\n        "group": "root"\n      }\n    },\n    {\n      "name": "usr/libexec",\n      "acl": {\n        "mode": 493,\n        "user": "root",\n        "group": "root"\n      }\n    },\n    {\n      "name": "usr/libexec/foxhole",\n      "acl": {\n        "mode": 493,\n        "user": "root",\n        "group": "root"\n      }\n    },\n    {\n      "name": "usr/libexec/foxhole/engines",\n      "acl": {\n        "mode": 493,\n        "user": "root",\n        "group": "root"\n      }\n    },\n    {\n      "name": "usr/libexec/foxhole/engines/hysteria2",\n      "acl": {\n        "mode": 493,\n        "user": "root",\n        "group": "root"\n      }\n    },\n    {\n      "name": "usr/libexec/foxhole/engines/hysteria2/5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d",\n      "acl": {\n        "mode": 493,\n        "user": "root",\n        "group": "root"\n      },\n      "files": [\n        {\n          "name": "capabilities.json",\n          "acl": {\n            "mode": 420,\n            "user": "root",\n            "group": "root"\n          },\n          "size": 189,\n          "mtime": 1792120747,\n          "hash": "a955f47d39794f3a5a0e4f7b2442656c8996ba3b2544e23f8ea17307c47f601d"\n        },\n        {\n          "name": "core-producer.json",\n          "acl": {\n            "mode": 420,\n            "user": "root",\n            "group": "root"\n          },\n          "size": 1974,\n          "mtime": 1792120747,\n          "hash": "afcb5623671da76bcb47ba1becdb60d044715cf431622f7ebbe3c21b27d1a403"\n        },\n        {\n          "name": "foxcore-cli",\n          "acl": {\n            "mode": 493,\n            "user": "root",\n            "group": "root"\n          },\n          "size": 9794976,\n          "mtime": 1792120747,\n          "hash": "a89ede004e6d8419aa98264ff4d4c9099d0f94f6280b1dd4c62e537807b5a072"\n        },\n        {\n          "name": "slot.json",\n          "acl": {\n            "mode": 420,\n            "user": "root",\n            "group": "root"\n          },\n          "size": 655,\n          "mtime": 1792120747,\n          "hash": "5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d"\n        }\n      ]\n    },\n    {\n      "name": "usr/share",\n      "acl": {\n        "mode": 493,\n        "user": "root",\n        "group": "root"\n      }\n    },\n    {\n      "name": "usr/share/licenses",\n      "acl": {\n        "mode": 493,\n        "user": "root",\n        "group": "root"\n      }\n    },\n    {\n      "name": "usr/share/licenses/foxcore-engine-hysteria2-flash-5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d",\n      "acl": {\n        "mode": 493,\n        "user": "root",\n        "group": "root"\n      },\n      "files": [\n        {\n          "name": "DEPENDENCY-LICENSES.txt",\n          "acl": {\n            "mode": 420,\n            "user": "root",\n            "group": "root"\n          },\n          "size": 2307017,\n          "mtime": 1792120747,\n          "hash": "393f635beb2a346f6874e1cd66f57bdd92c2031c91c82701f1b24dc68afb8c27"\n        },\n        {\n          "name": "LEGAL-PROVENANCE.json",\n          "acl": {\n            "mode": 420,\n            "user": "root",\n            "group": "root"\n          },\n          "size": 1582,\n          "mtime": 1792120747,\n          "hash": "6401e4b878b98c1b5adb73956f676e8fae3815a100e60b07662ef23603eb7791"\n        },\n        {\n          "name": "LICENSE",\n          "acl": {\n            "mode": 420,\n            "user": "root",\n            "group": "root"\n          },\n          "size": 35149,\n          "mtime": 1792120747,\n          "hash": "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"\n        },\n        {\n          "name": "RUNTIME-NOTICES.txt",\n          "acl": {\n            "mode": 420,\n            "user": "root",\n            "group": "root"\n          },\n          "size": 377356,\n          "mtime": 1792120747,\n          "hash": "6cb9a034659984a13fc6f3128202d638f18e58ad3489267a93f8dab8871b6631"\n        },\n        {\n          "name": "THIRD_PARTY_NOTICES.md",\n          "acl": {\n            "mode": 420,\n            "user": "root",\n            "group": "root"\n          },\n          "size": 5312,\n          "mtime": 1792120747,\n          "hash": "5ccccc073f313a4c71db9c086f4eef407254db0ddd868595809b1ab7e460df00"\n        }\n      ]\n    }\n  ]\n}\n')
IDENTITY = DOCUMENT['info']['name']
SLOT = 'usr/libexec/foxhole/engines/hysteria2/5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d/'
ALLOWED = {SLOT + leaf for leaf in ('foxcore-cli', 'slot.json', 'core-producer.json', 'capabilities.json')}
ALLOWED.update('usr/share/licenses/' + IDENTITY + '/' + leaf for leaf in ('LICENSE', 'THIRD_PARTY_NOTICES.md', 'DEPENDENCY-LICENSES.txt', 'RUNTIME-NOTICES.txt', 'LEGAL-PROVENANCE.json'))
ALLOWED.add('lib/apk/packages/' + IDENTITY + '.list')

class NativeRootTests(unittest.TestCase):
    def check_document(self, value):
        CATALOG.validate_engine_paths(value, ALLOWED)

    def test_actual_native_unnamed_root_and_all_payload_paths(self):
        self.check_document(copy.deepcopy(DOCUMENT))

    def test_native_empty_name_root(self):
        value = copy.deepcopy(DOCUMENT)
        value['paths'][0]['name'] = ''
        self.check_document(value)

    def test_root_cannot_carry_files(self):
        value = copy.deepcopy(DOCUMENT)
        value['paths'][0]['files'] = [dict(value['paths'][3]['files'][0])]
        with self.assertRaises(ValueError): self.check_document(value)

    def test_root_must_be_0755_root_root(self):
        for key, replacement in (('mode', 0o777), ('mode', 0o700), ('user', 'nobody'), ('group', 'nobody')):
            with self.subTest(key=key, replacement=replacement):
                value = copy.deepcopy(DOCUMENT)
                value['paths'][0]['acl'][key] = replacement
                with self.assertRaises(ValueError): self.check_document(value)

    def test_root_cannot_have_links_xattrs_or_unknown_fields(self):
        for place, key, value in (('root', 'target', '/tmp'), ('root', 'unknown', 1), ('acl', 'xattrs', {})):
            with self.subTest(place=place, key=key):
                candidate = copy.deepcopy(DOCUMENT)
                target = candidate['paths'][0] if place == 'root' else candidate['paths'][0]['acl']
                target[key] = value
                with self.assertRaises(ValueError): self.check_document(candidate)

    def test_duplicate_native_root_is_refused(self):
        value = copy.deepcopy(DOCUMENT)
        value['paths'].append({'name': '', 'acl': copy.deepcopy(value['paths'][0]['acl'])})
        with self.assertRaises(ValueError): self.check_document(value)

    def test_null_dot_absolute_and_unknown_paths_are_not_roots(self):
        for name in (None, '.', '/', '/usr', 'unknown', '../usr'):
            with self.subTest(name=name):
                value = copy.deepcopy(DOCUMENT)
                value['paths'][0]['name'] = name
                with self.assertRaises(ValueError): self.check_document(value)

    def test_child_directory_mode_and_duplicate_still_refused(self):
        value = copy.deepcopy(DOCUMENT)
        value['paths'][1]['acl']['mode'] = 0o777
        with self.assertRaises(ValueError): self.check_document(value)
        value = copy.deepcopy(DOCUMENT)
        value['paths'].append(copy.deepcopy(value['paths'][1]))
        with self.assertRaises(ValueError): self.check_document(value)

    def test_child_payload_link_and_incomplete_set_still_refused(self):
        value = copy.deepcopy(DOCUMENT)
        value['paths'][3]['files'][0]['target'] = '/tmp/other'
        with self.assertRaises(ValueError): self.check_document(value)
        value = copy.deepcopy(DOCUMENT)
        value['paths'][3]['files'].clear()
        with self.assertRaises(ValueError): self.check_document(value)


class UniqueIndexEntryTests(unittest.TestCase):
    ROW = {'name': 'foxcore-engine-hysteria2-flash-5febba87ef05e6ea9fdf9fcb012d05a7efbc888dc2c4903caedc46a0258ba26d', 'version': '1.0.0-r1', 'hashes': '71156d350fb381566bc1b6b9ec999bc4601d5b3cd595153ea5ab4b95228aa207', 'description': 'One verified protocol producer in a versioned immutable slot. It has no init scripts, service hooks or replacement of another engine.', 'arch': 'x86_64', 'license': 'GPL-3.0-or-later', 'origin': '/source/package/foxcore-engine', 'maintainer': 'FoxHole Team', 'installed-size': 12525362, 'file-size': 4502595, 'depends': ['libc']}

    def test_actual_unique_name_preserves_version_arch_size_and_distinct_hash_roles(self):
        self.assertNotEqual(self.ROW['hashes'], DOCUMENT['info']['hashes'])
        CATALOG.validate_unique_index_entry(DOCUMENT['info'], [copy.deepcopy(self.ROW)], 4502595)

    def test_same_immutable_name_at_another_version_or_arch_is_refused(self):
        for key, value in (('version', '1.0.0-r2'), ('arch', 'aarch64_generic')):
            with self.subTest(key=key):
                other = copy.deepcopy(self.ROW); other[key] = value
                with self.assertRaises(ValueError):
                    CATALOG.validate_unique_index_entry(DOCUMENT['info'], [copy.deepcopy(self.ROW), other], 4502595)

    def test_single_wrong_version_arch_or_archive_size_is_refused(self):
        for key, value in (('version', '1.0.0-r2'), ('arch', 'aarch64_generic'), ('file-size', 4502596)):
            with self.subTest(key=key):
                other = copy.deepcopy(self.ROW); other[key] = value
                with self.assertRaises(ValueError):
                    CATALOG.validate_unique_index_entry(DOCUMENT['info'], [other], 4502595)

if __name__ == '__main__':
    unittest.main()
