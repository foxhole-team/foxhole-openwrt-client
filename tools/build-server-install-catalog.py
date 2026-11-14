#!/usr/bin/env python3
"""Derive a SERVER-only runtime descriptor from real indexed compact artifacts."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def need(value, message):
    if not value:
        raise ValueError(message)

def validate_role(catalog, budget, architecture):
    roles = {'compact-client-engines-v1': 'compact-selected-budget-v1',
             'server-components-v1': 'server-component-budget-v1'}
    need(catalog.get('schema') == 2 and catalog.get('kind') in roles and
         catalog.get('development') is False and budget.get('schema') == 2 and
         budget.get('kind') == roles[catalog['kind']] and budget.get('includeServer') is True and
         budget.get('architecture') == architecture, 'Actual signed server component budget required')

def sha(path):
    need(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1,
         'Independent regular artifact required')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def document(path, maximum=2097152):
    sha(path)
    need(0 < path.stat().st_size <= maximum, 'Bounded metadata required')
    return json.loads(path.read_bytes())

def artifact(root, name):
    need(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,159}', name),
         'Unsafe artifact name')
    path = root / name
    sha(path)
    return path

def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--budget', type=Path, required=True)
    parser.add_argument('--architecture', choices=['aarch64_cortex-a53', 'x86_64'], required=True)
    parser.add_argument('--release-tag', required=True)
    parser.add_argument('--factory-keys', type=Path, required=True)
    parser.add_argument('--apk', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not args.output.exists() and re.fullmatch(r'v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}', args.release_tag),
         'Fresh output and exact release tag required')
    budget = document(args.budget)
    catalog = document(args.catalog)
    validate_role(catalog, budget, args.architecture)
    platform = [row for row in catalog['platforms'] if row['architecture'] == args.architecture]
    need(len(platform) == 1 and platform[0].get('server'), 'No qualified server in this platform catalog')
    platform = platform[0]
    pointer = platform['packageUniverse']
    universe_path = artifact(args.bundle, pointer['file'])
    need(sha(universe_path) == pointer['sha256'],
         'Actual package universe differs')
    universe = document(universe_path, 8388608)
    mode = budget['mode']
    need(mode in ('ram', 'flash'), 'Exact storage required')
    server = universe['server'][mode]
    declared = platform['server']['modes'][mode]
    need(server['name'] == ('hysteria-server-ram' if mode == 'ram' else 'hysteria') and
         all(server[key] == declared[key] for key in ('name', 'file', 'sha256')) and
         server == budget['server'], 'Native server budget binding differs')
    by_name = {row['name']: row for row in universe['packages']}
    pending = [server['name']]
    for name in pending:
        need(len(pending) <= 64 and name in by_name and name in universe['requires'], 'Bounded complete closure required')
        for dependency in universe['requires'][name]:
            if dependency not in pending:
                pending.append(dependency)
    need(not any(name == 'kernel' or name == 'foxhole-openwrt-client' or name.startswith('foxcore-')
                 for name in pending), 'SERVER role cannot change firmware, BASE or Core')
    packages = [row for row in universe['packages'] if row['name'] in pending]
    bindings = [row for row in universe['packageAuthentications'] if row['name'] in pending]
    index_names = {row['indexFile'] for row in bindings}
    indexes = [row for row in universe['repositoryIndexes'] if row['file'] in index_names]
    key_names = {name for row in indexes for name in row['trustKeyFiles']}
    keys = [row for row in universe['trustKeys'] if row['file'] in key_names]
    files = [*packages, *indexes, *keys]
    auth = {'architecture': universe['architecture'], 'supportedTargets': universe['supportedTargets'],
            'supportedOpenWrt': universe['supportedOpenWrt'],
            'packages': packages, 'packageAuthentications': bindings, 'repositoryIndexes': indexes,
            'trustKeys': keys, 'trustKeyBytes': sum(row['bytes'] for row in keys),
            'repositoryIndexBytes': sum(row['bytes'] for row in indexes),
            'filesSha256': {row['file']: row['sha256'] for row in files},
            'verification': universe['verification']}
    budgets = module('package-budget')
    actual = [budgets.metadata(args.apk, artifact(args.bundle, row['file'])) for row in packages]
    need(actual == packages, 'Server closure differs from actual APK metadata')
    budgets.indexed.verify(args.apk, args.bundle, auth, actual, [server['name']], args.architecture,
                           args.factory_keys, own_names=frozenset([server['name']]))
    producer_path = artifact(args.bundle, platform['server']['producer']['file'])
    need(sha(producer_path) == server['producerSha256'], 'Producer differs')
    volatile = artifact(args.bundle, server['volatileFile']) if mode == 'ram' else None
    with tempfile.TemporaryDirectory(prefix='foxhole-server-runtime-keys-') as temporary:
        own_keys = Path(temporary)
        canonical = [row for row in keys if row['sha256'] == budgets.indexed.CANONICAL_PUBLIC_SHA]
        need(len(canonical) == 1, 'Canonical P256 authority required')
        public = artifact(args.bundle, canonical[0]['file'])
        (own_keys / 'foxhole.pem').write_bytes(public.read_bytes())
        budgets.verify_server_payload(args.apk, [args.bundle / row['file'] for row in packages], packages,
                                       producer_path, mode, own_keys, False, volatile)
    producer = document(producer_path)
    evidence = universe['memoryEvidence']
    need(evidence.get('acceptedForRelease') is True and evidence.get('provisional') is not True,
         'Explicit accepted runtime memory evidence required')
    records = []
    for item in packages:
        raw = budgets.indexed.run([args.apk, 'adbdump', '--format', 'json', str(args.bundle / item['file'])])
        need(0 < len(raw) <= 8388608, 'Bounded native package metadata required')
        payload = json.loads(raw)
        need(isinstance(payload.get('info'), dict) and isinstance(payload.get('paths'), list),
             'Actual native package metadata required')
        preinstalled = item['name'] != server['name']
        if not preinstalled:
            need(not payload.get('scripts') and not payload.get('triggers'), 'Scripts/triggers are not a SERVER payload role')
        binding = [row for row in bindings if row['file'] == item['file']]
        need(len(binding) == 1, 'One native index binding required')
        index = next(row for row in indexes if row['file'] == binding[0]['indexFile'])
        members = []
        # BASE prerequisites are checked by their signed native identities only;
        # the SERVER transaction must never install or upgrade them.
        for directory in ([] if preinstalled else payload['paths']):
            need(directory['acl'] == {'mode': 493, 'user': 'root', 'group': 'root'}, 'Canonical directory ACL required')
            for file in directory.get('files', []):
                target = file.get('target')
                members.append({'path': '/'.join(part for part in [directory.get('name', ''), file['name']] if part),
                                'bytes': file['size'], 'sha256': None if target is not None else file['hash'],
                                'mode': file['acl']['mode'], 'target': target})
        records.append({'name': item['name'], 'version': item['version'], 'architecture': item['arch'],
                        'file': item['file'], 'sha256': item['sha256'], 'archiveBytes': item['archiveBytes'],
                        'installedBytes': item['installedBytes'], 'nativeId': binding[0]['packageIdentity'],
                        'indexFile': index['file'], 'keyFiles': index['trustKeyFiles'],
                        'depends': universe['requires'][item['name']], 'payload': members,
                        'preinstalledOnly': preinstalled})
    origin = 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/' + args.release_tag + '/'
    assets = [{'file': row['file'], 'sha256': row['sha256'],
               'bytes': row['archiveBytes'] if role == 'package' else row['bytes'], 'role': role,
               'url': origin + row['file']} for role, rows in [('package', packages), ('index', indexes), ('key', keys)]
              for row in rows]
    if volatile:
        assets.append({'file': volatile.name, 'sha256': sha(volatile), 'bytes': volatile.stat().st_size,
                       'role': 'binary', 'url': origin + volatile.name})
    entry = {'schema': 1, 'kind': 'server-install-entry-v1', 'architecture': args.architecture,
             'target': platform['supportedTargets'][0], 'openwrtRelease': '25.12.5', 'storage': mode.upper(),
             'releaseTag': args.release_tag, 'sourceCatalogSha256': sha(args.catalog), 'sourceBudgetSha256': sha(args.budget),
             'server': {'name': server['name'], 'version': next(row['version'] for row in packages if row['name'] == server['name']),
                        'binarySha256': server['binarySha256'], 'binaryBytes': producer['binaryBytes'],
                        'executableSha256': server['executableSha256'], 'producerSha256': server['producerSha256'],
                        'securityReceiptSha256': server['securityReceiptSha256'],
                        'runtimeMemoryBytes': server['runtimeMemoryBytes'], 'staticExecutable': True},
             'packages': records, 'assets': assets,
             'memoryEvidence': {'schema': 1, 'type': evidence['type'], 'description': evidence['description'],
                                'runtimeMemoryBytes': server['runtimeMemoryBytes'], 'acceptedForRelease': True},
             'flashReserveBytes': universe['flashReserveBytes'], 'ramReserveBytes': universe['ramReserveBytes']}
    args.output.write_text(json.dumps({'schema': 1, 'kind': 'verified-server-install-catalog-v1', 'entries': [entry]},
                                     ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'sha256': sha(args.output), 'entries': 1,
                      'serverPackage': server['name'], 'packages': len(packages), 'assets': len(assets),
                      'signatureVerified': True, 'nativeClosureVerified': True, 'publisherQualifiedByThisTool': False}))

if __name__ == '__main__':
    main()
