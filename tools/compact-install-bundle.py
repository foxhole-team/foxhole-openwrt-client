#!/usr/bin/env python3
"""Validate compact v2 metadata against actual signed APKs and native solvers.

This is a separate contract from the legacy five-role catalog. It does not sign,
fetch, publish, or turn a hypothetical module into a released engine.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}')
HEX = re.compile(r'[a-f0-9]{64}')
INSTALLERS = {
    'install.sh': ROOT / 'install.sh',
    **{name: ROOT / 'tools' / name for name in (
        'install-core.sh', 'install-compact.sh', 'install-plan.uc', 'install-plan-model.uc',
        'install-compact-plan.uc', 'engine-package-layout.uc', 'register-compact-engines.uc',
        'indexed-install.uc')},
}


def module(name: str):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'tools' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


legacy = module('package-catalog')
indexed = legacy.budgets.indexed


def sha(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError('Independent regular compact release asset required')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def asset(root: Path, name: str, maximum: int = 536870912) -> Path:
    if not isinstance(name, str) or NAME.fullmatch(name) is None:
        raise ValueError('Safe compact release asset name required')
    path = root / name
    sha(path)
    if not 0 < path.stat().st_size <= maximum:
        raise ValueError('Bounded nonempty compact release asset required')
    return path


def document(root: Path, name: str, maximum: int = 2097152) -> dict:
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError('Duplicate compact metadata key')
            result[key] = value
        return result
    value = json.loads(asset(root, name, maximum).read_bytes(), object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError('Compact metadata object required')
    return value


def native(argv: list[str], timeout: int = 120) -> bytes:
    result = subprocess.run(argv, capture_output=True, check=True, timeout=timeout)
    if (len(result.stdout) > 8388608 or len(result.stderr) > 1048576 or
            b'ERROR:' in result.stdout or b'ERROR:' in result.stderr):
        raise ValueError('Native compact artifact validation refused')
    return result.stdout


def engine_artifact_rows(root: Path, platform: dict) -> list[tuple[dict, Path]]:
    """Finite signed-artifact role from the global embedded catalog, not a runtime platform."""
    pointer = platform['engineCatalog']
    catalog = document(root, pointer['file'], 524288)
    if (sha(asset(root, pointer['file'], 524288)) != pointer['sha256'] or
            set(catalog) != {'schema', 'entries'} or type(catalog['schema']) is not int or catalog['schema'] != 1 or
            not isinstance(catalog['entries'], list) or not 1 <= len(catalog['entries']) <= 72):
        raise ValueError('Exact bounded global engine artifact catalog required')
    rows, identities, filenames = [], set(), set()
    for entry in catalog['entries']:
        identity = entry['id'], entry['storage'], entry['architecture']
        filename = entry['packageUrl'].rsplit('/', 1)[-1]
        if (identity in identities or filename in filenames or
                filename != entry['packageName'] + '-' + entry['packageVersion'] + '.apk' or
                type(entry['archiveBytes']) is not int or not 1 <= entry['archiveBytes'] <= 134217728):
            raise ValueError('Duplicate or invalid global engine artifact identity')
        path = asset(root, filename, 134217728)
        if sha(path) != entry['packageSha256'] or path.stat().st_size != entry['archiveBytes']:
            raise ValueError('Global engine artifact bytes differ from the anchored catalog')
        identities.add(identity); filenames.add(filename); rows.append((entry, path))
    return rows


def assets(root: Path, catalog: dict) -> set[str]:
    if (type(catalog.get('schema')) is not int or catalog['schema'] != 2 or
            catalog.get('kind') != 'compact-client-engines-v1' or
            not isinstance(catalog.get('platforms'), list) or not 1 <= len(catalog['platforms']) <= 16):
        raise ValueError('Separate compact v2 catalog required')
    names = {'package-catalog.json', 'foxhole-openwrt-apk.pem'}
    for platform in catalog['platforms']:
        for entry, archive in engine_artifact_rows(root, platform):
            names.add(archive.name)
        for key in ('engineCatalog', 'packageUniverse'):
            binding = platform[key]
            path = asset(root, binding['file'], 2097152)
            if sha(path) != binding['sha256']:
                raise ValueError('Compact metadata digest differs')
            names.add(binding['file'])
        universe = document(root, platform['packageUniverse']['file'])
        if len(universe.get('filesSha256', {})) > 1024:
            raise ValueError('Bounded package universe required')
        for name, digest in universe['filesSha256'].items():
            if sha(asset(root, name)) != digest:
                raise ValueError('Package universe asset differs')
            names.add(name)
        for client in platform['clients']:
            for key in ('producer', 'capabilities', 'slotManifest'):
                pointer = client[key]
                if sha(asset(root, pointer['file'], 131072)) != pointer['sha256']:
                    raise ValueError('Native module metadata digest differs')
                names.add(pointer['file'])
            if client['storage'] == 'ram':
                entry = client['entry']
                name = 'engine-' + entry['id'] + '-' + entry['architecture'] + '-' + entry['binarySha256'] + '.bin'
                if sha(asset(root, name, 67108864)) != entry['binarySha256']:
                    raise ValueError('RAM engine differs from its native producer')
                names.add(name)
        if platform.get('server') is not None:
            pointer = platform['server']['producer']
            if sha(asset(root, pointer['file'], 131072)) != pointer['sha256']:
                raise ValueError('Optional server producer digest differs')
            names.add(pointer['file'])
            producer = document(root, pointer['file'], 131072)
            legacy.budgets.provenance.verify(producer, root)
            for name, digest in producer['filesSha256'].items():
                if sha(asset(root, name, 33554432)) != digest:
                    raise ValueError('Optional server original notices differ')
                names.add(name)
            for server in universe.get('server', {}).values():
                if server.get('volatileFile'):
                    if sha(asset(root, server['volatileFile'], 67108864)) != server['binarySha256']:
                        raise ValueError('RAM server differs from its native producer')
                    names.add(server['volatileFile'])
    if len(names) + len(INSTALLERS) > 4096 or sum(asset(root, name).stat().st_size for name in names) > 2147483648:
        raise ValueError('Bounded complete compact bundle required')
    return names


def verify_payloads(root: Path, catalog: dict, apk: str, temporary: Path,
                    core_commit: str, core_source: str) -> None:
    entries, indexes, archives = {}, set(), {}
    for platform in catalog['platforms']:
        engine_catalog = document(root, platform['engineCatalog']['file'], 524288)
        if set(engine_catalog) != {'schema', 'entries'} or engine_catalog['schema'] != 1:
            raise ValueError('Strict engine catalog required')
        universe = document(root, platform['packageUniverse']['file'])
        for entry, archive in engine_artifact_rows(root, platform):
            key = entry['id'], entry['storage'], entry['architecture']
            if key in entries and entries[key] != entry:
                raise ValueError('Conflicting engine catalogs')
            entries[key] = entry
            archives[archive.name] = archive
            matches = [row for row in universe['repositoryIndexes'] if row['sha256'] == entry['indexSha256']]
            if len(matches) != 1 or matches[0]['sourceUrl'] != entry['indexUrl']:
                raise ValueError('Global engine artifact index identity differs')
            indexes.add(matches[0]['file'])
        for client in platform['clients']:
            entry = client['entry']
            producer = document(root, client['producer']['file'], 131072)
            if producer.get('sourceCommit') != core_commit or producer.get('sourceSha256') != core_source:
                raise ValueError('Actual current native module source required')
            name = entry['packageUrl'].rsplit('/', 1)[-1]
            archives[name] = asset(root, name, 134217728)
            matches = [row for row in universe['repositoryIndexes'] if row['sha256'] == entry['indexSha256']]
            if len(matches) != 1 or matches[0]['sourceUrl'] != entry['indexUrl']:
                raise ValueError('Engine index identity differs')
            indexes.add(matches[0]['file'])
        # The control base must embed this exact engine catalog.
        panel = asset(root, platform['basePackage']['file'])
        destination = temporary / ('base-' + platform['id']); destination.mkdir()
        keys = temporary / 'keys'
        native([apk, '--keys-dir', str(keys), 'verify', str(panel)])
        native([apk, '--keys-dir', str(keys), 'extract', '--no-chown', '--destination', str(destination), str(panel)])
        embedded = destination / 'usr/share/foxhole/engine-catalog.json'
        if sha(embedded) != platform['engineCatalog']['sha256']:
            raise ValueError('Control base embeds a different engine catalog')
        if not (destination / 'usr/share/foxhole/engine-package-layout.uc').is_file():
            raise ValueError('Control base lacks the current strict package format validator')
    if len(indexes) != 1:
        raise ValueError('One exact canonical engine-only index required')
    index = temporary / 'engines.adb'; shutil.copyfile(asset(root, next(iter(indexes)), 8388608), index)
    regenerated = temporary / 'actual-engines.json'
    native(['python3', str(ROOT / 'tools/build-engine-catalog.py'), '--apk', apk,
            '--public-key', str(root / 'foxhole-openwrt-apk.pem'), '--index', str(index),
            '--packages', *map(str, archives.values()), '--core-commit', core_commit,
            '--source-sha256', core_source, '--output', str(regenerated)], timeout=600)
    actual = json.loads(regenerated.read_bytes())
    by_key = {(row['id'], row['storage'], row['architecture']): row for row in actual['entries']}
    if by_key != entries:
        raise ValueError('Engine catalog differs from signed native payloads and legal notices')


def verify(root: Path, apk: str, ucode: str, keys: Path, development: bool,
           core_commit: str, core_source: str) -> set[str]:
    if re.fullmatch(r'[a-f0-9]{40}', core_commit) is None or HEX.fullmatch(core_source) is None:
        raise ValueError('Exact current native source binding required')
    catalog = document(root, 'package-catalog.json', 524288)
    if catalog.get('development') is not development:
        raise ValueError('Compact trust mode differs')
    names = assets(root, catalog)
    cases = 0
    for platform in catalog['platforms']:
        for mode in {client['storage'] for client in platform['clients']}:
            count = len({client['id'] for client in platform['clients'] if client['storage'] == mode})
            cases += (count + (1 if count > 1 else 0)) * len(platform['supportedOpenWrt']) * (
                2 if (platform.get('server') or {}).get('modes', {}).get(mode) else 1)
    if not 1 <= cases <= 64:
        raise ValueError('At most64 finite native compact closure checks per bundle')
    if sha(asset(root, 'foxhole-openwrt-apk.pem', 16384)) != indexed.CANONICAL_PUBLIC_SHA:
        raise ValueError('Canonical public signing identity required')
    for name, source in INSTALLERS.items():
        if sha(asset(root, name, 2097152)) != sha(source):
            raise ValueError('Compact installer differs from the checked-out source')
    with tempfile.TemporaryDirectory(prefix='foxhole-compact-recheck-') as work:
        temporary = Path(work)
        own_keys = temporary / 'keys'; own_keys.mkdir()
        shutil.copyfile(root / 'foxhole-openwrt-apk.pem', own_keys / 'foxhole-openwrt-apk.pem')
        verify_payloads(root, catalog, apk, temporary, core_commit, core_source)
        for platform in catalog['platforms']:
            covered = set()
            modes = sorted({client['storage'] for client in platform['clients']})
            for mode in modes:
                available = sorted({client['id'] for client in platform['clients'] if client['storage'] == mode})
                # Verify singles plus the whole common-mode graph.
                # Re-solve each real selection before router mutation.
                selections = sorted({(ident,) for ident in available} | {tuple(available)})
                for release in platform['supportedOpenWrt']:
                    for selected in selections:
                        for server in (False, True):
                            if server and not (platform.get('server') or {}).get('modes', {}).get(mode):
                                continue
                            raw = native([ucode, str(ROOT / 'tools/install-compact-plan.uc'), 'budget',
                                str(root / 'package-catalog.json'), platform['architecture'], release,
                                ','.join(selected), '1' if development else '0', platform['supportedTargets'][0],
                                str(root), mode, str(2**53 - 1), str(2**53 - 1), '0', '1' if server else '0'])
                            budget = json.loads(raw)
                            packages = budget['packages']
                            covered.update(row['file'] for row in packages)
                            actual = [legacy.budgets.metadata(apk, asset(root, row['file'])) for row in packages]
                            if actual != packages:
                                raise ValueError('Package universe differs from actual native APK metadata')
                            owned = frozenset(budget['rootPackages'])
                            actual_verification = indexed.verify(apk, root, budget, actual,
                                budget['rootPackages'] + ['kernel'], platform['architecture'], keys, own_names=owned)
                            if actual_verification != budget['verification']:
                                raise ValueError('Compact closure lacks actual native indexed authentication')
                            if server:
                                producer_file = platform['server']['producer']['file']
                                volatile = asset(root, budget['server']['volatileFile']) if mode == 'ram' else None
                                result = legacy.budgets.verify_server_payload(apk,
                                    [root / row['file'] for row in packages], packages, root / producer_file,
                                    mode, own_keys, False, volatile)
                                if (result['producerSha256'] != budget['server']['producerSha256'] or
                                        result['binarySha256'] != budget['server']['binarySha256']):
                                    raise ValueError('Optional server payload binding differs')
            universe = document(root, platform['packageUniverse']['file'])
            if covered != {row['file'] for row in universe['packages']}:
                raise ValueError('Package universe contains unselected or unavailable package roles')
    return names


def manifest(root: Path, expected: str) -> dict[str, str]:
    path = asset(root, 'SHA256SUMS', 1048576)
    if HEX.fullmatch(expected) is None or sha(path) != expected:
        raise ValueError('Independent compact manifest anchor differs')
    result = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]{0,159})', line)
        if not match or match[2] in result or match[2] == 'SHA256SUMS':
            raise ValueError('Exact unique compact manifest entries required')
        if sha(asset(root, match[2])) != match[1]:
            raise ValueError('Compact manifest asset differs')
        result[match[2]] = match[1]
    if not result or len(result) > 4096:
        raise ValueError('Bounded compact manifest required')
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--apk', required=True)
    parser.add_argument('--ucode', default='ucode')
    parser.add_argument('--factory-keys-dir', type=Path, required=True)
    parser.add_argument('--core-commit', required=True)
    parser.add_argument('--core-source-sha256', required=True)
    parser.add_argument('--development', action='store_true')
    args = parser.parse_args()
    root = args.input.resolve()
    if args.output:
        output = args.output.absolute()
        if output.exists() or output.is_symlink() or output == root or root in output.parents:
            raise ValueError('New compact bundle output outside original inputs required')
        value = document(root, 'package-catalog.json', 524288)
        names = assets(root, value)
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='foxhole-compact-bundle-', dir=output.parent) as temporary:
            prepared = Path(temporary) / 'bundle'; prepared.mkdir()
            for name in sorted(names):
                shutil.copyfile(asset(root, name), prepared / name)
            for name, path in INSTALLERS.items():
                shutil.copyfile(path, prepared / name)
            verified = verify(prepared, args.apk, args.ucode, args.factory_keys_dir,
                              args.development, args.core_commit, args.core_source_sha256)
            if set(path.name for path in prepared.iterdir()) != verified | set(INSTALLERS):
                raise ValueError('Unclassified compact bundle asset')
            text = ''.join(sha(path) + '  ' + path.name + '\n' for path in sorted(prepared.iterdir()))
            (prepared / 'SHA256SUMS').write_text(text)
            anchor = sha(prepared / 'SHA256SUMS')
            prepared.rename(output)
        print(json.dumps({'schema': 2, 'kind': 'compact-bundle-review-v1', 'manifestSha256': anchor,
                          'published': False, 'routingQualified': False}))
    else:
        if not args.manifest_sha256:
            parser.error('--manifest-sha256 is required for existing bundle verification')
        entries = manifest(root, args.manifest_sha256)
        required = verify(root, args.apk, args.ucode, args.factory_keys_dir,
                          args.development, args.core_commit, args.core_source_sha256) | set(INSTALLERS)
        if set(entries) != required or set(path.name for path in root.iterdir()) != required | {'SHA256SUMS'}:
            raise ValueError('Exact complete compact bundle required')
        print('Actual compact signed payloads, original legal material and finite native closures verified')


if __name__ == '__main__':
    main()
