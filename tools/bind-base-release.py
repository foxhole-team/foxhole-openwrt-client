#!/usr/bin/env python3
"""Prepare the catalog and package-universe changes for a two-revision BASE release."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
NAME = 'foxhole-openwrt-client'
SIGNER = 'fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1'
ORIGIN = 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/'


def load(tool):
    spec = importlib.util.spec_from_file_location(tool, ROOT / 'tools' / (tool + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked(root, name, maximum):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,159}', name):
        raise ValueError('Unexpected release asset name')
    path = root / name
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError('Bounded regular release asset required')
    return path


def inspect_role(source, apk, keys, role, version, work):
    policies = load('install-base-policies')
    revision = policies.REVISIONS[role]
    pkgver = f'{version}-r{revision}'
    archive = checked(source, f'{NAME}-{pkgver}.apk', 8388608)
    index = checked(source, 'base-ram.adb' if role == 'managed-ram' else 'base.adb', 1048576)
    subprocess.run([apk, '--keys-dir', keys, 'verify', archive, index],
                   check=True, capture_output=True, timeout=30)
    rows = json.loads(subprocess.check_output([apk, 'adbdump', '--format', 'json', index], timeout=30))['packages']
    if (len(rows) != 1 or rows[0].get('name') != NAME or rows[0].get('version') != pkgver or
            rows[0].get('arch') != 'noarch' or rows[0].get('file-size') != archive.stat().st_size or
            not re.fullmatch(r'[a-f0-9]{64}', rows[0].get('hashes', ''))):
        raise ValueError('BASE index must contain one matching signed native package')
    metadata = load('package-budget').metadata(apk, archive)
    if (metadata['name'], metadata['version'], metadata['arch'], metadata['installedBytes']) != (
            NAME, pkgver, 'noarch', rows[0]['installed-size']):
        raise ValueError('BASE archive metadata differs from the signed index')
    extracted, wanted = work / 'extracted', work / 'wanted'
    extracted.mkdir(); wanted.mkdir()
    subprocess.run([apk, '--keys-dir', keys, 'extract', '--no-chown', '--destination', extracted, archive],
                   check=True, capture_output=True, timeout=60)
    policies.install(ROOT / 'package/foxhole-openwrt-client/root/usr/share/foxhole', wanted, version, revision, role)
    for name in (policies.PRIMARY, policies.MODERN):
        actual = extracted / 'usr/share/foxhole' / name
        if actual.is_symlink() or (wanted / name).exists() != actual.exists() or (
                actual.exists() and digest(wanted / name) != digest(actual)):
            raise ValueError('Signed BASE contains the wrong firmware policy')
    # Same release/version and archive length alone cannot bind independent packages.
    repo, db, cache, fetched = (work / n for n in ('repository','database','cache','fetched'))
    for path in (repo, db, cache, fetched):
        path.mkdir()
    shutil.copyfile(archive, repo / archive.name)
    shutil.copyfile(index, repo / 'packages.adb')
    repositories = work / 'repositories.list'
    repositories.write_text(str(repo / 'packages.adb') + '\n')
    common = [apk, '--root', db, '--arch', 'aarch64_cortex-a53', '--no-network', '--no-cache',
              '--repositories-file', repositories, '--keys-dir', keys, '--cache-dir', cache]
    mode = [] if os.geteuid() == 0 else ['--usermode']
    subprocess.run(common + ['add', '--initdb', *mode], capture_output=True, check=True, timeout=30)
    subprocess.run(common + ['fetch', '--output', fetched, NAME], capture_output=True, check=True, timeout=60)
    if digest(fetched / archive.name) != digest(archive):
        raise ValueError('Native BASE fetch does not reproduce the submitted archive')
    return dict(metadata=metadata, packageIdentity=rows[0]['hashes'], indexFile=index.name,
                indexSha256=digest(index), indexBytes=index.stat().st_size)


def bind_platform(platform, universe, role, version):
    changed = [r for r in universe['packages'] if r['name'] == NAME]
    binding = [r for r in universe['packageAuthentications'] if r['name'] == NAME]
    if len(changed) != 1 or len(binding) != 1:
        raise ValueError('Unambiguous previous BASE binding required')
    old, old_binding = changed[0], binding[0]
    meta = role['metadata']
    if old['file'] != platform['basePackage']['file'] or old['file'] != old_binding['file']:
        raise ValueError('Previous BASE catalog and universe differ')
    if old['depends'] != meta['depends'] or old['provides'] != meta['provides']:
        raise ValueError('Changed BASE dependencies require a new native-solver universe')
    old_index = old_binding['indexFile']
    indexes = [r for r in universe['repositoryIndexes'] if r['file'] == old_index]
    if (len(indexes) != 1 or indexes[0]['role'] != 'foxhole' or
            any(r['indexFile'] == old_index and r['name'] != NAME for r in universe['packageAuthentications'])):
        raise ValueError('Previous index is not isolated to BASE')
    hashes = universe['filesSha256']
    if hashes.pop(old['file']) != old['sha256'] or hashes.pop(old_index) != indexes[0]['sha256']:
        raise ValueError('Previous universe content bindings differ')
    if meta['file'] in hashes or role['indexFile'] in hashes:
        raise ValueError('New BASE conflicts with a retained asset')
    old.clear(); old.update(meta)
    old_binding.update(file=meta['file'],version=meta['version'],architecture=meta['arch'],
                       indexFile=role['indexFile'],packageIdentity=role['packageIdentity'])
    indexes[0].update(file=role['indexFile'],bytes=role['indexBytes'],sha256=role['indexSha256'],
                      sourceUrl=ORIGIN+'v'+version+'/'+role['indexFile'])
    hashes[meta['file']] = meta['sha256']
    hashes[role['indexFile']] = role['indexSha256']
    platform['basePackage'] = dict(name=NAME,file=meta['file'],sha256=meta['sha256'],packageIdentity=role['packageIdentity'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--signed-bases', type=Path, required=True)
    parser.add_argument('--apk', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, output = args.input.resolve(), args.output.absolute()
    index = load('compact-install-bundle')
    entries = index.manifest(source, args.manifest_sha256)
    catalog_path = checked(source, 'package-catalog.json', 524288)
    key = checked(source, 'foxhole-openwrt-apk.pem', 16384)
    if (digest(catalog_path) != entries['package-catalog.json'] or digest(key) != SIGNER or
            entries[key.name] != SIGNER or output.exists() or output.is_symlink()):
        parser.error('An authenticated input family and new output directory are required')
    version = (ROOT / 'config/release-version.txt').read_text().strip()
    catalog = index.document(source, catalog_path.name, 524288)
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        work = Path(tmp)
        keys, result = work/'keys', work/'metadata'
        keys.mkdir(); result.mkdir()
        shutil.copyfile(key, keys/key.name)
        roles = {}
        for name in ('flash','managed-ram'):
            folder = work/name
            folder.mkdir()
            roles[name] = inspect_role(args.signed_bases, args.apk, keys, name, version, folder)
        seen = set()
        cudy_boards = set()
        for platform in catalog['platforms']:
            index.fresh_modes(platform)
            board = platform.get('freshInstallBoard')
            if board:
                if board['boardName'] in cudy_boards:
                    raise ValueError('Duplicate stock Cudy install role')
                cudy_boards.add(board['boardName'])
            old = platform['packageUniverse']
            path = checked(source, old['file'], 2097152)
            if path.name in seen or digest(path) != old['sha256'] or entries[path.name] != old['sha256']:
                raise ValueError('One authenticated package universe per platform is required')
            seen.add(path.name)
            universe = index.document(source, path.name)
            role = 'managed-ram' if (platform.get('freshInstallBoard') or {}).get('storageMode') == 'ram' else 'flash'
            bind_platform(platform, universe, roles[role], version)
            changed = result/path.name
            changed.write_text(json.dumps(universe, separators=(',',':'))+'\n')
            platform['packageUniverse'] = dict(file=path.name,sha256=digest(changed))
        if cudy_boards != {'cudy,wr3000-v1', 'cudy,wr3000s-v1'}:
            raise ValueError('Both Cudy installation roles are required for this delivery')
        (result/'package-catalog.json').write_text(json.dumps(catalog,separators=(',',':'))+'\n')
        result.rename(output)


if __name__ == '__main__':
    main()
