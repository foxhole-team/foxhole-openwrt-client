#!/usr/bin/env python3
"""Build a public engine catalog from exact canonically signed SDK APKs."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import shutil
import os
import tempfile

PUBLIC_RELEASE_PEM_DIGEST = 'fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1'
PROTOCOLS = {'vless', 'vmess', 'hysteria2', 'tuic', 'trojan', 'shadowsocks',
             'wireguard', 'naive', 'anytls', 'shadowtls', 'socks', 'http'}


def sha(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError('Regular public engine asset required')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(argv: list[str]) -> bytes:
    value = subprocess.run(argv, check=True, capture_output=True, timeout=60)
    if b'ERROR:' in value.stdout or b'ERROR:' in value.stderr or len(value.stdout) > 8 * 1024**2:
        raise ValueError('Native engine APK/index validation refused')
    return value.stdout


def load(path: Path) -> dict:
    if path.stat().st_size > 131072:
        raise ValueError('Bounded producer/manifest required')
    return json.loads(path.read_bytes())


def validate_engine_paths(document: dict, allowed: set[str]) -> None:
    """Validate finite native payload paths, including the APK root ACL record."""
    parents = {str(parent) for name in allowed for parent in Path(name).parents if str(parent) != '.'}
    seen_files, seen_dirs = set(), set()
    native_root_seen = False
    def acl(value, wanted):
        mode = value.get('mode')
        if isinstance(mode, str) and re.fullmatch(r'0?[0-7]{3,4}', mode):
            mode = int(mode, 8)
        return (type(mode) is int and mode == wanted and value.get('user') in ('root', '0') and
                value.get('group') in ('root', '0') and not value.get('xattrs'))
    for directory in document.get('paths', []):
        name = directory.get('name', '')
        if 'name' not in directory or name == '':
            if (native_root_seen or set(directory) - {'name', 'acl', 'files'} or
                    directory.get('acl') != {'mode': 0o755, 'user': 'root', 'group': 'root'} or
                    ('files' in directory and directory['files'] != [])):
                raise ValueError('Engine extraction refuses unsafe native root metadata')
            native_root_seen = True
            continue
        if (name not in parents or name in seen_dirs or not acl(directory.get('acl', {}), 0o755)):
            raise ValueError('Engine extraction refuses unsafe directory metadata')
        seen_dirs.add(name)
        for file in directory.get('files', []):
            path = name + '/' + file['name']
            if (path not in allowed or path in seen_files or file.get('target') is not None or
                    not acl(file.get('acl', {}), 0o755 if file['name'] == 'foxcore-cli' else 0o644)):
                raise ValueError('Engine extraction refuses unsafe or nonregular payload paths')
            seen_files.add(path)
    if seen_files != allowed:
        raise ValueError('Complete finite engine payload required')


def validate_unique_index_entry(info: dict, index_entries: list[dict], archive_bytes: int) -> None:
    """Bind a name-only native fetch to one exact canonical index entry."""
    matches = [row for row in index_entries if row['name'] == info['name']]
    if (len(matches) != 1 or
            (matches[0]['version'], matches[0]['arch'], matches[0]['file-size']) !=
            (info['version'], info['arch'], archive_bytes)):
        raise ValueError('Engine APK is not uniquely indexed by immutable name')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--index', type=Path, required=True)
    parser.add_argument('--packages', type=Path, nargs='+', required=True)
    parser.add_argument('--core-commit', required=True)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if (not 1 <= len(args.packages) <= 72 or len(set(args.packages)) != len(args.packages) or
            re.fullmatch(r'[a-f0-9]{40}', args.core_commit) is None or
            re.fullmatch(r'[a-f0-9]{64}', args.source_sha256) is None or
            sha(args.public_key) != PUBLIC_RELEASE_PEM_DIGEST or args.index.name != 'engines.adb' or
            args.index.stat().st_size > 8 * 1024**2 or args.output.exists()):
        raise ValueError('Exact canonical engine-only index and current Core source required')
    entries, seen = [], set()
    with tempfile.TemporaryDirectory(prefix='foxhole-engine-catalog-') as work:
        root = Path(work)
        keys = root / 'keys'; keys.mkdir()
        (keys / 'foxhole.pem').write_bytes(args.public_key.read_bytes())
        run([args.apk, '--keys-dir', str(keys), 'verify', str(args.index), *map(str, args.packages)])
        index = json.loads(run([args.apk, 'adbdump', '--format', 'json', str(args.index)]))
        if index.get('pkgname-spec') not in (None, '${name}-${version}.apk'):
            raise ValueError('Exact native package filenames required')
        index_entries = index['packages']
        repository = root / 'repository'; repository.mkdir()
        shutil.copyfile(args.index, repository / 'packages.adb')
        repositories = root / 'repositories'; repositories.write_text(str(repository / 'packages.adb') + '\n')
        for archive in args.packages:
            info = json.loads(run([args.apk, 'adbdump', '--format', 'json', str(archive)]))['info']
            filename = info['name'] + '-' + info['version'] + '.apk'
            if archive.name != filename or '/' in filename or '..' in filename:
                raise ValueError('Exact canonical archive filename required')
            shutil.copyfile(archive, repository / filename)
        package_names = set()
        for sequence, archive in enumerate(args.packages):
            archive_sha = sha(archive)
            document = json.loads(run([args.apk, 'adbdump', '--format', 'json', str(archive)]))
            info = document['info']
            if (document.get('scripts') or document.get('triggers') or
                    any(info.get(field) for field in ('provides', 'replaces', 'install-if', 'recommends'))):
                raise ValueError('Engine APK may not contain hooks or shared package replacements')
            package_names.add(info['name'])
            validate_unique_index_entry(info, index_entries, archive.stat().st_size)
            destination = root / ('payload-' + str(sequence)); destination.mkdir()
            # Verify canonical signatures before extracting owned input.
            identity = re.fullmatch(r'foxcore-engine-([a-z0-9]+)-(flash|ram)-([a-f0-9]{64})', info['name'])
            if identity is None or identity[1] not in PROTOCOLS:
                raise ValueError('Exact versioned engine package identity required')
            slot_root = 'usr/libexec/foxhole/engines/' + identity[1] + '/' + identity[3]
            license_root = 'usr/share/licenses/' + info['name']
            allowed = {slot_root + '/' + leaf for leaf in ('foxcore-cli', 'slot.json', 'core-producer.json', 'capabilities.json')}
            allowed.update(license_root + '/' + leaf for leaf in ('LICENSE', 'THIRD_PARTY_NOTICES.md', 'DEPENDENCY-LICENSES.txt', 'RUNTIME-NOTICES.txt', 'LEGAL-PROVENANCE.json'))
            allowed.add('lib/apk/packages/' + info['name'] + '.list')
            validate_engine_paths(document, allowed)
            database, fetched = root / ('db-' + str(sequence)), root / ('fetch-' + str(sequence))
            database.mkdir(); fetched.mkdir()
            common = [args.apk, '--root', str(database), '--arch', info['arch'], '--no-network', '--no-cache',
                      '--keys-dir', str(keys), '--repositories-file', str(repositories)]
            run(common + ['add', '--initdb'] + (['--usermode'] if os.geteuid() != 0 else []))
            run(common + ['fetch', '--output', str(fetched), info['name']])
            if sha(fetched / archive.name) != archive_sha:
                raise ValueError('Fresh native indexed fetch differs from signed catalog archive')
            run([args.apk, '--keys-dir', str(keys), 'extract', '--no-chown', '--destination', str(destination), str(archive)])
            manifests = list(destination.glob('usr/libexec/foxhole/engines/*/*/slot.json'))
            if len(manifests) != 1:
                raise ValueError('Exactly one immutable engine slot required')
            manifest_file = manifests[0]; manifest = load(manifest_file); manifest_sha = sha(manifest_file)
            ident, storage = manifest['id'], manifest['storage']
            if ident not in PROTOCOLS or storage not in ('FLASH', 'RAM'):
                raise ValueError('Exact supported single engine/storage required')
            package_name = 'foxcore-engine-' + ident + '-' + storage.lower() + '-' + manifest_sha
            if (info['name'] != package_name or manifest_file.parent.name != manifest_sha or
                    manifest_file.parent.parent.name != ident or info['arch'] != manifest['architecture']):
                raise ValueError('Package name/path/manifest identity differs')
            folder = manifest_file.parent
            producer = load(folder / 'core-producer.json'); caps = load(folder / 'capabilities.json')
            if (producer.get('exitCode') != 0 or producer.get('sourceCommit') != args.core_commit or
                    producer.get('sourceSha256') != args.source_sha256 or producer.get('protocols') != [ident] or
                    producer.get('binarySha256') != manifest['binarySha256'] or
                    sha(folder / 'core-producer.json') != manifest['producerSha256'] or
                    sha(folder / 'capabilities.json') != manifest['capabilitiesSha256'] or
                    sha(folder / 'foxcore-cli') != manifest['executableSha256'] or
                    caps.get('protocols') != [ident] or caps.get('router_contract_version') != 1 or
                    caps.get('platform') != 'linux' or caps.get('core_version') != manifest['version'] or
                    producer.get('coreVersion') != manifest['version']):
                raise ValueError('Actual single-protocol producer/capabilities/payload binding differs')
            notices = destination / 'usr/share/licenses' / package_name
            for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md'):
                if sha(notices / name) != producer['filesSha256'][name]:
                    raise ValueError('Engine native notice bytes differ')
            legal_spec = importlib.util.spec_from_file_location('engine_legal', Path(__file__).with_name('engine-legal.py'))
            legal = importlib.util.module_from_spec(legal_spec); legal_spec.loader.exec_module(legal)
            legal.validate(notices, manifest['legalProvenanceSha256'], producer,
                           sha(folder / 'core-producer.json'), ident)
            scope = ident, storage, info['arch']
            if scope in seen:
                raise ValueError('Only one current artifact per protocol/storage/architecture')
            seen.add(scope)
            base = 'https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/v' + manifest['version'] + '/'
            value = {key: item for key, item in manifest.items() if key != 'schema'}
            value.update(manifestSha256=manifest_sha, archiveBytes=archive.stat().st_size,
                         indexBytes=args.index.stat().st_size, installedBytes=info['installed-size'],
                         packageName=package_name, packageVersion=info['version'], packageSha256=archive_sha,
                         indexSha256=sha(args.index), packageUrl=base + package_name + '-' + info['version'] + '.apk',
                         indexUrl=base + 'engines.adb')
            entries.append(value)
        if package_names != {row['name'] for row in index_entries}:
            raise ValueError('Engine-only signed index has extra or missing packages')
    args.output.write_text(json.dumps({'schema': 1, 'entries': entries}, separators=(',', ':')) + '\n')
    print('Canonical package catalog generated; runtime qualification is a separate release gate')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
