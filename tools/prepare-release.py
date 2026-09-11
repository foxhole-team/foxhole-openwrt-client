#!/usr/bin/env python3
"""Verify a main candidate, sign its APKs, and prepare a release manifest."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('sign_apks', ROOT / 'tools/sign-apks.py')
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)
PAYLOAD = set(signing.PACKAGES) | {
    'install.sh', 'sdk.config', 'feeds.buildinfo', 'CANDIDATE.json',
    'foxhole-openwrt-client-source.zip', 'foxhole-openwrt-client-source.zip.sha256',
}


def verify(candidate, main_commit, tree):
    metadata = json.loads((candidate / 'RELEASE.json').read_text())
    source = candidate / 'release-candidate'
    if {p.name for p in source.iterdir()} != PAYLOAD | {'SHA256SUMS'}:
        raise ValueError('Unexpected candidate files')
    if any(p.is_symlink() or not p.is_file() for p in source.iterdir()):
        raise ValueError('Non-regular candidate file')
    if signing.digest(source / 'SHA256SUMS') != metadata['candidate_manifest_sha256']:
        raise ValueError('Candidate manifest mismatch')
    seen = set()
    for line in (source / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  ([A-Za-z0-9_.-]+)', line)
        if not match or match[2] not in PAYLOAD or match[2] in seen:
            raise ValueError('Invalid manifest entry')
        seen.add(match[2])
        if signing.digest(source / match[2]) != match[1]:
            raise ValueError('Candidate file hash mismatch')
    if seen != PAYLOAD:
        raise ValueError('Incomplete candidate manifest')
    record = json.loads((source / 'CANDIDATE.json').read_text())
    if metadata['main_commit'] != main_commit or metadata['source_tree'] != tree:
        raise ValueError('Candidate does not match checked-out main')
    if record != {
        'schema': 1, 'source_commit': metadata['dev_commit'], 'source_tree': tree,
        'target': 'openwrt-25.12.5-aarch64_generic',
        'package_signatures': 'unsigned', 'firmware_acceptance': 'pending',
    }:
        raise ValueError('Candidate provenance mismatch')
    if (source / 'install.sh').read_bytes() != (ROOT / 'install.sh').read_bytes():
        raise ValueError('Installer differs from checked-out main')
    return source, metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--apk', default='apk')
    args = parser.parse_args()
    git = lambda *argv: signing.run(['git', '-C', str(ROOT), *argv]).decode().strip()
    if git('branch', '--show-current') != 'main' or git('status', '--porcelain'):
        raise SystemExit('Release preparation requires a clean main checkout')
    main_commit, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
    signing.run(['git', '-C', str(ROOT), 'verify-commit', 'HEAD'])
    source, metadata = verify(args.candidate.resolve(), main_commit, tree)
    output = args.output.resolve()
    signing.sign(args.apk, source, output, args.key.absolute(),
                 ROOT / 'config/foxhole-openwrt-apk.pem')
    for name in PAYLOAD - set(signing.PACKAGES) - {'CANDIDATE.json'}:
        shutil.copyfile(source / name, output / name)
    shutil.copyfile(ROOT / 'config/release-signers.asc', output / 'release-signers.asc')
    archive = output / 'unsigned-candidate.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as z:
        for name in sorted(PAYLOAD | {'SHA256SUMS'}):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            z.writestr(info, (source / name).read_bytes())
    metadata.update({
        'version': (ROOT / 'config/release-version.txt').read_text().strip(),
        'package_signatures': 'ECDSA-P256-SHA256',
        'firmware_acceptance': 'pending',
        'unsigned_candidate_sha256': signing.digest(archive),
        'apk_signatures_sha256': signing.digest(output / 'APK-SIGNATURES.json'),
    })
    (output / 'RELEASE.json').write_text(json.dumps(metadata, indent=2) + '\n')
    manifest = ''.join(signing.digest(p) + '  ' + p.name + '\n'
                       for p in sorted(output.iterdir()))
    (output / 'SHA256SUMS').write_text(manifest)
    print('Release manifest SHA-256:', signing.digest(output / 'SHA256SUMS'))
    print('Sign SHA256SUMS with the owner GPG key before publishing.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'Release preparation failed: {type(error).__name__}; nothing published')
