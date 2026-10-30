#!/usr/bin/env python3
"""Inspect historical candidates; Stable releases require the Core bundle builder."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('sign_apks', ROOT / 'tools/sign-apks.py')
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)
LEGACY_PACKAGES = ('foxhole-openwrt-client-1.0.0-r1.apk',
                   'hysteria-2.12.2-r5.apk', 'hysteria-ram-2.12.2-r2.apk')
PAYLOAD = set(LEGACY_PACKAGES) | {
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
    raise SystemExit('Historical legacy release bundles are not qualified for Stable; use prepare-install-bundle.py with an authenticated Core catalog')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'Release preparation failed: {type(error).__name__}; nothing published')
