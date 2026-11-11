#!/usr/bin/env python3
"""Prepare a data-only Core feed from actual signed source inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE_SIGNER_FINGERPRINT = 'dd3b679990b46da7ddcf6d8be248cfd031b35b88e094ce67fcc5090d9d496c58'
CORE_ORIGIN = 'https://github.com/foxhole-team/foxhole-core/releases/download/'
SOURCE_FIELDS = {'schema', 'kind', 'producerCommit', 'publisherCommit', 'publisherTree',
                 'sourceContentSha256', 'sourceManifestSha256', 'contentJoinReceiptSha256'}
ENTRY_FIELDS = {'id', 'storage', 'version', 'architecture', 'binarySha256', 'executableSha256',
                'producerSha256', 'capabilitiesSha256', 'legalProvenanceSha256', 'manifestSha256',
                'sourceCommit', 'binaryBytes', 'archiveBytes', 'indexBytes', 'installedBytes',
                'runtimeMemoryBytes', 'reserveBytes', 'packageName', 'packageVersion',
                'packageSha256', 'indexSha256', 'packageUrl', 'indexUrl'}


def raw(path: Path, maximum: int = 1048576) -> bytes:
    if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= maximum:
        raise ValueError('Bounded regular public input required')
    return path.read_bytes()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact(value: object, fields: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('Closed Core feed record required')
    return value


def hex_value(value: object, length: int = 64) -> bool:
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{' + str(length) + '}', value) is not None


def verify_source(directory: Path, runner=subprocess.run) -> dict:
    envelope_raw = raw(directory / 'source-envelope.json')
    envelope = exact(json.loads(envelope_raw), SOURCE_FIELDS)
    if envelope['schema'] != 1 or envelope['kind'] != 'foxhole-signed-source-content-join-v1':
        raise ValueError('Signed source/content join required')
    for name in ['producerCommit', 'publisherCommit', 'publisherTree']:
        if not hex_value(envelope[name], 40):
            raise ValueError('Actual producer and publisher commits required')
    for name in ['sourceContentSha256', 'sourceManifestSha256', 'contentJoinReceiptSha256']:
        if not hex_value(envelope[name]):
            raise ValueError('Actual source receipt hashes required')
    signature = raw(directory / 'source-envelope.json.asc', 16384)
    if sha(raw(directory / 'source-manifest.json')) != envelope['sourceManifestSha256']:
        raise ValueError('Signed source manifest identity differs')
    if sha(raw(directory / 'content-join.json')) != envelope['contentJoinReceiptSha256']:
        raise ValueError('Signed source content join differs')
    key = raw(ROOT / 'config/release-signers.asc', 131072)
    if sha(key) != SOURCE_SIGNER_FINGERPRINT:
        raise ValueError('Pinned public source verification key changed')
    with tempfile.TemporaryDirectory(prefix='foxhole-core-source-verify-') as work:
        home = Path(work)
        ring = home / 'signers.gpg'
        runner(['gpg', '--batch', '--no-options', '--homedir', str(home), '--dearmor',
                '--output', str(ring)], input=key, check=True, capture_output=True, timeout=20)
        runner(['gpgv', '--homedir', str(home), '--keyring', str(ring),
                str(directory / 'source-envelope.json.asc'), str(directory / 'source-envelope.json')],
               check=True, capture_output=True, timeout=20)
    result = {name: envelope[name] for name in sorted(SOURCE_FIELDS - {'schema', 'kind'})}
    result['signatureReceiptSha256'] = sha(signature)
    return result


def validate_catalog(value: object, version: str, source: dict) -> dict:
    catalog = exact(value, {'schema', 'entries'})
    if catalog['schema'] != 1 or not isinstance(catalog['entries'], list) or not 1 <= len(catalog['entries']) <= 72:
        raise ValueError('Complete bounded engine catalog required')
    seen = set()
    for entry in catalog['entries']:
        exact(entry, ENTRY_FIELDS)
        if (entry['version'] != version or entry['sourceCommit'] != source['producerCommit'] or
                entry['id'] not in {'vless', 'hysteria2', 'wireguard'} or
                entry['storage'] not in {'FLASH', 'RAM'} or
                entry['architecture'] not in {'x86_64', 'aarch64_cortex-a53'}):
            raise ValueError('Qualified current protocol/target producer required')
        coordinate = entry['id'], entry['storage'], entry['architecture']
        if coordinate in seen:
            raise ValueError('Duplicate Core feed coordinate')
        seen.add(coordinate)
        for name in ENTRY_FIELDS:
            if name.endswith('Sha256') and not hex_value(entry[name]):
                raise ValueError('Exact engine artifact digest required')
        limits = {'binaryBytes': 67108864, 'archiveBytes': 134217728, 'indexBytes': 8388608,
                  'installedBytes': 536870912, 'runtimeMemoryBytes': 2147483648, 'reserveBytes': 2147483648}
        for name, maximum in limits.items():
            if type(entry[name]) is not int or not 0 < entry[name] <= maximum:
                raise ValueError('Bounded native resource values required')
        if entry['reserveBytes'] < 16777216:
            raise ValueError('Runtime reserve must remain explicit')
        package = f"foxcore-engine-{entry['id']}-{entry['storage'].lower()}-{entry['manifestSha256']}"
        directory = CORE_ORIGIN + 'v' + version + '/'
        if (entry['packageName'] != package or not isinstance(entry['packageVersion'], str) or
                re.fullmatch(re.escape(version) + r'-r[1-9][0-9]{0,5}', entry['packageVersion']) is None or
                entry['packageUrl'] != directory + package + '-' + entry['packageVersion'] + '.apk' or
                entry['indexUrl'] != directory + 'engines.adb'):
            raise ValueError('Closed immutable official Core release URL required')
    return catalog


def payload(directory: Path, version: str, sequence: int, minimum_base: str,
            published: int, expires: int, runner=subprocess.run) -> dict:
    if re.fullmatch(r'[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}', version) is None:
        raise ValueError('Exact actual Core release version required')
    if (type(sequence) is not int or not 1 <= sequence <= 0x7ffffffe or
            re.fullmatch(r'[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}-r[1-9][0-9]{0,5}', minimum_base) is None or
            type(published) is not int or type(expires) is not int or
            not 1577836800000 <= published < expires <= 9007199254740991):
        raise ValueError('Explicit compatibility, sequence and validity required')
    source = verify_source(directory, runner)
    catalog = validate_catalog(json.loads(raw(directory / 'engine-catalog.json', 262144)), version, source)
    return {'schema': 1, 'feedAbi': 1, 'channel': 'stable', 'sequence': sequence,
            'coreVersion': version, 'releaseTag': 'v' + version,
            'publishedAtUnixMs': published, 'expiresAtUnixMs': expires,
            'compatibility': {'stateAbi': 1, 'transactionAbi': 1, 'routerContractVersion': 1,
                              'osRelease': '25.12.5', 'targets': ['x86/64', 'mediatek/filogic'],
                              'minimumBaseVersion': minimum_base},
            'source': source, 'catalog': catalog}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--sequence', type=int, required=True)
    parser.add_argument('--minimum-base-version', required=True)
    parser.add_argument('--published-at-unix-ms', type=int, required=True)
    parser.add_argument('--expires-at-unix-ms', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-sha256')
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('Fresh metadata output required')
    value = payload(args.input, args.version, args.sequence, args.minimum_base_version,
                    args.published_at_unix_ms, args.expires_at_unix_ms)
    data = (json.dumps(value, separators=(',', ':')) + '\n').encode()
    if len(data) > 262144:
        raise ValueError('Core feed metadata exceeds its bound')
    if args.expected_sha256 is not None and (not hex_value(args.expected_sha256) or sha(data) != args.expected_sha256):
        raise ValueError('Explicit catalog package input identity differs')
    args.output.write_bytes(data)
    print(sha(data))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
