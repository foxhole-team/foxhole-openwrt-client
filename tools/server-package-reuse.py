#!/usr/bin/env python3
"""Bind existing incoming-server artifacts without building or publishing them."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import traceback
from urllib.parse import urlsplit

META_LIMIT = 1024 * 1024
BINARY_LIMIT = 64 * 1024 * 1024
PLATFORMS = {'x86': ('x86_64', 'linux-amd64', 'x86/64'),
             'filogic': ('aarch64_cortex-a53', 'linux-arm64', 'mediatek/filogic')}
SHA = re.compile(r'[a-f0-9]{64}')


def checked(path: Path, limit: int, expected: str | None = None) -> dict:
    info, parent = path.lstat(), path.parent.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or
            not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022 or not 0 < info.st_size <= limit):
        raise ValueError('Protected regular bounded input required')
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if expected is not None and (not SHA.fullmatch(expected) or digest != expected):
        raise ValueError('Pinned input digest differs')
    return {'path': str(path), 'sha256': digest, 'bytes': info.st_size}


def document(path: Path, expected: str | None = None) -> tuple[dict, dict]:
    binding = checked(path, META_LIMIT, expected)
    return json.loads(path.read_text()), binding


def release_base(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or parsed.hostname != 'github.com' or parsed.port not in (None, 443) or
            parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or
            not re.fullmatch(r'/foxhole-team/foxhole-openwrt-client/releases/download/[A-Za-z0-9_.-]+/?', parsed.path)):
        raise ValueError('Exact public HTTPS release asset namespace required')
    return value.rstrip('/')


def ram_binding(lines: list[str], producer: dict, desired_base: str | None, reserve: int | None) -> dict:
    if (len(lines) != 4 or not re.fullmatch(r'https://[A-Za-z0-9_./%+-]+', lines[0]) or
            lines[1] != producer['binarySha256'] or lines[2] != str(producer['binaryBytes']) or
            not lines[3].isdigit() or not 0 < int(lines[3]) <= 2**53 - 1):
        raise ValueError('RAM wrapper does not bind the exact native bytes and positive reserve')
    if reserve is not None and (type(reserve) is not int or not 0 < reserve <= 2**53 - 1):
        raise ValueError('Positive explicitly admitted RAM reserve required')
    desired = None if desired_base is None else release_base(desired_base) + '/hysteria-' + producer['binarySha256'] + '.bin'
    return {'currentURL': lines[0], 'currentReserveBytes': int(lines[3]),
            'desiredURL': desired, 'desiredReserveBytes': reserve,
            'wrapperRebuildRequired': desired is None or reserve is None or desired != lines[0] or reserve != int(lines[3]),
            'resourceAdmissionRequired': True, 'newNativeBuildRequired': False,
            'newPackageRevisionRequiredIfChanged': True}


def security_status(path: Path | None, expected: str | None, repository: str | None, now: dt.datetime) -> dict:
    result = {'admission': 'UNKNOWN_MISSING', 'shippingAdmitted': False,
              'coordinates': {'Go': 'go1.26.10', 'golang.org/x/net': 'v0.60.0'},
              'applicabilityReviewRequired': True, 'reportNotContentProof': True}
    if path is None:
        return result
    if expected is None or repository is None:
        raise ValueError('Pinned report digest and trusted scanner repository required')
    report, binding = document(path, expected)
    generated = dt.datetime.fromisoformat(report['generatedAt'].replace('Z', '+00:00'))
    if generated.tzinfo is None or now.tzinfo is None:
        raise ValueError('UTC-aware scanner times required')
    age = (now - generated).total_seconds()
    source = report.get('source', {})
    matched_source = isinstance(source, dict) and source.get('repository') == repository
    result.update(report=binding, generatedAt=generated.isoformat(), ageSeconds=age,
                  sourceMatched=matched_source, complete=report.get('complete') is True,
                  inventoryComplete=report.get('inventoryComplete') is True,
                  coverage=report.get('coverage'), exactCoordinateCandidateHashes=[])
    for finding in report.get('findings', []):
        if not isinstance(finding, dict) or str(finding.get('severity', '')).upper() not in {'HIGH', 'CRITICAL'}:
            continue
        text = json.dumps(finding, sort_keys=True)
        if re.search(r'\bgo?1\.26\.10\b|\b1\.26\.10\b', text) or ('golang.org/x/net' in text and '0.60.0' in text):
            result['exactCoordinateCandidateHashes'].append(hashlib.sha256(text.encode()).hexdigest())
    result['candidateMatchingIsNotAffectedRangeAnalysis'] = True
    if not matched_source:
        result['admission'] = 'UNKNOWN_SOURCE'
    elif age < -300 or age > 6 * 3600:
        result['admission'] = 'UNKNOWN_STALE'
    elif not result['complete'] or not result['inventoryComplete']:
        result['admission'] = 'UNKNOWN_INCOMPLETE'
    else:
        result['admission'] = 'APPLICABILITY_REVIEW_REQUIRED'
    return result


def run(apk: Path, arguments: list[str]) -> bytes:
    result = subprocess.run([str(apk), *arguments], capture_output=True, timeout=60)
    if result.returncode or len(result.stdout) > 8 * META_LIMIT:
        raise ValueError('Readonly APK inspection refused or exceeded its bound')
    return result.stdout


def metadata(apk: Path, path: Path) -> dict:
    value = json.loads(run(apk, ['adbdump', '--format', 'json', str(path)]))['info']
    if any(not isinstance(value.get(key), str) or not value[key] for key in ['name', 'version', 'arch', 'hashes']):
        raise ValueError('Exact APK identity required')
    return value


def load_helper():
    path = Path(__file__).with_name('package-budget.py')
    binding = checked(path, META_LIMIT)
    spec = importlib.util.spec_from_file_location('server_existing_budget', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, binding


def bind(args) -> dict:
    tool = checked(args.apk, BINARY_LIMIT, args.apk_sha256)
    canonical, canonical_binding = document(args.canonical / 'receipt.json', args.canonical_sha256)
    contract, contract_binding = document(args.canonical / 'actual-input-contract.json', args.contract_sha256)
    budget, helper_binding = load_helper()
    if canonical.get('exitCode') != 0 or canonical.get('publicKeySha256') != budget.indexed.CANONICAL_PUBLIC_SHA:
        raise ValueError('Canonical local package authority differs')
    key_binding = checked(args.public_key, 16384, budget.indexed.CANONICAL_PUBLIC_SHA)
    security = security_status(args.scan_report, args.scan_sha256, args.scan_repository, dt.datetime.now(dt.timezone.utc))
    platforms, legal = [], {}
    with tempfile.TemporaryDirectory(prefix='server-package-reuse-') as temporary:
        keys = Path(temporary) / 'keys'; keys.mkdir()
        shutil.copyfile(args.public_key, keys / args.public_key.name)
        for platform, (architecture, target, supported_target) in PLATFORMS.items():
            records = args.producer_records / target
            producer_path = records / 'hysteria-producer.json'
            source_rows = contract['platforms'][platform]['rows']
            if len(source_rows) != 2 or {row['storage'] for row in source_rows} != {'FLASH', 'RAM'}:
                raise ValueError('Exactly FLASH and RAM server source rows required')
            producer_hashes = {row['payload']['producerSha256'] for row in source_rows}
            if len(producer_hashes) != 1:
                raise ValueError('Server modes refer to different native producers')
            producer, producer_binding = document(producer_path, producer_hashes.pop())
            signed = args.canonical / platform / 'signed'
            index_binding = checked(signed / 'packages.adb', META_LIMIT, canonical['platforms'][platform]['indexSha256'])
            run(args.apk, ['--keys-dir', str(keys), 'verify', index_binding['path']])
            index = json.loads(run(args.apk, ['adbdump', '--format', 'json', index_binding['path']]))
            flash_row = next(row for row in source_rows if row['storage'] == 'FLASH')
            flash_name = flash_row['unsignedApkFile']
            flash_package = signed / flash_name
            carrier = checked(flash_package, BINARY_LIMIT,
                              canonical['platforms'][platform]['packages'][flash_name]['signed_sha256'])
            extracted = Path(temporary) / (platform + '-flash-carrier'); extracted.mkdir()
            run(args.apk, ['--keys-dir', str(keys), 'extract', '--no-chown', '--destination', str(extracted), str(flash_package)])
            checked(extracted / 'usr/share/foxhole/hysteria-producer.json', META_LIMIT, producer_binding['sha256'])
            root = Path(temporary) / (platform + '-checked-input-view'); root.mkdir()
            shutil.copyfile(producer_path, root / 'hysteria-producer.json')
            for name, digest in producer['filesSha256'].items():
                if not re.fullmatch(r'[A-Za-z0-9_.-]+', name):
                    raise ValueError('Unsafe legal provenance filename')
                member = 'usr/share/licenses/hysteria/' + name
                checked(extracted / member, META_LIMIT, digest)
                shutil.copyfile(extracted / member, root / name)
                item = {'sha256': digest, 'bytes': (root / name).stat().st_size,
                        'carrier': carrier['path'], 'member': member}
                if name in legal and legal[name]['sha256'] != digest:
                    raise ValueError('Server legal assets collide across architectures')
                legal[name] = item
                existing = args.assets / name
                if existing.exists():
                    checked(existing, META_LIMIT, digest)
            budget.provenance.verify(producer, root)
            native = checked(extracted / 'usr/bin/hysteria', BINARY_LIMIT, producer['binarySha256'])
            native = {'sha256': native['sha256'], 'bytes': native['bytes'],
                      'carrier': carrier['path'], 'member': 'usr/bin/hysteria'}
            if producer['target'] != target or native['bytes'] != producer['binaryBytes']:
                raise ValueError('Native server target or length differs')
            shutil.copyfile(extracted / 'usr/bin/hysteria', root / 'hysteria')
            checked_producer_path = root / 'hysteria-producer.json'
            packages = []
            for row in source_rows:
                name = row['unsignedApkFile']
                authority = canonical['platforms'][platform]['packages'][name]
                package = signed / name
                package_binding = checked(package, BINARY_LIMIT, authority['signed_sha256'])
                info = metadata(args.apk, package)
                if (info['name'], info['version'], info['arch']) != (row['packageName'], row['packageVersion'], architecture):
                    raise ValueError('Signed server package identity differs')
                matches = [entry for entry in index['packages'] if
                           (entry.get('name'), entry.get('version'), entry.get('arch')) ==
                           (info['name'], info['version'], info['arch'])]
                if len(matches) != 1 or matches[0].get('hashes') != info['hashes'] or info['hashes'] != authority['content_sha256']:
                    raise ValueError('Canonical server index identity differs')
                if matches[0].get('file-size') != package_binding['bytes']:
                    raise ValueError('Canonical server archive size differs')
                mode = row['storage'].lower()
                record = {'name': info['name'], 'version': info['version'], 'arch': architecture, 'file': name}
                budget.verify_server_payload(str(args.apk), [package], [record], checked_producer_path, mode, keys, False,
                                             root / 'hysteria' if mode == 'ram' else None)
                item = {**package_binding, 'name': info['name'], 'version': info['version'], 'architecture': architecture,
                        'storage': mode, 'signatureAndPayloadVerified': True,
                        'contentSha256': info['hashes'], 'proposedAssetFile': 'apk-' + package_binding['sha256'] + '.apk'}
                if mode == 'ram':
                    destination = Path(temporary) / platform; destination.mkdir()
                    run(args.apk, ['--keys-dir', str(keys), 'extract', '--no-chown', '--destination', str(destination), str(package)])
                    download = destination / 'usr/share/foxhole/hysteria-server-download.txt'
                    checked(download, 1024)
                    item['ramBinding'] = ram_binding(download.read_text().splitlines(), producer, args.release_base_url,
                                                     args.ram_reserve_bytes)
                packages.append(item)
            platforms.append({'architecture': architecture, 'supportedTargets': [supported_target],
                              'producer': producer_binding, 'nativeBinary': native, 'verifiedFLASHCarrier': carrier,
                              'producerAssetFile': 'hysteria-producer-' + architecture + '-' + producer_binding['sha256'] + '.json',
                              'binaryAssetFile': 'hysteria-' + native['sha256'] + '.bin',
                              'sourceCommit': producer['sourceCommit'], 'sourceSha256': producer['sourceSha256'],
                              'GoRuntimeVersion': producer['binaryRuntimeVersion'], 'sourceTestScope': producer['sourceTestScope'],
                              'sourceRepairReceiptSha256': producer['sourcePatch']['receiptSha256'],
                              'index': index_binding, 'packages': packages,
                              'catalogAndUniverseUpdateRequired': True, 'newNativeBuildRequired': False})
    if checked(Path(helper_binding['path']), META_LIMIT)['sha256'] != helper_binding['sha256']:
        raise ValueError('Existing verification helper changed during inspection')
    return {'schema': 1, 'kind': 'server-package-reuse-plan-v1', 'publicationPermitted': False,
            'security': security, 'apkTool': tool, 'publicKey': key_binding,
            'canonicalReceipt': canonical_binding, 'actualInputContract': contract_binding,
            'existingVerifier': helper_binding, 'platforms': platforms, 'sharedLegalAssets': legal,
            'newNativeBuildRequired': False, 'retainedTestsRelabeled': False,
            'releaseMetadataModified': False,
            'remaining': ['Fresh scanner applicability review for exact binary/module inputs',
                          'Choose final RAM HTTPS release namespace and admitted memory reserve',
                          'Rebuild only changed RAM wrappers with a new package revision',
                          'Root canonical signing/index update for changed packages',
                          'Bind server FLASH/RAM rows into catalog/universe and regenerate the verified bundle'],
            'runtimeMemoryQualificationNotInferred': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--canonical', type=Path, required=True)
    parser.add_argument('--canonical-sha256', required=True)
    parser.add_argument('--contract-sha256', required=True)
    parser.add_argument('--producer-records', type=Path, required=True)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--apk-sha256', required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--scan-report', type=Path)
    parser.add_argument('--scan-sha256')
    parser.add_argument('--scan-repository')
    parser.add_argument('--release-base-url', type=release_base)
    parser.add_argument('--ram-reserve-bytes', type=int)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    protected = [Path(__file__).resolve().parents[1], args.canonical.resolve(), args.producer_records.resolve(), args.assets.resolve()]
    if args.scan_report is not None:
        protected.append(args.scan_report.resolve().parent)
    parent = args.output.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022 or
            any(output.is_relative_to(root) for root in protected)):
        raise ValueError('Operational binding output must stay outside source and immutable inputs')
    result = bind(args)
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps({'bindingWritten': True, 'packagesVerified': 4, 'newNativeBuildRequired': False,
                      'securityAdmission': result['security']['admission'], 'publicationPermitted': False}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        location = traceback.extract_tb(error.__traceback__)[-1]
        print(json.dumps({'bindingWritten': False, 'errorType': type(error).__name__,
                          'location': Path(location.filename).name + ':' + str(location.lineno),
                          'detailsRedacted': True}), file=sys.stderr)
        raise SystemExit(1)
