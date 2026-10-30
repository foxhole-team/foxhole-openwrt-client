"""Exact original-text delivery for one engine producer; no source discovery."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

TEXTS = ('DEPENDENCY-LICENSES.txt', 'RUNTIME-NOTICES.txt')
AUTHORITY_KEYS = {'producerStageReceiptSha256', 'producerSummaryReceiptSha256',
                  'cargoCaptureSha256', 'selectedCargoSbomSha256',
                  'cargoOriginalNoticesReportSha256', 'runtimeOriginalNoticesReportSha256'}
FIELDS = {'schema', 'coreCommit', 'sourceArchiveSha256', 'target', 'protocols',
          'producerSha256', 'binarySha256', 'originalCoreNotices', 'files', 'authorities'}
SHA = re.compile(r'[a-f0-9]{64}')


SOURCE2_FIELDS = (FIELDS - {'sourceArchiveSha256'}) | {
    'sourceContentSha256', 'sourceManifestSha256', 'sourceAuthority'}
SOURCE2_AUTHORITY = {'commit', 'tree', 'signatureReceiptSha256', 'sourceBankReceiptSha256'}


def validate_source2(value: dict, producer: dict, producer_sha: str, protocol: str) -> None:
    authority = value.get('sourceAuthority')
    if (set(value) != SOURCE2_FIELDS or
            value.get('coreCommit') != producer.get('sourceCommit') or
            value.get('sourceContentSha256') != producer.get('sourceSha256') or
            not isinstance(value.get('sourceContentSha256'), str) or SHA.fullmatch(value['sourceContentSha256']) is None or
            not isinstance(value.get('sourceManifestSha256'), str) or SHA.fullmatch(value['sourceManifestSha256']) is None or
            not isinstance(authority, dict) or set(authority) != SOURCE2_AUTHORITY or
            authority.get('commit') != producer.get('sourceCommit') or
            not isinstance(authority.get('commit'), str) or re.fullmatch('[a-f0-9]{40}', authority['commit']) is None or
            not isinstance(authority.get('tree'), str) or re.fullmatch('[a-f0-9]{40}', authority['tree']) is None or
            any(not isinstance(authority.get(key), str) or SHA.fullmatch(authority[key]) is None
                for key in ('signatureReceiptSha256', 'sourceBankReceiptSha256')) or
            value.get('target') != producer.get('target') or value.get('protocols') != [protocol] or
            value.get('producerSha256') != producer_sha or
            value.get('binarySha256') != producer.get('binarySha256') or
            value.get('originalCoreNotices') != producer.get('filesSha256') or
            set(value.get('files', {})) != set(TEXTS) or
            set(value.get('authorities', {})) != AUTHORITY_KEYS or
            any(not isinstance(x, str) or SHA.fullmatch(x) is None for x in value['authorities'].values())):
        raise ValueError('Source-content legal authorities differ from the exact engine producer')


def file_hash(path: Path, maximum: int) -> str:
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Original legal delivery may not contain links')
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or
            info.st_mode & 0o022 or not 0 < info.st_size <= maximum):
        raise ValueError('Bounded owned original legal delivery required')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate(root: Path, expected: str, producer: dict, producer_sha: str, protocol: str) -> dict:
    if not SHA.fullmatch(expected or ''):
        raise ValueError('External actual legal provenance SHA required')
    path = root / 'LEGAL-PROVENANCE.json'
    if file_hash(path, 131072) != expected:
        raise ValueError('Original legal delivery provenance changed')
    value = json.loads(path.read_bytes())
    if type(value.get('schema')) is int and value['schema'] == 2:
        validate_source2(value, producer, producer_sha, protocol)
    elif (set(value) != FIELDS or type(value.get('schema')) is not int or value['schema'] != 1 or
            value.get('coreCommit') != producer.get('sourceCommit') or
            value.get('sourceArchiveSha256') != producer.get('sourceSha256') or
            value.get('target') != producer.get('target') or value.get('protocols') != [protocol] or
            value.get('producerSha256') != producer_sha or
            value.get('binarySha256') != producer.get('binarySha256') or
            value.get('originalCoreNotices') != producer.get('filesSha256') or
            set(value.get('files', {})) != set(TEXTS) or
            set(value.get('authorities', {})) != AUTHORITY_KEYS or
            any(not isinstance(x, str) or SHA.fullmatch(x) is None for x in value['authorities'].values())):
        raise ValueError('Original legal text authorities differ from the exact engine producer')
    total = 0
    for name in TEXTS:
        row = value['files'][name]
        if (set(row) != {'sha256', 'bytes'} or type(row.get('bytes')) is not int or
                not 0 < row['bytes'] <= 32 * 1024**2 or
                not isinstance(row.get('sha256'), str) or SHA.fullmatch(row['sha256']) is None or
                file_hash(root / name, 32 * 1024**2) != row['sha256'] or
                (root / name).stat().st_size != row['bytes']):
            raise ValueError('Original dependency/runtime text bytes changed')
        total += row['bytes']
    if total > 64 * 1024**2:
        raise ValueError('Original legal text delivery exceeds total budget')
    return value
