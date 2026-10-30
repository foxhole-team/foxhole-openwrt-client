#!/usr/bin/env python3
"""Verify the two external normal transaction artifacts before packaging."""
from pathlib import Path
import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import struct

SOURCE_SHA256 = 'e47373813001b0f5a36470b34b4f0390324182636233736b514e4c7e85fd4557'
TARGETS = {'x86_64': (62, '/lib/ld-musl-x86_64.so.1'),
           'aarch64_cortex-a53': (183, '/lib/ld-musl-aarch64.so.1')}
FACTS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def document(raw):
    def unique(items):
        result = {}
        for key, value in items:
            need(key not in result, 'Duplicate transaction manifest key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def typed_read(path, role, size=None):
    maximum = 16384 if role == 'manifest' else 8388608 if role in TARGETS else None
    need(maximum is not None, 'Unknown input role')
    path = Path(path)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'Linked transaction input refused')
    before, parent = path.lstat(), path.parent.lstat()
    facts = lambda value: tuple(getattr(value, key) for key in FACTS)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and stat.S_ISDIR(parent.st_mode) and
         not (before.st_mode | parent.st_mode) & 0o022 and 0 < before.st_size <= maximum and
         (size is None or before.st_size == size), 'Protected regular typed input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        need(facts(os.fstat(fd)) == facts(before), 'Transaction input changed before read')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        need(facts(os.fstat(fd)) == facts(before), 'Transaction input changed during read')
    finally:
        os.close(fd)
    need(len(raw) == before.st_size and facts(path.lstat()) == facts(before) and facts(path.parent.lstat()) == facts(parent),
         'Transaction input changed after read')
    return raw


def validate_manifest(value):
    need(isinstance(value, dict) and set(value) == {'schema', 'abi', 'sourceArchiveSha256', 'targets'} and
         type(value['schema']) is int and value['schema'] == 1 and type(value['abi']) is int and value['abi'] == 1 and
         value['sourceArchiveSha256'] == SOURCE_SHA256 and isinstance(value['targets'], dict) and
         set(value['targets']) == set(TARGETS), 'Exact transaction ABI/source/two-target manifest required')
    for row in value['targets'].values():
        need(isinstance(row, dict) and set(row) == {'elfSha256', 'elfBytes', 'gzipSha256', 'gzipBytes'}, 'Exact target identity fields required')
        for name in ('elfSha256', 'gzipSha256'):
            need(isinstance(row[name], str) and re.fullmatch('[0-9a-f]{64}', row[name]), 'Full target SHA256 required')
        need(type(row['elfBytes']) is int and 64 <= row['elfBytes'] <= 16777216 and
             type(row['gzipBytes']) is int and 1 <= row['gzipBytes'] <= 8388608, 'Bounded normal target sizes required')
    return value


def elf_closure(raw, architecture):
    machine, expected_interpreter = TARGETS[architecture]
    need(len(raw) >= 64 and raw[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', raw, 18)[0] == machine and
         struct.unpack_from('<H', raw, 16)[0] in (2, 3), 'Normal little-endian ELF64 target required')
    offset = struct.unpack_from('<Q', raw, 32)[0]
    size, count = struct.unpack_from('<HH', raw, 54)
    need(size == 56 and 1 <= count <= 64 and offset + size * count <= len(raw), 'Bounded ELF program headers required')
    headers = [struct.unpack_from('<IIQQQQQQ', raw, offset + i * size) for i in range(count)]
    for header in headers:
        need(header[2] + header[5] <= len(raw), 'ELF segment outside file')
    interpreter = [header for header in headers if header[0] == 3]
    dynamic = [header for header in headers if header[0] == 2]
    need(len(interpreter) == len(dynamic) == 1, 'One musl interpreter and dynamic table required')
    item = interpreter[0]
    text = raw[item[2]:item[2] + item[5]]
    need(text == expected_interpreter.encode() + b'\0', 'Exact musl interpreter required')
    item = dynamic[0]
    need(item[5] % 16 == 0 and item[5] <= 65536, 'Bounded ELF dynamic table required')
    entries = [struct.unpack_from('<QQ', raw, i) for i in range(item[2], item[2] + item[5], 16)]
    addresses = [value for tag, value in entries if tag == 5]
    sizes = [value for tag, value in entries if tag == 10]
    needed = [value for tag, value in entries if tag == 1]
    need(len(addresses) == len(sizes) == 1 and 1 <= sizes[0] <= 1048576 and len(needed) == 2, 'Exact runtime closure table required')
    location = [header[2] + addresses[0] - header[3] for header in headers if header[0] == 1 and
                header[3] <= addresses[0] and addresses[0] + sizes[0] <= header[3] + header[5]]
    need(len(location) == 1 and location[0] + sizes[0] <= len(raw), 'ELF string table outside loadable data')
    strings = raw[location[0]:location[0] + sizes[0]]
    libraries = []
    for value in needed:
        need(value < len(strings), 'ELF dependency name outside string table')
        end = strings.find(b'\0', value)
        need(end > value, 'Terminated ELF dependency name required')
        libraries.append(strings[value:end].decode('ascii'))
    need(len(set(libraries)) == 2 and set(libraries) == {'libgcc_s.so.1', 'libc.so'}, 'Only libgcc and musl runtime dependencies admitted')
    need(b'foxhole-apply\0' in raw and b'foxhole-recover\0' in raw, 'Production transaction applets missing')
    for marker in (b'FOXHOLE_QA_FAIL_WORLD', b'FOXHOLE_QA_FAIL_SYNC', b'FOXHOLE_QA_FAIL_DIRSYNC', b'FOXHOLE_QA_GATE',
                   b'foxhole-rollback\0', b'foxhole-apply-multi\0', b'foxhole-recover-multi\0'):
        need(marker not in raw, 'QA/research code is not a normal transaction artifact')
    return {'interpreter': expected_interpreter, 'needed': sorted(libraries)}


def verify_gzip(raw, row, architecture):
    need(len(raw) == row['gzipBytes'] and digest(raw) == row['gzipSha256'] and raw[:4] == b'\x1f\x8b\x08\x00' and raw[4:8] == b'\0' * 4,
         'Exact deterministic compressed target required')
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as stream:
        elf = stream.read(row['elfBytes'] + 1)
    need(len(elf) == row['elfBytes'] and digest(elf) == row['elfSha256'], 'Exact bounded uncompressed target required')
    return elf_closure(elf, architecture)


def verify(manifest_path, expected_sha256, inputs):
    need(isinstance(expected_sha256, str) and re.fullmatch('[0-9a-f]{64}', expected_sha256), 'Actual external manifest SHA256 required')
    raw = typed_read(manifest_path, 'manifest')
    need(digest(raw) == expected_sha256, 'External transaction manifest identity differs')
    value = validate_manifest(document(raw))
    packed, closure = {}, {}
    for architecture, row in value['targets'].items():
        packed[architecture] = typed_read(inputs[architecture], architecture, row['gzipBytes'])
        closure[architecture] = verify_gzip(packed[architecture], row, architecture)
    return raw, packed, closure


def install(directory, manifest, packed):
    directory = Path(directory)
    need(directory.is_dir() and not any(p.is_symlink() for p in (directory, *directory.parents)) and
         not directory.stat().st_mode & 0o022, 'Regular protected package destination required')
    files = {'transaction-tool.json': manifest, **{'transaction-' + key + '.gz': value for key, value in packed.items()}}
    need(all(not (directory / name).exists() and not (directory / name).is_symlink() for name in files), 'Refuse existing package input destinations')
    for name, data in files.items():
        with (directory / name).open('xb') as stream:
            stream.write(data)
        (directory / name).chmod(0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--x86-gzip', type=Path, required=True)
    parser.add_argument('--arm64-gzip', type=Path, required=True)
    parser.add_argument('--install-dir', type=Path)
    args = parser.parse_args()
    raw, packed, closure = verify(args.manifest, args.manifest_sha256,
                                  {'x86_64': args.x86_gzip, 'aarch64_cortex-a53': args.arm64_gzip})
    if args.install_dir is not None:
        install(args.install_dir, raw, packed)
    print(json.dumps({'schema': 1, 'manifestSha256': digest(raw), 'sourceArchiveSha256': SOURCE_SHA256,
                      'targetClosure': closure, 'runtimeOrRouterQualified': False}, sort_keys=True))


if __name__ == '__main__':
    main()
