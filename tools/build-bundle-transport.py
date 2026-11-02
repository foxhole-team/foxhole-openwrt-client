#!/usr/bin/env python3
"""Wrap a verified flat native bundle; do not sign, install or qualify artifacts."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile

NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}')
DEPENDENCY = re.compile(r'apk-[a-f0-9]{64}\.apk')
LINE = re.compile(r'([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]{0,159})')
TOOLS = ('install-compact.sh', 'bundle-transport-model.uc', 'bundle-transport.uc')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular(path, maximum=536870912):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or not 0 < info.st_size <= maximum:
        raise ValueError('Independent bounded protected public file required')
    return info


def build(root, expected, output):
    root, output = root.resolve(strict=True), output.absolute()
    if output.exists() or not re.fullmatch('[a-f0-9]{64}', expected):
        raise ValueError('Fresh output and trusted inner manifest SHA required')
    regular(root / 'SHA256SUMS', 1048576)
    if sha(root / 'SHA256SUMS') != expected:
        raise ValueError('Flat manifest digest mismatch')
    entries, folded = {}, set()
    for line in (root / 'SHA256SUMS').read_text('ascii').splitlines():
        match = LINE.fullmatch(line)
        if not match or match[2] in entries or match[2].lower() in folded or match[2] in ('SHA256SUMS', 'SHA256SUMS.asc', 'bundle-transport.json', 'native-install.tar'):
            raise ValueError('Unique safe flat source entries required')
        info = regular(root / match[2])
        if sha(root / match[2]) != match[1]:
            raise ValueError('Flat source file digest mismatch')
        entries[match[2]] = dict(sha256=match[1], bytes=info.st_size)
        folded.add(match[2].lower())
    if {p.name for p in root.iterdir()} != set(entries) | {'SHA256SUMS'}:
        raise ValueError('Exact normal unsigned flat bundle required; sign new outer manifest later')
    for name in TOOLS:
        if entries.get(name, {}).get('sha256') != sha(Path(__file__).parent / name):
            raise ValueError('Archive-aware installer/helper bytes must already pass normal bundle assembly')
    archived = {name: row for name, row in entries.items() if DEPENDENCY.fullmatch(name)}
    if not 1 <= len(archived) <= 1024 or any(row['bytes'] > 134217728 for row in archived.values()) or sum(row['bytes'] for row in archived.values()) > 2147483648:
        raise ValueError('Bounded upstream dependency bank required')
    tar_bytes = ((sum(512 + (row['bytes'] + 511) // 512 * 512 for row in archived.values()) + 1024 + 10239) // 10240) * 10240
    if tar_bytes > 536870912:
        raise ValueError('Transport archive exceeds maximum')
    if len(entries) - len(archived) + 3 >= 200:
        raise ValueError('Actual flat transport asset count must remain below200')
    if shutil.disk_usage(output.parent).free < 10 * 1024**3 + tar_bytes + sum(row['bytes'] for name, row in entries.items() if name not in archived):
        raise ValueError('Mac disk reserve10GiB required before packet copy')
    output.mkdir(mode=0o700)
    archive = output / 'native-install.tar'
    with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as stream:
        for name, row in sorted(archived.items()):
            header = tarfile.TarInfo('f-' + hashlib.sha256(name.encode('ascii')).hexdigest())
            header.size, header.mode, header.uid, header.gid, header.mtime = row['bytes'], 0o644, 0, 0, 0
            header.uname = header.gname = ''
            with (root / name).open('rb') as body:
                stream.addfile(header, body)
    if archive.stat().st_size != tar_bytes:
        raise ValueError('Canonical USTAR padded length mismatch')
    transport = dict(schema=1, archive=dict(file=archive.name, sha256=sha(archive), bytes=tar_bytes), entries=archived)
    descriptor = output / 'bundle-transport.json'
    descriptor.write_text(json.dumps(transport, sort_keys=True, separators=(',', ':')) + '\n')
    if descriptor.stat().st_size > 1048576:
        raise ValueError('Bounded transport descriptor required')
    for name in entries:
        if name not in archived:
            shutil.copyfile(root / name, output / name)
    sums = {name: row['sha256'] for name, row in entries.items()}
    sums.update({archive.name: transport['archive']['sha256'], descriptor.name: sha(descriptor)})
    (output / 'SHA256SUMS').write_text(''.join(f'{value}  {name}\n' for name, value in sorted(sums.items())))
    if any(sha(root / name) != row['sha256'] for name, row in entries.items()):
        raise ValueError('Original bundle changed during transport preparation')
    return dict(schema=1, kind='unsigned-plain-USTAR-transport-projection-not-native-qualification',
        originalFlatManifestSha256=expected, outerManifestSha256=sha(output / 'SHA256SUMS'),
        archive=transport['archive'], archivedMembers=len(archived), actualFlatAssets=len(list(output.iterdir())),
        originalInnerArtifactBytesUnchanged=True, signaturesOrNativeOrPhysicalAcceptance=None)


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(build(args.bundle, args.manifest_sha256, args.output), indent=2))


if __name__ == '__main__':
    main()
