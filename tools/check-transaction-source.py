#!/usr/bin/env python3
"""Admit only the exact source archive and its one upstream link."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile

SOURCE_SHA256 = 'e47373813001b0f5a36470b34b4f0390324182636233736b514e4c7e85fd4557'
SOURCE_BYTES = 388369
ARCHIVE_ROOT = 'apk-3.0.5-foxhole-transaction-v1'
SOURCE_PATH = 'native/transaction/apk-3.0.5-foxhole-transaction-v1-source.tar.gz'
LINK = 'src/apk-static.c'


def need(value, message):
    if not value:
        raise ValueError(message)


def read_source(path):
    path = Path(path)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'Linked source archive refused')
    before, parent = path.lstat(), path.parent.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    facts = lambda row: tuple(getattr(row, key) for key in fields)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not (before.st_mode | parent.st_mode) & 0o022 and
         before.st_size == SOURCE_BYTES, 'Exact regular source archive required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        need(facts(os.fstat(fd)) == facts(before), 'Source archive changed before read')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(SOURCE_BYTES + 1)
        need(facts(os.fstat(fd)) == facts(before), 'Source archive changed while reading')
    finally:
        os.close(fd)
    need(len(raw) == SOURCE_BYTES and facts(path.lstat()) == facts(before) and facts(path.parent.lstat()) == facts(parent),
         'Source archive changed after read')
    return raw


def inspect_members(raw):
    files, links, seen, modes = {}, {}, set(), {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        members = archive.getmembers()
        need(1 <= len(members) <= 1024 and sum(m.size for m in members) <= 8 * 1024**2, 'Bounded source members required')
        for member in members:
            path = PurePosixPath(member.name)
            need(not path.is_absolute() and '..' not in path.parts and path.parts and path.parts[0] == ARCHIVE_ROOT and
                 path.as_posix() == member.name.rstrip('/') and member.name.rstrip('/') not in seen,
                 'Unsafe or duplicate source member')
            seen.add(member.name.rstrip('/'))
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            if member.issym():
                need(relative == LINK and member.linkname == 'apk.c' and member.mode == 0o777 and not links, 'Only the exact upstream link is admitted')
                links[relative] = member.linkname
                continue
            need(not member.mode & 0o022 and not member.mode & 0o7000, 'Unexpected source mode')
            if member.isdir():
                continue
            need(member.isfile() and 0 <= member.size <= 1048576, 'Only regular bounded source members are admitted')
            need(relative not in ('.', '') and not any(part in ('.git', 'AGENTS.md', '__pycache__') for part in path.parts),
                 'Local state is not source')
            data = archive.extractfile(member).read()
            need(len(data) == member.size and not data.startswith((b'\x7fELF', b'PK\x03\x04', b'dex\n', b'\0asm')),
                 'Executable output is not source')
            files[relative] = data
            modes[relative] = 0o755 if member.mode & 0o111 else 0o644
    need(len(files) == 416 and links == {LINK: 'apk.c'} and 'src/apk.c' in files,
         'Exact 416 source files and one upstream link required')
    applet = files.get('src/app_foxhole_transaction.c', b'')
    need(set(re.findall(rb'\.name\s*=\s*"([^"]+)"', applet)) == {b'foxhole-apply', b'foxhole-recover'},
         'Only the two production transaction applets are admitted')
    return files, links, modes


def verify_source(raw):
    need(len(raw) == SOURCE_BYTES and hashlib.sha256(raw).hexdigest() == SOURCE_SHA256, 'Exact clean fork source identity required')
    files, links, modes = inspect_members(raw)
    identity = ''.join(name + '\0' + hashlib.sha256(data).hexdigest() + '\n' for name, data in sorted(files.items()))
    return {'schema': 1, 'sourceArchiveSha256': SOURCE_SHA256, 'regularFiles': len(files), 'upstreamLinks': links,
            'sourceFileMapSha256': hashlib.sha256(identity.encode()).hexdigest(), 'targetRuntimeQualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--archive', type=Path)
    group.add_argument('--stdin', action='store_true')
    args = parser.parse_args()
    raw = sys.stdin.buffer.read(SOURCE_BYTES + 1) if args.stdin else read_source(args.archive)
    print(json.dumps(verify_source(raw), sort_keys=True))


if __name__ == '__main__':
    main()
