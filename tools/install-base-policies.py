"""Install version-bound compatibility records for the two BASE update readers."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import tempfile


PRIMARY = 'update-policy.json'
MODERN = 'update-policy-v2.json'
REVISIONS = {'flash': 1, 'managed-ram': 2}


def unique(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            raise ValueError('Duplicate policy field')
        values[key] = value
    return values


def install(source, output, version, revision, role):
    if not re.fullmatch(r'[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}', version) or revision != REVISIONS[role]:
        raise ValueError('Incorrect release version or revision for this reader')
    common = dict(transactionAbi=1, stateAbi=1, targets=['x86/64', 'mediatek/filogic'],
                  releaseTag='v' + version, packageVersion=version + '-r1')
    legacy = {**common, 'schema': 1, 'osRelease': '25.12.5'}
    modern = {**common, 'schema': 2, 'supportedOpenWrt': ['25.12.5', '25.12.6']}
    for name, expected in [(PRIMARY, legacy), (MODERN, modern)]:
        actual = json.loads((source / name).read_bytes(), object_pairs_hook=unique)
        if actual != expected or any(type(actual[k]) is not int for k in ('schema', 'transactionAbi', 'stateAbi')):
            raise ValueError('Source compatibility records differ from the qualified firmware contract')
    records = {PRIMARY: modern} if role == 'flash' else {PRIMARY: legacy, MODERN: modern}
    bodies = {name: (json.dumps({**record, 'packageVersion': f'{version}-r{revision}'},
                                indent=2) + '\n').encode() for name, record in records.items()}
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(directory, fcntl.LOCK_EX)
        for name in (PRIMARY, MODERN):
            path = output / name
            if path.is_symlink():
                raise ValueError('Policy output must not be a symlink')
            if path.exists():
                info = path.stat()
                if (name not in bodies or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        stat.S_IMODE(info.st_mode) != 0o644 or path.read_bytes() != bodies[name]):
                    raise ValueError('Use separate clean output roots for different BASE revisions')
        added = []
        with tempfile.TemporaryDirectory(dir=output.parent) as stage:
            try:
                for name, body in bodies.items():
                    if (output / name).exists():
                        continue
                    temp = Path(stage) / name
                    temp.write_bytes(body)
                    temp.chmod(0o644)
                    os.link(temp, output / name)
                    added.append(output / name)
            except BaseException:
                for path in added:
                    path.unlink()
                raise
    finally:
        os.close(directory)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=REVISIONS, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--revision', required=True, type=int)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    install(args.source, args.output, args.version, args.revision, args.role)
