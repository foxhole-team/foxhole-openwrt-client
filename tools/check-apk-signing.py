#!/usr/bin/env python3
"""Exercise APK signatures with disposable keys and real candidate packages."""
import argparse
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('sign_apks', Path(__file__).with_name('sign-apks.py'))
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', required=True)
    parser.add_argument('--input', type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='foxhole-apk-test-') as temporary:
        root = Path(temporary)
        key, public = root / 'test.key', root / 'test.pem'
        signing.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                     'ec_paramgen_curve:P-256', '-out', str(key)])
        key.chmod(0o600)
        public.write_bytes(signing.run(['openssl', 'pkey', '-in', str(key), '-pubout']))
        signing.sign(args.apk, args.input, root / 'signed', key, public)
        trust = root / 'keys'
        trust.mkdir()
        empty = root / 'empty'
        empty.mkdir()
        shutil.copyfile(public, trust / 'test.pem')
        for name in signing.PACKAGES:
            signed = root / 'signed' / name
            rejected = subprocess.run([args.apk, '--keys-dir', str(empty), 'verify', str(signed)],
                                      capture_output=True)
            assert rejected.returncode, 'Unknown signing key was accepted'
            tampered = root / name
            data = bytearray(signed.read_bytes())
            data[-16] ^= 1
            tampered.write_bytes(data)
            rejected = subprocess.run([args.apk, '--keys-dir', str(trust), 'verify', str(tampered)],
                                      capture_output=True)
            assert rejected.returncode, 'Tampered APK was accepted'
    print('APK signing, content preservation, unknown-key and tamper checks passed.')


if __name__ == '__main__':
    main()
