#!/usr/bin/env python3
"""Rebuild the normal transaction helper with the recorded SDK inputs."""
from pathlib import Path, PurePosixPath
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import zlib

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
OFFER_SHA = 'df92280ae325021242d49fde13b6367f3f5460ce81364d5f62d4579c3b1023ba'
MBED_SHA = '8fb65fae8dcae5840f793c0a334860a411f884cc537ea290ce1c52bb64ca007a'
SDK_VERSION_SHA = 'ccc4753e805f2831f74605f983a7625cb1ca8e8195ebae79e39ed48158ef49d0'
TARGETS = {
 'x86_64': {'toolchain':'x86_64', 'triple':'x86_64-openwrt-linux-musl', 'cpu':'x86_64',
            'devBytes':77760,'devSha256':'45c00e3be9a7d2b03b73a3bd54888b0b29412250ca8a122c4dc1a3c34ba0e6fe'},
 'aarch64_cortex-a53': {'toolchain':'aarch64_cortex-a53','triple':'aarch64-openwrt-linux-musl','cpu':'aarch64',
            'devBytes':71303,'devSha256':'8919af1ff9aae890a48d5d2a28502d5144d9adc6bdc598632d86f08704aa0f59'}
}


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def module(name):
    path = ROOT / 'tools' / name
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def exact_input(path, size, pin):
    path = Path(path)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'Linked build input refused')
    before, parent = path.lstat(), path.parent.lstat()
    fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    facts = lambda value: tuple(getattr(value, key) for key in fields)
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == size and
         not (before.st_mode | parent.st_mode) & 0o022, 'Exact protected build input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        need(facts(os.fstat(fd)) == facts(before), 'Build input changed before open')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(size + 1)
        need(facts(os.fstat(fd)) == facts(before), 'Build input changed during read')
    finally:
        os.close(fd)
    need(len(raw) == size and digest(raw) == pin and facts(path.lstat()) == facts(before) and
         facts(path.parent.lstat()) == facts(parent), 'Build input identity changed')
    return raw


def extract_regular(raw, mode, destination, expected_root=None):
    destination.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(raw), mode=mode) as source:
        members = source.getmembers()
        need(len(members) <= 10000 and sum(m.size for m in members) <= 128*1024**2, 'Bounded dependency source required')
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            need(path.parts and not path.is_absolute() and '..' not in path.parts and member.name not in seen and
                 (expected_root is None or path.parts[0] == expected_root), 'Unsafe dependency source member')
            seen.add(member.name)
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            need(member.isfile() and member.size <= 8*1024**2, 'Only regular dependency source files admitted')
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with source.extractfile(member) as src, target.open('xb') as dst:
                shutil.copyfileobj(src, dst, 1048576)
            need(target.stat().st_size == member.size, 'Dependency source size differs')
            target.chmod(0o700 if member.mode & 0o111 else 0o600)


def deterministic_gzip(raw):
    packed = bytearray(gzip.compress(raw, compresslevel=9, mtime=0))
    need(packed[:4] == b'\x1f\x8b\x08\0' and packed[4:8] == b'\0'*4, 'Deterministic gzip header required')
    packed[9] = 3
    return bytes(packed)


def stop_owned_group(process):
    # The private group can retain children after its leader exits.
    group = process.pid
    need(group > 0 and group != os.getpgrp(), 'Private build process group required')

    def send(value):
        try:
            os.killpg(group, value)
            return True
        except ProcessLookupError:
            return False

    if send(signal.SIGTERM):
        deadline = time.monotonic() + 5
        while send(0) and time.monotonic() < deadline:
            process.poll()
            time.sleep(.05)
        if send(0):
            send(signal.SIGKILL)
    process.wait(timeout=5)
    deadline = time.monotonic() + 5
    while send(0) and time.monotonic() < deadline:
        time.sleep(.05)
    need(not send(0), 'Owned build process group did not stop')


def run_step(work, env, label, argv, timeout=600):
    log = work/(label+'.log')
    with log.open('xb') as output:
        process = subprocess.Popen([str(v) for v in argv], env=env, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        started = time.monotonic()
        try:
            while process.poll() is None:
                need(time.monotonic()-started<=timeout and log.stat().st_size<=8*1024**2, 'Bounded build limit')
                time.sleep(0.2)
        finally:
            stop_owned_group(process)
    need(process.returncode == 0, 'Build step failed: '+label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--architecture', choices=sorted(TARGETS), required=True)
    parser.add_argument('--source-inputs', type=Path, required=True)
    parser.add_argument('--zlib-dev', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--expected-manifest', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    sdk, work = args.sdk.resolve(), args.work.absolute()
    need(sdk.is_dir() and not work.exists() and not work.resolve().is_relative_to(ROOT), 'Fresh build work outside source tree required')
    source = module('check-transaction-source.py')
    inputs = module('check-transaction-inputs.py')
    fork = source.read_source(ROOT / source.SOURCE_PATH)
    source.verify_source(fork)
    row = TARGETS[args.architecture]
    developer = exact_input(args.zlib_dev, row['devBytes'], row['devSha256'])
    bundle = exact_input(args.source_inputs, 7630415, OFFER_SHA)
    with tarfile.open(fileobj=io.BytesIO(bundle), mode='r:gz') as archive:
        member = archive.getmember('foxhole-apk-transaction-v1-source-inputs/sources/mbedtls-3.6.6.tar.bz2')
        need(member.isfile() and member.size == 5508045, 'Complete recorded Mbed TLS source required')
        mbed = archive.extractfile(member).read()
    need(digest(mbed) == MBED_SHA, 'Mbed TLS source identity differs')
    version = sdk / 'include/version.mk'
    exact_input(version, 4461, SDK_VERSION_SHA)
    tools = sdk / ('staging_dir/toolchain-' + row['toolchain'] + '_gcc-14.3.0_musl/bin')
    host = sdk / 'staging_dir/host/bin'
    compiler, ar, strip = [tools / (row['triple'] + '-' + name) for name in ('gcc','ar','strip')]
    for path in (compiler, ar, strip, host/'meson.py', host/'ninja'):
        need(path.is_file() and path.resolve().is_relative_to(sdk), 'Self-contained SDK tool required')
    work.mkdir(mode=0o700)
    extract_regular(mbed, 'r:bz2', work/'mbed-src', 'mbedtls-3.6.6')
    extract_regular(developer, 'r:gz', work/'zlib')
    files, links, modes = source.inspect_members(fork)
    fork_root = work/'apk-src'/source.ARCHIVE_ROOT
    for name, raw in files.items():
        path = fork_root/name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o700 if modes[name] & 0o111 else 0o600)
    for name, target in links.items():
        (fork_root/name).symlink_to(target)
    env = {'PATH':f'{host}:{tools}:/usr/bin:/bin','TMPDIR':str(work),'LANG':'C.UTF-8',
           'STAGING_DIR':str(sdk/('staging_dir/target-'+row['toolchain']+'_musl')),
           'PKG_CONFIG_LIBDIR':str(work/'deps/lib/pkgconfig')+':'+str(work/'pkgconfig'),
           'SOURCE_DATE_EPOCH':'1793145600'}
    if 'HOME' in os.environ:
        env['HOME'] = os.environ['HOME']
    def run(label, argv, timeout=600):
        return run_step(work, env, label, argv, timeout)
    run('mbed-configure',['cmake','-S',work/'mbed-src/mbedtls-3.6.6','-B',work/'mbed-build',
        '-DCMAKE_SYSTEM_NAME=Linux','-DCMAKE_C_COMPILER='+str(compiler),'-DCMAKE_AR='+str(ar),
        '-DCMAKE_BUILD_TYPE=Release','-DENABLE_TESTING=OFF','-DENABLE_PROGRAMS=OFF',
        '-DUSE_SHARED_MBEDTLS_LIBRARY=OFF','-DUSE_STATIC_MBEDTLS_LIBRARY=ON',
        '-DCMAKE_POSITION_INDEPENDENT_CODE=ON','-DCMAKE_INSTALL_PREFIX='+str(work/'deps')])
    run('mbed-build',['cmake','--build',work/'mbed-build','-j2'])
    run('mbed-install',['cmake','--install',work/'mbed-build'])
    (work/'pkgconfig').mkdir(mode=0o700)
    (work/'pkgconfig/zlib.pc').write_text('prefix='+str(work/'zlib/usr')+'\nlibdir=${prefix}/lib\nincludedir=${prefix}/include\nName: zlib\nDescription: verified OpenWrt zlib\nVersion: 1.3.1\nLibs: -L${libdir} -lz\nCflags: -I${includedir}\n')
    cross = work/'cross.ini'
    cross.write_text("[binaries]\n"+f"c = '{compiler}'\nar = '{ar}'\nstrip = '{strip}'\n"+
        "pkg-config = '/usr/bin/pkg-config'\n[host_machine]\nsystem = 'linux'\n"+
        f"cpu_family = '{row['cpu']}'\ncpu = '{row['cpu']}'\nendian = 'little'\n"+
        '[properties]\nneeds_exe_wrapper = true\n')
    run('apk-configure',[host/'meson.py','setup',work/'apk-build',fork_root,'--cross-file',cross,
        '--buildtype=release','-Ddocs=disabled','-Dhelp=disabled','-Dlua=disabled','-Dpython=disabled',
        '-Dtests=disabled','-Dminimal=false','-Durl_backend=wget','-Dcrypto_backend=mbedtls',
        '-Dzstd=disabled','-Ddefault_library=static'])
    run('apk-build',[host/'ninja','-C',work/'apk-build','-j2'])
    output = work/'foxhole-transaction-normal'
    shutil.copyfile(work/'apk-build/src/apk', output)
    run('strip',[strip,'--strip-unneeded',output])
    elf = output.read_bytes()
    inputs.elf_closure(elf,args.architecture)
    packed = deterministic_gzip(elf)
    (work/'foxhole-transaction-normal.gz').write_bytes(packed)
    identity = {'elfSha256':digest(elf),'elfBytes':len(elf),'gzipSha256':digest(packed),'gzipBytes':len(packed)}
    if args.expected_manifest is not None:
        expected = inputs.validate_manifest(inputs.document(inputs.typed_read(args.expected_manifest,'manifest')))
        need(identity == expected['targets'][args.architecture], 'Rebuild differs from recorded target identity')
    (work/'artifact.json').write_text(json.dumps({'schema':1,'architecture':args.architecture,
        'sourceArchiveSha256':source.SOURCE_SHA256,**identity,'targetRuntimeQualified':False,
        'compressionZlibVersion':zlib.ZLIB_RUNTIME_VERSION},indent=2)+'\n')
    print(json.dumps(identity,sort_keys=True))


if __name__ == '__main__':
    main()
