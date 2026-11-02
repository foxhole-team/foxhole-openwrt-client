# Signed native RAM bootstrap

This is source WIP. Pure checks do not qualify native Ucode/APK, bank extraction,
HTTPS, physical mounts, service startup, VPN traffic or reboot recovery. Root must
assemble and sign the actual bank, fill the actual descriptor, install and qualify
it. The NULL descriptor template intentionally cannot be installed.

## Inputs and roles

The bank is a native signed APK named `foxhole-ram-bootstrap-bank`, with the actual
host architecture (`aarch64_cortex-a53` or `x86_64`). Its payload is restricted to
`usr/share/foxhole-ram-bootstrap-bank/{bank.json,root/**,adapters/**}` and necessary
ancestor directories. It has no scripts, triggers or package dependencies. It is
never installed in the host APK database. The bank's `root` must come from the
genuine native 75-package installation and BASE upgrade, with its native DB/world;
an extracted BASE tree or a source overlay cannot substitute for that generation.

`bank.json` has exactly these fields:

```
schema, kind, osRelease, target, arch, version, baseVersion,
baseSha256, stageDbSha256, hostNativePackageCount, mounts, files
```

`schema=1`, `kind=foxhole-ram-bootstrap-bank-v1`, `osRelease=25.12.5`.
The architecture/target pair is `aarch64_cortex-a53`/`mediatek/filogic` or
`x86_64`/`x86/64`. `version` is the BANK APK version; `baseVersion` is the distinct
native BASE package version. `baseSha256` identifies the original signed BASE APK.
The historical `hostNativePackageCount` field means exactly 75 packages in the
BANK DB, not in the host-global DB. `stageDbSha256` is the actual bank installed DB
SHA256. Root must obtain these values from actual artifacts and native output.

Every `files` entry has exactly:

```
{path, type, mode, bytes, sha256, linkTarget}
```

This list includes exactly all `root` and `adapters` paths, including their root
directories; it excludes `bank.json` to avoid self-reference. Types are `file`,
`directory`, `symlink`. Directory bytes are zero, hash/target null. Files have their
actual bytes/SHA256 and null target. Symlinks have mode 0777, target byte length,
null hash and their exact relative target. Links must stay inside their own root
or adapters namespace and point to a listed path. Hardlinks, devices, sockets and
FIFOs are refused. Native UID/GID must be root and regular files nlink1. Native
file/directory ACLs are preserved exactly, including legitimate 0700 directories;
there is no recursive chmod. Other-writable files/directories and special mode bits
are refused. Public mount directories must be 0755 and mounted files 0644/0755.
Root's export must exclude all owner data/private keys; `root/etc/foxhole/**` and
known private-data/key names are additionally rejected by the model.

Every `mounts` entry is exactly `{target,sourceRelative,role}`. Role `base` means
`root<target>` at one of the fixed public BASE paths. Role `dependency` admits only
`root/usr/lib/ucode/socket.so`; role `adapter` admits only
`adapters/openssl` → `/usr/bin/openssl`. Both are required, along with the BASE
module tree, RPC file and runtime/mobile init. Mutable configuration, host libraries,
host APK DB/world and this persistent bootstrap's init file are not mount targets.
Root must derive the complete public BASE mount list from the actual signed BASE.
The OpenSSL adapter and canonical RAM-aware mobile init must resolve the validated
active marker; their actual bytes are covered by the signed bank.

## Persistent descriptor and installation

`/etc/foxhole/ram-update/owner.json` retains the exact existing owner contract:
`{schema:1,abi:1,kind:"foxhole-ram-update-runtime-v1"}`. Private directories are 0700,
descriptor/trust/tools are 0600. `/etc/foxhole/ram-update/boot.json` has exactly:

```
schema: 1
kind: foxhole-ram-bootstrap-v1
artifact: {url, bytes, sha256}
version, baseVersion, arch, target, osRelease, baseSha256,
signerPemSha256, caFileSha256, recoveryOrigin, overlay (optional)
```

Bank/baseline identities must match the bank. The initial URL is HTTPS, without userinfo,
query, fragment or control characters. Artifact bytes are 1..33554432. Trust paths
are fixed below `/etc/foxhole/ram-update/bootstrap`: `keys/signer.pem`, optional
`ca.pem`, the five loader tools and `tools.json`. `caFileSha256=null` selects system
CA trust; a non-null hash requires the exact supplied public CA file. No private
keys, credentials, provider data, fixed deployment URL or future hash is shipped.

From a protected, root-owned directory, Root runs:

```
/bin/sh /absolute/tools/install-ram-bootstrap.sh \
  --descriptor /protected/actual-boot.json \
  --signer-pem /protected/actual-public-signer.pem \
  --ca /protected/actual-public-ca.pem
```

`boot.json` is bounded to 8192 bytes. `recoveryOrigin` is a required direct-HTTPS
feed prefix ending in `/`, with the same URL restrictions. It is configured by Root
from a real feed; it is never invented from a candidate URL. The optional `overlay`
may be absent/null or exactly:

```
{baseVersion, baseSha256, artifact: {url, bytes, sha256}}
```

Its BASE version must be strictly newer than the pinned bank BASE. Archive bytes
are at most 8 MiB, `artifact.sha256` equals `baseSha256`, and its URL is exactly
`recoveryOrigin + "foxhole-openwrt-client-" + baseVersion + ".apk"`. The same pinned
CA and signer apply. Bank artifact/version/baseVersion/baseSha256 stay immutable.
No flash APK or binary delta is stored; only bounded overlay metadata is committed.

Omit `--ca` only when system CA trust is intended. This first-install command refuses
existing bootstrap/descriptor/init/boot-link paths. It preserves the existing owner
namespace, validates source bytes and actual target platform, caps persistent tools
plus public trust/metadata at 128 KiB with a 512 KiB flash reserve, and creates only
its owned files and `S99foxhole-ram-bootstrap`. It does not download, activate, stop
VPN or start services. Partial installation is retained for owner inspection;
replacement/upgrade of bootstrap tools is not implemented.

## Cold boot

START=99 runs after existing FoxHole stubs and sysntpd. The loader requires no active
RAM marker, no prior fixed stage and no running FoxHole consumers. `/tmp` must be
actual tmpfs. It creates exactly `/tmp/foxhole-ram-stage-boot-v1` (0700); any partial
stage blocks a repeat invocation in that boot and is retained. It checks public trust
hashes, protected parents, platform and actual MemAvailable with a 16 MiB reserve.
The archive is downloaded only into RAM, with a streaming byte cap and 65-second
capture deadline. Native commands use fixed verify/dump/extract/query operations
with offline/no-cache flags for the bank. Optional overlay add is confined to its
private RAM root/cache, offline with scripts/hooks disabled. There is no host DB edit
or package-script execution.
The owned-PID/starttime, bounded-drainer capture utility is byte-identical to the
already qualified `engine-capture.uc`; only the new dispatch/admission needs target
qualification. Native payload writes inherit no FSIZE limit.

The loader verifies exact download length/SHA256, native APK signature and metadata
before extraction. APK3 extraction does not apply an empty-name root node to an
already existing destination: after signature/metadata validation, bootstrap explicitly
applies that signed mode to the payload destination. Before an overlay native add it
does the same for the private native root. Only that destination changes; parent STAGE
and all capture/IO directories remain 0700. If metadata has no empty-name node, the
existing private container mode is retained and is not claimed as a signed root ACL;
only listed nested payload paths are covered by the signed inventory check. Metadata is explicitly bounded to 4 MiB; installed payload to
128 MiB; `bank.json` to 1 MiB; inventory to 8192 entries. Native signed directory/file
ACLs, every regular-file hash and symlink target must equal the signed manifest and
actual extracted tree, including hidden entries. The APKv3 symlink target's native
hex encoding is decoded according to bundled `extract_v3.c` (S_IFLNK little endian);
hardlink/device encodings are refused. Hashing uses bounded batches of host
`/usr/bin/sha256sum`, avoiding a 32 MiB whole-file Ucode allocation.

The verified `root`/`adapters` move into the stage. A native query must report exactly
75 bank packages, with BASE at baseline `baseVersion`, and DB SHA must stay exact.

If an overlay is present, the loader then downloads its exact full signed BASE APK
from the direct recovery feed into RAM. It verifies byte count, SHA, canonical native
signature and the established BASE path/layout guard. In the genuine private native
RAM root, it requires `.foxhole-apk-cache` absent and creates a fresh owned cache,
then performs native simulate/add with no external repositories/network/scripts/hooks.
After both successful native captures have completed their owned cleanup, only this
fresh cache is removed. Its complete bounded tree is validated before any deletion;
symlinks, foreign devices/owners and hardlinks are refused except exact input-APK
inode aliases. Those links must account for the input nlink count exactly. Removing
only these cache links restores input nlink1 before its normal hash reread; reader
guards are unchanged. Failed native captures retain the stage/cache for review. The
cache is forbidden in bank inventories and does not enter the next generation.
The loader then verifies the native 75-package query. Every non-BASE package row and every non-BASE world pin must remain
exact. Pinned bank dependency/adapter files and symlinks are checked again; only BASE
files/directories, private native DB/world and its private cache may change. Every
new BASE payload hash/mode and its policy transaction/state ABI, release/version and
embedded signer must match before activation. Missing new dependencies fail closed.
The local-cache admission is supported by the bundled APK3.0.5 source described in
[RAM-SWITCH.md](RAM-SWITCH.md); no force/untrusted option is used. The actual RAM budget
includes the new package/cache and continuing processes; it is not an RSS measurement.

Fresh public mount targets are derived from the new signed BASE metadata, rather
than reusing the older bank-only BASE list. Only pinned OpenSSL/socket mounts remain
from the bank. Marker version/baseSHA and native DB SHA identify the actual overlay;
separate bankVersion/bankBaseVersion/bankBaseSha256 preserve baseline roles. With no
overlay, the original bank-only path is unchanged. A changed descriptor before
activation aborts; cold boot never writes it. The host
global DB/world hashes and file identities are fenced before and after activation.
Only absent, unstacked approved public mounts are bound read-only. A typed mount
ledger is written in the existing RAM-switch generations namespace, and an atomic
active marker records the real BASE version/SHA and native DB SHA. The marker's
stage path is compatible with the existing RAM update parser.

Then rpcd restarts and the four FoxHole units start using current authoritative
desired state. There is no activeServerId/PIN/pairing write, global uhttpd stop,
network/firewall reload or VPN policy restore from a stale snapshot. STARTED means
service startup was requested; the runtime alone reports actual tunneled traffic.
The bounded private `boot-last.json` never fabricates reboot qualification.

On a synchronous failure, new consumers quiesce before rollback, only successful
own binds are removed, only own missing targets are cleaned, and only the exact own
marker is removed. Partial download/stage/log/journal evidence remains private.
Abrupt kill/power-loss windows and rollback failure remain RECOVERY_REQUIRED; this
does not claim a journal replay engine or automatic repair of foreign mounts.

## HTTPS limitation and qualification

The stock-only path deliberately requires a direct HTTPS 200 endpoint and refuses
ANY uclient redirect evidence before artifact admission. Normal GitHub release 302
downloads are therefore not currently supported for cold boot. This is separate
from the existing RAM updater's download path. No extra curl dependency is installed.

The official [uclient-fetch source](https://github.com/openwrt/uclient/blob/master/uclient-fetch.c)
supports `--ca-certificate`, `--no-proxy` and native certificate validation, but logs
redirects using only `url->location` and host. The official
[URL parser](https://github.com/openwrt/uclient/blob/master/uclient.c) separates the
scheme from that location, so stderr cannot prove a redirect's scheme. Refusal is
post-download: it does not claim that a malicious trusted HTTPS server could not
cause initial HTTP contact. Requests carry no credentials/private headers, and no
redirected artifact is accepted. Stronger prevention/HTTPS redirect support requires
a separately qualified transport; there is no invented uclient flag or TLS fallback.

Qualification still required: native Ucode compilation and regex evaluation; actual
signed bank/CA; direct mirror HTTPS 200 and redirect/cert/hash refusal; memory/tmpfs
admission and bounded overflow/timeout; native extraction including symlinks;
host DB/world and private settings preservation; mount fault/rollback; current Stop;
actual reboot followed by API access and authenticated tunneled traffic. Persistent hot-update integration owns the atomic descriptor overlay commit and
rollback around the corresponding active-generation switch. It must bind the exact
prior descriptor/candidate, preserve bank/baseline/origin/trust fields, enforce the
8 KiB metadata/512 KiB flash-reserve policy, and restore the prior descriptor before
old-service restart on rollback. Bootstrap tools alone do not update that descriptor
or claim the hot path is qualified. After real cold-boot qualification, a committed
overlay reconstructs the same signed BASE target on the pinned native bank.

Pure checks: `node --test tests/ram-bootstrap.test.mjs`; `sh -n` for the new installer,
command helper and init template. These checks do not execute any target operation.
