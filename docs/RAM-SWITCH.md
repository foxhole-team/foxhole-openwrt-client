# RAM BASE generation switch

This helper is source WIP. Native Ucode compilation, OverlayFS/native APK transactions,
service quiescence and physical rollback are not qualified by its pure tests. It does
not implement boot reconstruction or establish reboot persistence.

The sole entry is `/usr/libexec/foxhole-ram-switch update-job-<32 lowercase hex>`.
The authenticated RAM update worker must already hold its engine lock and have saved
an INSTALLING/atomic job with `candidate`, `previous`, `plan.binding`, and its live
worker identity. The switch never reacquires that lock or writes the API job. It
writes only its own private journal, new native RAM generation, public mount targets
and active marker. Host APK DB/world, configuration, PIN, pairings and TLS identities
are not installation targets.

Integration must install these new files with the usual public package modes:

- `usr/libexec/foxhole-ram-switch` (0755)
- `usr/share/foxhole/ram-switch-{model,service}.uc` (0644)
- `usr/libexec/foxhole-ram-switch-command` (0755)

No existing package/API/Makefile integration is included here. Future signed BASE
packages must also contain the qualified RAM-aware canonical mobile init and keep
list. The helper uses those signed new files; it retains the previous external mobile
and keep adapters only as rollback sources. The previously admitted OpenSSL/socket
dependency mounts retain their exact source and hash.

## Native transaction

The candidate is independently checked against its selected receipt, archive SHA,
pinned public key, native signature, native `adbdump`, policy ABI and every BASE
payload hash/mode. A private read-only bind of the previous native RAM root becomes
the OverlayFS lower. Its DB files and world are copied into a private upper before
native APK runs. The existing BASE-only extraction is retained as a private diagnostic
copy, not used as an installed native DB.

The APK 3.0.5 source bundled in
`native/transaction/apk-3.0.5-foxhole-transaction-v1-source.tar.gz`
(SHA256 `e47373813001b0f5a36470b34b4f0390324182636233736b514e4c7e85fd4557`)
provides the cache admission:
`src/app_add.c:non_repository_check()` accepts `apk_db_cache_active()`;
`src/database.c:setup_cache()` opens a pre-existing root-relative cache and sets
`cache_packages`. `doc/apk-add.8.scd` documents local files and package-identity world
pins. Therefore add uses the pre-created private `.foxhole-apk-cache`, no network,
empty external repository selection, supplied public key, disabled scripts/hooks,
and simulate followed by the same install. It uses no force or untrusted option.
`--root-tmpfs=true` is admitted only after proving every lower/upper/work backing
filesystem is RAM from mountinfo. Unsupported/deep OverlayFS graphs fail before
service stop; flattening is not implemented.

The before/after native installed query must retain every non-BASE package row
exactly, with only BASE version changing. World must retain every non-BASE pin.
The old DB hash stays fixed. All signed BASE payload hashes/modes are checked again.
Admission uses actual MemAvailable with 16 MiB reserve and staging/DB/cache/capture
allowances; it is not a measured process-RSS or minimum-router-memory qualification.

## Existing mount ownership

An older active marker without a ledger is refused before service stop. It must be
migrated by a separately reviewed owner operation from actual mounts; paths must
never be guessed. The optional active marker field is:

`mountLedger=/etc/foxhole/ram-update/generations/generation-<32 lowercase hex>.json`

The root-owned bounded ledger has exactly:

```
schema: 1
abi: 1
kind: foxhole-ram-mount-ledger-v1
stage: <exact active marker stage>
baseSha256: <exact active marker archive SHA256>
mounts: [{target, source, type, dev: {major, minor}, inode, sha256, role}]
```

Each BASE source is exactly `<stage>/root<target>`. A retained adapter is admitted
only for the fixed OpenSSL, socket, mobile-init or keep-list target. File SHA256 is
mandatory; directories have null SHA256. Source and target must be protected,
root-owned and match their actual device/inode. Each target must have exactly one
read-only mount, with no nested ledger targets. Foreign mounts and stacks fail.
No `/etc/foxhole`, UCI, dynamic module directory or host APK DB target is allowed.

## Switch and failure

The journal lives at `/etc/foxhole/ram-update/switches/<jobId>.json` under the exact
`foxhole-ram-update-runtime-v1` owner namespace. Candidate preparation, actual RAM
admission, OverlayFS support and all native checks finish before consumers stop.
FoxHole services stop, actual owned consumers must exit within 15 seconds, then
rpcd stops and must exit within 20 seconds. Global uhttpd is never stopped.

Only successful unmounts and binds enter the rollback ledger. New public binds
replace old mounts without stacking; only allowed missing public targets are created.
The marker is replaced atomically after signed payload and native DB verification.
Job/worker/boot, principal revocation, state/module/world binding and Stop are rechecked.
Restart always reads current desired VPN state. A later Stop is accepted only with
its corresponding authoritative stopped state and never restored from a snapshot.

On a synchronous failure, restarted new consumers quiesce first, actual new mounts
are removed, only successfully removed old mounts return, and the exact old marker
is restored. Failure is returned even after rollback; the caller owns honest API
recovery status. A rollback failure records RECOVERY_REQUIRED. A previously existing
switch journal is never silently replayed. Abrupt kill/power failure, interrupted
syscall-to-journal windows and failed preparation artifacts require owner recovery;
there is no boot recovery/replay claim. Both RAM generations remain for review.

The existing outer worker deadline is also an integration limit: target qualification
must establish that native preparation, 15/20-second exit waits and rollback fit it.
Do not increase deadlines or claim cancellation recovery without that evidence.

Pure checks: `node --test tests/ram-switch.test.mjs`; shell syntax:
`sh -n package/foxhole-openwrt-client/root/usr/libexec/foxhole-ram-switch-command`.
