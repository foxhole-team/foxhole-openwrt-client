# RAM BASE update controller

`ram-update-service.uc` handles direct GitHub downloads, device upload, manual
and daily automatic checks through one candidate verifier and one APPLY worker.
It changes only BASE. Installed client engines and upstream Hysteria remain in
place. Current version comes from the protected active marker and its actual
isolated native APK database. The host database is never rewritten or projected
as containing BASE.

Direct checks query the fixed official `releases?per_page=10` endpoint, including
non-draft prereleases, and choose the highest complete numeric BASE version.
URLs are constructed from fixed repository/tag/filename rules; metadata URLs
provided by release assets are ignored. SHA256SUMS binds the downloaded archive,
which is then independently verified with native APK and the pinned public key.
Name, noarch, version, package layout, existing dependency-bank compatibility,
policy ABI/version/tag and every extracted file hash/mode precede AVAILABLE.
Downloaded package scripts are not executed.

The nonquiet four-second probe follows the official uclient-fetch exit model:
only exit4 with an exact connection-failed/timed-out diagnostic permits device
relay. Any SSL/certificate evidence, HTTP errors, malformed data, signature
failure or unknown capture result forbids that fallback. TLS validation is
always enabled and proxy environment variables are disabled. The implementation
uses the error mapping in the [official uclient-fetch source](https://github.com/openwrt/uclient/blob/master/uclient-fetch.c).

## Device transport

All methods require a current authenticated principal. They accept no URL,
script or signing-key parameter.

- `device_begin`: expectedRevision, requestId32hex, releaseTag, full version,
  fileSha256 and fileBytes1..8388608. It returns schema1, uploadId, nextOffset and
  maxChunkBytes65536. Same request/manifest is idempotent.
- `device_chunk`: uploadId, monotonic offset, canonical dataBase64 and
  chunkSha256. Only an exact last chunk may be repeated. A pending-chunk record
  recovers an append whose response/metadata acknowledgement was lost.
- `device_status`: uploadId returns nextOffset and complete. Read status before
  retrying a lost chunk response.
- `device_finish`: uploadId independently verifies the complete candidate before
  publishing normal update status AVAILABLE. A verified finish checkpoint can
  recover an archive rename/publication interruption without overwriting files.

One upload is active at a time in private RAM storage, with a ten-minute
monotonic/boot-bound TTL. Root-owned regular-file checks precede access. Expired
buffers are removed only by their exact owned role; no generic filesystem paths
or user profile data are imported. Stop or principal revocation invalidates an
unfinished upload. Native parsing, extraction and hashing retain a16MiB RAM
reserve in addition to their bounded byte budget; this is not a formal minimum
router-RAM qualification.

## Fixed selector contract, ABI1

The controller launches exactly:

```
/usr/libexec/foxhole-ram-switch update-job-<32 lowercase hex>
```

The helper reads `/etc/foxhole/update-job.json`, a root0600/nlink1 regular file
bounded to524288 bytes. Required admission fields are schema1,
deployment`RAM_BASE`, matching jobId, operation`APPLY`, state`INSTALLING`,
mutationStarted`true` and atomicPackagePhase`true`. The controller is the sole
writer of this shared job record.

`job.candidate` contains id`candidate-<32hex>`, full version, releaseTag, sha256,
bytes, installedBytes, archive, root and receiptSha256. Derive candidate directory
`/tmp/foxhole/ram-updates/candidates/<id>`; archive must be its `base.apk` and root
must be its `root`. `receipt.json` in that directory is bounded to524288 bytes,
matches receiptSha256, and contains schema1, id, version, releaseTag, sha256,
bytes, installedBytes, archive, root, policy and the native adbdump payload.

`job.previous` contains stage, root, version, sha256, markerSha256 and
stageDbSha256. Its root is stage`/root`; both hashes derive from actual protected
files. The helper may read the previous marker's stable dependency-bank pointer
only after its hash matches. `job.plan.binding` contains routerId, bootId,
worldSha256, registrySha256, activeProfileId, activeConfigSha256, stateRevision,
stateWithoutStop and stopIntent. Principal, automatic, policyRevision and the
pre-switch stopIntent remain on the job.

The helper may own only `/etc/foxhole/ram-update/` for persistent switch/boot
metadata. `owner.json` is exactly
`{schema:1,abi:1,kind:"foxhole-ram-update-runtime-v1"}`. Optional phase callback
`switch.json` is a root0600/nlink1 record <=16384 bytes with schema1, abi1, jobId,
phase, version, stage and baseSha256. Phases are PREPARING, VERIFIED, SWITCHING,
COMMITTED, ROLLED_BACK or RECOVERY_REQUIRED. The helper never edits the shared
job. A previousConnectionRestored boolean is valid only with actual routing
proof; package version verification alone does not prove reconnection.

The selector constructs a private OverlayFS view over its immutable dependency
bank and legitimately installs BASE into that view's native APK database using
an owned private RAM package cache. Scripts/hooks remain disabled. No force,
filesystem-type misclassification, host-root overlay or host database rewrite
is allowed. New missing dependencies are refused. Verify all BASE payload bytes,
ACLs, native package version and unchanged dependency identities before stopping
consumers or switching known public mounts. Preserve private configuration,
pairing, PIN, identity and module state; honor the latest Stop before reconnect.

Commit `/tmp/foxhole-ram-active.json` atomically as a protected root-owned record
with schema1, storage`RAM`, phase`active`, full version, actual baseSha256, stage
equal to the candidate directory and actual stageDbSha256. An optional
dependencyRoot identifies the immutable lower bank. Exit0 means this committed
marker and native stage version have been verified. The controller independently
rechecks version, archive identity, payload and protected data. Any failed or
unknown switch is RECOVERY_REQUIRED with no automatic APPLY replay. The helper
owns bounded child cleanup, rollback of public mounts/release pointer and boot
reconstruction; those are separate native qualification responsibilities.

## Lifecycle and compatibility

Automatic policy remains off when absent. Existing opt-in and scheduler history
are retained. An enabled policy records at most one daily attempt before network
access, then uses the same check/plan/apply path. Disabling before the atomic
phase prevents queued automatic installation. Backup journals and native engine
jobs are mutually excluded. Stop during download prevents APPLY; Stop after the
atomic phase remains authoritative and prevents old connection intent replay.

The public reason table is unchanged: pre-mutation Stop reports FAILED with
STALE_PLAN and cancelledByStop`true`, rather than an unknown CANCELLED enum.
The fixed helper/source-adapted model tests do not substitute for native parser,
crypto, filesystem, actual selector, boot or authenticated tunnel acceptance.
