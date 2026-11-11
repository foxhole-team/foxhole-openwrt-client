# Independent Core module updates

OpenWrt client 1.0.6 is the one-time BASE migration for the Core feed ABI 1.
Later compatible Core releases replace selected protocol modules through
the same authenticated update plan and job used by Android and the web panel.
They do not replace BASE, firmware, profiles, pairing records or update policy.
The existing `engines.*` RAM-overlay restriction remains in place.
The BASE update policy retains its exact legacy seven-field shape so the
existing RAM receiver can admit this migration. Feed ABI 1 is a compiled
consumer constant and is checked against signed feed and compatibility data;
it does not extend the old BASE policy document.

The official Core release contains `core-catalog.adb`, its metadata-only
`foxcore-update-catalog-<version>.apk`, and the actual qualified module assets.
Both index and metadata APK must verify with the existing pinned APK key.
The consumer also performs a NAME-only native fetch round trip before reading
the bounded metadata payload. The metadata APK is never installed and may
contain no scripts, extra dependencies, symlinks or extra payload files.
Only the packager's canonical `libc` dependency is admitted.

The signed metadata binds a stable channel, increasing sequence, publication
and expiry times, Core version, producer and publisher identities, source
content/signature/join receipts, minimum BASE version, consumer state and
transaction ABIs, router contract, OpenWrt release, targets and architectures.
Discovery requires a trustworthy clock and an unexpired compatible candidate.
An already installed signed catalog remains usable offline after discovery
expiry. Its separate highest-seen reference prevents rollback to an older
cohort even when an update rolls back the active modules.

Module indexes, APKs and raw RAM binaries use only the two fixed official
release origins: `foxhole-team/foxhole-core` and the existing
`foxhole-team/foxhole-openwrt-client`. Existing signed OpenWrt origins are
immutable. Core version is not a delivery tag or a package revision. Module
status and plan changes expose native package versions, including `-rN`;
the catalog separately retains the bound Core version and producer identity.
A newer wrapper with the same Core must retain the exact native binary.
An equal package version with different signed identity is rejected.

The module-only transaction adds immutable packages without removing the
previous slots. Its native solver must admit only the planned additions.
It checks unchanged BASE, unrelated package identities and world roots,
validates actual CLI capabilities and the active profile before stopping the
owned runtime, and uses the existing fresh traffic proof after a reconnect.
Capabilities must retain integer schema and router-contract versions. The
plan deadline is rechecked after staging and under the atomic state lock.
The previous generation and proof watermark are captured immediately before
the owned runtime stop. RAM process identity uses the admitted raw ELF while
retaining the separate immutable launcher and slot verification.
On failure, one bounded rollback restores the prior signed catalog, module
selection and owned connection. Owner settings are read fresh; a saved profile
or authentication snapshot is never written back during rollback.

Managed RAM operation requires the existing active generation marker, exact
native package database digest and read-only mount ledger. Unknown, writable,
nested or disk-backed stage mounts are rejected. Both old and new required
RAM binaries must be available before mutation. Admission retains the current
RAM and flash reserves; resource failures stay visible. This is a separate
managed transaction, not removal of the generic engine RAM fence.

When the router proves a connection failure, a paired app may relay a CORE
cohort through the existing `updates.device*` methods. `cohortKind=CORE`,
`assetId` and capability `coreCohortRelay=1` select the bounded extension;
an absent kind retains the existing BASE protocol. TLS, HTTP, key, signature
and certificate failures do not authorize this fallback. The router verifies
the signed metadata before requesting the exact module and rollback assets.
The phone accepts only typed official release URLs, checks sizes and hashes,
uses private temporary files and transfers one asset at a time. Per-asset
offsets, chunk digests and a ten-minute owner/boot/binding lifetime prevent
cross-asset replay. Lost acknowledgements use status reads or idempotent
staging calls. Transfer never applies a plan or replays an APPLY request.

Stop, changed profiles, revocation or changed router generation invalidate the
cohort. Final publication rechecks authorization and the complete owner-state
binding under the state lock after native verification. A Core-only check
does not make BASE current: status keeps `coreAvailability` and
`coreCohortSha256` separate, and the UI labels a pending BASE check explicitly.
A zero-change verified Core proof may advance a later BASE check for five
minutes while its complete binding remains unchanged. This lets an offline
managed RAM router reach the existing BASE relay instead of requesting the
same Core cohort repeatedly. CORE connection evidence cannot authorize a
BASE upload. Both paths retain their own confirmed connection-failure gate.

Fresh Android and web setup offers automatic updates enabled with an explicit
opt-out and a later Settings control. The web bootstrap uses a backend-proved
fresh setup and the ordinary revision-fenced settings transaction. Existing
enabled, disabled and legacy unconfigured policies are preserved. Backend and
direct CLI defaults remain off; there is no unconditional policy migration.

The producer tools require actual native receipts and verified source
signature/content joins. `FOXCORE_ENGINE_VERSION` parameterizes the existing
module Makefile; the default retains the historical producer version.
`tools/build-engine-catalog.py --delivery-repository core` admits only the
official Core origin and a tag matching the actual producer version.
`tools/build-core-update-catalog.py` builds bounded metadata only after its
source signature and content join pass. The metadata-only package Makefile
requires explicit sequence, compatibility, time and payload digest inputs.
No future hash, signature or release is generated from a placeholder.

BASE 1.0.6 and new Linux-musl Core modules still require native packaging,
canonical signatures, target admission, real authenticated traffic, rollback
and managed RAM qualification before release. Host model tests are not proof
of native APK execution, router installation or cold-boot recovery. Rebuilding
BASE is required again when a future Core needs a changed consumer ABI,
package layout, trust root or runtime contract; a compatible Core-only release
does not require rebuilding the complete OpenWrt package.
