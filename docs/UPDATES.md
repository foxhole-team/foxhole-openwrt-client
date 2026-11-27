# FoxHole software updates

Settings → FoxHole update checks and updates only the FoxHole panel/runtime
package and selected installed client protocol modules. It preserves each
module's FLASH/RAM choice. It does not install missing protocols, replace the
OpenWrt firmware or update unrelated system packages. An optional incoming
Hysteria server is preserved, rather than silently treated as a client module.

The current version is the installed native FoxHole package version. AVAILABLE
can also describe a module-only update with the same exact BASE package. The
confirmation lists changes, storage, required space and whether reconnection is
required. Every BASE replacement requires reconnection. CHECK_FAILED does not
mean that the installed version is current.

Fresh installations enable automatic package updates after the owner sets a PIN. Clear the checkbox during setup or pass `--no-auto-update` to the installer to opt out. Pairing an existing router preserves its update setting. You can change it later in Settings.
The authenticated choice persists on the router, including after an ordinary
phone unpair. The existing router history scheduler starts at most one attempt
per24h, recording the attempt before
network access. It stores no bearer token. Disabling the setting before mutation
prevents a queued automatic installation; an installation already changing
packages finishes or enters recovery. Phone revocation separately invalidates
pending manual authorization.

GitHub latest supplies only a tag hint. The updater verifies the signed native
APK index and BASE with the pinned public APK key, performs an isolated native
fetch round trip, validates the BASE layout and reads its signed embedded client
catalog. Version ordering uses native APK comparison. An older version or a
different body under the same version is refused. The signed metadata fixes
OpenWrt 25.12.5 or 25.12.6, x86/64 or mediatek/filogic, and the state/transaction ABI. Any
required unrelated dependency change is refused.

The v1.0.12 source builds two independently identified BASE packages.
The FLASH updater reads one signed row in `base.adb` and selects
`1.0.12-r1`. Its primary schema 2 policy lists 25.12.5 and 25.12.6,
including for the older 1.0.8 FLASH reader. The managed RAM updater
selects the highest matching BASE filename in the release and checks
its SHA256SUMS entry and native signature. That package is `1.0.12-r2`.
Its primary schema 1 record admits 25.12.5 for old readers. The schema 2
companion has the same revision. The fresh RAM catalog binds its separate
single-row `base-ram.adb`. Both versioned APKs belong in the same tagged
release. Each artifact still requires its exact kernel and architecture.

FLASH updates also need the installed version's original signed rollback
index at its previous tag. Managed RAM updates need the previous active
generation, mount ledger and a reachable, authenticated recovery source.
Use the fresh installer on routers without an existing FoxHole configuration.
The authenticated Cudy
catalog selects one board, firmware and package storage mode. WR3000 v1
on 25.12.5 requires an isolated RAM package root. Selecting FLASH stops
the installer. Automatic selection cannot fall back to a host package
installation. WR3000S v1 on 25.12.6 uses FLASH. Pairing with an already
installed router continues to use its existing authentication checks.

For these boards, the Hysteria2 installation check compares installed
package records and files with an inventory derived from the signed OpenWrt
factory image. The offline publisher checks the upstream signature on the
firmware checksums, the exact board image and its SquashFS contents. The
router reads the inventory bound by the release manifest and verifies
package ownership, hashes, modes, symlink targets and the native APK
audit. Router configuration can differ from factory defaults. A fresh
installation preserves existing settings and refuses an unqualified
replacement of the DNS service or upgrades to existing system packages.

Downloads reuse the existing uclient-fetch transport: fixed initial HTTPS
official repository, normal certificate validation, bounded time and size, and
no credentials sent to GitHub. uclient-fetch follows at most10 redirects; this
interface does not provide a per-hop host or TLS-only redirect policy. Redirect
locations and downloaded bytes remain untrusted until native signatures,
package identity, compatibility and layout checks succeed. No insecure TLS flag
or alternate signing key is accepted through RPC.

The updater retains verified recovery archives before mutation. It never
restores a stale profile, pairing or auth snapshot over a concurrent revocation.
Failure after mutation triggers one bounded package/selection recovery attempt.
If exact restoration cannot be proved, the durable state is RECOVERY_REQUIRED
and further mutations remain blocked. Insufficient flash/RAM, missing verified
RAM staging or an unavailable recovery archive fails before installation.

CHECK and APPLY acknowledge an accepted job quickly. Jobs survive rpcd restart;
after reconnecting and authenticating, status rediscovers the same principal's
active/last job. A lost APPLY response must never be automatically resubmitted.
Automatic progress is sanitized in status and does not expose another owner or
permit caller-owned job access for the scheduler.

The new API applies to packages shipping this updater. An older package with no
update capability is unsupported; its first deployment requires a separately
reviewed migration preserving existing configuration and PIN.

Native command semantics are documented in upstream APK
[version](https://github.com/alpinelinux/apk-tools/blob/v3.0.5/doc/apk-version.8.scd),
[extract](https://github.com/alpinelinux/apk-tools/blob/v3.0.5/doc/apk-extract.8.scd)
and [add](https://github.com/alpinelinux/apk-tools/blob/v3.0.5/doc/apk-add.8.scd).
Signature verification precedes extraction, which does not itself perform
dependency admission.

An authenticated Stop remains available while an update owns the engine lock.
It keeps the existing routing revision check and first records the durable stop
intent and clears the desired profile under the separate state lock. During
atomic package mutation, native service work is deferred until that phase ends.
The worker rechecks Stop under the state lock before publishing completion; it
never reconnects the old intent. Profile contents must otherwise remain exact.
A lost Stop response is also resolved by status reads, rather than replay.

An active legacy Hysteria client is a separate supported-profile limitation:
LEGACY_CONNECTION_ACTIVE asks you to disconnect the router VPN explicitly
before updating. The updater does not disconnect it automatically or reuse
a Core-only reconnect proof. The platform remains supported. A fresh manual
plan can reuse a still-verified cohort only after an exact Stop-only state
transition; an old confirmed plan cannot be replayed.

The hourly compressed history checkpoint remains mutable under its existing
writer. It has a narrow regular/root-owned/bounded metadata role, rather than
a false immutable-content guarantee. The updater does not delete, truncate or
restore that checkpoint; BASE payload paths cannot write inside /etc/foxhole.
Other profile, pairing, PIN, configuration and certificate contents retain
exact preservation checks. The engine registry is separately validated for
exact slot/selection restoration and a monotonically increasing revision.

The same hourly writer also owns exactly history.json.gz.new while gzip is
running. That temporary path can be empty or absent and is metadata-checked,
never treated as an immutable snapshot or touched by updater cleanup. The
final checkpoint must continue to exist if it existed before the update.
