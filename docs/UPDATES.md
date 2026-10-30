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

Direct CLI/backend installations leave automatic updating off by default.
A fresh Android phone Setup shows a separate automatic-update checkbox enabled
with an explicit opt-out; its policy is written after installation and pairing.
Pairing an existing router preserves its policy. Later changes use Settings.
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
OpenWrt25.12.5, x86/64 or mediatek/filogic, and the state/transaction ABI. Any
required unrelated dependency change is refused.

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
