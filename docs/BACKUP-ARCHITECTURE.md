# Settings backup and restore

The Settings floppy icon saves or restores a bounded JSON document after a
native confirmation. The file includes FoxHole settings, routing exceptions,
server profiles and clients, including their VPN access details. It is private
user material. The browser keeps it out of local storage and sends restores only
to the same authenticated HTTPS origin. Older routers do not advertise
`backupSupported`; the entry stays hidden and the frontend calls no backup RPC.

The document contains the complete validated state plus these eight typed UCI panel
options: `mode`, `telemetry_interval`, `standalone`, `lan_devices`, `mobile_devices`,
`dns_via_tunnel`, `preserve_loopback_socks` and `tun_mtu`. It also contains the
automatic-update enabled choice. Scheduler timestamps are retained and its
revision advances. Network, DHCP, firewall, firmware, package databases and
installed protocol modules are outside the restore scope.

PIN records, pairing credentials, phone journals and TLS identity are neither
exported nor restored. A backup conflicting with a current phone-owned client
or device is refused; revoked phone client credentials cannot be restored over
their current revocation. Validation is repeated at apply time.

## Transaction boundary

`backup.export` and `backup.validate` require the current authenticated panel
session. `backup.apply` validates the expected revision, confirmation and unique
request ID, writes a private recoverable journal, and acknowledges `PREPARED`.
A fixed background worker rechecks the persisted principal and performs the
restore. RPC remains available for Stop, PIN changes and pairing revocation.

The worker owns the engine lock. It writes typed UCI configuration and the
update-policy choice before replacing `state.json`, which is the commit point.
A synchronized `STATE_COMMITTING` marker precedes that replacement.
Before that replacement, it rechecks the principal, security-record hashes,
state revision/content and Stop-intent generation under the state lock. The
state lock is released during the other file writes so a later Stop or
revocation can invalidate the operation. Stop still wins when the router was
already disconnected and only the Stop-intent generation changed.
If a Stop or client-access revocation waits on the final state lock, only the
exact journal's old revision is bridged to its proven current after-state.
Other stale revisions remain refused.

Journal snapshots and metadata use private `0700` directories and `0600` files.
They are synchronized before mutation. Space admission includes before/after
copies, configuration staging, atomic replacement and a reserve. Only the
previous completed journal's verified owned files are pruned for a new restore.

Recovery compares recorded before/after hashes. A precommit interruption rolls
back only the transaction's own UCI/policy writes; independently changed files
are never overwritten. A proven state commit finishes forward. A later Stop is
retained during either outcome. Ambiguous state becomes `RECOVERY_REQUIRED` and
blocks further product changes. No stale authentication or identity snapshot
is restored.

Normal product calls and package/module mutations are guarded while the journal
is pending. Startup hooks recover before FoxHole consumers start. A stopped
runtime may perform cleanup or enforce its disconnected kill-switch policy
while a live restore owns the engine lock; that fallback cannot launch a tunnel.
The existing RAM package/module update restrictions remain in place.

The browser resolves accepted or uncertain operations through `backup.status`.
It never repeats APPLY after a lost response. Restored settings and a successful
service restart are separate from proof of authenticated tunneled traffic.

## Verification scope

Focused frontend tests cover file bounds, validation, native cancellation,
session cancellation, capability gating and uncertain response handling.
`backup-service-transaction.test.mjs` executes the transaction source with
in-memory filesystem, UCI and principal adapters to exercise failure ordering,
rollback, forward recovery, Stop and revocation. That harness is not native
Ucode or flash-durability proof; those require isolated target qualification.
