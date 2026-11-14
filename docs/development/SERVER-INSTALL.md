# Optional incoming VPN server

`settings.vpnServerEnabled` defaults to `false`. An existing explicit boolean survives settings reads and old clients that omit the field. The generic settings API cannot change it: enabling requires a separate authenticated confirmation. Disabling stops managed incoming listeners and clears their firewall ports; it retains profiles, keys, pairings, PIN and installed components.

The incoming protocol is Hysteria2. It is separate from the outgoing Core Hysteria2 client module. A verified existing full server is reused with zero download bytes. The public-IP notice describes a prerequisite; neither a profile nor an installed binary proves that a UDP port is reachable from outside.

## Authority and installation boundary

`server-install-catalog.json` is embedded in the signed BASE package. Its entries are derived from the existing compact catalog, accepted package budget, native signed APK/index identities, complete dependency closure, actual Hysteria producer, source/security receipt and memory evidence. `tools/build-server-install-catalog.py` repeats the bounded native server checks. It neither signs nor qualifies a producer by itself. An empty catalog means no published compatible server installer; it must never be filled with estimated sizes, placeholder hashes or Core client artifacts.

The SERVER role uses a private generation root and its own native APK database. On RAM installations, the source database is the validated active RAM generation, rather than the underlying host database. The worker snapshots that database, runs an offline native solver and indexed fetch, disables package scripts, then installs only the exact server closure in the new private root. All preexisting package identities stay unchanged. No server operation invokes the BASE/Core transaction ABI or changes the host package database, firmware or network configuration.

The plan counts exact missing authenticated assets. Existing cache files reduce the download only after size, hash and ownership checks. Staging reserves account for native fetch copies, installed payload, volatile binary, database snapshots and bounded journals. FLASH and RAM reserves are not consumed by the payload budget.

Activation writes an intent journal before stopping managed listeners. It atomically publishes a verified generation pointer and the setting, retains the previous generation, then checks startup. Failure restores the previous pointer, consent and flag while preserving owner data. An unproven rollback remains `RECOVERY_REQUIRED` and blocks competing updates. Accepted RAM consent refers to one exact descriptor; boot restoration can download that component again when network and resource checks pass. It cannot select another version automatically. Source tests do not replace native APK, router or cold-boot qualification.

## Wire contract

All three methods require the normal authenticated token and HTTPS at the standalone gateway:

- `vpnServer.plan {token}` returns `schema`, `revision`, `planSha256`, `action` (`reuse`, `install` or `unavailable`), `available`, `downloadBytes` and `component`. An install also provides `storage`, `budget` and `components`. Planning never downloads or starts a service.
- `vpnServer.set {token, revision, enabled, confirmed, planSha256}` requires explicit confirmation and a current digest to enable. Reuse when enabling returns the normal state. Installation and disabling return a scoped job. A disable worker waits briefly before stopping the incoming VPN path, then verifies managed process termination and an empty firewall port set. A queued response is not a success acknowledgment; a lost incoming connection requires a later state/job read from LAN.
- `vpnServer.job {token, jobId}` returns `schema`, `jobId`, `state`, `step`, `progressPercent` and `failureReason`. Terminal states are `SUCCEEDED`, `FAILED` and `RECOVERY_REQUIRED`. Read the normal state after success.

`phone.capabilities.vpnServer` is optional and contains exactly `{schema: 1, enabled, available}`. `inboundProtocols` and `phoneRemoteProvisioning` are not advertised when disabled or unverified. Existing capability fields keep their meaning; an incoming server does not imply a legacy outgoing client.

`package.status.routerInfo` is an optional object containing only `schema`, `firmwareVersion`, `model` and `architecture`; unknown values are null. This discovery response never includes board serial numbers, MAC/IP addresses, profile credentials or routing lists. Routing summaries remain authenticated state data.
