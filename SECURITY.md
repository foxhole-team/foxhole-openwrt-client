# Security policy

Report vulnerabilities through [GitHub private reporting](https://github.com/foxhole-team/foxhole-openwrt-client/security/advisories/new)
when enabled; otherwise request a private maintainer channel. Include the
commit, firmware version and redacted reproduction. Exclude profiles,
keys, QR exports, certificates, backups and unredacted logs. Rotate leaked
credentials; removing a Git file does not revoke them.

## Trust boundaries

- Keep router administration LAN-only; the package does not restrict an
  existing WAN management policy. The panel PIN does not replace router
  authentication. Change the initial PIN before normal operation.
- Authenticate the checksum manifest independently and trust the release
  APK key. The README command also verifies the installer before execution.
  `--development` bypasses APK signatures for explicit local testing only.
- Incoming users fall back to direct egress when upstream disconnects.
  Shared UDP/443 has one LAN ACL, independently of the LAN kill switch.
- RAM mode needs an upstream HTTPS download after reboot. Settings remain
  on flash; temporary backups must be copied off-router.

See [architecture](docs/ARCHITECTURE.md), [release gates](docs/RELEASE.md)
and [recovery](docs/ROLLBACK.md).
