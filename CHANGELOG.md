# Changelog

## 0.1.0-r41 — public beta 1.0 (unreleased)

- Local agent instructions are excluded from Git and source archives.
- P-256 APK signatures, pinned installer trust bootstrap and local release
  preparation with unchanged-content verification and archived candidates.
- Main automatically prepares a prerelease draft after its signature and
  matching dev candidate pass; owner hardware signing remains local.
- Real APK signing, unknown-key and tamper tests during SDK builds.
- Installer reads OpenWrt package architecture from `/etc/apk/arch`.
- SDK builds select only the three deliverable packages and dependencies;
  cleanup handles read-only Go caches and preserves compiler failures.
- Automatic dev checks and APK candidate builds; signed main requires a
  successful dev run with the same source tree and preserves its artifacts.
- Pinned owner verification key and local GPG release signing procedure.
- Shared FoxHole branding, separate English/Russian READMEs, concise English
  architecture diagrams, CLI, recovery and release documentation.
- Checksum-pinned GitHub installation example with download/tamper tests;
  CI documentation checks and manual verification dispatch.
- GIF source export support; decorative code comment removed.
- Independent public source snapshot without prototype Git history.
- Hysteria TUN, country/device/domain policies, inbound UDP/443 users,
  LAN kill switch and persistent 30-day history from the prototype.
- Flash-first installer; RAM binary storage requires explicit `--ram`.
- SHA-256 verification, memory/overlay checks and pre-install backups.
- Inactive configuration examples, bilingual README, licenses, security
  policy, rollback and signed-release checklist.
- CI, installer regressions, ucode models and deterministic source archive.
- Original dashboard screenshot retained unchanged by owner request.

Official feed admission and universal device compatibility are not claimed.
Complete clean-VM and load/reboot acceptance before production use.
