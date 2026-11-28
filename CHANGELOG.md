# Changelog

## 1.0.20 Beta (FLASH r1 · RAM r2)

- Minor interface bug fixes.

## 1.0.19 Beta (FLASH r1 · RAM r2)

- The Light and Dark themes show the fox in color. Night uses a monochrome logo and controls.

## 1.0.18 Beta (FLASH r1 · RAM r2)

- The Light theme now matches the Android apps. Settings use the same row dividers in all three themes.

## 1.0.17 Beta (FLASH r1 · RAM r2)

- About now shows a table. Font appears above Theme. Dialogs close from the header.
- Server edits can be cancelled. Routing rules can be tested before saving. A wrong PIN highlights only the entry dots.

## 1.0.16 Beta (FLASH r1 · RAM r2)

- The top bar blurs only while scrolling. Dark uses the FoxHole VPN palette. The black palette is now called Night.

## 1.0.15 Beta (FLASH r1 · RAM r2)

- Square icon buttons, glass top bar and simpler dialog controls. Aligned chart chevrons and refreshed the Journal icon.

## 1.0.14 Beta (FLASH r1 · RAM r2)

- Frontend optimization.

## 1.0.13 Beta (FLASH r1 · RAM r2)

- The Bash installer is available as a checksum-verified release asset. Updated the Journal refresh icon.

## 1.0.12 Beta (FLASH r1 · RAM r2)

- Games without VPN uses a standard switch in Settings. Open Routing from Add. Expand and collapse arrows have sharp corners.

## 1.0.11 Beta (FLASH r1 · RAM r2)

- Games without VPN has a gamepad icon and checkbox next to country-based routing. The subscription form is simpler.

## 1.0.10 Beta (FLASH r1 · RAM r2)

- Install from macOS, Linux or Windows over SSH.
- Package updates check the router API after switching. If the check fails, the updater attempts to restore the previous working version.
- The RAM journal shows the last 10 VPN events for the current boot. Software status lists standalone Hysteria 2, and the panel has smaller expand controls.
- Import supported Hysteria 2, VLESS and WireGuard subscriptions in LuCI with the matching protocol installed. The router refreshes them hourly over HTTPS, including subscriptions sent from Guard or VPN.
- Games without VPN routes supported Dota 2 and CS2 relay traffic, League of Legends and VALORANT traffic via Riot Direct, and Fortnite latency checks directly when country-based direct routing covers the whole LAN.

## 1.0.9 Beta (FLASH r1 · RAM r2)

- The installer checks the router model, OpenWrt version and available memory. Installation stops if the plan affects unrelated system packages.
- Fixed package updates. You can check the version and turn automatic updates on or off in the web panel.
- Fixed home VPN server management and creation of the first client.
- The “VPN protocols” section checks the installed core and shows the available actions. You can reinstall or remove an inactive module managed by the package manager.
- Settings and help now fit wide screens. You can remove the package from LuCI or the terminal.

## 1.0.8 Beta

- Added support for OpenWrt 25.12.6
- Interface optimization
- Added an optional, verified Hysteria2 server package with public static IP checks
- Updated Help, application update checks, and About
- Fixed server controls, router details, chart outage rendering, and the font picker
- FLASH-only journal with up to 30 days of circular retention and bounded storage use
- Improved router management over VPN and RAM package reinstallation

## 1.0.7 Beta

- Interface optimization
- Added an optional, verified Hysteria2 server package with public static IP checks
- Updated Help, application update checks, and About
- Fixed server controls, router details, chart outage rendering, and the font picker
- FLASH-only journal with up to 30 days of circular retention and bounded storage use
- Improved router management over VPN and RAM package reinstallation

## 1.0.6 Beta

- Prepare independent signed Core module updates without replacing the OpenWrt package, profiles, pairings or firmware
- Keep module package versions and Core producer identity separate, with authenticated plans, resource admission and bounded rollback
- Relay a verified Core asset cohort through paired Android apps when the router has a confirmed connection failure
- Enable automatic updates for fresh Android and web setup with an explicit opt-out; preserve existing and legacy policies
- Preserve the legacy BASE policy shape for RAM migration and verify the actual RAM executable during reconnect
- Stage RAM module updates from their verified catalog delivery release when it differs from the Core version

This BASE introduces the independent signed Core feed. Managed RAM updates require an existing verified recovery generation; cold-boot recovery remains unqualified.

Companion apps: FoxHole VPN 1.0.6 and Guard 1.0.7 fix initial router installation and setup. Guard also updates Tor transports Lyrebird and conjure-client.

Previous companion Android releases: FoxHole VPN 1.0.5 and Guard 1.0.6 add Android 7 support and improve notification styling. FoxHole VPN adds website routing; Guard improves web-address routing filters.

## 1.0.5 Beta

- Added Arabic language and RTL support and completed log-panel translations

- Bound the outbound Hysteria Go memory budget to 32 MiB with GOGC 75
- Defer live log collectors when available RAM is below 32 MiB, while reporting current runtime metadata
- Bound generated Hysteria client receive windows to 1–2 MiB per stream and 2–8 MiB per connection

## 1.0.4 Beta

- Added a view of package logs, kernel out-of-memory events, and the last recorded FoxHole Core state
- Reduced memory use when processing traffic history
- Fixed RAM-module downloads and updated documentation for the prepared RAM-installation recovery components

Persistent bootstrap activation is not performed. Recovery after a cold boot is not yet verified; the ELF library-path check remains unresolved.

## 1.0.3 Beta

- Fixed verification of the compact installation archive on OpenWrt
- Fixed verification of the standard certificate symlink when preparing RAM-package recovery
- Added the VPN process exit code to connection-drop diagnostics
- Fixed VPN module links for OpenWrt client updates

## 1.0.2 Beta

- Fixed LAN access to the API and operation of the web interface
- Fixed charts and settings display
- Added backup and restore for settings, VPN profiles and clients
- Added a view of paired mobile devices
- Extended the PIN to six digits and added lockout after incorrect attempts. PIN changes are available through LuCI
- Added support for pairing up to 10 mobile devices
- Fixed verification of release data from GitHub
- Improved notifications, confirmation dialogs, the help section and tips

## 1.0.1 Public Beta - 2026-10-30

- Update selectable Linux engines to FoxHole Core 1.0.1, including DNS policy, reload, import and bootstrap fixes

- Bind paired inbound profile exports to bounded app-only origin metadata;
  retain native URI/QR formats and recheck pairing before marked replies.

- Require explicit first-setup agreement in the CLI, web panel and both Android clients; preserve existing agreement and update-policy records
- Apply and recover BASE plus approved new modules through one authenticated native transaction while preserving the original unversioned world roots

- Package a separate GPL2 native transaction utility for the two supported
  OpenWrt targets; bind explicit external artifacts and declare libgcc.
- Keep complete corresponding source as a separate release asset, with
  original notices and a recorded SDK build/install recipe in public source.

- Recheck authenticated Core proof and live routing identities after policy
  changes before reporting a connection; invalidate cached identities when probing.
- Accept content and manifest based native legal metadata in both the SDK
  and installed router registry, retaining archive based producer validation.

- Preserve registered native completion during command readiness handoff;
  validate owner and process generation without losing its exit status.

- Add Japanese, German, French, Spanish and Chinese interface translations
- Reap owned native command children with blocked SIGCHLD and preserve
  completed engine transactions during recovery reconciliation.

- Build the optional Hysteria server with Go 1.26.10; advance FLASH/RAM package revisions to 2.12.2-r5/r4 and preserve separate source-test, compiler and target-runtime provenance

### Included features

- Add signed FoxHole software updates from router Settings and both Android apps
  Keep selected protocol storage, profiles and pairing; automatic updates
  are an explicit router setting and check once a day.

- Build the separate Hysteria server with Go 1.26.10 and the pinned x/net 0.60
  security repair; reject new UDP sends after session closure and retain
  the combined patch, source hashes, fresh test receipt and original notices.

- Add owned Core routing, protected profile admission, authenticated local
  relays and exact VPN-bound proof; retain legacy Hysteria options.
- Bind selectable protocol packages and flash/RAM installation to actual
  native producers, authenticated dependency budgets and the existing kernel ABI.
- Add private LAN TLS pairing with revocable phone credentials and a
  one-use setup bootstrap that preserves an existing PIN.
- Keep subscription source, selected node and exact admitted profile input
  private; expose portable copies and genuine protocol capabilities.
- Add bounded provider handoff leases and separate pinned HY2 remote setup
  Home automation remains disabled pending firmware and device acceptance.
- Include native licenses, both RAM payloads and runtime memory evidence in
  package budgets; reject foreign cache files and bound country downloads.
- Prepare complete signed installation review bundles with all selected
  assets; reject provisional laboratory memory policies for public bundles.
- Admit genuine separate server producers in SDK builds and retain both
  Core/server RAM packages without mixing the legacy RAM wrapper.
- Retain original signed OpenWrt indexes and verify upstream identities
  with native offline fetch before indexed installation; account for keys
  and verification staging without re-signing upstream packages.
- Verify installed native producers, binaries and capabilities before
  writing the setup receipt; reject incomplete or mismatched evidence.
- Select authenticated package checksums when replacing same-version
  feature builds; retain complete payload and capability readback.

## 0.1.0-r41 - public beta 1.0 (unreleased)

- Local agent instructions are excluded from Git and source archives
- P-256 APK signatures, pinned installer trust bootstrap and local release
  preparation with unchanged-content verification and archived candidates.
- Main automatically prepares a prerelease draft after its signature and
  matching dev candidate pass; owner hardware signing remains local.
- Real APK signing, unknown-key and tamper tests during SDK builds
- Installer reads OpenWrt package architecture from `/etc/apk/arch`
- SDK builds select only the three deliverable packages and dependencies;
  cleanup handles read-only Go caches and preserves compiler failures.
- Automatic dev checks and APK candidate builds; signed main requires a
  successful dev run with the same source tree and preserves its artifacts.
- Pinned owner verification key and local GPG release signing procedure
- Shared FoxHole branding, separate English/Russian READMEs, concise English
  architecture diagrams, CLI, recovery and release documentation.
- Checksum-pinned GitHub installation example with download/tamper tests;
  CI documentation checks and manual verification dispatch.
- GIF source export support; decorative code comment removed
- Independent public source snapshot without prototype Git history
- Hysteria TUN, country/device/domain policies, inbound UDP/443 users,
  LAN kill switch and persistent 30-day history from the prototype.
- Flash-first installer; RAM binary storage requires explicit `--ram`
- SHA-256 verification, memory/overlay checks and pre-install backups
- Inactive configuration examples, bilingual README, licenses, security
  policy, rollback and signed-release checklist.
- CI, installer regressions, ucode models and deterministic source archive
- Original dashboard screenshot retained unchanged by owner request

Official feed admission and universal device compatibility are not claimed.
Complete clean-VM and load/reboot acceptance before production use.
