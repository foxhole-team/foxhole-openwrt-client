# Build and release

Source preparation is not an official OpenWrt feed approval. This project
is a third-party public beta. No release is published by these scripts.

## Verification

Node 22+, Python 3.11+ and Gitleaks 8.30.1:

```sh
npm ci --ignore-scripts
npm run check
npm run test:installer
npm run build:source
```

The ZIP is an allowlisted, uncompressed source snapshot with fixed
timestamps, order and permissions; SHA-256 is written beside it.
The tests compare two independent archives byte for byte. Credentials,
archives and symlinks are rejected before export. This proves source
archive reproducibility, not identical APKs across different SDK hosts.

CI runs those checks on push/PR; preparing the files locally runs no
GitHub Actions. The APK workflow is manual, produces unsigned build
artifacts only, and never deploys to a router.

## APK build

Use a fresh Linux x86_64 builder (Ubuntu 24.04), with build-essential,
bison, flex, gawk, gettext, git, libncurses-dev, libssl-dev, python3,
python3-setuptools, rsync, unzip, file, time, curl and zstd. Run as a
non-root user:

```sh
sh tools/build-openwrt.sh
```

The script pins the [OpenWrt 25.12.5 ARM64 SDK](https://downloads.openwrt.org/releases/25.12.5/targets/armsr/armv8/),
Go 1.25.0 (SHA-256 checked), feed commits, source date and Hysteria 2.12.2.
Hysteria source and RAM binary digests are pinned in their package recipes.
Go module versions/checksums come from the pinned upstream source; automatic
toolchain switching is disabled. Live OpenWrt router feeds used to install
dependencies are not an immutable snapshot: archive them for strict release
reproduction. Retain SDK config, dependency versions and artifact hashes.

## Clean installation gate

Boot a **disposable** OpenWrt 25.12 ARM64 VM with a matching kernel and APK
feeds, an initialized network and enough flash/RAM. Do not run this test on
an owner's router. Copy this source checkout and the built APK bundle into
the VM. Obtain the SHA-256 of the bundle's SHA256SUMS from the build host.
Then, in the VM:

```sh
FOXHOLE_DISPOSABLE_TEST=1 sh tests/clean-install.sh /tmp/bundle TRUSTED_SHA256
# Repeat on another fresh VM to test the RAM provider:
FOXHOLE_DISPOSABLE_TEST=1 sh tests/clean-install.sh /tmp/bundle TRUSTED_SHA256 --ram
```

This installs **real APKs**, checks services/RPC and unchanged network,
DHCP and firewall UCI. The separate Node installer harness mocks APK and
system resources: it does not establish firmware compatibility. Also test
reboot, VPN egress, UDP, DNS, rule precedence, WAN isolation and sustained
load. RAM boot requires direct HTTPS access to the pinned upstream download;
it is not a workaround for insufficient working RAM.

## Publication checklist (explicit owner approval required)

Local preparation passed host tests, isolated ucode/RPC tests, the source
archive reproducibility test and an unsigned panel APK packaging smoke test.
The complete pinned SDK build, clean 25.12 VM installation, reboot and
real traffic/load acceptance are still required before the first release.

1. All checks above pass on a clean builder and clean VM; compare a second
   APK build before claiming APK reproducibility.
2. Inspect every archive, screenshot and checksum manifest for secrets.
3. Create a signed release tag, for example `v0.1.0-beta.1`, on the reviewed
   commit; verify it with `git verify-tag`.
4. Sign the APKs using OpenWrt/APK-compatible offline signing tooling.
   Recompute SHA256SUMS **after** APK signing, then detach-sign that
   manifest with the owner's hardware-backed GPG key. Verify both layers.
   Never put signing keys in this repository or generic CI secrets.
5. Publish a prerelease through GitHub Release for the signed tag, including
   APKs, source ZIP, install.sh, SHA256SUMS and SHA256SUMS.asc.
6. Distribute the public verification key/fingerprint through an independent
   trusted channel and document APK trust-key installation on the router.
   A checksum downloaded next to an artifact alone is not authentication.
7. Install from that GitHub Release in a new VM without `--development`.
   Only then advertise that tagged installation URL.

No signed APK trust key, release tag or GitHub Release is created during
local preparation. `--development` explicitly bypasses APK signatures
for manifest-pinned test bundles; never recommend it as production trust.
