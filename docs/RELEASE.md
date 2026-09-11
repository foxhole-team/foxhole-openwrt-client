# Verification and release

Public beta 1.0 is a third-party package. Host tests and source archive
reproducibility do not establish firmware compatibility or APK reproducibility.

## Local verification

Use Node 22+, Python 3.11+ and Gitleaks 8.30.1:

```sh
npm ci --ignore-scripts
npm run check
npm run test:installer
npm run build:source
```

`check` validates source syntax, comments, documentation, isolated Node
regressions and the public export with Gitleaks. Installer tests mock the
router and APK manager. Source-build tests compare two independent ZIPs:
allowlisted files, fixed order/timestamps/permissions and a SHA-256 sidecar.

`npm run test:model` additionally executes ucode/RPC/probe tests in an
existing `foxhole-public-model-check` Docker container with this checkout
mounted read-only at `/workspace` and ucode installed. It does not provision
the container or run on a router.

## GitHub Actions

| Workflow | Trigger | Checks / output |
| --- | --- | --- |
| [verify](../.github/workflows/ci.yml) | Pull request to `main`/`dev`; push to either branch; manual | Host checks; a `dev` push then builds the APK candidate. |
| [build-unsigned-apk](../.github/workflows/build-apk.yml) | Called by the `dev` gate; manual | Pinned SDK build, source ZIP, checksums and source identity. |
| [release-candidate](../.github/workflows/release.yml) | Push to `main`; manual on `main` | Verify the owner signature, preserve the successful `dev` candidate and prepare a draft for local signing. |

Promote the tested `dev` tree to `main` only after the complete `verify` run
succeeds. The `main` tip must be GitHub-verified and carry a valid OpenPGP
signature from the pinned owner signing subkey and primary key:

```text
Signing: 0B954B66780BDA4F5FC995224C80DC5BBBB25151
Primary: 7D82C6B1AC24714024F37DFE1871E0B91FEAB141
```

The gate verifies that signature with the committed
[public key](../config/release-signers.asc). It selects a successful `dev`
push from the last 24 hours whose Git tree equals `main` and whose candidate
is unexpired. Manual builds alone do not satisfy this gate.

The candidate contains three unsigned APKs, `install.sh`, `sdk.config`,
`feeds.buildinfo`, source ZIP and its hash, `CANDIDATE.json`, and `SHA256SUMS`.
`main` verifies the exact file set, all hashes and source identity, then
retains those bytes unchanged with a separate `RELEASE.json`. Artifacts are
kept for seven days. `SHA256SUMS.asc` is absent until local hardware signing.

Build and verification jobs have read-only permissions. A separate job can
create an unpublished prerelease draft for `config/release-version.txt`; it
refuses to replace an existing published release or a draft for another
commit. CI does not hold private keys or publish releases. Inspect actual run
results through the [GitHub CLI](CLI.md). Ucode execution and firmware
traffic acceptance remain separate gates.

## APK build and firmware acceptance

On a non-root Linux x86_64 builder, use Ubuntu 24.04 and the prerequisites
listed in the [APK workflow](../.github/workflows/build-apk.yml):

```sh
sh tools/build-openwrt.sh
```

The script pins OpenWrt SDK 25.12.5, Go 1.25.0, feed commits, Hysteria 2.12.2
and source date. SDK, compiler and Hysteria digests are checked; automatic
Go toolchain switching is disabled. Retain SDK configuration, feed revisions,
dependency versions and hashes; live router dependency feeds are mutable.

SDK-wide package and kernel-module selection is disabled. The three
deliverable packages select their dependencies through `make defconfig`;
the build verifies those selections, including `kmod-tun`. This avoids
the SDK-wide selection of unrelated packages; target-selected modules can
still remain in the SDK configuration. Dependencies still build from source;
measure duration from completed CI runs rather than the job timeout.
Cleanup makes temporary Go module caches writable and retains build failures.
Before export, the SDK signs copies with a disposable test key, verifies all
three signatures, rejects unknown keys and damaged APKs, and checks that
signing preserves package content. Production candidates remain unsigned.

Copy the checkout and APK bundle to a disposable OpenWrt 25.12 ARM64 VM
with matching kernel/feeds and initialized networking. Test each mode on a
fresh VM, using the manifest hash obtained from the build host:

```sh
FOXHOLE_DISPOSABLE_TEST=1 sh tests/clean-install.sh /tmp/bundle TRUSTED_SHA256
FOXHOLE_DISPOSABLE_TEST=1 sh tests/clean-install.sh /tmp/bundle TRUSTED_SHA256 --ram
```

The harness installs real APKs, checks RPC/services and unchanged network,
DHCP and firewall UCI. Then verify reboot, LAN VPN egress, UDP/DNS, rule
precedence, WAN isolation and sustained load. RAM boot needs direct HTTPS.
These firmware gates remain pending; compare independent APK builds before
claiming binary reproducibility.

## Package signing and owner GPG signatures

The committed [P-256 public key](../config/foxhole-openwrt-apk.pem) is the
APK trust anchor. Its PEM SHA-256 is pinned in `install.sh`. The private key
and encrypted recovery backup stay in the owner's vault, beside the Android
signing material. They must never enter Git, workflow secrets or artifacts.
The owner YubiKey signs Git commits, tags, and the final `SHA256SUMS`.

From a clean `main` checkout, use `apk-tools 3.0.5`, OpenSSL, Python and GPG:

```sh
python3 -B tools/prepare-release.py --candidate /tmp/foxhole-release --output /tmp/foxhole-signed --key "$FOXHOLE_APK_KEY" --apk "$APK_TOOL"
git tag -s "v$(cat config/release-version.txt)" -m "FoxHole OpenWrt Client $(cat config/release-version.txt)"
git verify-tag "v$(cat config/release-version.txt)"
gpg --armor --detach-sign /tmp/foxhole-signed/SHA256SUMS
gpg --verify /tmp/foxhole-signed/SHA256SUMS.asc /tmp/foxhole-signed/SHA256SUMS
```

The preparation tool verifies candidate hashes and source identity, then
signs each APK separately. It verifies the signature and compares both
versions after removing signatures and normalizing compression. This
preserves package metadata, install scripts and file contents. Separate
calls also avoid the multi-file signing state issue in apk-tools 3.0.5.
The output includes `APK-SIGNATURES.json` and the complete original
`unsigned-candidate.zip`, so source provenance remains independently
checkable after package hashes change. The final manifest covers both.

1. Verify signed APKs on a clean OpenWrt 25.12 target. The installer checks
   the pinned key and package signatures, simulates dependencies, makes its
   backup, then installs the key and packages. Check-only mode does not
   change permanent trust. Existing different keys are never replaced.
2. Push the verified signed tag. Upload the complete signed asset set to
   the matching draft, then download it and compare every file and signature.
3. Publish as a prerelease while firmware traffic/load/reboot acceptance is
   pending. State the tested environment and remaining limits in the notes.

GPG signatures authenticate the release; the P-256 key authenticates APKs.
Normal installation requires neither `--development` nor `--allow-untrusted`.
The explicit development option remains available for isolated unsigned
candidate testing. It must not appear in signed-release install commands.

Use release notes for concrete tag/hash installation commands. The README
keeps placeholders: a manifest hash embedded in a source ZIP covered by that
same manifest would create a circular checksum dependency.

## Firmware acceptance

Signed flash and RAM packages were installed without a trust bypass in
separate official OpenWrt 25.12.5 ARM64 rootfs containers. Package signature
verification, dependency resolution, public-key installation and DHCP
preservation passed. The flash Hysteria binary reported version 2.12.2.
These containers did not run a complete procd/ubus boot; service lifecycle,
VPN traffic and firmware reboot behavior were not validated by that test.

Successful signature checks and package installation do not establish VPN
compatibility. Complete clean-VM reboot, LAN egress, DNS/UDP, WAN isolation
and sustained-load checks before advertising production readiness. Compare
independent APK builds before claiming binary reproducibility.
