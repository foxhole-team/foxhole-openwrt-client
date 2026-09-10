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
| [verify](../.github/workflows/ci.yml) | Pull request; push to `main` or `dev`; manual | Host checks, documentation, installer regressions, source archive, clean diff. |
| [build-unsigned-apk](../.github/workflows/build-apk.yml) | Manual | Pinned Linux SDK build; unsigned APK bundle retained for seven days. |

Workflows have read-only repository permissions and do not sign, publish
or deploy. Remote run results must be checked separately; see [GitHub CLI](CLI.md).
Ucode execution and clean-firmware traffic acceptance are separate gates.

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

## Signed release

After firmware acceptance and owner authorization:

1. Review the exported files; create and verify a signed tag on the reviewed
   commit. Sign APKs with OpenWrt/APK-compatible tooling.
2. Recompute `SHA256SUMS` after signing; include APKs, `install.sh` and source
   ZIP. Detach-sign the manifest with the owner's hardware-backed key.
3. Publish a GitHub prerelease with the artifacts, manifest and `.asc`
   signature. Distribute verification fingerprints and APK trust-key setup
   through an independent trusted channel; keep signing keys outside Git/CI.
4. Fill in the README tag/manifest hash, keeping its installer digest equal
   to the published script. Test installation without `--development` in a
   fresh VM before advertising that release command.

Local preparation creates no signed tag, trust key or published release.
