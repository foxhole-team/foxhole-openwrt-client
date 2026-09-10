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
| [release-candidate](../.github/workflows/release.yml) | Push to `main`; manual on `main` | Verify the owner signature and preserve the identical successful `dev` candidate for local signing. |

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

Workflows have read-only repository permissions. They do not sign, tag,
publish or deploy, and no private key is stored in CI. Inspect actual run
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

## Signed prototype prerelease

With owner authorization, a prototype prerelease can distribute reviewed
source and unsigned APK candidates while firmware acceptance is pending.
State that limitation in the release notes. GPG signs the source identity
and release manifest; it does not create an APK v3 package signature or
make an APK key trusted by the router. APK production trust is not yet
configured. Keep the installer's signature checks enabled.

1. Download the successful `main` candidate; verify `RELEASE.json`, the
   referenced `dev` run, source identity and every manifest entry.
2. Create and verify a GPG-signed annotated tag on that `main` commit using
   the owner's YubiKey. Never replace an existing tag or release.
3. Stage the verified payload plus `RELEASE.json` and the public verification
   key. Recompute `SHA256SUMS` for the staged release files; detach-sign it
   locally as `SHA256SUMS.asc` and verify the signature.
4. Create a draft GitHub prerelease, upload the complete asset set, download
   it again and compare bytes. Publish the verified draft as a prerelease.
   Keep the candidate manifest and signed release manifest distinguishable:
   `RELEASE.json` records the original candidate manifest hash.

Use release notes for concrete tag/hash installation commands. The README
keeps placeholders: embedding the release manifest hash in a source ZIP
covered by that same manifest would create a circular checksum dependency.

## Installable release

Complete the firmware gates above, sign APKs with OpenWrt/APK-compatible
tooling, and independently distribute the APK trust key. Then recompute and
GPG-sign the final manifest after APK signing. In a fresh VM, verify the
published bundle and install without `--development` before advertising
production installation. Prototype APKs remain for explicit isolated
`--development` testing; GPG verification does not remove that distinction.
