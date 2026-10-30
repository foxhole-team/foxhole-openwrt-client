# Verification and release

The forthcoming 1.0 release uses selectable Core client modules. The incoming
Hysteria server is optional in compact catalogs. Host checks do not establish firmware
compatibility or reproducible APKs. Keep the release unpublished until actual
firmware gates and owner review are complete.

The catalog path requires actual native producers, complete authenticated dependency
closures, APK payload checks, exact kernel ABI and reviewed memory evidence.
For compact schema 2, use `tools/compact-install-bundle.py` with `--input`,
`--apk`, `--factory-keys-dir`, `--core-commit` and `--core-source-sha256`. Add
`--output` to prepare a review bundle, or `--manifest-sha256` to verify an existing
bundle. Legacy schema 1 uses `tools/prepare-install-bundle.py` and
`tools/verify-install-bundle.py`. Provisional laboratory resource policies cannot
enter a public bundle. Neither path publishes a release.

For Core variants, `canonical-apk-and-upstream-index-v1` binds the byte-exact
original signed OpenWrt indexes and firmware keys to every package identity.
FoxHole APKs retain individual canonical signatures. Upstream packages are
authenticated by native offline fetch against their original signed entries,
then compared to the separately anchored whole-archive hashes. Do not re-sign
upstream APKs, trim signed indexes, use `--link` or reuse a fetch destination.
Same-size payload tampering, wrong keys, unindexed files, missing dependencies
and a different live kernel must fail before installation changes the router.
Indexed roots include the authenticated package checksum selector. A name and
version alone can retain a different feature build with the same version; the
installed binary, producer and capability readback must still match the proposal.

The server producer requires fresh complete upstream tests on its exact modified
source. Its record binds the network dependency repair and the UDP close fix,
compiled Go 1.26.10 identity, original notices and the complete-suite receipt.
The retained source suite used Go 1.26.9; the current compiler qualification
and target-runtime evidence remain separate records.
Validate physical package logs and the separate whole integration run before
building either architecture. Old-source passes, partial results and instrumented
diagnostic runs cannot qualify the new binary. Public DoH tests use their original
endpoint through a disposable restricted network; stress-buffer changes belong
only to the disposable test kernel, never the builder host.

The server dependency scan retains two known findings: unused S2 dictionary
encoding and deprecated OpenPGP packages. The Hysteria-specific policy expires
on 12 November 2026. It qualifies only the exact AMD64/ARM64 CGO0 Linux binaries
whose compiled import closures exclude those packages. A new binary, module
version, affected import, advisory, stale scan or expired exception must fail:

```sh
python3 -B tools/check-hysteria-security.py --policy config/hysteria-osv-exceptions.json --evidence /tmp/package-evidence --shipping /tmp/server-producers --scan /tmp/public-scan
```

Keep the physical producer/binary, package graph, selected-file hashes, public
query/response and primary advisory files. The scan directory must also include
the exact query as `query-payload.json` and its successful request receipt.
Qualified exceptions do not mean a zero-finding scan or firmware acceptance.

The historical three-package CI candidate and `prepare-release.py` path below
remain separate from the complete 1.0 catalog pipeline. Their old installation
results must not be reported as current Core, pairing or home-handoff acceptance.
`build-openwrt.sh` accepts `--core-input` and `--server-input` with separate pinned
RAM URLs/reserves. Core mode builds its own RAM wrapper and the separate server
wrapper; it excludes the legacy Hysteria RAM package. Producer validation and
complete catalog checks remain required after SDK packaging.

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

`npm run check` explicitly runs the Python package/catalog regressions
and native ucode layout and candidate tests. The lab recipe builds ucode from the
checksum-pinned official source via `tools/ci-install-ucode.sh`; a local
check needs Python3 and that ucode/fs tool installed. Missing tools fail.

`npm run test:model` additionally executes ucode/RPC/probe tests in an
existing `foxhole-public-model-check` Docker container with this checkout
mounted read-only at `/workspace` and ucode installed. It does not provision
the container or run on a router.

Host syntax compilation uses the documented runtime-extension flags:

```sh
ucode -cdynlink=uci,dynlink=ubus -o /dev/null script.uc
```

Only OpenWrt's UCI and ubus imports are deferred. The filesystem, digest and
local source modules remain real, and model/probe fixtures still execute in
native ucode. This host syntax boundary does not prove UCI/ubus runtime loading;
the installed firmware must provide and exercise both extensions separately.

## GitHub checks and lab builds

GitHub runs fast source syntax and metadata checks. Full tests, dependency
verification, SDK/native/APK builds and firmware acceptance run in Git LAN
or the lab, with actual results bound to the reviewed source and inputs.

| Location | Role |
| --- | --- |
| [source-checks](../.github/workflows/ci.yml) | Fast syntax and metadata on `main`/`dev` pushes, pull requests or manual dispatch; no build or test qualification. |
| [verification recipe](../.github/lab-workflows/ci.yml) | Retained full verification recipe for the lab. |
| [unsigned APK recipe](../.github/lab-workflows/build-apk.yml) | Retained pinned SDK, source ZIP, checksums and source identity recipe. |
| [candidate recipe](../.github/lab-workflows/release.yml) | Retained signature and candidate preservation recipe for local signing. |

The files in `.github/lab-workflows` preserve the previous heavy recipes.
GitHub does not schedule them from this directory. Use the reviewed lab
stage commands and keep their actual logs and receipts. A GitHub metadata
check alone does not qualify a candidate or release.

The following signature and candidate-selection details describe the
retained historical pipeline; they do not establish a current lab result.
Promote the tested `dev` tree to `main` only after full Git LAN or lab
verification succeeds for that exact tree. The `main` tip must be GitHub-verified and carry a valid OpenPGP
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
commit. Private keys remain outside the build environment, and publication
requires owner review. Keep actual lab logs and receipts; the active metadata
checks can be inspected through the [GitHub CLI](CLI.md). Ucode execution and firmware
traffic acceptance remain separate gates.

## APK build and firmware acceptance

On a non-root Linux x86_64 builder, use Ubuntu 24.04 and the prerequisites
listed in the [APK lab recipe](../.github/lab-workflows/build-apk.yml):

```sh
sh tools/build-openwrt.sh
```

The script pins OpenWrt SDK 25.12.5, Go 1.26.10, feed commits, Hysteria 2.12.2
and source date. SDK, compiler and Hysteria digests are checked; automatic
Go toolchain switching is disabled. Retain SDK configuration, feed revisions,
dependency versions and hashes; live router dependency feeds are mutable.

SDK-wide package and kernel-module selection is disabled. The three
deliverable packages select their dependencies through `make defconfig`;
the build verifies those selections, including `kmod-tun`. This avoids
the SDK-wide selection of unrelated packages; target-selected modules can
still remain in the SDK configuration. Dependencies still build from source;
measure duration from completed lab builds rather than the job timeout.
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
3. Keep the draft unpublished while firmware traffic/load/reboot acceptance
   or owner review is pending. State the tested environment and remaining limits.

GPG signatures authenticate the release; the P-256 key authenticates APKs.
Normal installation requires neither `--development` nor `--allow-untrusted`.
Core development catalogs may use explicit provisional resource policies;
they still require the full authenticated package chain. Historical legacy
installers and ARM-only download packages are refused by the Stable build and
release paths. Existing legacy configuration import remains supported.

Use release notes for concrete tag/hash installation commands. The README
keeps placeholders: a manifest hash embedded in a source ZIP covered by that
same manifest would create a circular checksum dependency.

## Historical legacy package acceptance

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
