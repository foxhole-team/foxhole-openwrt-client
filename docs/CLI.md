# Command reference

## Installer

Run on the supported OpenWrt target as root. Authenticate `SHA256SUMS`
independently and replace `HASH` with its SHA-256. For GitHub downloads,
use the verified one-command bootstrap in the [README](../README.md).

```sh
sh install.sh --help
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --ram --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --vless --wg --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --server --ram --apply
```

| Option | Meaning |
| --- | --- |
| `--bundle DIR` | Signed APKs, `foxhole-openwrt-apk.pem` and `SHA256SUMS`. |
| `--base-url HTTPS_URL` | Release asset directory; mutually exclusive with `--bundle`. |
| `--manifest-sha256 HASH` | Required authenticated manifest hash. |
| `--apply` | Back up, then install; otherwise verify and simulate without installing. |
| `--license` | Display the agreement and exit without installing. |
| `--accept-license` | Explicitly accept the displayed agreement for noninteractive installation; never infer consent. |
| `--flash` | Explicit persistent engine storage; also the default. |
| `--ram` | Explicit volatile engine storage; cannot be combined with `--flash`. |
| `--auto` | Select a verified flash budget, otherwise an available RAM module set. |
| `--hy2` | Hysteria2 only; the default outbound selection. |
| `--vless`, `--wg` / `-wg` | Select or combine released client modules. |
| `--all` | Request every recognized protocol; refuses if any module is unavailable. |
| `--server` | Add the incoming Hysteria server for your devices; compact catalogs only. Default: client modules only. |
| `--development` | Allow a development catalog and provisional resource policies; APK and index authentication remains required. |

Compact schema 2 catalogs combine released modules in one storage mode. The
compact installer is for initial setup only; add and update protocols through
paired **Router VPN → Protocols** management. Legacy schema 1 catalogs require
one exact variant. Other recognized flags are listed in the [README](../README.md).
The authenticated
catalog binds the exact native producer, actual capabilities, complete APK
closure, runtime memory evidence and matching SDK/kernel ABI. The installer
never upgrades the kernel to satisfy a mismatched module dependency.

On a newly installed router, the trusted SSH setup calls
`/usr/libexec/foxhole-bootstrap-enroll` without arguments. Its private stdout
contains a four-digit, one-use, five-minute bootstrap PIN; do not print or save
that response. The phone immediately replaces it with a user PIN. A previously
configured PIN is preserved. Control, pairing and incoming server setup remain
separate authenticated steps.

With `--apply`, an interactive installer displays the agreement and asks `[y/N]`, defaulting to No. Read it first with `sh install.sh --license`. Noninteractive installation must explicitly add `--accept-license` after acceptance. Check-only runs without `--apply` do not install packages. The phone wizard keeps agreement separate from its automatic-update choice.

## Router diagnostics

```sh
ubus list foxhole
/usr/libexec/foxhole-runtime status
ip -4 rule show
ip -6 rule show
ip -4 route show table 201
ip -6 route show table 201
```

RPC registration and `connected` status are control-plane observations;
verify actual LAN traffic through the tunnel for acceptance. Runtime service
control can interrupt traffic:

```sh
/etc/init.d/foxhole-runtime restart
/etc/init.d/foxhole-runtime stop
```

The saved profile and kill-switch policy still apply. Use the panel for
profile changes and the [rollback procedure](ROLLBACK.md) for removal.

## Development and GitHub CLI

[Verification commands and prerequisites](RELEASE.md) apply to the local
checkout. `npm run check:docs` checks documentation alone; `npm run check`
also runs source and installer regressions.

GitHub runs fast source syntax and metadata checks. With an authenticated
GitHub CLI, inspect or request those checks on a reviewed, published ref:

```sh
gh run list --repo foxhole-team/foxhole-openwrt-client --workflow ci.yml
gh run view RUN_ID --repo foxhole-team/foxhole-openwrt-client --exit-status
gh workflow run ci.yml --repo foxhole-team/foxhole-openwrt-client --ref REVIEWED_REF
```

Dispatch acceptance is not check success. Inspect the resulting run.
Full tests, dependency verification, native/SDK/APK builds and candidate
preparation run in Git LAN or the lab. The retained
[verification](../.github/lab-workflows/ci.yml),
[APK](../.github/lab-workflows/build-apk.yml) and
[candidate](../.github/lab-workflows/release.yml) recipes are reference files;
GitHub does not schedule or dispatch them from `.github/lab-workflows`.

Keep the actual lab logs, receipts, source identity and artifact hashes.
Verify provenance and checksums before local APK and GPG signing; see the
[release procedure](RELEASE.md). Publication requires owner review.
