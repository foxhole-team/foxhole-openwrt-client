# Command reference

## Installer

Run on the supported OpenWrt target as root. Authenticate `SHA256SUMS`
independently and replace `HASH` with its SHA-256. For GitHub downloads,
use the verified one-command bootstrap in the [README](../README.md).

```sh
sh install.sh --help
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --ram --apply
```

| Option | Meaning |
| --- | --- |
| `--bundle DIR` | Local APKs and `SHA256SUMS`. |
| `--base-url HTTPS_URL` | Release asset directory; mutually exclusive with `--bundle`. |
| `--manifest-sha256 HASH` | Required authenticated manifest hash. |
| `--apply` | Back up, then install; otherwise update APK indexes and simulate. |
| `--ram` | Explicit volatile engine storage; default is flash. |
| `--development` | Bypass APK signatures for isolated manifest-pinned testing. |

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
also runs source and installer regressions. With an authenticated GitHub
CLI, inspect remote runs:

```sh
gh run list --repo foxhole-team/foxhole-openwrt-client --workflow ci.yml
gh run view RUN_ID --repo foxhole-team/foxhole-openwrt-client --exit-status
```

To request checks or an unsigned build on a reviewed, published ref:

```sh
gh workflow run ci.yml --repo foxhole-team/foxhole-openwrt-client --ref REVIEWED_REF
gh workflow run build-apk.yml --repo foxhole-team/foxhole-openwrt-client --ref REVIEWED_REF
```

Dispatch acceptance is not build success. Inspect the resulting run; the
APK workflow uploads artifacts and does not publish a release.
