#!/bin/sh
set -eu
umask 077
[ "${FOXHOLE_DISPOSABLE_TEST:-}" = 1 ] || {
  echo 'Run only in a disposable OpenWrt VM with FOXHOLE_DISPOSABLE_TEST=1' >&2
  exit 2
}
[ "$#" -ge 2 ] || { echo 'Usage: clean-install.sh BUNDLE MANIFEST_SHA256 [--ram]' >&2; exit 2; }
[ -r /etc/openwrt_release ] && [ "$(id -u)" = 0 ]
! apk info -e foxhole-openwrt-client >/dev/null 2>&1
[ ! -e /etc/foxhole/state.json ]
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
bundle=$1
manifest=$2
shift 2
stage=$(mktemp -d /tmp/foxhole-clean-test.XXXXXX)
trap 'rm -rf "$stage"' EXIT
cp /etc/config/network "$stage/network"
cp /etc/config/dhcp "$stage/dhcp"
cp /etc/config/firewall "$stage/firewall"
sh "$root/install.sh" --bundle "$bundle" --manifest-sha256 "$manifest" \
  --apply "$@"
apk info -e foxhole-openwrt-client
for service in foxhole-runtime foxhole-history foxhole-inbound; do
  /etc/init.d/"$service" enabled
done
for file in network dhcp firewall; do
  cmp /etc/config/"$file" "$stage/$file"
done
test -s /www/foxhole.html
test -x /usr/libexec/foxhole-runtime
test "$(uci get foxhole.panel.mode)" = runtime
ubus -t 10 list foxhole | grep -qx foxhole
hysteria version
echo 'Clean APK install and configuration-preservation smoke passed.'
echo 'VPN traffic, reboot, WAN isolation and load need separate acceptance.'
