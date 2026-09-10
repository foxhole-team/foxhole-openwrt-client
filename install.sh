#!/bin/sh
set -eu
umask 077

base_url=''
bundle=''
manifest_hash=''
mode=flash
apply=0
development=0
while [ "$#" -gt 0 ]; do
 case "$1" in
  --base-url) base_url=${2:?}; shift 2 ;;
  --bundle) bundle=${2:?}; shift 2 ;;
  --manifest-sha256) manifest_hash=${2:?}; shift 2 ;;
  --ram) mode=ram; shift ;;
  --apply) apply=1; shift ;;
  --development) development=1; shift ;;
  --help|-h)
   echo 'Usage: sh install.sh --bundle DIR|--base-url HTTPS_URL --manifest-sha256 HASH [--ram] [--apply] [--development]'
   echo 'Default: persistent flash. --ram explicitly selects volatile Hysteria storage.'
   exit 0 ;;
  *) echo 'Unknown option; use --help' >&2; exit 2 ;;
 esac
done
if [ -n "$bundle" ] && [ -n "$base_url" ]; then
 echo 'Choose either --bundle or --base-url' >&2; exit 2
fi
if [ -z "$bundle" ]; then
 case "$base_url" in https://*) ;; *) echo 'HTTPS release URL required' >&2; exit 2 ;; esac
fi
[ "$(id -u)" = 0 ] || { echo 'Run on the router as root' >&2; exit 1; }
[ -r /etc/openwrt_release ] || exit 1
. /etc/openwrt_release
case "$DISTRIB_RELEASE" in 25.12.*) ;; *) echo 'This installer currently requires OpenWrt 25.12 APK' >&2; exit 1 ;; esac
[ "$(uname -m)" = aarch64 ] || { echo 'ARM64 artifacts required' >&2; exit 1; }
command -v apk >/dev/null
command -v sha256sum >/dev/null
case "$manifest_hash" in ''|*[!a-fA-F0-9]*) echo 'Trusted manifest SHA256 required' >&2; exit 1 ;; esac
[ "${#manifest_hash}" = 64 ] || exit 1
[ -z "$(uci changes)" ] || { echo 'Commit or revert pending UCI changes first' >&2; exit 1; }

flash=$(df -Pk /overlay | awk 'NR==2 {print $4}')
ram=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
case "$flash:$ram" in *[!0-9:]*|:*|*:) echo 'Resource counters unavailable' >&2; exit 1 ;; esac
minimum=32768
minimum_ram=49152
if [ "$mode" = ram ]; then minimum=4096; minimum_ram=98304; fi
if [ "$flash" -lt "$minimum" ]; then
 echo 'Insufficient flash; no automatic fallback and no packages changed.' >&2
 [ "$mode" != flash ] || echo 'If RAM permits, explicitly re-run with --ram.' >&2
 exit 1
fi
if [ "$ram" -lt "$minimum_ram" ]; then
 echo "Mode $mode needs at least $minimum_ram KiB available RAM; nothing installed" >&2
 exit 1
fi
arch=$(apk --print-arch)
[ "$arch" = aarch64_generic ] || { echo 'This bundle requires aarch64_generic' >&2; exit 1; }

stage=$(mktemp -d /tmp/foxhole-install.XXXXXX)
keep_stage=0
trap '[ "$keep_stage" = 1 ] || rm -rf "$stage"' EXIT
echo "Private installation stage: $stage"
fetch() {
 name=$1
 if [ -n "$bundle" ]; then
  [ -f "$bundle/$name" ] && [ ! -L "$bundle/$name" ] || exit 1
  cp "$bundle/$name" "$stage/$name"
 else
  case "$base_url" in https://*) ;; *) echo 'HTTPS release URL required' >&2; exit 1 ;; esac
  uclient-fetch -q -T 60 -O "$stage/$name" "${base_url%/}/$name"
 fi
}
fetch SHA256SUMS
printf '%s  %s\n' "$manifest_hash" "$stage/SHA256SUMS" | sha256sum -c - >/dev/null
panel=foxhole-openwrt-client-0.1.0-r41.apk
engine=hysteria-ram-2.12.2-r1.apk
[ "$mode" != flash ] || engine=hysteria-2.12.2-r2.apk
for file in "$engine" "$panel"; do
 fetch "$file"
 hash=$(awk -v name="$file" '$2==name {print $1}' "$stage/SHA256SUMS")
 [ "${#hash}" = 64 ] || { echo 'Artifact missing from trusted manifest' >&2; exit 1; }
 printf '%s  %s\n' "$hash" "$stage/$file" | sha256sum -c - >/dev/null
done
trust=''
if [ "$development" = 1 ]; then
 trust=--allow-untrusted
 echo 'Development artifacts: manifest pinned; package signatures bypassed explicitly'
fi
apk update
apk add --simulate $trust "$stage/$engine" "$stage/$panel"
echo "Validated mode=$mode flash_kib=$flash available_ram_kib=$ram"
[ "$apply" = 1 ] || { echo 'Check only; use --apply to install'; exit 0; }
keep_stage=1
sysupgrade -k -b "$stage/sysupgrade-before.tar.gz"
cp -p /etc/config/dhcp "$stage/dhcp.before"
if [ -d /etc/foxhole ]; then tar -czf "$stage/foxhole-before.tar.gz" -C /etc foxhole; fi
if ! apk add $trust "$stage/$engine" "$stage/$panel"; then
 echo "Installation failed; preserve $stage for recovery. Existing VPN was not intentionally removed." >&2
 exit 1
fi
cmp -s /etc/config/dhcp "$stage/dhcp.before" || {
 echo 'DHCP changed during installation; inspect the backup before continuing' >&2
 exit 1
}
echo 'Package installed. Set a non-default panel PIN and import a server profile.'
echo 'Inbound listener provisioning and firmware reboot acceptance remain separate steps.'
