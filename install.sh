#!/bin/sh
set -eu
umask 077

show_license() {
 cat <<'FOXHOLE_LICENSE_V1'
FoxHole OpenWRT Client · license agreement (version 1)

1. The package must be used strictly in accordance with applicable law.

2. FoxHole OpenWRT Client is not antivirus software and does not guarantee detection or neutralization of executable malicious files.

3. The developers are not liable for possible damage arising from use of the package.

4. Use of the package constitutes full acceptance of the license terms of all its internal components and data sets.

5. By continuing, you confirm your agreement with every provision of this agreement.
FOXHOLE_LICENSE_V1
}

base_url=''
bundle=''
manifest_hash=''
mode=flash
requested_mode=''
apply=0
license_accepted=0
development=0
protocols=''
all_protocols=0
include_server=0
server_intent=0
apk_key=foxhole-openwrt-apk.pem
public_sha256=fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1
while [ "$#" -gt 0 ]; do
 case "$1" in
  --base-url) base_url=${2:?}; shift 2 ;;
  --bundle) bundle=${2:?}; shift 2 ;;
  --manifest-sha256) manifest_hash=${2:?}; shift 2 ;;
  --flash|--ram|--auto)
   next_mode=${1#--}
   if [ -n "$requested_mode" ] && [ "$requested_mode" != "$next_mode" ]; then
    echo 'Choose one storage mode: --flash, --ram or --auto' >&2; exit 2
   fi
   mode=$next_mode
   requested_mode=$next_mode
   shift ;;
  --apply) apply=1; shift ;;
  --accept-license) license_accepted=1; shift ;;
  --license) show_license; exit 0 ;;
  --server) include_server=1; server_intent=1; shift ;;
  --development) development=1; shift ;;
  --legacy-hy2) echo 'Historical legacy installer is not qualified for Stable; use the verified Core installer' >&2; exit 2 ;;
  --hy2) protocols="${protocols}hysteria2,"; shift ;;
  --wg|-wg) protocols="${protocols}wireguard,"; shift ;;
  --vless|--vmess|--tuic|--trojan|--shadowsocks|--naive|--anytls|--shadowtls|--socks|--http)
   protocols="$protocols${1#--},"; shift ;;
  --all) all_protocols=1; shift ;;
  --help|-h)
   echo 'Usage: sh install.sh --bundle DIR|--base-url HTTPS_URL --manifest-sha256 HASH [--hy2 --vless --wg|--all] [--flash|--ram|--auto] [--server] [--apply --accept-license]'
   echo 'Default: Hysteria2 only, persistent flash. Exact verified release variant required.'
   echo 'Read the license agreement with --license. Installation requires explicit acceptance.'
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
case "$manifest_hash" in ''|*[!a-fA-F0-9]*) echo 'Trusted manifest SHA256 required' >&2; exit 1 ;; esac
[ "${#manifest_hash}" = 64 ] || exit 1
if [ "$apply" = 1 ] && [ "$license_accepted" != 1 ]; then
 show_license >&2
 if [ -t 0 ] && [ -t 1 ]; then
  printf 'Accept the license agreement? [y/N] ' >&2
  IFS= read -r answer || answer=''
  case "$answer" in y|Y|yes|YES) license_accepted=1 ;; esac
 fi
 [ "$license_accepted" = 1 ] || { echo 'License agreement not accepted; read --license, then use --accept-license to install' >&2; exit 2; }
fi
stage=$(mktemp -d /tmp/foxhole-bootstrap.XXXXXX)
trap 'rm -rf "$stage"' EXIT
fetch_small() {
 name=$1
 case "$name" in SHA256SUMS|package-catalog.json|install-core.sh|install-compact.sh) ;; *) exit 1 ;; esac
 if [ -n "$bundle" ]; then
  [ -f "$bundle/$name" ] && [ ! -L "$bundle/$name" ] || exit 1
  [ "$(wc -c < "$bundle/$name")" -le 2097152 ] || exit 1
  cp "$bundle/$name" "$stage/$name"
 else
  (ulimit -f 4096
   uclient-fetch -q -T 60 -O "$stage/$name" "${base_url%/}/$name")
 fi
 [ "$(wc -c < "$stage/$name")" -le 2097152 ] || exit 1
}
verify_small() {
 hash=$(awk -v name="$1" '$2==name {print $1}' "$stage/SHA256SUMS")
 case "$hash" in *[!a-f0-9]*) exit 1 ;; esac
 [ "${#hash}" = 64 ] || exit 1
 printf '%s  %s\n' "$hash" "$stage/$1" | sha256sum -c - >/dev/null
}
fetch_small SHA256SUMS
printf '%s  %s\n' "$manifest_hash" "$stage/SHA256SUMS" | sha256sum -c - >/dev/null
fetch_small package-catalog.json
verify_small package-catalog.json
command -v ucode >/dev/null
contract=$(ucode -e '
 import * as fs from "fs";
 let p=ARGV[0],s=fs.lstat(p);
 if(s?.type!="file" || s.size<=0 || s.size>524288)exit(1);
 let v=json(fs.readfile(p,524289));
 if(type(v.schema)!="int")exit(1);
 if(v.schema==1)print("legacy");
 else if(v.schema==2 && v.kind=="compact-client-engines-v1")print("compact");
 else exit(1);
' -- "$stage/package-catalog.json")
case "$contract" in
 legacy)
  [ "$server_intent" = 0 ] || { echo 'Explicit server selection requires a compact catalog' >&2; exit 2; }
  script=install-core.sh ;;
 compact) script=install-compact.sh ;;
 *) exit 1 ;;
esac
fetch_small "$script"
verify_small "$script"
protocols=${protocols%,}
[ "$all_protocols" = 0 ] || protocols=all
protocols=${protocols:-hysteria2}
if [ "$contract" = compact ]; then
 sh "$stage/$script" --bundle "$bundle" --base-url "$base_url" \
  --manifest-sha256 "$manifest_hash" --mode "$mode" --protocols "$protocols" \
  --apply "$apply" --license-accepted "$license_accepted" --development "$development" --include-server "$include_server"
else
 sh "$stage/$script" --bundle "$bundle" --base-url "$base_url" \
  --manifest-sha256 "$manifest_hash" --mode "$mode" --protocols "$protocols" \
  --apply "$apply" --license-accepted "$license_accepted" --development "$development"
fi
exit "$?"
