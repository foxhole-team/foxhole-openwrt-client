#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  echo 'Run this installer with Bash.' >&2
  exit 2
fi
set -euo pipefail
export LC_ALL=C

usage() {
  cat <<'HELP'
Usage: bash foxhole-openwrt-install.sh --release TAG --manifest-sha256 HASH
       --installer-sha256 HASH [--host IPV4] [--flash|--ram|--auto]
       [--no-auto-update]

Connects over SSH to the selected OpenWrt router. The preferred IPv4
gateway is used if --host is omitted. FLASH is the default storage.
Verify the release manifest and router installer hashes independently.
HELP
}

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 2
}

valid_ipv4() {
  local address=$1 octet
  local -a octets
  [[ $address =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -r -a octets <<< "$address"
  for octet in "${octets[@]}"; do
    [[ $octet == 0 || $octet != 0* ]] || return 1
    (( octet <= 255 )) || return 1
  done
  (( octets[0] > 0 && octets[0] != 127 && octets[0] < 224 ))
}

default_gateway() {
  local system routes best='' best_metric=0 candidate metric i
  local -a fields
  system=$(uname -s) || return 1
  case $system in
    Darwin) routes=$(route -n get -inet default 2>/dev/null) || return 1 ;;
    Linux) routes=$(ip -4 route show default 2>/dev/null) || return 1 ;;
    MINGW*|MSYS*|CYGWIN*) routes=$(route.exe print -4 2>/dev/null) || return 1 ;;
    *) return 1 ;;
  esac
  while IFS=$' \t\r' read -r -a fields; do
    candidate='' metric=0
    case $system in
      Darwin)
        [[ ${fields[0]-} == gateway: ]] || continue
        candidate=${fields[1]-}
        ;;
      Linux)
        [[ ${fields[0]-} == default && ${fields[1]-} == via ]] || continue
        candidate=${fields[2]-}
        for (( i=3; i<${#fields[@]}; i++ )); do
          if [[ ${fields[i]} == metric ]]; then
            metric=${fields[i+1]-}
            break
          fi
        done
        ;;
      *)
        [[ ${fields[0]-} == 0.0.0.0 && ${fields[1]-} == 0.0.0.0 ]] || continue
        candidate=${fields[2]-}
        metric=${fields[4]-}
        ;;
    esac
    valid_ipv4 "$candidate" || continue
    [[ $metric =~ ^[0-9]{1,10}$ ]] || continue
    metric=$((10#$metric))
    if [[ -z $best ]] || (( metric < best_metric )); then
      best=$candidate
      best_metric=$metric
    fi
  done <<< "$routes"
  [[ -n $best ]] || return 1
  printf '%s\n' "$best"
}

host='' release_tag='' manifest_hash='' installer_hash='' storage='' auto_update=1
while (( $# > 0 )); do
  case $1 in
    --help|-h) usage; exit 0 ;;
    --flash|--ram|--auto)
      [[ -z $storage ]] || fail 'Choose one storage mode: --flash, --ram or --auto.'
      storage=$1
      shift
      continue
      ;;
    --no-auto-update) auto_update=0; shift; continue ;;
  esac
  option=${1%%=*}
  case $option in
    --host|--release|--manifest-sha256|--installer-sha256) ;;
    *) fail 'Unknown option. Run with --help.' ;;
  esac
  if [[ $1 == *=* ]]; then
    value=${1#*=}
    shift
  else
    (( $# >= 2 )) || fail "Missing value for $option."
    value=$2
    shift 2
  fi
  case $option in
    --host) valid_ipv4 "$value" || fail 'Enter a valid IPv4 router address.'; host=$value ;;
    --release) release_tag=$value ;;
    --manifest-sha256) manifest_hash=$value ;;
    --installer-sha256) installer_hash=$value ;;
  esac
done

[[ $release_tag =~ ^v(0|[1-9][0-9]{0,5})(\.(0|[1-9][0-9]{0,5})){2}(-r[1-9][0-9]{0,5})?$ ]] ||
  fail 'Enter the verified release tag.'
[[ $manifest_hash =~ ^[a-fA-F0-9]{64}$ && $installer_hash =~ ^[a-fA-F0-9]{64}$ ]] ||
  fail 'Enter both independently verified SHA-256 values.'
manifest_hash=$(printf '%s' "$manifest_hash" | tr 'A-F' 'a-f')
installer_hash=$(printf '%s' "$installer_hash" | tr 'A-F' 'a-f')
if [[ -z $host ]]; then
  host=$(default_gateway) || fail 'Specify the OpenWrt router IPv4 address with --host.'
fi
command -v ssh >/dev/null || fail 'The OpenSSH client is required.'

# Only validated tokens enter the remote shell header.
read -r -d '' install_on_router <<'ROUTER' || :
set -eu
if [ ! -r /etc/openwrt_release ]; then
  echo 'The selected SSH host is not an OpenWrt router.' >&2; exit 1
fi
. /etc/openwrt_release
if [ "${DISTRIB_ID:-}" != OpenWrt ]; then
  echo 'The selected SSH host is not an OpenWrt router.' >&2; exit 1
fi
url="https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/$release_tag"
installer=$(mktemp /tmp/foxhole-install.XXXXXX)
trap 'rm -f "$installer"' EXIT
uclient-fetch -q -T 60 -O "$installer" "$url/install.sh"
printf '%s  %s\n' "$installer_hash" "$installer" | sha256sum -c -
set -- "$storage"
if [ "$auto_update" = 0 ]; then set -- "$@" --no-auto-update; fi
sh "$installer" --base-url "$url" --manifest-sha256 "$manifest_hash" "$@" --apply
ROUTER
printf -v remote "release_tag='%s'\nmanifest_hash='%s'\ninstaller_hash='%s'\nstorage='%s'\nauto_update='%s'\n%s\n" \
  "$release_tag" "$manifest_hash" "$installer_hash" "${storage:---flash}" "$auto_update" "$install_on_router"
printf 'Connecting to the OpenWrt router over SSH at %s\n' "$host" >&2
MSYS2_ARG_CONV_EXCL='*' exec ssh -tt -o ConnectTimeout=10 -o StrictHostKeyChecking=ask \
  -o ClearAllForwardings=yes -- "root@$host" "$remote"
