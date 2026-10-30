#!/bin/sh
set -eu
umask 022
descriptor_limit=$(ulimit -n)
case "$descriptor_limit" in
  unlimited) ulimit -n 4096 ;;
  *) [ "$descriptor_limit" -le 4096 ] || ulimit -n 4096 ;;
esac

[ "$(uname -s):$(uname -m)" = Linux:x86_64 ] || {
  echo 'Build host must be Linux x86_64 (native or disposable container)' >&2
  exit 1
}
for tool in curl sha256sum tar zstd make git python3 openssl; do command -v "$tool" >/dev/null; done
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
target=arm64
core_input=''
core_source=''
requested=''
all_protocols=0
core_download=''
core_ram_reserve=''
server_input=''
server_download=''
server_ram_reserve=''
out=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --target) target=${2:?}; shift 2 ;;
    --core-input) core_input=${2:?}; shift 2 ;;
    --core-source-sha256) core_source=${2:?}; shift 2 ;;
    --core-download-url) core_download=${2:?}; shift 2 ;;
    --core-ram-reserve-bytes) core_ram_reserve=${2:?}; shift 2 ;;
    --server-input) server_input=${2:?}; shift 2 ;;
    --server-download-url) server_download=${2:?}; shift 2 ;;
    --server-ram-reserve-bytes) server_ram_reserve=${2:?}; shift 2 ;;
    --wg|-wg) requested="${requested}wireguard,"; shift ;;
    --hy2) requested="${requested}hysteria2,"; shift ;;
    --vless|--vmess|--tuic|--trojan|--shadowsocks|--naive|--anytls|--shadowtls|--socks|--http)
      requested="$requested${1#--},"; shift ;;
    --all) all_protocols=1; shift ;;
    --*) echo 'Unknown build option' >&2; exit 2 ;;
    *)
       [ -z "$out" ] || {
         echo 'One output directory required' >&2; exit 2
       }
       out=$1; shift ;;
  esac
done
[ "$all_protocols" = 0 ] || requested=all
if [ -n "$core_download" ]; then
  [ -n "$core_input" ] && [ -n "$core_source" ] && [ -n "$core_ram_reserve" ] || {
    echo 'Core RAM requires verified producer inputs, URL and working reserve' >&2; exit 2
  }
fi
case "$target" in arm64|x86_64|filogic) ;; *) echo 'Unsupported SDK target' >&2; exit 2 ;; esac
architecture=aarch64
[ "$target" != x86_64 ] || architecture=x86_64
if [ -n "$server_input" ]; then
  case "$server_input" in /*) ;; *) server_input="$PWD/$server_input" ;; esac
  if [ -n "$server_download" ]; then
    python3 "$root/tools/check-hysteria-package-input.py" --input "$server_input" \
      --architecture "$architecture" --download-url "$server_download" \
      --ram-reserve-bytes "$server_ram_reserve"
  else
    [ -z "$server_ram_reserve" ] || { echo 'Server reserve requires a pinned RAM URL' >&2; exit 2; }
    python3 "$root/tools/check-hysteria-package-input.py" --input "$server_input" --architecture "$architecture"
  fi
elif [ -n "$server_download" ] || [ -n "$server_ram_reserve" ]; then
  echo 'Server RAM requires a verified native producer' >&2; exit 2
fi
if [ -n "$core_input" ]; then
  [ -n "$core_source" ] || { echo 'Core producer source digest required' >&2; exit 2; }
  case "$core_input" in /*) ;; *) core_input="$PWD/$core_input" ;; esac
  architecture=aarch64
  [ "$target" != x86_64 ] || architecture=x86_64
  python3 "$root/tools/check-core-package-input.py" --input "$core_input" \
    --architecture "$architecture" --version 1.0.1 --source-sha256 "$core_source"
  python3 - "$core_input/core-producer.json" "$requested" <<'PY'
import json, sys
protocols = set(json.load(open(sys.argv[1]))['protocols'])
requested = sys.argv[2] or 'hysteria2,'
expected = {'vless','vmess','hysteria2','tuic','trojan','shadowsocks',
            'wireguard','naive','anytls','shadowtls','socks','http'} if requested == 'all' else set(filter(None, requested.split(',')))
assert protocols == expected, 'Core producer protocols do not match requested build'
PY
elif [ -n "$requested" ] || [ -n "$core_source" ]; then
  echo 'Protocol selection requires genuine Core producer inputs' >&2; exit 2
fi
out=${out:-"$root/dist/openwrt-25.12.5-$target"}
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac
[ ! -e "$out" ] || { echo 'Output directory must be new' >&2; exit 1; }
scratch=$(mktemp -d /tmp/foxhole-sdk.XXXXXX)
cleanup() {
  status=$?
  trap - EXIT
  # Go module cache directories are read-only after extraction.
  if ! chmod -R u+w "$scratch" || ! rm -rf "$scratch"; then
    [ "$status" -ne 0 ] || status=1
  fi
  exit "$status"
}
trap cleanup EXIT
sdk_url=https://downloads.openwrt.org/releases/25.12.5/targets/armsr/armv8/openwrt-sdk-25.12.5-armsr-armv8_gcc-14.3.0_musl.Linux-x86_64.tar.zst
sdk_hash=1b0316604a3e820b2b008a1baff3f9dac6716af942bef800930e58c7de98c98b
if [ "$target" = x86_64 ]; then
  sdk_url=https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/openwrt-sdk-25.12.5-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst
  sdk_hash=0c8df0151a1e88feb7c03d694d61f6a18d51872815b7c811d76e2b77504d5e9c
fi
if [ "$target" = filogic ]; then
  sdk_url=https://downloads.openwrt.org/releases/25.12.5/targets/mediatek/filogic/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64.tar.zst
  sdk_hash=ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25
fi
go_url=https://go.dev/dl/go1.26.10.linux-amd64.tar.gz
go_hash=ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5
fetch() {
  curl --fail --location --proto '=https' --proto-redir '=https' \
    --retry 3 --connect-timeout 20 --max-time 900 -o "$scratch/$3" "$1"
  printf '%s  %s\n' "$2" "$scratch/$3" | sha256sum -c -
}
fetch "$sdk_url" "$sdk_hash" sdk.tar.zst
fetch "$go_url" "$go_hash" go.tar.gz
mkdir "$scratch/sdk"
tar --zstd -xf "$scratch/sdk.tar.zst" -C "$scratch/sdk" --strip-components=1
tar -xzf "$scratch/go.tar.gz" -C "$scratch"
cp "$root/tools/feeds.conf" "$scratch/sdk/feeds.conf"
printf 'src-link foxhole %s/package\n' "$root" >> "$scratch/sdk/feeds.conf"
export SOURCE_DATE_EPOCH=1788825600
export GOTOOLCHAIN=local
export FOXHOLE_GO="$scratch/go/bin/go"
cd "$scratch/sdk"
./scripts/feeds update -a
packages='hysteria foxhole-openwrt-client'
[ -z "$core_input" ] || packages="$packages foxcore-cli"
[ -z "$core_download" ] || packages="$packages foxcore-cli-ram"
[ -z "$server_download" ] || packages="$packages hysteria-server-ram"
./scripts/feeds install -f -p foxhole $packages
cat > .config <<'EOF'
# CONFIG_ALL is not set
# CONFIG_ALL_NONSHARED is not set
# CONFIG_ALL_KMODS is not set
# CONFIG_SIGNED_PACKAGES is not set
CONFIG_PACKAGE_hysteria=m
CONFIG_PACKAGE_foxhole-openwrt-client=m
EOF
[ -z "$core_input" ] || echo CONFIG_PACKAGE_foxcore-cli=m >> .config
[ -z "$core_download" ] || echo CONFIG_PACKAGE_foxcore-cli-ram=m >> .config
[ -z "$server_download" ] || echo CONFIG_PACKAGE_hysteria-server-ram=m >> .config
make defconfig
for option in ALL ALL_NONSHARED ALL_KMODS SIGNED_PACKAGES; do
  if grep -Eq "^CONFIG_$option=[ym]$" .config; then
    echo "Unexpected SDK option: $option" >&2
    exit 1
  fi
done
grep -Eq '^CONFIG_PACKAGE_kmod-tun=[ym]$' .config
for package in $packages; do
  grep -qx "CONFIG_PACKAGE_$package=m" .config
  make -j2 "package/feeds/foxhole/$package/compile" CONFIG_SIGNED_PACKAGES= \
    FOXCORE_PACKAGE_INPUT="$core_input" FOXCORE_SOURCE_SHA256="$core_source" \
    FOXCORE_DOWNLOAD_URL="$core_download" FOXCORE_RAM_RESERVE_BYTES="$core_ram_reserve" \
    HYSTERIA_PACKAGE_INPUT="$server_input" HYSTERIA_DOWNLOAD_URL="$server_download" \
    HYSTERIA_RAM_RESERVE_BYTES="$server_ram_reserve" V=s
done
mkdir -p "$out"
find bin/packages -type f \( -name 'foxhole-openwrt-client-*.apk' \
  -o -name 'hysteria-*.apk' -o -name 'foxcore-cli-*.apk' \) -exec cp '{}' "$out/" \;
cp "$root/install.sh" "$out/"
test -f "$out/foxhole-openwrt-client-1.0.1-r1.apk"
if find "$out" -name 'hysteria-ram-*.apk' | grep -q .; then
  echo 'Historical unqualified Hysteria RAM package cannot enter a Stable bundle' >&2
  exit 1
fi
[ -z "$core_input" ] || test -f "$out/foxcore-cli-1.0.0-r1.apk"
[ -z "$core_download" ] || test -f "$out/foxcore-cli-ram-1.0.0-r1.apk"
[ -z "$server_download" ] || test -f "$out/hysteria-server-ram-2.12.2-r2.apk"
test -f "$out/hysteria-2.12.2-r5.apk"
cp .config "$out/sdk.config"
cp "$root/tools/feeds.conf" "$out/feeds.buildinfo"
PYTHONDONTWRITEBYTECODE=1 python3 "$root/tools/check-apk-signing.py" \
  --apk "$scratch/sdk/staging_dir/host/bin/apk" --input "$out"
(cd "$out" && sha256sum ./*.apk install.sh sdk.config feeds.buildinfo |
  sed 's|  \./|  |' > SHA256SUMS)
echo "Unsigned APK bundle: $out"
echo 'Run clean VM acceptance before signing or publishing.'
