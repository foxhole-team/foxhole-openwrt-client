#!/bin/sh
set -eu
umask 022

[ "$(uname -s):$(uname -m)" = Linux:x86_64 ] || {
  echo 'Build host must be Linux x86_64 (native or disposable container)' >&2
  exit 1
}
for tool in curl sha256sum tar zstd make git python3 openssl; do command -v "$tool" >/dev/null; done
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
out=${1:-"$root/dist/openwrt-25.12.5-arm64"}
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
go_url=https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
go_hash=2852af0cb20a13139b3448992e69b868e50ed0f8a1e5940ee1de9e19a123b613
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
./scripts/feeds install -f -p foxhole hysteria hysteria-ram foxhole-openwrt-client
cat > .config <<'EOF'
# CONFIG_ALL is not set
# CONFIG_ALL_NONSHARED is not set
# CONFIG_ALL_KMODS is not set
# CONFIG_SIGNED_PACKAGES is not set
CONFIG_PACKAGE_hysteria=m
CONFIG_PACKAGE_hysteria-ram=m
CONFIG_PACKAGE_foxhole-openwrt-client=m
EOF
make defconfig
for option in ALL ALL_NONSHARED ALL_KMODS SIGNED_PACKAGES; do
  if grep -Eq "^CONFIG_$option=[ym]$" .config; then
    echo "Unexpected SDK option: $option" >&2
    exit 1
  fi
done
grep -Eq '^CONFIG_PACKAGE_kmod-tun=[ym]$' .config
for package in hysteria hysteria-ram foxhole-openwrt-client; do
  grep -qx "CONFIG_PACKAGE_$package=m" .config
  make -j2 "package/feeds/foxhole/$package/compile" CONFIG_SIGNED_PACKAGES= V=s
done
mkdir -p "$out"
find bin/packages -type f \( -name 'foxhole-openwrt-client-*.apk' \
  -o -name 'hysteria-*.apk' \) -exec cp '{}' "$out/" \;
cp "$root/install.sh" "$out/"
test -f "$out/foxhole-openwrt-client-0.1.0-r41.apk"
test -f "$out/hysteria-ram-2.12.2-r1.apk"
test -f "$out/hysteria-2.12.2-r2.apk"
cp .config "$out/sdk.config"
cp "$root/tools/feeds.conf" "$out/feeds.buildinfo"
PYTHONDONTWRITEBYTECODE=1 python3 "$root/tools/check-apk-signing.py" \
  --apk "$scratch/sdk/staging_dir/host/bin/apk" --input "$out"
(cd "$out" && sha256sum ./*.apk install.sh sdk.config feeds.buildinfo |
  sed 's|  \./|  |' > SHA256SUMS)
echo "Unsigned APK bundle: $out"
echo 'Run clean VM acceptance before signing or publishing.'
