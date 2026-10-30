#!/usr/bin/env bash
set -euo pipefail
# Same source and build recipe as the qualified lab tools.
work=$(mktemp -d "${RUNNER_TEMP:?}/foxhole-ucode.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  cmake build-essential libjson-c-dev libssl-dev libmd-dev pkg-config zstd
curl --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' --connect-timeout 20 \
  --max-time 120 --max-filesize 8388608 \
  --output "$work/source.tar.zst" \
  'https://sources.openwrt.org/ucode-2026.01.16~85922056.tar.zst'
printf '%s  %s\n' \
  8c6f586f90e704827dc8736bf3726d15989a978c6a726a52d51e33f8019403b6 \
  "$work/source.tar.zst" | sha256sum -c -
mkdir "$work/source"
tar --zstd -xf "$work/source.tar.zst" -C "$work/source" \
  --strip-components=1
cmake -S "$work/source" -B "$work/build" \
  -DCMAKE_BUILD_TYPE=Release -DNL80211_SUPPORT=OFF -DRTNL_SUPPORT=OFF \
  -DUBUS_SUPPORT=OFF -DUCI_SUPPORT=OFF -DULOOP_SUPPORT=OFF \
  -DLOG_SUPPORT=OFF -DDEBUG_SUPPORT=OFF -DDIGEST_SUPPORT=ON
cmake --build "$work/build" -j2
sudo cmake --install "$work/build"
sudo ldconfig
/usr/local/bin/ucode -e 'import * as fs from "fs"; if (type(fs.open) != "function") die("fs module missing"); print("pinned ucode fs ready\n");'
printf '%s\n' /usr/local/bin >> "${GITHUB_PATH:?}"
