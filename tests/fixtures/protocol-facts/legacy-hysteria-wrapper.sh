#!/bin/sh
set -eu
umask 077

[ "$(uname -m)" = aarch64 ] || {
	echo 'Hysteria RAM package requires ARM64' >&2
	exit 1
}
cache=/tmp/foxhole-hysteria
digest=ebfacc1ec3a0edfd742cd68ce17f292a6092e606b9d11f99b035c1d888f3d709
url=https://github.com/HyNetworks/hysteria/releases/download/app%2Fv2.12.2/hysteria-linux-arm64

[ ! -L "$cache" ] || exit 1
mkdir -p "$cache"
chmod 700 "$cache"

valid() {
	[ -f "$cache/hysteria" ] && [ ! -L "$cache/hysteria" ] &&
		printf '%s  %s\n' "$digest" "$cache/hysteria" |
		sha256sum -c - >/dev/null 2>&1
}

(
	flock -x 9
	valid && exit 0
	[ "$(awk '/MemAvailable:/{print $2}' /proc/meminfo)" -ge 49152 ] || {
		echo 'Insufficient free RAM for Hysteria download' >&2
		exit 1
	}
	partial="$cache/download.$$"
	trap 'rm -f "$partial"' EXIT HUP INT TERM
	ulimit -f 65536
	uclient-fetch -4 -T 60 -O "$partial" "$url" >/dev/null 2>&1 || {
		echo 'Hysteria download failed' >&2
		exit 1
	}
	printf '%s  %s\n' "$digest" "$partial" |
		sha256sum -c - >/dev/null 2>&1 || {
		echo 'Hysteria checksum mismatch' >&2
		exit 1
	}
	chmod 700 "$partial"
	mv "$partial" "$cache/hysteria"
) 9>"$cache/lock"

exec "$cache/hysteria" "$@"
