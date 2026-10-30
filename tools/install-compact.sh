#!/bin/sh
set -eu
umask 077

file_info() {
 ucode -e '
  import * as fs from "fs";
  let info = fs.lstat(ARGV[1]);
  if (!info) exit(1);
  let mode = sprintf("%o", info.mode & 07777);
  switch (ARGV[0]) {
   case "%u": print(info.uid); break;
   case "%u:%a": print(info.uid + ":" + mode); break;
   case "%u:%a:%h": print(info.uid + ":" + mode + ":" + info.nlink); break;
   case "%u:%a:%h:%s": print(info.uid + ":" + mode + ":" + info.nlink + ":" + info.size); break;
   case "%F:%u:%a": print(info.type + ":" + info.uid + ":" + mode); break;
   default: exit(1);
  }
 ' -- "$1" "$2"
}


bundle='' base_url='' manifest_hash='' mode=flash protocols=hysteria2 apply=0 license_accepted=0 development=0 include_server=0
while [ "$#" -gt 0 ]; do
 case "$1" in
  --bundle) bundle=${2-}; shift 2 ;;
  --base-url) base_url=${2-}; shift 2 ;;
  --manifest-sha256) manifest_hash=${2:?}; shift 2 ;;
  --mode) mode=${2:?}; shift 2 ;;
  --protocols) protocols=${2:?}; shift 2 ;;
  --apply) apply=${2:?}; shift 2 ;;
  --license-accepted) license_accepted=${2:?}; shift 2 ;;
  --include-server) include_server=${2:?}; shift 2 ;;
  --development) development=${2:?}; shift 2 ;;
  *) echo 'Unsupported Core installer option' >&2; exit 2 ;;
 esac
done
[ "$(id -u)" = 0 ] || exit 1
case "$license_accepted" in 0|1) ;; *) exit 2 ;; esac
if [ "$apply" = 1 ] && [ "$license_accepted" != 1 ]; then
 echo 'Explicit license agreement acceptance required; use install.sh --license and --accept-license' >&2
 exit 2
fi
case "$mode" in flash|ram|auto) ;; *) exit 2 ;; esac
case "$include_server" in 0|1) ;; *) exit 2 ;; esac
case "$apply:$development" in 0:0|0:1|1:0|1:1) ;; *) exit 2 ;; esac
[ -z "$(uci changes)" ] || { echo 'Commit or revert pending UCI changes first' >&2; exit 1; }
. /etc/openwrt_release
architecture=$(cat /etc/apk/arch)
target=${DISTRIB_TARGET:?OpenWrt target missing}
case "$architecture:$target" in aarch64_generic:armsr/armv8|aarch64_cortex-a53:mediatek/filogic|x86_64:x86/64) ;; *)
 echo 'No verified package target for this router' >&2; exit 1 ;; esac
for tool in apk ucode sha256sum sysupgrade; do command -v "$tool" >/dev/null; done
stage=$(mktemp -d /tmp/foxhole-core-install.XXXXXX)
keep_stage=0
transaction_phase=checking
pending_constraint=''
install_complete=false
transaction_lock=/tmp/foxhole-core-bootstrap.lock
transaction_lock_held=0
acquire_transaction_lock() {
 if ! mkdir -m 700 "$transaction_lock" 2>/dev/null; then
  echo 'Another installation is active or incomplete; inspect it before restarting the router' >&2
  return 1
 fi
 transaction_lock_held=1
}
finish() {
 code=$?
 trap - EXIT INT TERM HUP
 if [ "$keep_stage" = 1 ]; then
  printf '{"schema":1,"exitCode":%s,"phase":"%s","pendingConstraint":"%s","complete":%s}\n' \
   "$code" "$transaction_phase" "$pending_constraint" "$install_complete" > "$stage/transaction-state.json" || exit 1
  if [ "$code" != 0 ]; then
   printf 'Installation incomplete; phase: %s; private recovery files: %s\n' "$transaction_phase" "$stage" >&2
   [ -z "$pending_constraint" ] || printf 'Owned temporary constraint retained or pending: %s\n' "$pending_constraint" >&2
  fi
 else
  rm -rf "$stage" || exit 1
 fi
 if [ "$transaction_lock_held" = 1 ]; then
  if [ "$code" = 0 ]; then
   rmdir "$transaction_lock" || exit 1
  else
   echo 'Installation lock retained; inspect the private recovery files before restarting the router' >&2
  fi
 fi
 exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# Fresh bootstrap only; paired management handles upgrades.
[ ! -e /etc/foxhole ] && [ ! -L /etc/foxhole ] || { echo 'Existing FoxHole state requires paired management' >&2; exit 1; }
(ulimit -f 16384
 apk --no-network --no-cache query --from installed --installed --fields name,status --format json > "$stage/prior-owned.json")
ucode -e '
 import * as fs from "fs";
 let rows=json(fs.readfile(ARGV[0],8388609));
 if (type(rows)!="array" || length(rows)>4096) exit(1);
 for (let row in rows) if (index(["foxhole-openwrt-client","foxcore-cli","foxcore-cli-ram","hysteria","hysteria-server-ram"],row.name)>=0 || match(row.name||"",/^foxcore-engine-/)) exit(1);
' -- "$stage/prior-owned.json"
fetch() {
 name=$1
 limit_bytes=${2:-2097152}
 case "$name" in ''|*[!A-Za-z0-9_.-]*|.*) exit 1 ;; esac
 if [ -n "$bundle" ]; then
  [ -f "$bundle/$name" ] && [ ! -L "$bundle/$name" ] || exit 1
  [ "$(wc -c < "$bundle/$name")" -le "$limit_bytes" ] || exit 1
  cp "$bundle/$name" "$stage/$name"
 else
  case "$base_url" in https://*) ;; *) exit 1 ;; esac
  (ulimit -f "$(( (limit_bytes + 511) / 512 ))"
   uclient-fetch -q -T 60 -O "$stage/$name" "${base_url%/}/$name")
 fi
 [ "$(wc -c < "$stage/$name")" -le "$limit_bytes" ] || exit 1
}
verify() {
 hash=$(awk -v name="$1" '$2==name {print $1}' "$stage/SHA256SUMS")
 case "$hash" in *[!a-f0-9]*) exit 1 ;; esac
 [ "${#hash}" = 64 ] || { echo 'Incomplete authenticated release manifest' >&2; exit 1; }
 [ -z "${2-}" ] || [ "$hash" = "$2" ] || exit 1
 printf '%s  %s\n' "$hash" "$stage/$1" | sha256sum -c - >/dev/null
}
fetch SHA256SUMS
printf '%s  %s\n' "$manifest_hash" "$stage/SHA256SUMS" | sha256sum -c - >/dev/null
for name in package-catalog.json install-plan.uc install-plan-model.uc install-compact-plan.uc engine-package-layout.uc register-compact-engines.uc indexed-install.uc; do
 fetch "$name"; verify "$name"
done
ucode "$stage/install-plan.uc" select "$stage/package-catalog.json" "$architecture" \
 "$DISTRIB_RELEASE" "$protocols" "$development" "$target" "$include_server" > "$stage/metadata.list"
while read -r file digest; do fetch "$file"; verify "$file" "$digest"; done < "$stage/metadata.list"
flash=$(df -Pk /overlay | awk 'NR==2 {print $4}')
ram=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
case "$flash:$ram" in *[!0-9:]*|:*|*:) exit 1 ;; esac
backup_bytes=0
sysupgrade -l > "$stage/backup.list"
while IFS= read -r file; do
 [ -n "$file" ] || continue
 bytes=$(wc -c < "$file")
 case "$bytes" in ''|*[!0-9]*) exit 1 ;; esac
 backup_bytes=$((backup_bytes + bytes + 2048))
done < "$stage/backup.list"
if [ -e /etc/foxhole ] || [ -L /etc/foxhole ]; then
 [ -d /etc/foxhole ] && [ ! -L /etc/foxhole ] || exit 1
 private_backup=$(du -sk /etc/foxhole | awk '{print $1}')
 case "$private_backup" in ''|*[!0-9]*) exit 1 ;; esac
 backup_bytes=$((backup_bytes + private_backup * 1024 + 4096))
fi
ucode "$stage/install-compact-plan.uc" budget "$stage/package-catalog.json" "$architecture" \
 "$DISTRIB_RELEASE" "$protocols" "$development" "$target" "$stage" "$mode" \
 "$((flash * 1024))" "$((ram * 1024))" "$backup_bytes" "$include_server" > "$stage/compact-budget.json"
ucode "$stage/install-compact-plan.uc" list "$stage/compact-budget.json" > "$stage/plan.list"
key=foxhole-openwrt-apk.pem
public_sha256=fa220a28fd8662fc5f617f46594bafe2415b4f605136570dc3c446caeb7d1ef1
mkdir "$stage/keys"
fetch "$key"; verify "$key" "$public_sha256"
[ ! -L /etc/apk/keys ] && [ -d /etc/apk/keys ] || exit 1
case "$(file_info '%u:%a' /etc/apk/keys)" in
 0:755|0:750|0:700|0:555|0:550|0:500) ;;
 *) exit 1 ;;
esac
[ ! -L "/etc/apk/keys/$key" ] || exit 1
if [ -e "/etc/apk/keys/$key" ]; then
 [ -f "/etc/apk/keys/$key" ] && cmp -s "/etc/apk/keys/$key" "$stage/$key" || {
  echo 'Existing APK trust key differs' >&2; exit 1
 }
fi
while read -r kind file digest bytes; do
 if [ "$kind" = kernel ]; then
  apk --no-network --no-cache query --from installed --installed --match name \
   --fields name,version,arch,depends,status --format json kernel > "$stage/kernel-installed.json"
  ucode "$stage/install-plan.uc" installed-kernel "$stage/kernel-installed.json" "$file" "$architecture"
  continue
 fi
 case "$kind" in
  asset|kernelAsset|engineVolatile:*|serverVolatile|index|trustKey) ;;
  *) continue ;;
 esac
 fetch "$file" "$bytes"; verify "$file" "$digest"
 [ "$(wc -c < "$stage/$file")" -eq "$bytes" ] || exit 1
done < "$stage/plan.list"
budget_file=$(awk '$1=="budget" {print $2}' "$stage/plan.list")
ucode "$stage/indexed-install.uc" plan "$stage/$budget_file" > "$stage/indexed.list"
mkdir "$stage/repositories"
while read -r kind index role public digest; do
 [ "$kind" = key ] || continue
 directory="$stage/repositories/$index"
 [ -d "$directory" ] || mkdir "$directory"
 [ -d "$directory/keys" ] || mkdir "$directory/keys"
 case "$role" in
  foxhole) [ "$digest" = "$public_sha256" ] || exit 1 ;;
  upstream)
   matched=0
   for existing in /etc/apk/keys/*; do
    [ -f "$existing" ] && [ ! -L "$existing" ] || continue
    case "$(file_info '%u:%a' "$existing")" in 0:644|0:444|0:600|0:400) ;; *) continue ;; esac
    [ "$(sha256sum "$existing" | awk '{print $1}')" = "$digest" ] || continue
    matched=1
   done
   [ "$matched" = 1 ] && [ "$digest" != "$public_sha256" ] || {
    echo 'Upstream signing key differs from installed firmware authority' >&2; exit 1
   } ;;
  *) exit 1 ;;
 esac
 cp "$stage/$public" "$directory/keys/$public"
 [ -f "$stage/keys/$public" ] || cp "$stage/$public" "$stage/keys/$public"
done < "$stage/indexed.list"
: > "$stage/repositories.list"
while read -r kind file role ignored; do
 [ "$kind" = index ] || continue
 directory="$stage/repositories/$file"
 apk --keys-dir "$directory/keys" verify "$stage/$file"
 ln -T "$stage/$file" "$directory/packages.adb"
 (ulimit -f 131072
  apk adbdump --format json "$directory/packages.adb" > "$stage/dump.$file.json")
 ucode "$stage/indexed-install.uc" index "$stage/$budget_file" "$file" "$stage/dump.$file.json"
 rm -f "$stage/dump.$file.json"
 printf '%s\n' "$directory/packages.adb" >> "$stage/repositories.list"
done < "$stage/indexed.list"
while read -r kind file index package version; do
 [ "$kind" = package ] || continue
 directory="$stage/repositories/$index"
 ln -T "$stage/$file" "$directory/$package-$version.apk"
 # Exact own roots come from the already authenticated budget plan.
 signature_required=$(awk -v name="$package" '
  $1 == "durable" && $2 == name { found++ }
  END { if (found > 1) exit 1; print found + 0 }
 ' "$stage/indexed.list")
 case "$signature_required" in
  1) apk --keys-dir "$directory/keys" verify "$stage/$file" ;;
  0) ;;
  *) exit 1 ;;
 esac
 if ucode -e 'import * as fs from "fs";let v=json(fs.readfile(ARGV[0],2097153));let n=ARGV[1];for(let m in v.modules||[])if(m.entry.packageName==n)exit(0);exit(2);' -- "$stage/compact-budget.json" "$package"; then
  apk adbdump --format json "$stage/$file" > "$stage/module-layout.json"
  ucode "$stage/install-compact-plan.uc" layout "$stage/compact-budget.json" "$package" "$stage/module-layout.json"
 else
  result=$?; [ "$result" = 2 ] || exit "$result"
 fi
done < "$stage/indexed.list"
set --
while read -r kind request ignored; do
 [ "$kind" != exact ] || set -- "$@" "$request"
done < "$stage/indexed.list"
[ "$#" -gt 0 ] || exit 1
mkdir "$stage/database" "$stage/cache" "$stage/verified-fetch"
offline() {
 apk --no-network --no-cache --keys-dir "$stage/keys" \
  --repositories-file "$stage/repositories.list" --cache-dir "$stage/cache" "$@"
}
[ -f /etc/apk/world ] && [ ! -L /etc/apk/world ] || exit 1
case "$(file_info '%u:%a:%h' /etc/apk/world)" in 0:644:1|0:600:1|0:444:1|0:400:1) ;; *) exit 1 ;; esac
anchor=$(sha256sum "$stage/SHA256SUMS" | awk '{print $1}')
temporary_constraint=.foxhole-exact-$(printf '%.16s' "$anchor")
ucode "$stage/indexed-install.uc" world-before "$stage/$budget_file" /etc/apk/world "$temporary_constraint" > "$stage/world.before"
offline query --from installed --installed --match name --format json "$temporary_constraint" > "$stage/prior-temporary.json"
ucode -e 'import * as fs from "fs"; let v=json(fs.readfile(ARGV[0],65537)); if (type(v)!="array" || length(v)) exit(1);' -- "$stage/prior-temporary.json"
kernel=$(awk '$1=="exact" && $2~/^kernel><X1/ {print $2}' "$stage/indexed.list")
case "$kernel" in kernel\>\<X1????????????????????????????????????????) ;; *) exit 1 ;; esac
offline query --from installed --installed --fields name,version,arch,status --format json --recursive "$kernel" \
 > "$stage/kernel-identity.json" 2> "$stage/kernel-identity.stderr"
ucode "$stage/indexed-install.uc" kernel-query "$stage/$budget_file" "$stage/kernel-identity.json" "$stage/kernel-identity.stderr"
offline --root "$stage/database" --arch "$architecture" add --initdb
offline --root "$stage/database" --arch "$architecture" query --format json --recursive "$@" \
 > "$stage/query.json" 2> "$stage/query.stderr"
! grep -q 'ERROR:' "$stage/query.stderr" || exit 1
ucode "$stage/indexed-install.uc" query "$stage/$budget_file" "$stage/query.json"
# Equal-size files skip APK checks; use a new fetch directory.
offline --root "$stage/database" --arch "$architecture" fetch --recursive \
 --output "$stage/verified-fetch" "$@"
ucode "$stage/indexed-install.uc" fetch "$stage/$budget_file" "$stage/verified-fetch" > "$stage/fetch.list"
while read -r file digest bytes; do
 printf '%s  %s\n' "$digest" "$stage/verified-fetch/$file" | sha256sum -c - >/dev/null
done < "$stage/fetch.list"
offline query --format json --recursive "$@" > "$stage/live-query.json" 2> "$stage/live-query.stderr"
! grep -q 'ERROR:' "$stage/live-query.stderr" || exit 1
ucode "$stage/indexed-install.uc" query "$stage/$budget_file" "$stage/live-query.json"
offline add --simulate --virtual "$temporary_constraint" "$@" > "$stage/exact-simulate.log"
cmp -s /etc/apk/world "$stage/world.before"
echo 'Exact compact modules and complete package budgets verified'
[ "$apply" = 1 ] || { echo 'Check only; use --apply to install'; exit 0; }
acquire_transaction_lock
keep_stage=1
[ -z "$(uci changes)" ] || { echo 'Commit or revert pending UCI changes first' >&2; exit 1; }
[ ! -e /etc/foxhole ] && [ ! -L /etc/foxhole ] || { echo 'Existing FoxHole state requires paired management' >&2; exit 1; }
(ulimit -f 16384
 apk --no-network --no-cache query --from installed --installed --fields name,status --format json > "$stage/prior-owned-locked.json")
ucode -e '
 import * as fs from "fs";
 let rows=json(fs.readfile(ARGV[0],8388609));
 if (type(rows)!="array" || length(rows)>4096) exit(1);
 for (let row in rows) if (index(["foxhole-openwrt-client","foxcore-cli","foxcore-cli-ram","hysteria","hysteria-server-ram"],row.name)>=0 || match(row.name||"",/^foxcore-engine-/)) exit(1);
' -- "$stage/prior-owned-locked.json"
cmp -s /etc/apk/world "$stage/world.before"
transaction_phase=backup
sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall > "$stage/config.before"
uname -r > "$stage/kernel.before"
sysupgrade -k -b "$stage/sysupgrade-before.tar.gz"
cp -p /etc/config/dhcp "$stage/dhcp.before"
if [ -e /etc/foxhole ] || [ -L /etc/foxhole ]; then
 [ -d /etc/foxhole ] && [ ! -L /etc/foxhole ] || exit 1
 tar -czf "$stage/foxhole-before.tar.gz" -C /etc foxhole
fi
# Start services only after the verified RAM cache is ready.
while read -r kind file digest bytes; do
 case "$kind" in
  engineVolatile:*)
   engine=${kind#engineVolatile:}
   case "$engine" in anytls|http|hysteria2|naive|shadowsocks|shadowtls|socks|trojan|tuic|vless|vmess|wireguard) ;; *) exit 1 ;; esac
   cache_root=/tmp/foxhole/engine-binaries/$engine; binary_name=foxcore-cli
   parents="/tmp/foxhole /tmp/foxhole/engine-binaries $cache_root" ;;
  serverVolatile) cache_root=/tmp/foxhole-hysteria-server-binary; binary_name=hysteria; parents="$cache_root" ;;
  *) continue ;;
 esac
 for directory in $parents "$cache_root/$digest"; do
  if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then mkdir -m 700 "$directory"; fi
  [ ! -L "$directory" ] && [ "$(file_info '%F:%u:%a' "$directory")" = 'directory:0:700' ] || exit 1
 done
 cached="$cache_root/$digest/$binary_name"
 if [ -e "$cached" ] || [ -L "$cached" ]; then
  [ -f "$cached" ] && [ ! -L "$cached" ] &&
   [ "$(file_info '%u:%a:%h' "$cached")" = '0:700:1' ] || exit 1
  printf '%s  %s\n' "$digest" "$cached" | sha256sum -c - >/dev/null
 else
  chmod 700 "$stage/$file"
  ln -T "$stage/$file" "$cached"
  rm -f "$stage/$file"
 fi
done < "$stage/plan.list"
if [ ! -e "/etc/apk/keys/$key" ]; then
 temporary=$(mktemp /etc/apk/keys/.foxhole.XXXXXX)
 cp "$stage/$key" "$temporary"; chmod 644 "$temporary"
 ln -T "$temporary" "/etc/apk/keys/$key" || { rm -f "$temporary"; exit 1; }
 rm -f "$temporary"
fi
transaction_phase=installing-exact
pending_constraint=$temporary_constraint
offline add --virtual "$temporary_constraint" "$@" > "$stage/exact-install.log"
offline query --from installed --installed --match name --fields name,version,arch,status --format json \
 "$temporary_constraint" > "$stage/created-temporary.json"
created_constraint=$(ucode "$stage/indexed-install.uc" temporary-created "$stage/$budget_file" \
 "$stage/created-temporary.json" "$temporary_constraint")
pending_constraint=$created_constraint
offline query --from installed --installed --fields name,version,arch,status --format json --recursive "$@" \
 > "$stage/exact-installed.json" 2> "$stage/exact-installed.stderr"
! grep -q 'ERROR:' "$stage/exact-installed.stderr" || exit 1
ucode "$stage/indexed-install.uc" query-installed "$stage/$budget_file" "$stage/exact-installed.json"
transaction_phase=durable-roots
set --
while read -r kind request ignored; do
 [ "$kind" != durable ] || set -- "$@" "$request"
done < "$stage/indexed.list"
[ "$#" -gt 0 ] || exit 1
offline add --simulate "$@" > "$stage/roots-simulate.log"
offline add "$@" > "$stage/roots-install.log"
ucode "$stage/indexed-install.uc" world-after "$stage/$budget_file" "$stage/world.before" /etc/apk/world "$pending_constraint"
transaction_phase=removing-temporary
offline del --simulate "$temporary_constraint" > "$stage/temporary-purge-prediction.log"
ucode "$stage/indexed-install.uc" purge-only "$stage/$budget_file" "$stage/temporary-purge-prediction.log" "$pending_constraint"
offline del "$temporary_constraint" > "$stage/temporary-purge.log"
pending_constraint=''
ucode "$stage/indexed-install.uc" world-after "$stage/$budget_file" "$stage/world.before" /etc/apk/world
transaction_phase=verifying-installed
set --
while read -r kind request ignored; do
 [ "$kind" != exact ] || set -- "$@" "$request"
done < "$stage/indexed.list"
[ "$#" -gt 0 ] || exit 1
offline query --from installed --installed --fields name,version,arch,status --format json --recursive "$@" \
 > "$stage/final-installed.json" 2> "$stage/final-installed.stderr"
! grep -q 'ERROR:' "$stage/final-installed.stderr" || exit 1
ucode "$stage/indexed-install.uc" query-installed "$stage/$budget_file" "$stage/final-installed.json"
ucode "$stage/install-compact-plan.uc" installed "$stage/$budget_file" > "$stage/installed.list"
while read -r kind path digest; do
 case "$kind" in
  file) printf '%s  %s\n' "$digest" "$path" | sha256sum -c - >/dev/null ;;
  capabilities)
   (ulimit -f 4096
    "$path" capabilities > "$stage/installed-capabilities.json")
   printf '%s  %s\n' "$digest" "$stage/installed-capabilities.json" | sha256sum -c - >/dev/null ;;
  *) exit 1 ;;
 esac
done < "$stage/installed.list"
cmp -s /etc/config/dhcp "$stage/dhcp.before" || {
 echo 'DHCP changed; inspect the private backup before continuing' >&2; exit 1
}

sha256sum /etc/config/network /etc/config/dhcp /etc/config/firewall > "$stage/config.after"
uname -r > "$stage/kernel.after"
cmp -s "$stage/config.before" "$stage/config.after"
cmp -s "$stage/kernel.before" "$stage/kernel.after"

transaction_phase=registering-compact-engines
ucode "$stage/register-compact-engines.uc" "$stage/compact-budget.json"
catalog_sha=$(sha256sum "$stage/package-catalog.json" | awk '{print $1}')
chosen_mode=$(awk '$1=="mode" {print $2}' "$stage/plan.list")
receipt=/usr/share/foxhole/package-manifest.json
if [ -e "$receipt" ] || [ -L "$receipt" ]; then
 [ -f "$receipt" ] && [ ! -L "$receipt" ] && [ "$(file_info %u "$receipt")" = 0 ] || exit 1
fi
temporary=$(mktemp /usr/share/foxhole/.package-manifest.XXXXXX)
if ! ucode "$stage/install-compact-plan.uc" receipt "$stage/compact-budget.json" "$catalog_sha" > "$temporary"; then
 rm -f "$temporary"; exit 1
fi
chmod 644 "$temporary"
mv -f "$temporary" "$receipt"
transaction_phase=complete
/usr/libexec/foxhole-license --accept 1 >/dev/null
install_complete=true
echo 'Verified compact client modules installed; router pairing and incoming profile creation are separate'
