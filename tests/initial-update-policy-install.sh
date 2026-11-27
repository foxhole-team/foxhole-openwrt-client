#!/bin/sh
# Run in a disposable OpenWrt container with /source mounted
# read-only.
set -eu
umask 077
test -e /.dockerenv && test "$(id -u)" = 0
awk '$5=="/etc/foxhole" && / - tmpfs / {found=1} END {exit !found}' /proc/self/mountinfo
awk '$5=="/tmp" && / - tmpfs / {found=1} END {exit !found}' /proc/self/mountinfo
test -z "$(ls -A /etc/foxhole)"
test ! -e /var/run/foxhole-initial-auto-update
mkdir -p /var/run
scenario=${1:?scenario}
choice=none
set --
case "$scenario" in
 default) choice=true ;;
 install-off) choice=false; set -- --no-auto-update ;;
 legacy-off) printf '%s\n' '{"schema":1,"revision":2,"enabled":false,"lastAttemptAtUnixMs":null}' > /etc/foxhole/update-policy.json ;;
 legacy-auth) printf '%s\n' '{"schema":1,"changed":true}' > /etc/foxhole/auth.json ;;
 legacy-pair) printf '%s\n' '{"schema":1,"devices":[{"id":"old"}]}' > /etc/foxhole/pairing.json ;;
 reset) printf '%s\n' '{"schema":1,"changed":false,"resetPending":true}' > /etc/foxhole/auth.json ;;
 retained-off) printf '%s\n' '{"schema":1,"enabled":false}' > /etc/foxhole/initial-package-update.json; choice=false ;;
 check-only) set -- --no-auto-update ;;
 *) exit 2 ;;
esac
for record in /etc/foxhole/*.json; do
 if [ -f "$record" ]; then sha256sum "$record"; fi
done > /tmp/before.sha256
fixture=$(mktemp -d /tmp/initial-policy.XXXXXX)
printf '%s\n' '{"schema":2,"kind":"compact-client-engines-v1"}' > "$fixture/package-catalog.json"
# Only the compact dispatcher is a fixture. The bootstrap,
# private store, OS file ownership,
# ucode policy model and package postinstall helper all run from
# source.
cat > "$fixture/install-compact.sh" <<'STAGE'
#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
 if [ "$1" = --apply ]; then apply=$2; fi
 shift 2
done
case "$apply" in
 0) test ! -e /var/run/foxhole-initial-auto-update ;;
 1) test -d /var/run/foxhole-initial-auto-update
    /usr/libexec/foxhole-initial-update-policy ;;
 *) exit 12 ;;
esac
STAGE
(cd "$fixture" && sha256sum package-catalog.json install-compact.sh > SHA256SUMS)
manifest=$(sha256sum "$fixture/SHA256SUMS"); manifest=${manifest%% *}
if [ "$scenario" != check-only ]; then set -- "$@" --apply --accept-license; fi
sh /source/install.sh --bundle "$fixture" --manifest-sha256 "$manifest" "$@"
test ! -e /var/run/foxhole-initial-auto-update
if [ -s /tmp/before.sha256 ]; then sha256sum -c /tmp/before.sha256; fi
if [ "$choice" = none ]; then
 test ! -e /etc/foxhole/initial-package-update.json
else
 ucode -e 'import * as fs from "fs"; import * as record from "/usr/share/foxhole/initial-update-choice.uc";
 import * as model from "/usr/share/foxhole/update-model.uc";
 let p=fs.lstat("/etc/foxhole/initial-package-update.json");
 let expected=ARGV[0]=="true";
 if (p.uid!=0 || p.nlink!=1 || (p.mode & 0o7777)!=0o600 || record.pending()!=expected) exit(1);
 if (model.policy(null,null).enabled) exit(2);
 for (let selection in [true,false,null]) {
   let stored=model.first_owner_choice(null,record.pending(),selection,false);
   if (stored!=(expected && selection!=false) || model.policy(null,{changed:true,initialPackageAutoUpdate:stored}).enabled!=stored) exit(3);
 }' -- "$choice"
fi
printf 'PASS initial installer policy %s\n' "$scenario"
