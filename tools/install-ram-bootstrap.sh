#!/bin/sh
# Install only a bounded bootstrap and public trust. No download or activation here.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset LD_PRELOAD LD_LIBRARY_PATH APK_CONFIG UCODE_PATH UCODE_CPATH
descriptor=''; signer=''; ca=''; fetch_helper=''; fetch_sha256=''; prepared_stage=''
while [ "$#" -gt 0 ]; do
 case "$1" in
  --descriptor) descriptor=${2:?}; shift 2 ;;
  --signer-pem) signer=${2:?}; shift 2 ;;
  --ca) ca=${2:?}; shift 2 ;;
  --fetch-helper) fetch_helper=${2:?}; shift 2 ;;
  --fetch-helper-sha256) fetch_sha256=${2:?}; shift 2 ;;
  --prepared-stage) prepared_stage=${2:?}; shift 2 ;;
  --help|-h) echo 'install-ram-bootstrap.sh --descriptor FILE --signer-pem PUBLIC_PEM --fetch-helper VERIFIED_ELF --fetch-helper-sha256 HASH [--ca PUBLIC_CA] [--prepared-stage /tmp/foxhole-ram.NAME]'; exit 0 ;;
  *) exit 2 ;;
 esac
done
[ "$(id -u)" = 0 ] && [ -n "$descriptor" ] && [ -n "$signer" ] && [ -n "$fetch_helper" ] || exit 2
case "$fetch_sha256" in ''|*[!a-f0-9]*) exit 2 ;; esac
[ "${#fetch_sha256}" = 64 ] || exit 2
directory=${0%/*}
case "$directory" in /*) ;; *) echo 'Use an absolute installer path' >&2; exit 2 ;; esac
for tool in /usr/bin/apk /usr/bin/ucode /usr/bin/sha256sum; do [ -x "$tool" ] || exit 1; done
/bin/sh -n "$directory/ram-bootstrap-command.sh"
/bin/sh -n "$directory/ram-bootstrap.init"
# Compile entry scripts; imported source models retain their module context.
for file in ram-bootstrap-admit.uc ram-bootstrap-capture.uc ram-bootstrap.uc ram-bootstrap-prerequisites.uc; do
 /usr/bin/ucode -c -o /dev/null "$directory/$file"
done
exec /usr/bin/ucode "$directory/ram-bootstrap.uc" install "$directory" "$descriptor" "$signer" "$ca" "$fetch_helper" "$prepared_stage" "$fetch_sha256"
