#!/bin/sh
# Install only a bounded bootstrap and public trust. No download or activation here.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset LD_PRELOAD LD_LIBRARY_PATH APK_CONFIG
descriptor=''; signer=''; ca=''
while [ "$#" -gt 0 ]; do
 case "$1" in
  --descriptor) descriptor=${2:?}; shift 2 ;;
  --signer-pem) signer=${2:?}; shift 2 ;;
  --ca) ca=${2:?}; shift 2 ;;
  --help|-h) echo 'install-ram-bootstrap.sh --descriptor FILE --signer-pem PUBLIC_PEM [--ca PUBLIC_CA]'; exit 0 ;;
  *) exit 2 ;;
 esac
done
[ "$(id -u)" = 0 ] && [ -n "$descriptor" ] && [ -n "$signer" ] || exit 2
directory=${0%/*}
case "$directory" in /*) ;; *) echo 'Use an absolute installer path' >&2; exit 2 ;; esac
for tool in /usr/bin/apk /usr/bin/ucode /bin/uclient-fetch /usr/bin/sha256sum; do [ -x "$tool" ] || exit 1; done
/bin/sh -n "$directory/ram-bootstrap-command.sh"
/bin/sh -n "$directory/ram-bootstrap.init"
# Parse before any installation or native operation. Target-native semantics need qualification.
for file in ram-bootstrap-model.uc ram-bootstrap-admit.uc ram-bootstrap-capture.uc ram-bootstrap.uc; do
 /usr/bin/ucode -c -o /dev/null "$directory/$file"
done
exec /usr/bin/ucode "$directory/ram-bootstrap.uc" install "$directory" "$descriptor" "$signer" "$ca"
