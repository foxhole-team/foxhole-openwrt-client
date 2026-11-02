#!/bin/sh
# Owned native APK capture for prepare-only RAM roots.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset LD_PRELOAD LD_LIBRARY_PATH APK_CONFIG

trusted_stage() {
 case "$1" in /tmp/foxhole-ram[.-]*/native-*.io) ;; *) exit 1 ;; esac
 case "$1" in *[!a-zA-Z0-9/_.-]*|*/../*|*/./*) exit 1 ;; esac
 [ "$1" = "${0%/*}" ] || exit 1
 ucode -e '
  import * as fs from "fs";
  let p=ARGV[0],a=fs.lstat(fs.dirname(p)),d=fs.lstat(p);
  if(a?.type!="directory"||a.uid!=0||(a.mode&0o7777)!=0o700||d?.type!="directory"||d.uid!=0||(d.mode&0o7777)!=0o700)exit(1);
  for(let n in ["helper","utility.uc"]){let s=fs.lstat(p+"/"+n);if(s?.type!="file"||s.uid!=0||s.nlink!=1||(s.mode&0o7777)!=0o600||s.size<1||s.size>32768)exit(1);}
 ' -- "$1"
}
if [ "${1-}" = --owned-child ]; then
 stage=$2; role=$3; owner=$4; shift 4
 trusted_stage "$stage"
 utility=$stage/utility.uc
 ucode "$utility" register "$stage" "$role" "$owner" "$$"
 case "$role" in
  stdout|stderr) set -C; exec ucode "$utility" drain "$stage/$role" "$2" > "$1" ;;
  timer) exec ucode "$utility" watch "$stage" "$owner" "$1" ;;
  native) exec "$@" </dev/null > "$stage/stdout" 2> "$stage/stderr" ;;
  *) exit 1 ;;
 esac
fi

if [ "${1-}" != --run ]; then
 # Public entry: RAM_STAGE LOG_ROLE TIMEOUT_MS /usr/bin/apk ARGS...
 [ "$#" -ge 4 ] || exit 2
 ram_stage=$1; log=$2; deadline=$3; shift 3
 directory=${0%/*}
 case "$directory" in /*) ;; *) exit 2 ;; esac
 utility=$directory/ram-native-command.uc
 ucode -c -o /dev/null "$utility"
 ucode "$utility" lock "$ram_stage"
 exec 9>>"$ram_stage/native-capture.lock"
 flock -xn 9
 io=$(ucode "$utility" setup "$ram_stage" "$log" "$deadline" "$0" "$utility" "$@")
 exec /bin/sh "$io/helper" --run "$ram_stage/$log.stdout" "$ram_stage/$log.stderr" "$deadline" "$@"
fi
shift
output=${1:?bounded stdout}
error_output=${2:?bounded stderr}
deadline=${3:?native timeout milliseconds}
shift 3
stage=${0%/*}
trusted_stage "$stage"
utility=$stage/utility.uc
ucode "$utility" arguments "$stage" "$output" "$error_output" "$deadline" "$@"
case "$output" in */index-dump.stdout) limit=16777216 ;; *) limit=1048576 ;; esac
owner=$(ucode "$utility" owner "$$")
stdout_pid=''; stderr_pid=''; native_pid=''; timer_pid=''
finish() {
 result=$1
 trap - EXIT HUP INT TERM
 set +e
 clean=0
 for role in timer native stdout stderr; do
  case "$role" in timer) pid=$timer_pid ;; native) pid=$native_pid ;; stdout) pid=$stdout_pid ;; stderr) pid=$stderr_pid ;; esac
  if [ -n "$pid" ]; then
   if ucode "$utility" stop "$stage" "$role" "$owner" "$pid"; then wait "$pid" 2>/dev/null || :; else clean=1; fi
  fi
 done
 if [ "$result" = 143 ] && ucode "$utility" timedout "$stage" "$owner"; then result=124; fi
 if [ "$clean" = 0 ]; then ucode "$utility" clean "$stage" "$owner" || clean=1; fi
 if [ "$result" = 0 ] && [ "$clean" != 0 ]; then result=1; fi
 exit "$result"
}
trap 'finish $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
ucode "$utility" prepare "$stage" "$owner"
ucode "$utility" makepipe "$stage" "$owner" stdout
ucode "$utility" makepipe "$stage" "$owner" stderr
/bin/sh "$0" --owned-child "$stage" stdout "$owner" "$output" "$limit" &
stdout_pid=$!
ucode "$utility" ready "$stage" stdout "$owner" "$stdout_pid"
/bin/sh "$0" --owned-child "$stage" stderr "$owner" "$error_output" 1048576 &
stderr_pid=$!
ucode "$utility" ready "$stage" stderr "$owner" "$stderr_pid"
/bin/sh "$0" --owned-child "$stage" timer "$owner" "$deadline" &
timer_pid=$!
ucode "$utility" ready "$stage" timer "$owner" "$timer_pid"
# Only the sinks are bounded; APK payload writes inherit no FSIZE limit.
/bin/sh "$0" --owned-child "$stage" native "$owner" "$@" &
native_pid=$!
ucode "$utility" ready "$stage" native "$owner" "$native_pid"
wait_owned() {
 wait_role=$1; wait_pid=$2; wait_done=false
 while :; do
  ucode "$utility" poll "$stage" "$wait_role" "$owner" "$wait_pid"
  wait_state=$?
  case "$wait_state" in
   0) wait_done=true; wait "$wait_pid"; return $? ;;
   10) ucode -e 'if(sleep(200)!=true)exit(1);' || return 1 ;;
   *) return 1 ;;
  esac
 done
}
set +e
wait_owned native "$native_pid"; native_result=$?
[ "$wait_done" = true ] || exit 1
native_pid=''
wait_owned stdout "$stdout_pid"; stdout_result=$?
if [ "$wait_done" != true ]; then [ "$native_result" = 0 ] && exit 1; exit "$native_result"; fi
stdout_pid=''
wait_owned stderr "$stderr_pid"; stderr_result=$?
if [ "$wait_done" != true ]; then [ "$native_result" = 0 ] && exit 1; exit "$native_result"; fi
stderr_pid=''
set -e
[ "$native_result" = 0 ] || exit "$native_result"
[ "$stdout_result" = 0 ] && [ "$stderr_result" = 0 ] || exit 1
