#!/bin/sh
# Bootstrap the frozen pre-CLI zmosh QUIC gateway, then replace this
# bootstrap-only process with the separately hash-bound stdio bridge.
set -eu

if [ "$#" -ne 9 ]; then
    echo "usage: launch-zmosh-quic HOST UDP_HOST SSH_CONFIG REMOTE SESSION PTY_ECHO BRIDGE CONNECT_LOG SERVER_STDERR" >&2
    exit 2
fi

host=$1
udp_host=$2
ssh_config=$3
remote=$4
session=$5
pty_echo=$6
bridge=$7
connect_log=$8
server_stderr=$9
# POSIX shells replace fd 0 with /dev/null for asynchronous lists. Preserve
# the caller's PTY on a nonstandard descriptor before starting either child.
exec 3<&0

case "$session" in
    *[!A-Za-z0-9_-]*|'') echo "invalid benchmark session" >&2; exit 2 ;;
esac
for path in "$remote" "$pty_echo" "$bridge" "$ssh_config"; do
    case "$path" in
        *[!A-Za-z0-9_./-]*) echo "unsafe benchmark path: $path" >&2; exit 2 ;;
    esac
done

# Never put the raw bootstrap record in an evidence directory. A late SSH
# write must remain private even after the bridge has started.
umask 077
bootstrap_dir=$(mktemp -d "${TMPDIR:-/tmp}/everudp-quic-bootstrap.XXXXXX")
bootstrap_record=$bootstrap_dir/record
ssh_pid=
bridge_pid=

cleanup() {
    status=$?
    trap - EXIT INT TERM HUP
    [ -z "${bridge_pid:-}" ] || kill -TERM "$bridge_pid" 2>/dev/null || true
    [ -z "$ssh_pid" ] || kill -TERM "$ssh_pid" 2>/dev/null || true
    [ -z "$ssh_pid" ] || wait "$ssh_pid" 2>/dev/null || true
    rm -f -- "$bootstrap_record"
    rmdir -- "$bootstrap_dir" 2>/dev/null || true
    exit "$status"
}
trap cleanup EXIT INT TERM HUP

: >"$connect_log"
/usr/bin/ssh -F "$ssh_config" "$host" -- \
    "$remote serve --exact-session $session $pty_echo" \
    </dev/null >"$bootstrap_record" 2>"$server_stderr" &
ssh_pid=$!

attempt=0
while ! /usr/bin/grep -q '^ZMX_CONNECT ' "$bootstrap_record"; do
    if ! kill -0 "$ssh_pid" 2>/dev/null; then
        wait "$ssh_pid" || true
        echo "zmosh QUIC bootstrap exited before a connect record" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 200 ]; then
        echo "zmosh QUIC bootstrap timed out" >&2
        exit 1
    fi
    /usr/bin/sleep 0.05
done

record=$(/usr/bin/grep -m1 '^ZMX_CONNECT ' "$bootstrap_record")
set -f
# The record alphabet was constrained by the producer and is validated again
# below; word splitting is intentional and pathname expansion is disabled.
set -- $record
if [ "$#" -ne 4 ]; then
    echo "invalid zmosh QUIC connect record" >&2
    exit 1
fi
prefix=$1
protocol=$2
port=$3
key=$4
if [ "$prefix" != ZMX_CONNECT ] || [ "$protocol" != quic ]; then
    echo "invalid zmosh QUIC connect record" >&2
    exit 1
fi
case "$port" in *[!0-9]*|'') echo "invalid zmosh QUIC port" >&2; exit 1 ;; esac
case "$key" in *[!A-Za-z0-9+/=]*|'') echo "invalid zmosh QUIC key" >&2; exit 1 ;; esac
printf 'ZMX_CONNECT quic %s [REDACTED]\n' "$port" >"$connect_log"

# An asynchronous POSIX-shell command otherwise inherits /dev/null as stdin
# when job control is disabled. Make the PTY descriptors explicit.
"$bridge" "$udp_host" "$port" "$key" <&3 >&1 &
bridge_pid=$!
wait "$bridge_pid"
bridge_status=$?
bridge_pid=
exit "$bridge_status"
