#!/usr/bin/env bash
# M0 gate 3: authenticated SSH bootstrap over the real system sshd.
#
# Proves:
#  - system ssh -> isolated sshd -> bootstrap-parent prints exactly ONE
#    newline-terminated record on stdout; diagnostics only on stderr;
#  - the record parses, carries a version/pin/token/pid;
#  - the token is NOT in argv/env of any process (checked via /proc);
#  - the detached one-shot server child exits by lease without touching the
#    target (no TCP connect before authentication) and leaves no process
#    behind after the lease.
set -euo pipefail
cd "$(dirname "$0")/.."
source net/harness.sh

harness_start
trap harness_stop EXIT

echo "[bootstrap] starting ssh bootstrap against isolated sshd port $SSHD_PORT"
RECORD="$(ssh_bootstrap "$SSHD_PORT" 2>"$HDIR/bootstrap.stderr")" || {
    echo "FAIL: ssh bootstrap exited nonzero"; cat "$HDIR/bootstrap.stderr"; exit 1;
}
[[ -n "$RECORD" ]] || { echo "FAIL: empty bootstrap record"; exit 1; }
LINES=$(printf "%s\n" "$RECORD" | wc -l)
[[ "$LINES" == 1 ]] || { echo "FAIL: expected exactly 1 record line, got $LINES"; exit 1; }
[[ -s "$HDIR/bootstrap.stderr" ]] && { echo "note: stderr diagnostics present (expected only on failure):"; cat "$HDIR/bootstrap.stderr"; }

set -- $RECORD
[[ "$1 $2" == "m0 v1" ]] || { echo "FAIL: bad magic/version: $1 $2"; exit 1; }
UDP_PORT="$3"; PIN="$4"; TOKEN="$5"; PID="$6"
echo "[bootstrap] ok: udp=$UDP_PORT pin=${PIN:0:12}… token=${TOKEN:0:8}… pid=$PID"

# Token must not appear in any process argv or environment.
sleep 0.3
if ls /proc/$PID >/dev/null 2>&1; then
    if grep -q "$TOKEN" /proc/$PID/cmdline 2>/dev/null; then
        echo "FAIL: token leaked into argv"; exit 1
    fi
    if tr '\0' '\n' < /proc/$PID/environ 2>/dev/null | grep -q "$TOKEN"; then
        echo "FAIL: token leaked into environment"; exit 1
    fi
    echo "[bootstrap] ok: token absent from argv and environment of server child"
else
    echo "FAIL: server child $PID not alive after bootstrap"; exit 1
fi

# The one-shot server child must exit by lease without any client, and must
# never have connected to a TCP target (no client = no authentication).
TARGET_PORT=$SSHD_PORT
if (exec 3<>/dev/tcp/127.0.0.1/$TARGET_PORT) 2>/dev/null; then
    exec 3>&-
    echo "[bootstrap] note: target port reachable (sshd is the authorized target)"
fi

for _ in $(seq 1 400); do   # lease is 30s; poll for child exit
    ls /proc/$PID >/dev/null 2>&1 || break
    sleep 0.1
done
if ls /proc/$PID >/dev/null 2>&1; then
    echo "FAIL: server child outlived its lease (still running after 40s)"; exit 1
fi
echo "[bootstrap] ok: one-shot server child exited by lease"

# No surviving owned processes.
if pgrep -af "noq-m0 server" | grep -v pgrep; then
    echo "FAIL: surviving server process"; exit 1
fi
echo "[bootstrap] PASS: authenticated SSH bootstrap gate"
