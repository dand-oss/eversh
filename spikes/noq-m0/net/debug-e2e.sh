#!/usr/bin/env bash
# Debug helper: single outer ssh over the spike ProxyCommand with live process
# inspection. Not an evidence gate.
set -uo pipefail
cd "$(dirname "$0")/.."
source net/harness.sh
harness_start
trap harness_stop EXIT
echo "PORT=$SSHD_PORT"
NOQ_M0_DEBUG=1 timeout 15 ssh -F none -i "$HDIR/client_key" \
    -o UserKnownHostsFile="$HDIR/known_hosts" -o StrictHostKeyChecking=yes \
    -o BatchMode=yes \
    -o ProxyCommand="$BIN proxy %n %p -i $HDIR/client_key -o UserKnownHostsFile=$HDIR/known_hosts -o StrictHostKeyChecking=yes -F none" \
    -p "$SSHD_PORT" 127.0.0.1 "echo hello-from-quic" 2>"$HDIR/dbg.stderr"
echo "outer rc=$?"
echo "--- proxy stderr:"
cat "$HDIR/dbg.stderr"
echo "--- live noq-m0 processes:"
pgrep -af "debug/noq-m0" || echo none
echo "--- sshd log tail:"
tail -5 "$HDIR/sshd.log"
