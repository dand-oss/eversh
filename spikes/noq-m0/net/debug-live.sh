#!/usr/bin/env bash
# Debug helper 2: start harness, run the outer ssh in the background, snapshot
# the world after 8s, then let everything settle. Not an evidence gate.
set -uo pipefail
cd "$(dirname "$0")/.."
source net/harness.sh
harness_start
echo "PORT=$SSHD_PORT HDIR=$HDIR"
NOQ_M0_DEBUG=1 ssh -vv -F none -i "$HDIR/client_key" \
    -o UserKnownHostsFile="$HDIR/known_hosts" -o StrictHostKeyChecking=yes \
    -o BatchMode=yes \
    -o ProxyCommand="$BIN proxy %n %p -i $HDIR/client_key -o UserKnownHostsFile=$HDIR/known_hosts -o StrictHostKeyChecking=yes -F none" \
    -p "$SSHD_PORT" 127.0.0.1 "echo hello-from-quic" >"$HDIR/out.txt" 2>"$HDIR/sshvv.log" &
SSHPID=$!
for _ in $(seq 1 8); do sleep 1; done
{
  echo "=== live processes:"
  pgrep -af "debug/noq-m0" || true
  echo "=== ssh -vv tail:"
  tail -6 "$HDIR/sshvv.log"
  echo "=== target sshd log tail:"
  tail -6 "$HDIR/sshd.log"
} > "$HDIR/snapshot.txt"
kill $SSHPID 2>/dev/null
wait $SSHPID 2>/dev/null
cat "$HDIR/snapshot.txt"
echo "=== final proxy stderr (from sshvv.log grep):"
grep "noq-m0 proxy" "$HDIR/sshvv.log" || true
harness_stop
