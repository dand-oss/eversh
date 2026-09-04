#!/usr/bin/env bash
# Mosh control: authoritative echo arrival via pcap under identical netem.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
OUT=${1:?output prefix}
TRIALS=${2:?trials}
PORT=${3:?port}
TMP=$(mktemp -d)
cleanup() {
    [[ -z ${SERVER_PID:-} ]] || kill -KILL "$SERVER_PID" 2>/dev/null || :
    [[ -z ${TCPDUMP_PID:-} ]] || sudo -n /usr/bin/kill "$TCPDUMP_PID" 2>/dev/null || :
    sudo -n /usr/bin/pkill -f "tcpdump -i lo.*port $PORT" 2>/dev/null || :
    rm -rf -- "$TMP"
}
trap cleanup EXIT

MOSH_OUTPUT=$(mosh-server new -p "$PORT" -- /usr/bin/python3 -u "$ROOT/net/echo1.py" 2>"$TMP/server.err")
read -r _ _ PORT_ACTUAL KEY <<<"$MOSH_OUTPUT"
[[ -n $KEY ]] || { cat "$TMP/server.err" >&2; exit 1; }
PORT=$PORT_ACTUAL
sudo -n /usr/bin/tcpdump -i lo -nn -U -w "$TMP/mosh.pcap" "udp port $PORT" 2>"$TMP/tcpdump.err" &
TCPDUMP_PID=$!
sleep 1
python3 "$ROOT/net/drive-mosh.py" "$PORT" "$KEY" "$TRIALS" "$TMP/events.json" 0.1
sleep 1
sudo -n /usr/bin/chmod 644 "$TMP/mosh.pcap" 2>/dev/null || :
python3 "$ROOT/net/parse-pcap.py" "$TMP/mosh.pcap" "$TMP/events.json" "$OUT" "$PORT"
cat "$OUT"
