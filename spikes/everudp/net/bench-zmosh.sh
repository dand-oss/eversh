#!/usr/bin/env bash
# zmosh control: isolated ZMX session, explicit UDP gateway, and pcap echo.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
OUT=${1:?output prefix}
TRIALS=${2:?trials}
TMP=$(mktemp -d)
export ZMX_DIR="$TMP/zmx"
mkdir -p "$ZMX_DIR"
SERVE_PID=
TCPDUMP_PID=
cleanup() {
    [[ -z ${TCPDUMP_PID:-} ]] || sudo -n /usr/bin/kill "$TCPDUMP_PID" 2>/dev/null || :
    [[ -z ${SERVE_PID:-} ]] || kill -KILL "$SERVE_PID" 2>/dev/null || :
    env -u ZMX_SESSION ZMX_DIR="$ZMX_DIR" zmosh kill everudp-bench >/dev/null 2>&1 || :
    rm -rf -- "$TMP"
}
trap cleanup EXIT

env -u ZMX_SESSION TERM=xterm-256color ZMX_DIR="$ZMX_DIR" \
    zmosh run everudp-bench /usr/bin/python3 -u "$ROOT/net/echo1.py"
sleep 0.5
env -u ZMX_SESSION TERM=xterm-256color ZMX_DIR="$ZMX_DIR" \
    zmosh serve everudp-bench >"$TMP/serve.out" 2>"$TMP/serve.err" &
SERVE_PID=$!
for _ in $(seq 1 50); do
    [[ -s $TMP/serve.out ]] && break
    sleep 0.1
done
read -r _ _ PORT KEY <"$TMP/serve.out"
[[ $PORT =~ ^[0-9]+$ && -n $KEY ]] || { cat "$TMP/serve.out" "$TMP/serve.err" >&2; exit 1; }
sudo -n /usr/bin/tcpdump -i lo -nn -U -w "$TMP/zmosh.pcap" "udp port $PORT" 2>"$TMP/tcpdump.err" &
TCPDUMP_PID=$!
sleep 1
python3 "$ROOT/net/drive-cmd.py" "$TMP/events.json" "$TRIALS" 0.15 \
    env -u ZMX_SESSION TERM=xterm-256color ZMX_DIR="$ZMX_DIR" \
    zmosh attach -r 127.0.0.1 everudp-bench
sleep 1
sudo -n /usr/bin/chmod 644 "$TMP/zmosh.pcap" 2>/dev/null || :
python3 "$ROOT/net/parse-pcap.py" "$TMP/zmosh.pcap" "$TMP/events.json" "$OUT" "$PORT"
cat "$OUT"
