#!/usr/bin/env bash
# One preregistered 5 s outage-recovery observation for the UDP substrate.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
SPIKE=$ROOT/spikes/everudp/target/release/everudp-spike
OUT=${1:-/tmp/everudp-outage.txt}
IP=/usr/bin/ip
TC=/usr/sbin/tc
TAG=o$((RANDOM & 32767))
cleanup() {
    set +e
    kill "${SERVER_PID:-}" 2>/dev/null
    "$IP" netns del "${TAG}c" 2>/dev/null
    "$IP" netns del "${TAG}s" 2>/dev/null
}
trap cleanup EXIT
$IP netns add "${TAG}s"
$IP netns add "${TAG}c"
$IP link add "${TAG}s" type veth peer name "${TAG}c"
$IP link set "${TAG}s" netns "${TAG}s"
$IP link set "${TAG}c" netns "${TAG}c"
$IP -n "${TAG}s" link set lo up
$IP -n "${TAG}c" link set lo up
$IP -n "${TAG}s" addr add 10.243.0.1/24 dev "${TAG}s"
$IP -n "${TAG}c" addr add 10.243.0.2/24 dev "${TAG}c"
$IP -n "${TAG}s" link set "${TAG}s" up
$IP -n "${TAG}c" link set "${TAG}c" up
$IP netns exec "${TAG}s" "$SPIKE" udp-server --bind 10.243.0.1:60400 \
    --key-hex 0707070707070707 >/dev/null 2>&1 &
SERVER_PID=$!
sleep 0.3
reach_once() {
    $IP netns exec "${TAG}c" timeout 2 "$SPIKE" reach --transport udp \
        --host 10.243.0.1:60400 --key-hex 0707070707070707 >/dev/null 2>&1
}
reach_once || { echo "pre-outage reach failed" >&2; exit 1; }
$IP netns exec "${TAG}c" $TC qdisc replace dev "${TAG}c" root netem loss 100%
start=$SECONDS
while (( SECONDS - start < 5 )); do
    if reach_once; then
        echo "unexpected success during outage" >&2
        exit 1
    fi
    sleep 0.5
done
$IP netns exec "${TAG}c" $TC qdisc del dev "${TAG}c" root
restore_start=$(date +%s%N)
for _ in $(seq 1 20); do
    if reach_once; then
        break
    fi
    sleep 0.1
done
restore_end=$(date +%s%N)
if ! reach_once; then
    echo "post-outage reach failed" >&2
    exit 1
fi
printf 'outage_seconds=5\nbounded_failures_during_outage=true\nrecovery_after_restore_ms=%d\n' \
    "$(( (restore_end - restore_start) / 1000000 ))" >"$OUT"
cat "$OUT"
