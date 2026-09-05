#!/usr/bin/env bash
# Exact-SHA idle and unauthenticated-load resource gate for authenticated UDP.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SPIKE=${EVERUDP_BIN:-$ROOT/spikes/everudp/target/release/everudp-spike}
OUTDIR=${1:?usage: resource-gate.sh OUTDIR}
RUN_USER=${SUDO_USER:-$(stat -c %U "$ROOT")}
IP=/usr/bin/ip
TIME=/usr/bin/time
TIME_FORMAT=$'user_seconds=%U\nsystem_seconds=%S\nmax_rss_kib=%M\nexit_status=%x'
COUNT=10000
PAYLOAD_BYTES=1200
IDLE_SECONDS=5
MAX_IDLE_CPU_SECONDS=0.10
MAX_RSS_GROWTH_KIB=8192

if (( EUID != 0 )); then
    echo "resource gate requires root network-namespace privileges" >&2
    exit 2
fi
for executable in "$SPIKE" /usr/bin/python3 /usr/bin/ping /usr/sbin/sysctl /usr/bin/jq "$TIME"; do
    [[ -x $executable ]] || { echo "missing executable: $executable" >&2; exit 1; }
done
[[ -f $NET/hostile-flood.py ]] || { echo "missing hostile flood driver" >&2; exit 1; }
[[ ! -e $OUTDIR ]] || { echo "refusing to overwrite resource output: $OUTDIR" >&2; exit 1; }

run_user() {
    /usr/bin/sudo -n -H -u "$RUN_USER" "$@"
}

HEAD_SHA=$(run_user git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(run_user git -C "$ROOT" rev-parse HEAD^{tree})
DIRTY_STATE=$(run_user git -C "$ROOT" status --porcelain=v1)
if [[ -n $DIRTY_STATE && ${EVERUDP_ALLOW_DIRTY:-0} != 1 ]]; then
    echo "refusing exact-SHA resource gate from a dirty worktree" >&2
    exit 1
fi
DIRTY_JSON=false
[[ -z $DIRTY_STATE ]] || DIRTY_JSON=true

mkdir -p "$OUTDIR"
TAG=r$((RANDOM & 32767))
SERVER_NS=${TAG}s
CLIENT_NS=${TAG}c
SERVER_PID=
cleaned=0
cleanup() {
    (( cleaned )) && return
    cleaned=1
    set +e
    [[ -z $SERVER_PID ]] || kill -KILL "$SERVER_PID" 2>/dev/null
    for ns in "$CLIENT_NS" "$SERVER_NS"; do
        "$IP" netns pids "$ns" 2>/dev/null | xargs -r kill -KILL 2>/dev/null
        "$IP" netns del "$ns" 2>/dev/null
    done
    "$IP" link del "${TAG}c" 2>/dev/null
}
trap cleanup EXIT

$IP netns add "$SERVER_NS"
$IP netns add "$CLIENT_NS"
$IP link add "${TAG}s" type veth peer name "${TAG}c"
$IP link set "${TAG}s" netns "$SERVER_NS"
$IP link set "${TAG}c" netns "$CLIENT_NS"
$IP -n "$SERVER_NS" link set "${TAG}s" name s0
$IP -n "$CLIENT_NS" link set "${TAG}c" name c0
$IP netns exec "$SERVER_NS" /usr/sbin/sysctl -qw net.ipv6.conf.all.disable_ipv6=1
$IP netns exec "$CLIENT_NS" /usr/sbin/sysctl -qw net.ipv6.conf.all.disable_ipv6=1
$IP -n "$SERVER_NS" link set lo up
$IP -n "$CLIENT_NS" link set lo up
$IP -n "$SERVER_NS" addr add 10.244.0.1/24 dev s0
$IP -n "$CLIENT_NS" addr add 10.244.0.2/24 dev c0
$IP -n "$SERVER_NS" link set s0 up
$IP -n "$CLIENT_NS" link set c0 up
SERVER_MAC=$($IP -j -n "$SERVER_NS" link show dev s0 | jq -r '.[0].address')
CLIENT_MAC=$($IP -j -n "$CLIENT_NS" link show dev c0 | jq -r '.[0].address')
$IP -n "$CLIENT_NS" neigh replace 10.244.0.1 lladdr "$SERVER_MAC" nud permanent dev c0
$IP -n "$SERVER_NS" neigh replace 10.244.0.2 lladdr "$CLIENT_MAC" nud permanent dev s0
$IP netns exec "$CLIENT_NS" /usr/bin/ping -q -c 1 -W 1 10.244.0.1 \
    >"$OUTDIR/neighbor-warmup.txt"
sleep 1

STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
$IP netns exec "$SERVER_NS" "$SPIKE" udp-server \
    --bind 10.244.0.1:60400 \
    --key-hex 62bc8275e2d0fa1d11abb04d07d7e47731c70879c2d343bc47deb577df13ee7d \
    >"$OUTDIR/server.stdout" 2>"$OUTDIR/server.stderr" &
SERVER_PID=$!
sleep 0.3
kill -0 "$SERVER_PID" 2>/dev/null || { cat "$OUTDIR/server.stderr" >&2; exit 1; }

snapshot() {
    local label=$1
    [[ -r /proc/$SERVER_PID/status && -r /proc/$SERVER_PID/stat ]] || {
        echo "server disappeared before $label snapshot" >&2
        exit 1
    }
    {
        printf 'pid=%s\n' "$SERVER_PID"
        sed -n -E '/^(Name|VmPeak|VmHWM|VmRSS|Threads):/p' "/proc/$SERVER_PID/status"
        awk '{printf "user_ticks=%s\nsystem_ticks=%s\n", $14, $15}' "/proc/$SERVER_PID/stat"
    } >"$OUTDIR/process-$label.txt"
    $IP -s -j -n "$SERVER_NS" link show dev s0 >"$OUTDIR/network-server-$label.json"
    $IP -s -j -n "$CLIENT_NS" link show dev c0 >"$OUTDIR/network-client-$label.json"
}

snapshot idle-before
sleep "$IDLE_SECONDS"
snapshot idle-after

snapshot hostile-before
$IP netns exec "$CLIENT_NS" "$TIME" -f "$TIME_FORMAT" \
    -o "$OUTDIR/resource-hostile-client.txt" \
    /usr/bin/python3 "$NET/hostile-flood.py" 10.244.0.1 60400 \
    --count "$COUNT" --size "$PAYLOAD_BYTES" >"$OUTDIR/hostile.json" \
    2>"$OUTDIR/hostile.stderr"
sleep 0.5
kill -0 "$SERVER_PID" 2>/dev/null || { echo "server died under hostile load" >&2; exit 1; }
snapshot hostile-after

$IP netns exec "$CLIENT_NS" timeout 5 "$SPIKE" reach --transport udp \
    --host 10.244.0.1:60400 \
    --key-hex 62bc8275e2d0fa1d11abb04d07d7e47731c70879c2d343bc47deb577df13ee7d \
    >"$OUTDIR/legitimate.json" 2>"$OUTDIR/legitimate.stderr"
kill -0 "$SERVER_PID" 2>/dev/null || { echo "server died after legitimate association" >&2; exit 1; }
snapshot legitimate-after
FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

python3 - "$OUTDIR" "$HEAD_SHA" "$TREE_SHA" "$DIRTY_JSON" \
    "$STARTED_UTC" "$FINISHED_UTC" "$SPIKE" "$COUNT" "$PAYLOAD_BYTES" \
    "$IDLE_SECONDS" "$MAX_IDLE_CPU_SECONDS" "$MAX_RSS_GROWTH_KIB" <<'PY'
import hashlib
import json
import os
import re
import sys
from pathlib import Path

(
    outdir_raw, head, tree, dirty_raw, started, finished, binary, count,
    payload_bytes, idle_seconds, max_idle_cpu, max_rss_growth,
) = sys.argv[1:]
outdir = Path(outdir_raw)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def process(label):
    text = (outdir / f"process-{label}.txt").read_text(encoding="utf-8")
    def value(name):
        match = re.search(rf"^{name}(?:\s*:\s*|=)([0-9]+)", text, re.MULTILINE)
        if not match:
            raise SystemExit(f"missing {name} in process-{label}.txt")
        return int(match.group(1))
    return {
        "user_ticks": value("user_ticks"),
        "system_ticks": value("system_ticks"),
        "rss_kib": value("VmRSS"),
        "hwm_kib": value("VmHWM"),
        "threads": value("Threads"),
    }

def network(side, label):
    data = json.loads((outdir / f"network-{side}-{label}.json").read_text(encoding="utf-8"))[0]
    stats = data["stats64"]
    return {
        "rx_bytes": stats["rx"]["bytes"],
        "rx_packets": stats["rx"]["packets"],
        "tx_bytes": stats["tx"]["bytes"],
        "tx_packets": stats["tx"]["packets"],
    }

def delta(before, after):
    result = {name: after[name] - before[name] for name in before}
    if any(value < 0 for value in result.values()):
        raise SystemExit("counter regression")
    return result

idle_before = process("idle-before")
idle_after = process("idle-after")
hostile_before = process("hostile-before")
hostile_after = process("hostile-after")
clock_ticks = os.sysconf("SC_CLK_TCK")
idle_cpu_seconds = (
    idle_after["user_ticks"] + idle_after["system_ticks"]
    - idle_before["user_ticks"] - idle_before["system_ticks"]
) / clock_ticks
idle_server_network = delta(network("server", "idle-before"), network("server", "idle-after"))
hostile_server_network = delta(
    network("server", "hostile-before"), network("server", "hostile-after")
)
hostile_client_network = delta(
    network("client", "hostile-before"), network("client", "hostile-after")
)
rss_growth_kib = max(0, hostile_after["rss_kib"] - hostile_before["rss_kib"])
hostile = json.loads((outdir / "hostile.json").read_text(encoding="utf-8"))
legitimate = json.loads((outdir / "legitimate.json").read_text(encoding="utf-8"))

verdict = {
    "idle_cpu_pass": idle_cpu_seconds <= float(max_idle_cpu),
    "idle_zero_tx_pass": idle_server_network["tx_packets"] == 0,
    "hostile_count_pass": hostile["sent_datagrams"] == int(count),
    "hostile_zero_amplification_pass": hostile["response_datagrams"] == 0
    and hostile_server_network["tx_packets"] == 0,
    "hostile_rss_growth_pass": rss_growth_kib <= int(max_rss_growth),
    "legitimate_after_hostile_pass": legitimate.get("reach") is True,
}
verdict["resource_gate_pass"] = all(verdict.values())
receipts = {
    path.name: digest(path)
    for path in sorted(outdir.iterdir())
    if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
}
manifest = {
    "schema_version": 1,
    "source": {"head_sha": head, "tree_sha": tree, "dirty": dirty_raw == "true"},
    "started_utc": started,
    "finished_utc": finished,
    "method": {
        "idle_seconds": int(idle_seconds),
        "hostile_datagrams": int(count),
        "hostile_payload_bytes_each": int(payload_bytes),
        "server_binary_sha256": digest(binary),
        "ceilings": {
            "idle_cpu_seconds": float(max_idle_cpu),
            "idle_tx_packets": 0,
            "hostile_response_packets": 0,
            "hostile_rss_growth_kib": int(max_rss_growth),
        },
    },
    "observed": {
        "idle_cpu_seconds": idle_cpu_seconds,
        "idle_server_network": idle_server_network,
        "hostile_server_network": hostile_server_network,
        "hostile_client_network": hostile_client_network,
        "hostile_rss_growth_kib": rss_growth_kib,
        "hostile_driver": hostile,
        "legitimate_after_hostile": legitimate,
    },
    "receipt_files": receipts,
    "verdict": verdict,
}
(outdir / "manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
if not verdict["resource_gate_pass"]:
    raise SystemExit("resource gate failed")
PY

(
    cd "$OUTDIR"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' \
        | sort -z | xargs -0 sha256sum >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
jq -c '.verdict + .observed' "$OUTDIR/manifest.json"
echo "resource gate complete: $OUTDIR"
