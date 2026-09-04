#!/usr/bin/env bash
# Paired everudp/zmosh end-to-end PTY benchmark under deterministic 5% loss.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
TRIALS=${1:?usage: bench-parity.sh TRIALS SEED OUTDIR [everudp-first|zmosh-first]}
BLOCK_SEED=${2:?usage: bench-parity.sh TRIALS SEED OUTDIR [everudp-first|zmosh-first]}
OUTDIR=${3:?usage: bench-parity.sh TRIALS SEED OUTDIR [everudp-first|zmosh-first]}
ORDER=${4:-}
LOSS_PCT=5
GAP_MS=100

if ! [[ $TRIALS =~ ^[0-9]+$ && $BLOCK_SEED =~ ^[0-9]+$ ]]; then
    echo "trials and seed must be positive integers" >&2
    exit 2
fi
if (( TRIALS < 30 )) && [[ ${EVERUDP_ALLOW_SHORT:-0} != 1 ]]; then
    echo "at least 30 trials are required; set EVERUDP_ALLOW_SHORT=1 only for harness smoke tests" >&2
    exit 2
fi
if (( BLOCK_SEED < 1 || BLOCK_SEED > 2147483646 )); then
    echo "seed must be in [1, 2147483646]" >&2
    exit 2
fi
if [[ -z $ORDER ]]; then
    if (( BLOCK_SEED % 2 )); then
        ORDER=everudp-first
    else
        ORDER=zmosh-first
    fi
fi
if [[ $ORDER != everudp-first && $ORDER != zmosh-first ]]; then
    echo "order must be everudp-first or zmosh-first" >&2
    exit 2
fi

EVERUDP_BIN=${EVERUDP_BIN:-$ROOT/spikes/everudp/target/release/everudp-spike}
ZMOSH_PREFIX=${ZMOSH_PREFIX:-/tmp/zmosh-059-out}
ZMOSH_BIN=${ZMOSH_BIN:-$ZMOSH_PREFIX/bin/zmosh}
ZMOSH_SOURCE_COMMIT=${ZMOSH_SOURCE_COMMIT:-dfc8395b5edcd237bf82712fbde879c6e8be7dfa}
ZMOSH_SOURCE_TREE=${ZMOSH_SOURCE_TREE:-1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514}
IP=/usr/bin/ip
TC=/usr/sbin/tc

for executable in "$EVERUDP_BIN" "$ZMOSH_BIN" "$IP" "$TC" /usr/bin/python3 /usr/bin/cc; do
    [[ -x $executable ]] || { echo "missing executable: $executable" >&2; exit 1; }
done
for required in "$ZMOSH_PREFIX/include/zmosh/zmosh.h" "$ZMOSH_PREFIX/lib/libzmosh.a" "$NET/zmosh-bench.c" "$NET/echo1.py"; do
    [[ -f $required ]] || { echo "missing input: $required" >&2; exit 1; }
done

HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(git -C "$ROOT" rev-parse HEAD^{tree})
DIRTY_STATE=$(git -C "$ROOT" status --porcelain=v1)
DIRTY_JSON=false
[[ -z $DIRTY_STATE ]] || DIRTY_JSON=true
if [[ -n $DIRTY_STATE && ${EVERUDP_ALLOW_DIRTY:-0} != 1 ]]; then
    echo "refusing exact-SHA benchmark from a dirty worktree" >&2
    exit 1
fi

mkdir -p "$OUTDIR"
TMP=$(mktemp -d)
TAG=p$((RANDOM & 32767))
SERVER_NS=${TAG}s
CLIENT_NS=${TAG}c
SESSION=everudp-$TAG
ZMX_DIR=$TMP/zmx
SERVER_PID=
ZMOSH_PID=
cleaned=0

cleanup() {
    (( cleaned )) && return
    cleaned=1
    set +e
    [[ -z $SERVER_PID ]] || kill -KILL "$SERVER_PID" 2>/dev/null
    [[ -z $ZMOSH_PID ]] || kill -KILL "$ZMOSH_PID" 2>/dev/null
    if "$IP" netns list | grep -q "^$SERVER_NS "; then
        "$IP" netns exec "$SERVER_NS" /usr/bin/env -u ZMX_SESSION ZMX_DIR="$ZMX_DIR" \
            "$ZMOSH_BIN" kill "$SESSION" >/dev/null 2>&1
    fi
    for ns in "$CLIENT_NS" "$SERVER_NS"; do
        "$IP" netns pids "$ns" 2>/dev/null | xargs -r kill -KILL 2>/dev/null
        "$IP" netns del "$ns" 2>/dev/null
    done
    "$IP" link del "${TAG}c" 2>/dev/null
    rm -rf -- "$TMP"
}
trap cleanup EXIT

mkdir -p "$ZMX_DIR"
/usr/bin/cc -O3 -Wall -Wextra -Werror -no-pie \
    -I "$ZMOSH_PREFIX/include" "$NET/zmosh-bench.c" \
    "$ZMOSH_PREFIX/lib/libzmosh.a" -o "$TMP/zmosh-bench" -lpthread

$IP netns add "$SERVER_NS"
$IP netns add "$CLIENT_NS"
$IP link add "${TAG}s" type veth peer name "${TAG}c"
$IP link set "${TAG}s" netns "$SERVER_NS"
$IP link set "${TAG}c" netns "$CLIENT_NS"
$IP -n "$SERVER_NS" link set "${TAG}s" name s0
$IP -n "$CLIENT_NS" link set "${TAG}c" name c0
$IP -n "$SERVER_NS" link set lo up
$IP -n "$CLIENT_NS" link set lo up
$IP -n "$SERVER_NS" addr add 10.242.0.1/24 dev s0
$IP -n "$CLIENT_NS" addr add 10.242.0.2/24 dev c0
$IP -n "$SERVER_NS" link set s0 up
$IP -n "$CLIENT_NS" link set c0 up

CLIENT_SEED=$BLOCK_SEED
SERVER_SEED=$((BLOCK_SEED + 1000003))

reset_netem() {
    local label=$1
    $IP netns exec "$CLIENT_NS" $TC qdisc replace dev c0 root netem \
        loss random "${LOSS_PCT}%" seed "$CLIENT_SEED"
    $IP netns exec "$SERVER_NS" $TC qdisc replace dev s0 root netem \
        loss random "${LOSS_PCT}%" seed "$SERVER_SEED"
    $IP netns exec "$CLIENT_NS" $TC -s qdisc show dev c0 >"$OUTDIR/netem-$label-client.txt"
    $IP netns exec "$SERVER_NS" $TC -s qdisc show dev s0 >"$OUTDIR/netem-$label-server.txt"
}

run_everudp() {
    $IP netns exec "$SERVER_NS" "$EVERUDP_BIN" udp-pty-server \
        --bind 10.242.0.1:60200 --key-hex 0707070707070707 \
        --echo-command "/usr/bin/python3 -u $NET/echo1.py" \
        >"$OUTDIR/everudp-server.stdout" 2>"$OUTDIR/everudp-server.stderr" &
    SERVER_PID=$!
    sleep 0.3
    reset_netem everudp
    $IP netns exec "$CLIENT_NS" "$EVERUDP_BIN" bench \
        --transport udp --prediction on --trials "$TRIALS" \
        --server 10.242.0.1:60200 >"$OUTDIR/everudp.json" \
        2>"$OUTDIR/everudp.stderr"
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=
}

run_zmosh() {
    $IP netns exec "$SERVER_NS" /usr/bin/env -u ZMX_SESSION TERM=xterm-256color ZMX_DIR="$ZMX_DIR" \
        "$ZMOSH_BIN" run "$SESSION" /usr/bin/python3 -u "$NET/echo1.py" >/dev/null
    sleep 0.3
    $IP netns exec "$SERVER_NS" /usr/bin/env -u ZMX_SESSION TERM=xterm-256color ZMX_DIR="$ZMX_DIR" \
        "$ZMOSH_BIN" serve "$SESSION" >"$TMP/zmosh-connect.txt" \
        2>"$OUTDIR/zmosh-server.stderr" &
    ZMOSH_PID=$!
    for _ in $(seq 1 50); do
        grep -q '^ZMX_CONNECT' "$TMP/zmosh-connect.txt" && break
        sleep 0.1
    done
    local zport zkey
    read -r _ _ zport zkey <"$TMP/zmosh-connect.txt"
    [[ -n ${zkey:-} ]] || { echo "zmosh gateway did not publish bootstrap" >&2; exit 1; }
    reset_netem zmosh
    local samples
    samples=$($IP netns exec "$CLIENT_NS" "$TMP/zmosh-bench" \
        10.242.0.1 "$zport" "$zkey" "$TRIALS" "$GAP_MS")
    /usr/bin/python3 - "$OUTDIR/zmosh.json" "$samples" "$TRIALS" <<'PY'
import json
import math
import sys

path, raw, expected = sys.argv[1], sys.argv[2], int(sys.argv[3])
samples = json.loads(raw)
if len(samples) != expected:
    raise SystemExit(f"expected {expected} zmosh samples, got {len(samples)}")
ordered = sorted(value for value in samples if value > 0)

def nearest_rank(p):
    if not ordered:
        return 0
    return ordered[max(0, math.ceil(p * len(ordered)) - 1)]

with open(path, "w", encoding="utf-8") as stream:
    json.dump({
        "transport": "zmosh-udp",
        "trials": expected,
        "nonzero": len(ordered),
        "median_us": nearest_rank(0.50),
        "p95_us": nearest_rank(0.95),
        "max_us": ordered[-1] if ordered else 0,
        "samples": samples,
    }, stream, separators=(",", ":"))
    stream.write("\n")
PY
    kill "$ZMOSH_PID" 2>/dev/null || true
    wait "$ZMOSH_PID" 2>/dev/null || true
    ZMOSH_PID=
    $IP netns exec "$SERVER_NS" /usr/bin/env -u ZMX_SESSION ZMX_DIR="$ZMX_DIR" \
        "$ZMOSH_BIN" kill "$SESSION" >/dev/null 2>&1 || true
}

STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if [[ $ORDER == everudp-first ]]; then
    run_everudp
    run_zmosh
else
    run_zmosh
    run_everudp
fi
FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

EVERUDP_SHA=$(sha256sum "$EVERUDP_BIN" | awk '{print $1}')
ZMOSH_SHA=$(sha256sum "$ZMOSH_BIN" | awk '{print $1}')
ZMOSH_BENCH_SHA=$(sha256sum "$TMP/zmosh-bench" | awk '{print $1}')
EVERUDP_RESULT_SHA=$(sha256sum "$OUTDIR/everudp.json" | awk '{print $1}')
ZMOSH_RESULT_SHA=$(sha256sum "$OUTDIR/zmosh.json" | awk '{print $1}')
KERNEL=$(uname -srmo)
CPU_MODEL=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)

/usr/bin/python3 - "$OUTDIR/manifest.json" <<PY
import json

manifest = {
    "schema_version": 1,
    "source": {
        "head_sha": "$HEAD_SHA",
        "tree_sha": "$TREE_SHA",
        "dirty": "$DIRTY_JSON" == "true",
    },
    "command": ["spikes/everudp/net/bench-parity.sh", $TRIALS, $BLOCK_SEED, "$OUTDIR", "$ORDER"],
    "started_utc": "$STARTED_UTC",
    "finished_utc": "$FINISHED_UTC",
    "topology": "two Linux network namespaces joined by one veth pair",
    "workload": "rotating one-byte printable input through Python echo1.py on a real PTY",
    "trials_per_candidate": $TRIALS,
    "inter_trial_ms": $GAP_MS,
    "loss": {
        "kind": "symmetric independent netem random loss",
        "percent_each_direction": $LOSS_PCT,
        "client_seed": $CLIENT_SEED,
        "server_seed": $SERVER_SEED,
        "reset_before_each_candidate": True,
    },
    "order": "$ORDER",
    "host": {"kernel": "$KERNEL", "cpu_model": "$CPU_MODEL"},
    "artifacts": {
        "everudp": {"path": "$EVERUDP_BIN", "sha256": "$EVERUDP_SHA"},
        "zmosh": {
            "path": "$ZMOSH_BIN",
            "sha256": "$ZMOSH_SHA",
            "source_commit": "$ZMOSH_SOURCE_COMMIT",
            "source_tree": "$ZMOSH_SOURCE_TREE",
        },
        "zmosh_bench": {"source": "spikes/everudp/net/zmosh-bench.c", "sha256": "$ZMOSH_BENCH_SHA"},
    },
    "results": {
        "everudp.json": "$EVERUDP_RESULT_SHA",
        "zmosh.json": "$ZMOSH_RESULT_SHA",
    },
}
with open("$OUTDIR/manifest.json", "w", encoding="utf-8") as stream:
    json.dump(manifest, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

echo "parity block complete: $OUTDIR"
