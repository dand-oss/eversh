#!/usr/bin/env bash
# Exact-SHA five-second total-loss and fresh-association recovery gate.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
SPIKE=$ROOT/spikes/everudp/target/release/everudp-spike
OUTDIR=${1:-$ROOT/target/qualification/everudp/outage}
RUN_USER=${SUDO_USER:-$(stat -c %U "$ROOT")}
IP=/usr/bin/ip
TC=/usr/sbin/tc
OUTAGE_SECONDS=5
PORT=60400

if (( EUID != 0 )); then
    echo "outage gate requires root network-namespace privileges" >&2
    exit 2
fi
for executable in "$SPIKE" "$IP" "$TC" /usr/bin/timeout /usr/bin/python3 /usr/bin/jq; do
    [[ -x $executable ]] || { echo "missing executable: $executable" >&2; exit 1; }
done
[[ ! -e $OUTDIR ]] || { echo "refusing to overwrite outage output: $OUTDIR" >&2; exit 1; }

run_user() {
    /usr/bin/sudo -n -H -u "$RUN_USER" "$@"
}

HEAD_SHA=$(run_user git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(run_user git -C "$ROOT" rev-parse HEAD^{tree})
DIRTY_STATE=$(run_user git -C "$ROOT" status --porcelain=v1)
if [[ -n $DIRTY_STATE && ${EVERUDP_ALLOW_DIRTY:-0} != 1 ]]; then
    echo "refusing exact-SHA outage gate from a dirty worktree" >&2
    exit 1
fi
DIRTY_JSON=false
[[ -z $DIRTY_STATE ]] || DIRTY_JSON=true

mkdir -p "$OUTDIR"
printf 'phase\tattempt\texit_code\telapsed_ms\n' >"$OUTDIR/attempts.tsv"
TAG=o$((RANDOM & 32767))
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
$IP -n "$SERVER_NS" link set lo up
$IP -n "$CLIENT_NS" link set lo up
$IP -n "$SERVER_NS" addr add 10.243.0.1/24 dev s0
$IP -n "$CLIENT_NS" addr add 10.243.0.2/24 dev c0
$IP -n "$SERVER_NS" link set s0 up
$IP -n "$CLIENT_NS" link set c0 up
SERVER_MAC=$($IP -j -n "$SERVER_NS" link show dev s0 | jq -r '.[0].address')
CLIENT_MAC=$($IP -j -n "$CLIENT_NS" link show dev c0 | jq -r '.[0].address')
$IP -n "$CLIENT_NS" neigh replace 10.243.0.1 lladdr "$SERVER_MAC" nud permanent dev c0
$IP -n "$SERVER_NS" neigh replace 10.243.0.2 lladdr "$CLIENT_MAC" nud permanent dev s0

LAST_CODE=
LAST_ELAPSED_MS=
reach_once() {
    local phase=$1 attempt=$2
    local stem="$OUTDIR/$phase-$attempt"
    $IP netns exec "$SERVER_NS" "$SPIKE" udp-server \
        --bind "10.243.0.1:$PORT" \
        --key-hex 62bc8275e2d0fa1d11abb04d07d7e47731c70879c2d343bc47deb577df13ee7d \
        >"$stem-server.stdout" 2>"$stem-server.stderr" &
    SERVER_PID=$!
    sleep 0.1
    kill -0 "$SERVER_PID" 2>/dev/null || { cat "$stem-server.stderr" >&2; exit 1; }
    local started finished
    started=$(date +%s%N)
    set +e
    $IP netns exec "$CLIENT_NS" /usr/bin/timeout 3 "$SPIKE" reach \
        --transport udp --host "10.243.0.1:$PORT" \
        --key-hex 62bc8275e2d0fa1d11abb04d07d7e47731c70879c2d343bc47deb577df13ee7d \
        >"$stem-client.stdout" 2>"$stem-client.stderr"
    LAST_CODE=$?
    set -e
    finished=$(date +%s%N)
    LAST_ELAPSED_MS=$(( (finished - started) / 1000000 ))
    printf '%s\t%s\t%s\t%s\n' "$phase" "$attempt" "$LAST_CODE" \
        "$LAST_ELAPSED_MS" >>"$OUTDIR/attempts.tsv"
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=
}

STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
reach_once pre 1
(( LAST_CODE == 0 )) || { echo "pre-outage reach failed" >&2; exit 1; }

$IP netns exec "$CLIENT_NS" $TC qdisc replace dev c0 root netem loss 100%
$IP netns exec "$SERVER_NS" $TC qdisc replace dev s0 root netem loss 100%
$IP netns exec "$CLIENT_NS" $TC -s qdisc show dev c0 >"$OUTDIR/netem-client-outage-before.txt"
$IP netns exec "$SERVER_NS" $TC -s qdisc show dev s0 >"$OUTDIR/netem-server-outage-before.txt"
outage_started=$(date +%s%N)
attempt=0
while :; do
    attempt=$((attempt + 1))
    reach_once outage "$attempt"
    (( LAST_CODE != 0 )) || { echo "unexpected success during total loss" >&2; exit 1; }
    grep -qx 'everudp-spike: UDP association handshake timed out' \
        "$OUTDIR/outage-$attempt-client.stderr" || {
        echo "outage failure lacked exact timeout diagnosis" >&2
        exit 1
    }
    now=$(date +%s%N)
    (( now - outage_started >= OUTAGE_SECONDS * 1000000000 )) && break
done
outage_finished=$(date +%s%N)
$IP netns exec "$CLIENT_NS" $TC -s qdisc show dev c0 >"$OUTDIR/netem-client-outage-after.txt"
$IP netns exec "$SERVER_NS" $TC -s qdisc show dev s0 >"$OUTDIR/netem-server-outage-after.txt"
$IP netns exec "$CLIENT_NS" $TC qdisc del dev c0 root
$IP netns exec "$SERVER_NS" $TC qdisc del dev s0 root

restore_started=$(date +%s%N)
recovery_attempt=0
while (( recovery_attempt < 20 )); do
    recovery_attempt=$((recovery_attempt + 1))
    reach_once recovery "$recovery_attempt"
    (( LAST_CODE != 0 )) || break
    sleep 0.1
done
restore_finished=$(date +%s%N)
(( LAST_CODE == 0 )) || { echo "post-outage recovery failed" >&2; exit 1; }
FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

python3 - "$OUTDIR" "$HEAD_SHA" "$TREE_SHA" "$DIRTY_JSON" \
    "$STARTED_UTC" "$FINISHED_UTC" "$SPIKE" "$OUTAGE_SECONDS" \
    "$outage_started" "$outage_finished" "$restore_started" "$restore_finished" <<'PY'
import csv
import hashlib
import json
import sys
from pathlib import Path

(
    outdir_raw, head, tree, dirty_raw, started, finished, binary,
    required_seconds, outage_started, outage_finished, restore_started,
    restore_finished,
) = sys.argv[1:]
outdir = Path(outdir_raw)
with (outdir / "attempts.tsv").open(encoding="utf-8") as stream:
    attempts = list(csv.DictReader(stream, delimiter="\t"))
for row in attempts:
    for field in ("attempt", "exit_code", "elapsed_ms"):
        row[field] = int(row[field])
pre = [row for row in attempts if row["phase"] == "pre"]
outage = [row for row in attempts if row["phase"] == "outage"]
recovery = [row for row in attempts if row["phase"] == "recovery"]
observed_outage_ms = (int(outage_finished) - int(outage_started)) // 1_000_000
recovery_ms = (int(restore_finished) - int(restore_started)) // 1_000_000
verdict = {
    "preflight_pass": len(pre) == 1 and pre[0]["exit_code"] == 0,
    "outage_duration_pass": observed_outage_ms >= int(required_seconds) * 1000,
    "bounded_diagnosed_failures_pass": len(outage) >= 1
    and all(row["exit_code"] != 0 and row["elapsed_ms"] <= 3000 for row in outage),
    "post_restore_recovery_pass": bool(recovery) and recovery[-1]["exit_code"] == 0,
}
verdict["outage_gate_pass"] = all(verdict.values())

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

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
        "loss": "100% symmetric netem on both egress paths",
        "minimum_outage_seconds": int(required_seconds),
        "association_scope": "each probe uses a fresh one-association server process",
        "server_binary_sha256": digest(binary),
    },
    "observed": {
        "outage_duration_ms": observed_outage_ms,
        "outage_failure_count": len(outage),
        "post_restore_recovery_ms": recovery_ms,
        "post_restore_attempts": len(recovery),
        "attempts": attempts,
    },
    "receipt_files": receipts,
    "verdict": verdict,
}
(outdir / "manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
if not verdict["outage_gate_pass"]:
    raise SystemExit("outage gate failed")
PY

(
    cd "$OUTDIR"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' \
        | sort -z | xargs -0 sha256sum >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
jq -c '.verdict + .observed' "$OUTDIR/manifest.json"
echo "outage gate complete: $OUTDIR"
