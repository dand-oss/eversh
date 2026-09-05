#!/usr/bin/env bash
# Exact-SHA repeated real-PTY terminal-grid correctness gate.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/../../.." && pwd -P)
TRIALS=${1:-30}
OUT=${2:-$ROOT/target/qualification/everudp/oracle.json}
BIN=${EVERUDP_BIN:-$ROOT/spikes/everudp/target/release/everudp-spike}
EXPECTED=echo,mismatch-correction,duplicate-reorder,full-screen,resize,tmux,no-echo,epoch-reset-resync

if ! [[ $TRIALS =~ ^[0-9]+$ ]] || (( TRIALS < 30 )); then
    echo "oracle gate requires at least 30 trials" >&2
    exit 2
fi
[[ -x $BIN ]] || { echo "missing release binary: $BIN" >&2; exit 1; }
for executable in /usr/bin/python3 /usr/bin/script /usr/bin/tmux; do
    [[ -x $executable ]] || { echo "missing oracle dependency: $executable" >&2; exit 1; }
done

HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(git -C "$ROOT" rev-parse HEAD^{tree})
[[ -z $(git -C "$ROOT" status --porcelain=v1) ]] || {
    echo "refusing exact-SHA oracle gate from a dirty worktree" >&2
    exit 1
}

TMP=$(mktemp -d)
cleanup() {
    rm -rf -- "$TMP"
}
trap cleanup EXIT

STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
for ((trial = 1; trial <= TRIALS; trial++)); do
    "$BIN" oracle >>"$TMP/runs.txt"
done
FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

mkdir -p "$(dirname -- "$OUT")"
RAW_OUT=$(dirname -- "$OUT")/oracle-runs.txt
cp "$TMP/runs.txt" "$RAW_OUT"
BIN_SHA=$(sha256sum "$BIN" | awk '{print $1}')
KERNEL=$(uname -srmo)
PYTHON_VERSION=$(/usr/bin/python3 --version 2>&1)
SCRIPT_VERSION=$(/usr/bin/script --version | head -1)
TMUX_VERSION=$(/usr/bin/tmux -V)

/usr/bin/python3 - "$RAW_OUT" "$OUT" <<PY
import hashlib
import json
import math
import re
import sys

raw_path, output_path = sys.argv[1:]
pattern = re.compile(
    r"^oracle: PASS workloads=(\\S+) correction_us=(\\d+) "
    r"password_prediction_displays=(\\d+) "
    r"persistent_predictions_applied=(\\d+) persistent_corrections=(\\d+)$"
)
runs = []
for line_number, line in enumerate(open(raw_path, encoding="utf-8"), 1):
    match = pattern.fullmatch(line.rstrip("\\n"))
    if not match:
        raise SystemExit(f"malformed oracle output on line {line_number}: {line!r}")
    (
        workloads,
        correction_us,
        password_predictions,
        predictions_applied,
        corrections,
    ) = match.groups()
    if workloads != "$EXPECTED":
        raise SystemExit(f"wrong workload set on line {line_number}: {workloads}")
    if int(password_predictions) != 0:
        raise SystemExit(f"password prediction on line {line_number}")
    if int(predictions_applied) != 9:
        raise SystemExit(
            f"wrong persistent prediction count on line {line_number}: {predictions_applied}"
        )
    if int(corrections) != 5:
        raise SystemExit(
            f"wrong persistent correction count on line {line_number}: {corrections}"
        )
    runs.append(int(correction_us))

if len(runs) != $TRIALS:
    raise SystemExit(f"expected {$TRIALS} runs, got {len(runs)}")
ordered = sorted(runs)
p95 = ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]
passed = p95 < 300_000
receipt = {
    "schema_version": 1,
    "source": {
        "head_sha": "$HEAD_SHA",
        "tree_sha": "$TREE_SHA",
        "dirty": False,
        "binary_sha256": "$BIN_SHA",
    },
    "command": ["spikes/everudp/net/oracle-gate.sh", $TRIALS, "$OUT"],
    "started_utc": "$STARTED_UTC",
    "finished_utc": "$FINISHED_UTC",
    "host": {
        "kernel": "$KERNEL",
        "python": "$PYTHON_VERSION",
        "script": "$SCRIPT_VERSION",
        "tmux": "$TMUX_VERSION",
    },
    "oracle": {
        "terminal_model": "vt100 0.16.2 independent authoritative/reconstructed grids",
        "grid_fields": [
            "dimensions", "cursor", "cells", "foreground", "background",
            "bold", "dim", "italic", "underline", "inverse", "wide-cell",
            "wrapped-row", "alternate-screen", "hidden-cursor",
        ],
        "workloads": "$EXPECTED".split(","),
        "real_pty_runs": len(runs),
        "password_prediction_displays": 0,
        "persistent_replica": True,
        "persistent_predictions_applied_per_run": 9,
        "persistent_corrections_per_run": 5,
        "correction_timing_boundary": (
            "start after predicted input is visible in the persistent vt100 grid; "
            "stop after authoritative reconcile, full redraw, and corrected grid capture"
        ),
        "correction_samples_us": runs,
        "correction_p95_us": p95,
        "correction_p95_limit_us": 300_000,
    },
    "raw_runs": {
        "path": "oracle-runs.txt",
        "sha256": hashlib.sha256(open(raw_path, "rb").read()).hexdigest(),
    },
    "verdict": {"pass": passed},
}
with open(output_path, "w", encoding="utf-8") as stream:
    json.dump(receipt, stream, indent=2, sort_keys=True)
    stream.write("\\n")
if not passed:
    raise SystemExit(f"correction p95 {p95} us exceeds 300000 us")
print(f"oracle gate: PASS runs={len(runs)} correction_p95_us={p95} receipt={output_path}")
PY
