#!/usr/bin/env bash
# Rootless, paired development sweep for the frozen everudp QUIC matrix.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
TRIALS=${1:-200}
OUTDIR=${2:?usage: tune-profiles.sh [TRIALS] OUTDIR}
RESAMPLES=${EVERUDP_TUNING_RESAMPLES:-20000}
SEED_0=910001
SEED_5=910003

if ! [[ $TRIALS =~ ^[0-9]+$ ]] || (( TRIALS < 20 || TRIALS > 10000 )); then
    echo "trials must be an integer in [20, 10000]" >&2
    exit 2
fi
if (( TRIALS < 200 )) && [[ ${EVERUDP_ALLOW_SHORT:-0} != 1 ]]; then
    echo "at least 200 trials are required for selection; set EVERUDP_ALLOW_SHORT=1 only for harness validation" >&2
    exit 2
fi
if ! [[ $RESAMPLES =~ ^[0-9]+$ ]] || (( RESAMPLES < 100 )); then
    echo "EVERUDP_TUNING_RESAMPLES must be an integer of at least 100" >&2
    exit 2
fi

for executable in cargo git python3 /usr/bin/time taskset sha256sum; do
    command -v "$executable" >/dev/null || { echo "missing executable: $executable" >&2; exit 1; }
done

HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(git -C "$ROOT" rev-parse HEAD^{tree})
DIRTY=$(git -C "$ROOT" status --porcelain=v1)
if [[ -n $DIRTY && ${EVERUDP_ALLOW_DIRTY:-0} != 1 ]]; then
    echo "refusing tuning sweep from a dirty worktree" >&2
    exit 1
fi

mkdir -p "$OUTDIR"
OUTDIR=$(cd -- "$OUTDIR" && pwd -P)
if [[ -n $(find "$OUTDIR" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    echo "tuning output directory must be empty: $OUTDIR" >&2
    exit 1
fi

if [[ -n ${EVERUDP_TUNE_BIN:-} ]]; then
    TUNE_BIN=$EVERUDP_TUNE_BIN
    [[ -x $TUNE_BIN ]] || { echo "missing tuning binary: $TUNE_BIN" >&2; exit 1; }
else
    cargo build --manifest-path "$ROOT/Cargo.toml" --release --locked \
        -p everudp --example everudp-tune --features tuning
    TUNE_BIN=$ROOT/target/release/examples/everudp-tune
fi

CPU=${EVERUDP_TUNING_CPU:-$(python3 - <<'PY'
import os
print(min(os.sched_getaffinity(0)))
PY
)}
taskset -c "$CPU" true
GOVERNOR=unavailable
if [[ -r /sys/devices/system/cpu/cpu$CPU/cpufreq/scaling_governor ]]; then
    GOVERNOR=$(</sys/devices/system/cpu/cpu$CPU/cpufreq/scaling_governor)
fi

PROFILES=()
for rtt in 25 100 333; do
    for ack in off every-1ms every-other-5ms; do
        for gso in off on; do
            PROFILES+=("rtt$rtt-$ack-gso-$gso")
        done
    done
done

STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DIRTY_BOOL=false
[[ -z $DIRTY ]] || DIRTY_BOOL=true
python3 - "$OUTDIR/manifest.json" "$HEAD_SHA" "$TREE_SHA" "$TRIALS" \
    "$SEED_0" "$SEED_5" "$CPU" "$GOVERNOR" "$TUNE_BIN" "$DIRTY_BOOL" \
    "$ROOT" "$NET/tune-profiles.sh" "$NET/analyze-tuning.py" \
    "${PROFILES[@]}" <<'PY'
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

(
    path, head, tree, trials, seed0, seed5, cpu, governor, binary_raw, dirty,
    root_raw, harness_raw, analyzer_raw, *profiles,
) = sys.argv[1:]
binary = Path(binary_raw)
root = Path(root_raw)
harness = Path(harness_raw)
analyzer = Path(analyzer_raw)
manifest = {
    "schema_version": 1,
    "source": {"head_sha": head, "tree_sha": tree, "dirty": dirty == "true"},
    "trials": int(trials),
    "seeds": {"0": int(seed0), "5": int(seed5)},
    "profiles": profiles,
    "cells": [0, 5],
    "timer": "immediately before ClientAssociation::queue_input through exact OutputOperation acceptance by the local sink",
    "correctness": "one exact byte, sequence, application ACK, and sink call per trial; no output during the post-cell quiet window",
    "topology": "current-thread Tokio runtime, real noq QUIC endpoints, deterministic bidirectional userspace UDP loss proxy",
    "ranking": "correct profiles only; worst-cell p95, then p50, then CPU",
    "selection": "retain preregistered default unless paired block-stratified 95% p95 ratio interval is wholly below 1.00",
    "host": {"kernel": platform.release(), "machine": platform.machine(), "cpu": int(cpu), "governor": governor},
    "toolchain": {
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "cargo": subprocess.check_output(["cargo", "--version"], text=True).strip(),
        "python": platform.python_version(),
    },
    "binary": {"path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()},
    "harness": {
        "path": str(harness.relative_to(root)),
        "sha256": hashlib.sha256(harness.read_bytes()).hexdigest(),
    },
    "analyzer": {
        "path": str(analyzer.relative_to(root)),
        "sha256": hashlib.sha256(analyzer.read_bytes()).hexdigest(),
    },
}
Path(path).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

failures=0
for profile in "${PROFILES[@]}"; do
    remainder=${profile#rtt}
    rtt=${remainder%%-*}
    remainder=${remainder#*-}
    ack=${remainder%-gso-*}
    gso=${profile##*-gso-}
    for loss in 0 5; do
        seed=$SEED_0
        (( loss == 0 )) || seed=$SEED_5
        stem=$profile-loss$loss
        if taskset -c "$CPU" /usr/bin/time -f '%U %S %M %e' \
            -o "$OUTDIR/$stem.time" \
            "$TUNE_BIN" "$rtt" "$ack" "$gso" "$loss" "$TRIALS" "$seed" \
            >"$OUTDIR/$stem.json.tmp" 2>"$OUTDIR/$stem.stderr"; then
            mv "$OUTDIR/$stem.json.tmp" "$OUTDIR/$stem.json"
        else
            status=$?
            printf 'exit=%d\n' "$status" >"$OUTDIR/$stem.failed"
            rm -f "$OUTDIR/$stem.json.tmp"
            failures=$((failures + 1))
        fi
    done
done
FINISHED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

python3 - "$OUTDIR/manifest.json" "$STARTED" "$FINISHED" "$failures" <<'PY'
import json
import sys
from pathlib import Path

path, started, finished, failures = sys.argv[1:]
manifest = json.loads(Path(path).read_text(encoding="utf-8"))
manifest["started_utc"] = started
manifest["finished_utc"] = finished
manifest["failed_cells"] = int(failures)
Path(path).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "$NET/analyze-tuning.py" "$OUTDIR" "$OUTDIR/selection.json" \
    --resamples "$RESAMPLES"
(
    cd "$OUTDIR"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' \
        | sort -z | xargs -0 sha256sum >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
