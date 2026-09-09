#!/usr/bin/env bash
# Decisive stage-zero cutoff: two reversed 200-trial blocks in both loss cells.
set -Eeuo pipefail

if (( EUID != 0 )); then
    echo "everudp floor qualification requires root" >&2
    exit 77
fi

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
BUILD=${1:?usage: qualify-floor.sh EXACT_BUILD OUTROOT [TRIALS]}
OUTROOT=${2:?usage: qualify-floor.sh EXACT_BUILD OUTROOT [TRIALS]}
TRIALS=${3:-200}
BUILD=$(realpath -m -- "$BUILD")
OUTROOT=$(realpath -m -- "$OUTROOT")
RUN_USER=${SUDO_USER:-$(stat -c %U "$ROOT")}

[[ -f $BUILD/provenance.json && -f $BUILD/SHA256SUMS ]] || {
    echo "exact floor build provenance is incomplete: $BUILD" >&2
    exit 1
}
(cd "$BUILD" && sha256sum -c SHA256SUMS >/dev/null)
[[ ! -e $OUTROOT ]] || { echo "refusing to overwrite floor evidence: $OUTROOT" >&2; exit 1; }
if (( TRIALS != 200 )) && [[ ${EVERUDP_ALLOW_SHORT:-0} != 1 ]]; then
    echo "floor qualification requires exactly 200 observations per block" >&2
    exit 2
fi

HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(git -C "$ROOT" rev-parse 'HEAD^{tree}')
[[ -z $(git -C "$ROOT" status --porcelain=v1 --untracked-files=all) ]] || {
    echo "refusing floor qualification from a dirty worktree" >&2
    exit 1
}
[[ $(jq -r '.source.head_sha' "$BUILD/provenance.json") == "$HEAD_SHA" \
    && $(jq -r '.source.tree_sha' "$BUILD/provenance.json") == "$TREE_SHA" \
    && $(jq -r '.source.clean' "$BUILD/provenance.json") == true ]] || {
    echo "floor build does not match the clean candidate SHA" >&2
    exit 1
}

mkdir -p "$OUTROOT/build"
chown -- "$RUN_USER" "$OUTROOT"
install -m 0644 "$BUILD/provenance.json" "$OUTROOT/build/provenance.json"
STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
seal_incomplete() {
    local status=$?
    trap - EXIT INT TERM HUP
    /usr/bin/python3 -B "$NET/seal_floor_invalid.py" "$OUTROOT" "$HEAD_SHA" "$TREE_SHA" \
        "qualification did not finish; exit $status"
    exit "$status"
}
trap seal_incomplete EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

declare -a BLOCKS=()
run_block() {
    local loss=$1 index=$2 seed=$3 order=$4
    local path=$OUTROOT/loss${loss}-block${index}
    EVERUDP_PERF_BUILD="$BUILD" "$NET/bench-performance-block.sh" \
        "$TRIALS" "$loss" "$seed" "$path" "$order"
    BLOCKS+=("$path")
}

run_block 0 1 74001 everudp-floor,zmosh-udp
run_block 0 2 74002 zmosh-udp,everudp-floor
run_block 5 1 75001 everudp-floor,zmosh-udp
run_block 5 2 75002 zmosh-udp,everudp-floor
FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

/usr/bin/python3 - "$OUTROOT" "$HEAD_SHA" "$TREE_SHA" "$TRIALS" \
    "$STARTED_UTC" "$FINISHED_UTC" "${BLOCKS[@]}" <<'PY'
import hashlib
import json
import math
import random
import statistics
import sys
from pathlib import Path

out = Path(sys.argv[1])
head, tree, trials_raw, started, finished = sys.argv[2:7]
paths = [Path(raw) for raw in sys.argv[7:]]
trials = int(trials_raw)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]

cells = {}
passed = True
for loss in (0, 5):
    selected = [path for path in paths if path.name.startswith(f"loss{loss}-")]
    by_candidate = {"everudp-floor": [], "zmosh-udp": []}
    blocks = {name: [] for name in by_candidate}
    packets = {name: 0 for name in by_candidate}
    packet_block_ratios = []
    for path in selected:
        manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
        if any(manifest.get(field, False) for field in
               ("diagnostic_tracing", "native_stage_tracing", "reactor_work_tracing", "reactor_partition_tracing")):
            raise SystemExit("instrumented diagnostic blocks cannot qualify performance")
        for name in by_candidate:
            result = json.loads((path / name / "result.json").read_text(encoding="utf-8"))
            samples = result["samples_us"]
            if len(samples) != trials or result["transcript_failures"] != 0:
                raise SystemExit(f"invalid floor block result: {path}/{name}")
            blocks[name].append(samples)
            by_candidate[name].extend(samples)
            packet_evidence = manifest["loss_evidence"][name]
            if packet_evidence.get("measurement_window") != "post-warmup-start-barrier-to-pre-teardown-finish-barrier":
                raise SystemExit("missing measured packet window")
            attempts = packet_evidence["summed_egress_attempt_delta"]
            if type(attempts) is not int or attempts <= 0:
                raise SystemExit("invalid attempted-packet denominator")
            packets[name] += attempts
        packet_block_ratios.append(
            manifest["loss_evidence"]["everudp-floor"]["summed_egress_attempt_delta"] /
            manifest["loss_evidence"]["zmosh-udp"]["summed_egress_attempt_delta"])
    if any(len(values) != trials * 2 for values in by_candidate.values()):
        raise SystemExit(f"loss {loss}: floor evidence is incomplete")
    floor_p50 = statistics.median(by_candidate["everudp-floor"])
    control_p50 = statistics.median(by_candidate["zmosh-udp"])
    ratio = floor_p50 / control_p50

    rng = random.Random(76000 + loss)
    ratios = []
    for _ in range(20000):
        resampled = {}
        for name, candidate_blocks in blocks.items():
            combined = []
            for block in candidate_blocks:
                combined.extend(rng.choices(block, k=len(block)))
            resampled[name] = statistics.median(combined)
        ratios.append(resampled["everudp-floor"] / resampled["zmosh-udp"])
    upper95 = sorted(ratios)[math.ceil(0.95 * len(ratios)) - 1]
    packet_ratio = packets["everudp-floor"] / packets["zmosh-udp"]
    cell_pass = ratio <= 0.90 and packet_ratio <= 1.60 and all(value <= 1.60 for value in packet_block_ratios)
    passed = passed and cell_pass
    cells[str(loss)] = {
        "observations_per_candidate": trials * 2,
        "everudp_floor": {
            "p50_us": floor_p50,
            "p95_us": percentile(by_candidate["everudp-floor"], 0.95),
            "summed_egress_attempts": packets["everudp-floor"],
        },
        "zmosh_udp": {
            "p50_us": control_p50,
            "p95_us": percentile(by_candidate["zmosh-udp"], 0.95),
            "summed_egress_attempts": packets["zmosh-udp"],
        },
        "p50_ratio": ratio,
        "packet_attempt_ratio": packet_ratio,
        "packet_attempt_block_ratios": packet_block_ratios,
        "p50_ratio_bootstrap_upper95": upper95,
        "cutoff": 0.90,
        "pass": cell_pass,
    }

analysis = {
    "schema_version": 1,
    "purpose": "authenticated-noq-datagram-stage-zero-cutoff",
    "criterion": "p50 ratio <= 0.90 per cell and packet-attempt ratio <= 1.60 per block and cell",
    "bootstrap": {
        "resamples": 20000,
        "block_stratified": True,
        "upper95_reported_not_gating": True,
    },
    "cells": cells,
    "pass": passed,
}
(out / "analysis.json").write_text(
    json.dumps(analysis, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
receipt = {
    "schema_version": 1,
    "status": "INVALID",
    "quantitative_gate_status": "PASS" if passed else "FAIL",
    "invalid_reasons": ["Required allocation/component attribution is not yet collected and validated (eversh-5fc.20)"],
    "candidate": {"head_sha": head, "tree_sha": tree},
    "started_utc": started,
    "finished_utc": finished,
    "stage_zero_only": True,
    "production_actor_integration_authorized": False,
    "analysis": {"path": "analysis.json", "sha256": digest(out / "analysis.json")},
    "blocks": [
        {
            "path": path.name,
            "manifest_sha256": digest(path / "manifest.json"),
            "sha256sums_sha256": digest(path / "SHA256SUMS"),
        }
        for path in paths
    ],
}
(out / "receipt.json").write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

(
    cd "$OUTROOT"
    find . -type f ! -name SHA256SUMS -printf '%P\0' \
        | sort -z | xargs -0 sha256sum >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
chown -R "$RUN_USER" "$OUTROOT"
STATUS=$(jq -r .status "$OUTROOT/receipt.json")
echo "everudp stage-zero floor $STATUS: $OUTROOT"
[[ $STATUS == PASS ]]
