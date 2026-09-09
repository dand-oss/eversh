#!/usr/bin/env bash
# Run and seal the two-cell, six-permutation, three-candidate performance gate.
set -Eeuo pipefail

if (( EUID != 0 )); then
    echo "everudp performance qualification requires root" >&2
    exit 77
fi

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
BUILD=${1:?usage: qualify-performance.sh EXACT_BUILD OUTROOT [TRIALS]}
OUTROOT=${2:?usage: qualify-performance.sh EXACT_BUILD OUTROOT [TRIALS]}
TRIALS=${3:-200}
BUILD=$(realpath -m -- "$BUILD")
OUTROOT=$(realpath -m -- "$OUTROOT")
RUN_USER=${SUDO_USER:-$(stat -c %U "$ROOT")}
CLEANED=0

cleanup() {
    local status=$?
    (( CLEANED == 0 )) || exit "$status"
    CLEANED=1
    set +e
    trap - EXIT INT TERM HUP
    if [[ -d $OUTROOT ]] && ! chown -R -- "$RUN_USER" "$OUTROOT"; then
        echo "could not return performance artifacts to $RUN_USER" >&2
        status=1
    fi
    exit "$status"
}

[[ -f $BUILD/provenance.json && -f $BUILD/SHA256SUMS ]] || {
    echo "exact build provenance is incomplete: $BUILD" >&2
    exit 1
}
(cd "$BUILD" && sha256sum -c SHA256SUMS >/dev/null)
[[ ! -e $OUTROOT ]] || { echo "refusing to overwrite performance evidence: $OUTROOT" >&2; exit 1; }
if (( TRIALS != 200 )) && [[ ${EVERUDP_ALLOW_SHORT:-0} != 1 ]]; then
    echo "release qualification requires exactly 200 observations per block" >&2
    exit 2
fi

HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(git -C "$ROOT" rev-parse 'HEAD^{tree}')
[[ -z $(git -C "$ROOT" status --porcelain=v1 --untracked-files=all) ]] || {
    echo "refusing performance qualification from a dirty worktree" >&2
    exit 1
}
[[ $(jq -r '.source.head_sha' "$BUILD/provenance.json") == "$HEAD_SHA" \
    && $(jq -r '.source.tree_sha' "$BUILD/provenance.json") == "$TREE_SHA" \
    && $(jq -r '.source.clean' "$BUILD/provenance.json") == true ]] || {
    echo "performance build does not match the clean candidate SHA" >&2
    exit 1
}

trap cleanup EXIT
trap 'exit 130' INT TERM HUP
mkdir -p "$OUTROOT/build"
chown -- "$RUN_USER" "$OUTROOT"
install -m 0644 "$BUILD/provenance.json" "$OUTROOT/build/provenance.json"
/usr/bin/python3 - "$BUILD" "$OUTROOT/build/artifacts.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

build = Path(sys.argv[1])
destination = Path(sys.argv[2])
provenance_path = build / "provenance.json"
source_manifest = build / "SHA256SUMS"
provenance = json.loads(provenance_path.read_text(encoding="utf-8"))

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

artifacts = {}
for name, recorded in sorted(provenance.get("artifacts", {}).items()):
    path = build / recorded["path"]
    expected = recorded["sha256"]
    actual = digest(path)
    if actual != expected:
        raise SystemExit(f"artifact digest changed for {name}")
    artifacts[name] = {
        "sha256": actual,
        "size_bytes": path.stat().st_size,
    }

if len(artifacts) != 6:
    raise SystemExit("performance build must contain exactly six named artifacts")

manifest = {
    "schema_version": 1,
    "artifacts_embedded": False,
    "disposition": (
        "content-addressed exact-build artifacts; binaries are reproducible from "
        "the copied provenance and intentionally not embedded in release evidence"
    ),
    "exact_build_provenance_sha256": digest(provenance_path),
    "source_build_manifest_sha256": digest(source_manifest),
    "artifacts": artifacts,
}
destination.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

ORDERS=(
    everudp,zmosh-udp,zmosh-quic
    everudp,zmosh-quic,zmosh-udp
    zmosh-udp,everudp,zmosh-quic
    zmosh-udp,zmosh-quic,everudp
    zmosh-quic,everudp,zmosh-udp
    zmosh-quic,zmosh-udp,everudp
)
BLOCKS=()
for loss in 0 5; do
    loss_dir=$OUTROOT/loss${loss}
    mkdir -p "$loss_dir"
    chown -- "$RUN_USER" "$loss_dir"
    ordinal=0
    for order in "${ORDERS[@]}"; do
        ordinal=$((ordinal + 1))
        if (( loss == 0 )); then
            seed=$((920000 + ordinal))
        else
            seed=$((930000 + ordinal))
        fi
        block=$loss_dir/block-$seed
        BLOCKS+=("$block")
        echo "performance qualification: loss=$loss block=$ordinal/6 order=$order"
        EVERUDP_PERF_BUILD="$BUILD" "$NET/bench-performance-block.sh" \
            "$TRIALS" "$loss" "$seed" "$block" "$order" \
            > >(tee "$OUTROOT/loss${loss}/block-$seed.console.log") \
            2> >(tee "$OUTROOT/loss${loss}/block-$seed.console.stderr" >&2)
    done
done

ANALYZE_ARGS=("${BLOCKS[@]}" --trials "$TRIALS" --bootstrap 20000 --output "$OUTROOT/analysis.json")
if (( TRIALS != 200 )); then
    ANALYZE_ARGS+=(--allow-smoke)
fi
ANALYZE_STATUS=0
/usr/bin/python3 "$NET/analyze-performance.py" "${ANALYZE_ARGS[@]}" || ANALYZE_STATUS=$?
if (( ANALYZE_STATUS != 0 )); then
    # A release-gate miss deliberately exits 1 after writing analysis.json.
    # Preserve and seal that exact failure instead of letting `set -e` strand
    # an otherwise complete sample set without its terminal receipt.
    [[ $ANALYZE_STATUS == 1 && -s $OUTROOT/analysis.json ]] || exit "$ANALYZE_STATUS"
    jq -e '.verdict.qualification_outcome == "FAIL"' \
        "$OUTROOT/analysis.json" >/dev/null
fi
FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUTCOME=$(jq -r '.verdict.qualification_outcome' "$OUTROOT/analysis.json")
if (( TRIALS != 200 )); then
    OUTCOME=SMOKE
fi

/usr/bin/python3 - "$OUTROOT" "$BUILD" "$HEAD_SHA" "$TREE_SHA" \
    "$STARTED_UTC" "$FINISHED_UTC" "$TRIALS" "$OUTCOME" \
    "$ANALYZE_STATUS" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

(
    out_raw, build_raw, head, tree, started, finished, trials, outcome,
    analyze_status,
) = sys.argv[1:]
out = Path(out_raw)
build = Path(build_raw)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

analysis = json.loads((out / "analysis.json").read_text(encoding="utf-8"))
receipt = {
    "schema_version": 1,
    "source": {"head_sha": head, "tree_sha": tree, "clean": True},
    "started_utc": started,
    "finished_utc": finished,
    "trials_per_candidate_per_block": int(trials),
    "observations_per_candidate_per_cell": int(trials) * 6,
    "cells": [0, 5],
    "blocks_per_cell": 6,
    "candidate_count": 3,
    "build_provenance_sha256": digest(build / "provenance.json"),
    "build_artifact_manifest_sha256": digest(out / "build" / "artifacts.json"),
    "analysis_sha256": digest(out / "analysis.json"),
    "analyzer_exit_status": int(analyze_status),
    "verdict": analysis["verdict"],
    "qualification_outcome": outcome,
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
jq -c '{cells,verdict}' "$OUTROOT/analysis.json"
if [[ $OUTCOME == PASS ]]; then
    echo "performance qualification PASS: $OUTROOT"
elif [[ $OUTCOME == SMOKE ]]; then
    echo "performance harness smoke PASS: $OUTROOT"
else
    echo "performance qualification FAIL (sealed evidence retained): $OUTROOT" >&2
    exit 1
fi
