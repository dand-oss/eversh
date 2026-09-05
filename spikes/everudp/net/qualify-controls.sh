#!/usr/bin/env bash
# Run and seal the frozen eight-cell control/resource qualification.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
OUTROOT=${1:?usage: qualify-controls.sh OUTROOT [TRIALS]}
TRIALS=${2:-30}
RUN_USER=${SUDO_USER:-$(stat -c %U "$ROOT")}

if (( EUID != 0 )); then
    echo "control qualification requires root network-namespace privileges" >&2
    exit 2
fi
[[ $TRIALS =~ ^[0-9]+$ ]] && (( TRIALS >= 30 )) || {
    echo "control qualification requires at least 30 trials per candidate" >&2
    exit 2
}
[[ ! -e $OUTROOT ]] || { echo "refusing to overwrite qualification: $OUTROOT" >&2; exit 1; }

run_user() {
    /usr/bin/sudo -n -H -u "$RUN_USER" "$@"
}

HEAD_SHA=$(run_user git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(run_user git -C "$ROOT" rev-parse HEAD^{tree})
[[ -z $(run_user git -C "$ROOT" status --porcelain=v1) ]] || {
    echo "refusing control qualification from a dirty worktree" >&2
    exit 1
}

mkdir -p "$OUTROOT"
STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

run_cell() {
    local name=$1 loss=$2 delay=$3 reorder=$4
    echo "starting matrix cell $name"
    "$NET/bench-matrix.sh" "$TRIALS" "$loss" "$OUTROOT/$name" "$delay" "$reorder" \
        > >(tee "$OUTROOT/$name.console.log") \
        2> >(tee "$OUTROOT/$name.console.stderr" >&2)
}

run_cell loss0 0 0 0
run_cell loss1 1 0 0
run_cell loss5 5 0 0
run_cell loss10 10 0 0
run_cell loss25 25 0 0
run_cell loss5-jitter25 5 25 0
run_cell loss5-jitter50 5 50 0
run_cell loss5-reorder2 5 0 2

"$NET/resource-gate.sh" "$OUTROOT/resource" \
    > >(tee "$OUTROOT/resource.console.log") \
    2> >(tee "$OUTROOT/resource.console.stderr" >&2)
"$NET/outage.sh" "$OUTROOT/outage" \
    > >(tee "$OUTROOT/outage.console.log") \
    2> >(tee "$OUTROOT/outage.console.stderr" >&2)

set +e
run_user /usr/bin/python3 "$NET/analyze-controls.py" "$OUTROOT" \
    --trials "$TRIALS" --bootstrap 20000 --seed 9015 >"$OUTROOT/analysis.json" \
    2>"$OUTROOT/analysis.stderr"
ANALYSIS_CODE=$?
set -e
if (( ANALYSIS_CODE != 0 )); then
    cat "$OUTROOT/analysis.stderr" >&2
    jq -c '.verdict // .' "$OUTROOT/analysis.json" >&2 2>/dev/null || true
    exit "$ANALYSIS_CODE"
fi

FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 - "$OUTROOT" "$HEAD_SHA" "$TREE_SHA" "$STARTED_UTC" \
    "$FINISHED_UTC" "$TRIALS" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

outroot = Path(sys.argv[1])
head, tree, started, finished, trials = sys.argv[2:]
cells = (
    "loss0", "loss1", "loss5", "loss10", "loss25",
    "loss5-jitter25", "loss5-jitter50", "loss5-reorder2",
)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def verify_directory(path):
    entries = (path / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    for line in entries:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or digest(path / match.group(2)) != match.group(1):
            raise SystemExit(f"checksum verification failed under {path}")

analysis = json.loads((outroot / "analysis.json").read_text(encoding="utf-8"))
if analysis["source"]["head_sha"] != head or analysis["source"]["tree_sha"] != tree:
    raise SystemExit("matrix analysis source identity mismatch")
if not analysis["verdict"]["matrix_pass"]:
    raise SystemExit("matrix analysis did not pass")

cell_manifests = {}
for cell in cells:
    verify_directory(outroot / cell)
    manifest_path = outroot / cell / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["source"] != {"head_sha": head, "tree_sha": tree, "dirty": False}:
        raise SystemExit(f"{cell} source identity mismatch")
    cell_manifests[cell] = digest(manifest_path)

child_gates = {}
for name, verdict_name in (("resource", "resource_gate_pass"), ("outage", "outage_gate_pass")):
    path = outroot / name
    verify_directory(path)
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["source"] != {"head_sha": head, "tree_sha": tree, "dirty": False}:
        raise SystemExit(f"{name} source identity mismatch")
    if not manifest["verdict"][verdict_name]:
        raise SystemExit(f"{name} gate did not pass")
    child_gates[name] = {
        "manifest_sha256": digest(manifest_path),
        "verdict": manifest["verdict"],
    }

receipt = {
    "schema_version": 1,
    "source": {"head_sha": head, "tree_sha": tree, "clean": True},
    "started_utc": started,
    "finished_utc": finished,
    "trials_per_candidate_per_cell": int(trials),
    "cells": cell_manifests,
    "analysis_sha256": digest(outroot / "analysis.json"),
    "child_gates": child_gates,
    "verdict": {
        "matrix_pass": True,
        "resource_gate_pass": True,
        "outage_gate_pass": True,
        "control_qualification_pass": True,
    },
}
(outroot / "receipt.json").write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

(
    cd "$OUTROOT"
    find . -type f ! -name CONTROL_SHA256SUMS -printf '%P\0' \
        | sort -z | xargs -0 sha256sum >CONTROL_SHA256SUMS
    sha256sum -c CONTROL_SHA256SUMS >/dev/null
)
jq -c '.verdict' "$OUTROOT/receipt.json"
echo "control qualification complete: $OUTROOT"
