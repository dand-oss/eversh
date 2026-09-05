#!/usr/bin/env bash
# Run and seal six alternating-order 5%-loss parity blocks.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
OUTROOT=${1:?usage: qualify-parity.sh OUTROOT [TRIALS]}
TRIALS=${2:-100}
RUN_USER=${SUDO_USER:-$(stat -c %U "$ROOT")}

if (( EUID != 0 )); then
    echo "parity qualification requires root network-namespace privileges" >&2
    exit 2
fi
[[ $TRIALS =~ ^[0-9]+$ ]] && (( TRIALS >= 30 )) || {
    echo "parity qualification requires at least 30 trials per candidate" >&2
    exit 2
}
[[ ! -e $OUTROOT ]] || { echo "refusing to overwrite parity output: $OUTROOT" >&2; exit 1; }

run_user() {
    /usr/bin/sudo -n -H -u "$RUN_USER" "$@"
}

HEAD_SHA=$(run_user git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(run_user git -C "$ROOT" rev-parse HEAD^{tree})
[[ -z $(run_user git -C "$ROOT" status --porcelain=v1) ]] || {
    echo "refusing parity qualification from a dirty worktree" >&2
    exit 1
}

mkdir -p "$OUTROOT"
STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
BLOCKS=()
for ordinal in 1 2 3 4 5 6; do
    seed=$((13000 + ordinal))
    block="$OUTROOT/block-$seed"
    BLOCKS+=("$block")
    echo "starting parity block $ordinal/6 (seed $seed)"
    "$NET/bench-parity.sh" "$TRIALS" "$seed" "$block" \
        > >(tee "$OUTROOT/block-$seed.console.log") \
        2> >(tee "$OUTROOT/block-$seed.console.stderr" >&2)
done

run_user /usr/bin/python3 "$NET/analyze-parity.py" "${BLOCKS[@]}" \
    --bootstrap 20000 --seed 9015 >"$OUTROOT/analysis.json"
jq -e '.verdict.preregistered_point_rule_pass
    and .verdict.exact_sha_evidence_pass
    and .verdict.observed_loss_evidence_pass
    and .verdict.conservative_upper95_equivalence_pass' \
    "$OUTROOT/analysis.json" >/dev/null
FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

python3 - "$OUTROOT" "$HEAD_SHA" "$TREE_SHA" "$STARTED_UTC" \
    "$FINISHED_UTC" "$TRIALS" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

outroot = Path(sys.argv[1])
head, tree, started, finished, trials = sys.argv[2:]

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

analysis = json.loads((outroot / "analysis.json").read_text(encoding="utf-8"))
if analysis["source"]["head_sha"] != head or analysis["source"]["tree_sha"] != tree:
    raise SystemExit("parity source identity mismatch")
receipt = {
    "schema_version": 1,
    "source": {"head_sha": head, "tree_sha": tree, "clean": True},
    "started_utc": started,
    "finished_utc": finished,
    "blocks": {
        path.name: digest(path / "manifest.json")
        for path in sorted(outroot.glob("block-*"))
        if path.is_dir()
    },
    "trials_per_candidate_per_block": int(trials),
    "analysis_sha256": digest(outroot / "analysis.json"),
    "verdict": analysis["verdict"],
}
(outroot / "receipt.json").write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

(
    cd "$OUTROOT"
    find . -type f ! -name SHA256SUMS -printf '%P\0' \
        | sort -z | xargs -0 sha256sum >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
jq -c '{pooled,uncertainty,verdict}' "$OUTROOT/analysis.json"
echo "parity qualification complete: $OUTROOT"
