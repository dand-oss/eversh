#!/usr/bin/env bash
# Run the complete everudp spike qualification at one clean source identity.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
OUTROOT=${1:?usage: qualify-final.sh OUTROOT}
RUN_USER=${SUDO_USER:-$(stat -c %U "$ROOT")}

if (( EUID != 0 )); then
    echo "final qualification requires root network-namespace privileges" >&2
    exit 2
fi
[[ ! -e $OUTROOT ]] || { echo "refusing to overwrite final output: $OUTROOT" >&2; exit 1; }

run_user() {
    /usr/bin/sudo -n -H -u "$RUN_USER" "$@"
}

HEAD_SHA=$(run_user git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(run_user git -C "$ROOT" rev-parse HEAD^{tree})
[[ -z $(run_user git -C "$ROOT" status --porcelain=v1) ]] || {
    echo "refusing final qualification from a dirty worktree" >&2
    exit 1
}

mkdir -p "$OUTROOT"
chown "$RUN_USER" "$OUTROOT"
STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

run_user /usr/bin/env \
    EVERUDP_ZIG="${EVERUDP_ZIG:-}" \
    ZMOSH_SOURCE_REPO="${ZMOSH_SOURCE_REPO:-/home/appsmith/asv/ports/repo/zmosh}" \
    "$NET/build-exact.sh" "$OUTROOT/build" \
    > >(tee "$OUTROOT/build.console.log") \
    2> >(tee "$OUTROOT/build.console.stderr" >&2)
BUILD_ARTIFACTS=$OUTROOT/build/artifacts
export EVERUDP_BIN=$BUILD_ARTIFACTS/bin/everudp-spike
export EVERSH_BIN=$BUILD_ARTIFACTS/bin/eversh
export ZMOSH_PREFIX=$BUILD_ARTIFACTS
export ZMOSH_BIN=$BUILD_ARTIFACTS/bin/zmosh
export ZMOSH_BENCH_BIN=$BUILD_ARTIFACTS/bin/zmosh-bench
export ZMOSH_SOURCE_COMMIT=dfc8395b5edcd237bf82712fbde879c6e8be7dfa
export ZMOSH_SOURCE_TREE=1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514

python3 - "$OUTROOT/source.json" "$HEAD_SHA" "$TREE_SHA" "$STARTED_UTC" <<'PY'
import json
import sys

path, head, tree, started = sys.argv[1:]
with open(path, "w", encoding="utf-8") as stream:
    json.dump(
        {
            "source": {"head_sha": head, "tree_sha": tree, "clean": True},
            "started_utc": started,
        },
        stream,
        indent=2,
        sort_keys=True,
    )
    stream.write("\n")
PY

"$NET/qualify-controls.sh" "$OUTROOT/controls" 30 \
    > >(tee "$OUTROOT/controls.console.log") \
    2> >(tee "$OUTROOT/controls.console.stderr" >&2)
"$NET/qualify-parity.sh" "$OUTROOT/parity" 100 \
    > >(tee "$OUTROOT/parity.console.log") \
    2> >(tee "$OUTROOT/parity.console.stderr" >&2)
"$NET/oracle-gate.sh" 30 "$OUTROOT/oracle.json" \
    > >(tee "$OUTROOT/oracle.console.log") \
    2> >(tee "$OUTROOT/oracle.console.stderr" >&2)
"$NET/reachability.sh" "$OUTROOT/reachability" 20 \
    > >(tee "$OUTROOT/reachability.console.log") \
    2> >(tee "$OUTROOT/reachability.console.stderr" >&2)

run_user /usr/bin/env PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 "$NET/verify-closure.py" \
    --controls "$OUTROOT/controls" \
    --parity "$OUTROOT/parity" \
    --oracle "$OUTROOT/oracle.json" \
    --reachability "$OUTROOT/reachability" \
    --build-provenance "$OUTROOT/build/provenance.json" \
    --expected-head "$HEAD_SHA" --expected-tree "$TREE_SHA" \
    --output "$OUTROOT/closure.json" \
    > >(tee "$OUTROOT/closure.console.log") \
    2> >(tee "$OUTROOT/closure.console.stderr" >&2)

FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 - "$OUTROOT/source.json" "$FINISHED_UTC" <<'PY'
import json
import sys

path, finished = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    data = json.load(stream)
data["finished_utc"] = finished
with open(path, "w", encoding="utf-8") as stream:
    json.dump(data, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

(
    cd "$OUTROOT"
    find . -type f ! -name FINAL_SHA256SUMS -printf '%P\0' \
        | sort -z | xargs -0 sha256sum >FINAL_SHA256SUMS
    sha256sum -c FINAL_SHA256SUMS >/dev/null
)
jq -c '.verdict' "$OUTROOT/closure.json"
echo "final everudp qualification complete: $OUTROOT"
