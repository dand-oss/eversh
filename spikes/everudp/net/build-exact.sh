#!/usr/bin/env bash
# Build every measured candidate from pinned source in fresh, isolated targets.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
OUTDIR=${1:?usage: build-exact.sh OUTDIR}
ZMOSH_REPOSITORY=${ZMOSH_SOURCE_REPO:-/home/appsmith/asv/ports/repo/zmosh}
ZMOSH_COMMIT=dfc8395b5edcd237bf82712fbde879c6e8be7dfa
ZMOSH_TREE=1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514
ZIG=${EVERUDP_ZIG:-$(command -v zig || true)}

[[ ! -e $OUTDIR ]] || { echo "refusing to overwrite exact build: $OUTDIR" >&2; exit 1; }
for executable in /usr/bin/git /usr/bin/cc "$(command -v cargo)" "$(command -v rustc)"; do
    [[ -x $executable ]] || { echo "missing build executable: $executable" >&2; exit 1; }
done
[[ -x $ZIG ]] || { echo "set EVERUDP_ZIG to the Zig 0.15.2 executable" >&2; exit 1; }
[[ $($ZIG version) == 0.15.2 ]] || {
    echo "zmosh exact build requires Zig 0.15.2 (got $($ZIG version))" >&2
    exit 1
}
[[ -d $ZMOSH_REPOSITORY ]] || { echo "missing zmosh source repository: $ZMOSH_REPOSITORY" >&2; exit 1; }

HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(git -C "$ROOT" rev-parse HEAD^{tree})
[[ -z $(git -C "$ROOT" status --porcelain=v1) ]] || {
    echo "refusing exact build from a dirty eversh worktree" >&2
    exit 1
}
[[ $(git -C "$ZMOSH_REPOSITORY" cat-file -t "$ZMOSH_COMMIT") == commit ]] || {
    echo "pinned zmosh commit is absent from $ZMOSH_REPOSITORY" >&2
    exit 1
}
[[ $(git -C "$ZMOSH_REPOSITORY" rev-parse "$ZMOSH_COMMIT^{tree}") == "$ZMOSH_TREE" ]] || {
    echo "pinned zmosh tree does not match its registered identity" >&2
    exit 1
}

mkdir -p "$OUTDIR/artifacts/bin" "$OUTDIR/artifacts/include/zmosh" \
    "$OUTDIR/artifacts/lib" "$OUTDIR/logs"
TMP=$(mktemp -d)
cleanup() {
    rm -rf -- "$TMP"
}
trap cleanup EXIT

STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ROOT_TARGET=$TMP/eversh-target
SPIKE_TARGET=$TMP/everudp-target
ZMOSH_CLONE=$TMP/zmosh-source
ZMOSH_PREFIX=$TMP/zmosh-prefix
ZMOSH_CACHE=$TMP/zmosh-cache
ZIG_GLOBAL_CACHE=$TMP/zig-global-cache

CARGO_TARGET_DIR=$ROOT_TARGET cargo build --locked --release \
    --manifest-path "$ROOT/Cargo.toml" -p eversh \
    >"$OUTDIR/logs/eversh-build.stdout" 2>"$OUTDIR/logs/eversh-build.stderr"
CARGO_TARGET_DIR=$SPIKE_TARGET cargo build --locked --release \
    --manifest-path "$ROOT/spikes/everudp/Cargo.toml" \
    >"$OUTDIR/logs/everudp-build.stdout" 2>"$OUTDIR/logs/everudp-build.stderr"
install -m 0755 "$ROOT_TARGET/release/eversh" "$OUTDIR/artifacts/bin/eversh"
install -m 0755 "$SPIKE_TARGET/release/everudp-spike" \
    "$OUTDIR/artifacts/bin/everudp-spike"

git clone --shared --no-checkout "$ZMOSH_REPOSITORY" "$ZMOSH_CLONE" \
    >"$OUTDIR/logs/zmosh-clone.stdout" 2>"$OUTDIR/logs/zmosh-clone.stderr"
git -C "$ZMOSH_CLONE" checkout --detach "$ZMOSH_COMMIT" \
    >"$OUTDIR/logs/zmosh-checkout.stdout" 2>"$OUTDIR/logs/zmosh-checkout.stderr"
[[ $(git -C "$ZMOSH_CLONE" rev-parse HEAD) == "$ZMOSH_COMMIT" \
    && $(git -C "$ZMOSH_CLONE" rev-parse HEAD^{tree}) == "$ZMOSH_TREE" \
    && -z $(git -C "$ZMOSH_CLONE" status --porcelain=v1) ]] || {
    echo "fresh zmosh clone did not resolve to the pinned clean source" >&2
    exit 1
}
(
    cd "$ZMOSH_CLONE"
    "$ZIG" build -p "$ZMOSH_PREFIX" -Doptimize=ReleaseFast \
        --cache-dir "$ZMOSH_CACHE" --global-cache-dir "$ZIG_GLOBAL_CACHE"
) >"$OUTDIR/logs/zmosh-build.stdout" 2>"$OUTDIR/logs/zmosh-build.stderr"
(
    cd "$ZMOSH_CLONE"
    "$ZIG" build lib -p "$ZMOSH_PREFIX" -Doptimize=ReleaseFast \
        --cache-dir "$ZMOSH_CACHE" --global-cache-dir "$ZIG_GLOBAL_CACHE"
) >"$OUTDIR/logs/zmosh-lib-build.stdout" 2>"$OUTDIR/logs/zmosh-lib-build.stderr"
install -m 0755 "$ZMOSH_PREFIX/bin/zmosh" "$OUTDIR/artifacts/bin/zmosh"
install -m 0644 "$ZMOSH_PREFIX/include/zmosh/zmosh.h" \
    "$OUTDIR/artifacts/include/zmosh/zmosh.h"
install -m 0644 "$ZMOSH_PREFIX/lib/libzmosh.a" "$OUTDIR/artifacts/lib/libzmosh.a"

/usr/bin/cc -O3 -Wall -Wextra -Werror -no-pie \
    -I "$OUTDIR/artifacts/include" "$ROOT/spikes/everudp/net/zmosh-bench.c" \
    "$OUTDIR/artifacts/lib/libzmosh.a" -o "$OUTDIR/artifacts/bin/zmosh-bench" \
    -lpthread >"$OUTDIR/logs/zmosh-bench-build.stdout" \
    2>"$OUTDIR/logs/zmosh-bench-build.stderr"

FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CARGO_VERSION=$(cargo --version)
RUSTC_VERSION=$(rustc --version)
ZIG_VERSION=$($ZIG version)
CC_VERSION=$(/usr/bin/cc --version)
GIT_VERSION=$(git --version)
python3 - "$OUTDIR" "$ROOT" "$HEAD_SHA" "$TREE_SHA" "$ZMOSH_COMMIT" \
    "$ZMOSH_TREE" "$STARTED_UTC" "$FINISHED_UTC" "$CARGO_VERSION" \
    "$RUSTC_VERSION" "$ZIG_VERSION" "$CC_VERSION" "$GIT_VERSION" <<'PY'
import hashlib
import json
import platform
import sys
from pathlib import Path

(
    out_raw, root_raw, head, tree, zmosh_commit, zmosh_tree, started,
    finished, cargo_version, rustc_version, zig_version, cc_version,
    git_version,
) = sys.argv[1:]
out = Path(out_raw)
root = Path(root_raw)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

artifact_paths = {
    "everudp": "artifacts/bin/everudp-spike",
    "eversh": "artifacts/bin/eversh",
    "zmosh": "artifacts/bin/zmosh",
    "zmosh_bench": "artifacts/bin/zmosh-bench",
    "zmosh_header": "artifacts/include/zmosh/zmosh.h",
    "zmosh_library": "artifacts/lib/libzmosh.a",
}
provenance = {
    "schema_version": 1,
    "source": {"head_sha": head, "tree_sha": tree, "clean": True},
    "zmosh_source": {"commit": zmosh_commit, "tree": zmosh_tree},
    "started_utc": started,
    "finished_utc": finished,
    "host": {"platform": platform.platform()},
    "tools": {
        "cargo": cargo_version,
        "rustc": rustc_version,
        "zig": zig_version,
        "cc": cc_version,
        "git": git_version,
    },
    "build": {
        "fresh_output": True,
        "isolated_cargo_targets": True,
        "isolated_zig_caches": True,
        "eversh_profile": "release",
        "everudp_profile": "release",
        "zmosh_optimize": "ReleaseFast",
        "commands": [
            "cargo build --locked --release -p eversh",
            "cargo build --locked --release --manifest-path spikes/everudp/Cargo.toml",
            "zig build -Doptimize=ReleaseFast",
            "zig build lib -Doptimize=ReleaseFast",
            "cc -O3 -Wall -Wextra -Werror -no-pie zmosh-bench.c libzmosh.a -lpthread",
        ],
    },
    "inputs": {
        "root_cargo_lock": {"sha256": digest(root / "Cargo.lock")},
        "spike_cargo_lock": {"sha256": digest(root / "spikes/everudp/Cargo.lock")},
        "zmosh_bench_source": {
            "sha256": digest(root / "spikes/everudp/net/zmosh-bench.c")
        },
    },
    "artifacts": {
        name: {"path": relative, "sha256": digest(out / relative)}
        for name, relative in artifact_paths.items()
    },
}
(out / "provenance.json").write_text(
    json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

echo "exact source build complete: $OUTDIR"
