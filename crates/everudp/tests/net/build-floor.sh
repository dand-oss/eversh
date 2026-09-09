#!/usr/bin/env bash
# Build the authenticated v4 QUIC-DATAGRAM floor, frozen zmosh UDP control,
# and common PTY fixtures from exact source into one sealed directory.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
OUTDIR=${1:?usage: build-floor.sh OUTDIR}
OUTDIR=$(realpath -m -- "$OUTDIR")
ZMOSH_REPOSITORY=${ZMOSH_SOURCE_REPO:-/home/appsmith/asv/ports/repo/zmosh}
ZMOSH_UDP_COMMIT=dfc8395b5edcd237bf82712fbde879c6e8be7dfa
ZMOSH_UDP_TREE=1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514
ZIG_0152=${EVERUDP_ZIG_0152:-}
FLOOR_FEATURES=cli,reliable-datagram-spike
case ${EVERUDP_FLOOR_DIAGNOSTICS:-0} in
    0) ;;
    1) FLOOR_FEATURES+=,floor-diagnostics ;;
    *) echo "EVERUDP_FLOOR_DIAGNOSTICS must be 0 or 1" >&2; exit 2 ;;
esac
case ${EVERUDP_FLOOR_SEND_FAST_PATH:-0} in
    0) ;;
    1) FLOOR_FEATURES+=,floor-send-fast-path ;;
    *) echo "EVERUDP_FLOOR_SEND_FAST_PATH must be 0 or 1" >&2; exit 2 ;;
esac
case ${EVERUDP_FLOOR_ACK_INLINE_STORAGE:-0} in
    0) ;;
    1) FLOOR_FEATURES+=,floor-ack-inline-storage ;;
    *) echo "EVERUDP_FLOOR_ACK_INLINE_STORAGE must be 0 or 1" >&2; exit 2 ;;
esac
case ${EVERUDP_FLOOR_SINGLE_OWNER:-0} in
    0) ;;
    1)
        [[ $FLOOR_FEATURES == cli,reliable-datagram-spike ]] || {
            echo "single-owner floor requires diagnostics and other experiments disabled" >&2
            exit 2
        }
        FLOOR_FEATURES+=,floor-single-owner
        ;;
    *) echo "EVERUDP_FLOOR_SINGLE_OWNER must be 0 or 1" >&2; exit 2 ;;
esac

[[ ! -e $OUTDIR ]] || { echo "refusing to overwrite exact floor build: $OUTDIR" >&2; exit 1; }
[[ -x $ZIG_0152 ]] || { echo "set EVERUDP_ZIG_0152 to the Zig 0.15.2 executable" >&2; exit 1; }
[[ $($ZIG_0152 version) == 0.15.2 ]] || { echo "frozen zmosh UDP requires Zig 0.15.2" >&2; exit 1; }
for executable in /usr/bin/git /usr/bin/cc "$(command -v cargo)" "$(command -v rustc)"; do
    [[ -x $executable ]] || { echo "missing build executable: $executable" >&2; exit 1; }
done
for source in "$NET/pty-bench.c" "$NET/pty-echo.c"; do
    [[ -f $source ]] || { echo "missing floor build input: $source" >&2; exit 1; }
done
[[ -d $ZMOSH_REPOSITORY ]] || { echo "missing zmosh repository: $ZMOSH_REPOSITORY" >&2; exit 1; }

HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(git -C "$ROOT" rev-parse 'HEAD^{tree}')
[[ -z $(git -C "$ROOT" status --porcelain=v1 --untracked-files=all) ]] || {
    echo "refusing exact floor build from a dirty eversh worktree" >&2
    exit 1
}
[[ $(git -C "$ZMOSH_REPOSITORY" cat-file -t "$ZMOSH_UDP_COMMIT") == commit ]] || {
    echo "missing frozen zmosh UDP commit: $ZMOSH_UDP_COMMIT" >&2
    exit 1
}
[[ $(git -C "$ZMOSH_REPOSITORY" rev-parse "$ZMOSH_UDP_COMMIT^{tree}") == "$ZMOSH_UDP_TREE" ]] || {
    echo "frozen zmosh UDP tree mismatch" >&2
    exit 1
}

mkdir -p "$OUTDIR/artifacts/bin" "$OUTDIR/logs"
TMP=$(mktemp -d /tmp/everudp-floor-build.XXXXXX)
cleanup() {
    local status=$?
    trap - EXIT INT TERM HUP
    rm -rf -- "$TMP"
    exit "$status"
}
trap cleanup EXIT INT TERM HUP

STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ROOT_TARGET=$TMP/eversh-target
UDP_SOURCE=$TMP/zmosh-udp-source
UDP_PREFIX=$TMP/zmosh-udp-prefix
UDP_CACHE=$TMP/zmosh-udp-cache
UDP_GLOBAL_CACHE=$TMP/zmosh-udp-global-cache

CARGO_TARGET_DIR=$ROOT_TARGET CARGO_PROFILE_RELEASE_LTO=fat \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_PANIC=abort \
    RUSTFLAGS='' CARGO_ENCODED_RUSTFLAGS='' cargo build --locked --release \
    --manifest-path "$ROOT/Cargo.toml" -p everudp \
    --features "$FLOOR_FEATURES" --example everudp-floor \
    >"$OUTDIR/logs/everudp-floor-build.stdout" \
    2>"$OUTDIR/logs/everudp-floor-build.stderr"
install -m 0755 "$ROOT_TARGET/release/examples/everudp-floor" \
    "$OUTDIR/artifacts/bin/everudp-floor"

/usr/bin/cc -std=c11 -O3 -Wall -Wextra -Werror \
    "$NET/pty-bench.c" -o "$OUTDIR/artifacts/bin/pty-bench" -lutil \
    >"$OUTDIR/logs/pty-bench-build.stdout" 2>"$OUTDIR/logs/pty-bench-build.stderr"
/usr/bin/cc -std=c11 -O3 -Wall -Wextra -Werror \
    "$NET/pty-echo.c" -o "$OUTDIR/artifacts/bin/pty-echo" \
    >"$OUTDIR/logs/pty-echo-build.stdout" 2>"$OUTDIR/logs/pty-echo-build.stderr"

git clone --shared --no-checkout "$ZMOSH_REPOSITORY" "$UDP_SOURCE" \
    >"$OUTDIR/logs/zmosh-udp-clone.stdout" 2>"$OUTDIR/logs/zmosh-udp-clone.stderr"
git -C "$UDP_SOURCE" checkout --detach "$ZMOSH_UDP_COMMIT" \
    >"$OUTDIR/logs/zmosh-udp-checkout.stdout" 2>"$OUTDIR/logs/zmosh-udp-checkout.stderr"
[[ $(git -C "$UDP_SOURCE" rev-parse HEAD) == "$ZMOSH_UDP_COMMIT" \
    && $(git -C "$UDP_SOURCE" rev-parse 'HEAD^{tree}') == "$ZMOSH_UDP_TREE" \
    && -z $(git -C "$UDP_SOURCE" status --porcelain=v1 --untracked-files=all) ]] || {
    echo "zmosh UDP clone is not the frozen clean source" >&2
    exit 1
}
(
    cd "$UDP_SOURCE"
    "$ZIG_0152" build -Doptimize=ReleaseFast -p "$UDP_PREFIX" \
        --cache-dir "$UDP_CACHE" --global-cache-dir "$UDP_GLOBAL_CACHE"
) >"$OUTDIR/logs/zmosh-udp-build.stdout" 2>"$OUTDIR/logs/zmosh-udp-build.stderr"
install -m 0755 "$UDP_PREFIX/bin/zmosh" "$OUTDIR/artifacts/bin/zmosh-udp"

FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CARGO_VERSION=$(cargo --version)
RUSTC_VERSION=$(rustc --version)
CC_VERSION=$(/usr/bin/cc --version | head -1)
GIT_VERSION=$(git --version)
ZIG_VERSION=$($ZIG_0152 version)
ZIG_SHA=$(sha256sum "$ZIG_0152" | awk '{print $1}')

/usr/bin/python3 - "$OUTDIR" "$ROOT" "$NET" "$HEAD_SHA" "$TREE_SHA" \
    "$ZMOSH_UDP_COMMIT" "$ZMOSH_UDP_TREE" "$STARTED_UTC" "$FINISHED_UTC" \
    "$CARGO_VERSION" "$RUSTC_VERSION" "$CC_VERSION" "$GIT_VERSION" \
    "$ZIG_VERSION" "$ZIG_SHA" "$FLOOR_FEATURES" <<'PY'
import hashlib
import json
import platform
import sys
from pathlib import Path

(
    out_raw, root_raw, net_raw, head, tree, udp_commit, udp_tree,
    started, finished, cargo_version, rustc_version, cc_version,
    git_version, zig_version, zig_sha, features,
) = sys.argv[1:]
out = Path(out_raw)
root = Path(root_raw)
net = Path(net_raw)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

artifact_names = ("everudp-floor", "zmosh-udp", "pty-bench", "pty-echo")
input_names = ("pty-bench.c", "pty-echo.c")
provenance = {
    "schema_version": 1,
    "purpose": "authenticated-noq-datagram-stage-zero-floor",
    "source": {"head_sha": head, "tree_sha": tree, "clean": True},
    "zmosh_source": {"commit": udp_commit, "tree": udp_tree, "clean": True},
    "started_utc": started,
    "finished_utc": finished,
    "host": {"platform": platform.platform()},
    "tools": {
        "cargo": cargo_version,
        "rustc": rustc_version,
        "cc": cc_version,
        "git": git_version,
        "zig_0_15_2": {"version": zig_version, "sha256": zig_sha},
    },
    "isolation": {
        "fresh_detached_zmosh_clone": True,
        "isolated_cargo_target": True,
        "isolated_zig_local_cache": True,
        "isolated_zig_global_cache": True,
    },
    "everudp_build": {
        "cargo_features": features.split(","),
        "diagnostic_build": "floor-diagnostics" in features.split(","),
        "udp_send_fast_path_experiment": "floor-send-fast-path" in features.split(","),
        "ack_inline_storage_experiment": "floor-ack-inline-storage" in features.split(","),
        "single_owner_experiment": "floor-single-owner" in features.split(","),
        "target": "example everudp-floor",
        "profile": {"lto": "fat", "codegen_units": 1, "panic": "abort", "rustflags": "", "target_cpu": "portable default"},
    },
    "inputs": {
        "Cargo.lock": digest(root / "Cargo.lock"),
        "everudp-floor.rs": digest(root / "crates/everudp/examples/everudp-floor.rs"),
        **{name: digest(net / name) for name in input_names},
    },
    "artifacts": {
        name: {
            "path": f"artifacts/bin/{name}",
            "sha256": digest(out / "artifacts" / "bin" / name),
        }
        for name in artifact_names
    },
    "commands": [
        f"CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_PANIC=abort RUSTFLAGS='' CARGO_ENCODED_RUSTFLAGS='' cargo build --locked --release -p everudp --features {features} --example everudp-floor",
        "zig-0.15.2 build -Doptimize=ReleaseFast (zmosh UDP)",
        "cc -std=c11 -O3 -Wall -Wextra -Werror pty-bench.c -lutil",
        "cc -std=c11 -O3 -Wall -Wextra -Werror pty-echo.c",
    ],
}
(out / "provenance.json").write_text(
    json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

(
    cd "$OUTDIR"
    find . -type f ! -name SHA256SUMS -printf '%P\0' \
        | sort -z | xargs -0 sha256sum >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
echo "exact floor build PASS: $OUTDIR"
