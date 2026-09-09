#!/usr/bin/env bash
# Build the matched reliable-STREAM modes and frozen UDP control.
# Adapted from build-floor.sh; the historical datagram recipe remains unchanged.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
OUTDIR=${1:?usage: build-stream-floor.sh OUTDIR}
OUTDIR=$(realpath -m -- "$OUTDIR")
ZMOSH_REPOSITORY=${ZMOSH_SOURCE_REPO:-/home/appsmith/asv/ports/repo/zmosh}
ZMOSH_UDP_COMMIT=dfc8395b5edcd237bf82712fbde879c6e8be7dfa
ZMOSH_UDP_TREE=1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514
ZIG_0152=${EVERUDP_ZIG_0152:-}
FLOOR_FEATURES=cli,stream-floor
for option in EVERUDP_FLOOR_DIAGNOSTICS EVERUDP_FLOOR_SEND_FAST_PATH \
    EVERUDP_FLOOR_ACK_INLINE_STORAGE EVERUDP_FLOOR_SINGLE_OWNER; do
    [[ ${!option:-0} == 0 ]] || { echo "stream build forbids $option" >&2; exit 2; }
done
for option in RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTC_BOOTSTRAP CARGO_BUILD_TARGET; do
    [[ -z ${!option:-} ]] || { echo "stream build forbids $option" >&2; exit 2; }
done

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
TMP=$(mktemp -d /tmp/everudp-stream-build.XXXXXX)
cleanup() {
    local status=$?
    trap - EXIT INT TERM HUP
    if [[ $TMP == /tmp/everudp-stream-build.* && -d $TMP && ! -L $TMP ]]; then
        rm -rf -- "$TMP"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM HUP

STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ROOT_TARGET=$TMP/eversh-target
SOURCE=$TMP/eversh-source
mkdir "$SOURCE"
git -C "$ROOT" archive "$HEAD_SHA" | tar -x -C "$SOURCE"
SOURCE_NET=$SOURCE/crates/everudp/tests/net
STREAM_CARGO_HOME=$TMP/cargo-home
mkdir "$STREAM_CARGO_HOME"
# Cargo also searches cwd ancestors. Do not inherit unrelated local config.
for directory in "$SOURCE" "$TMP" /tmp /; do
    [[ ! -e $directory/.cargo/config && ! -e $directory/.cargo/config.toml ]] || {
        echo "unexpected Cargo configuration in isolated source ancestry" >&2; exit 1;
    }
done
CARGO_EXECUTABLE=$(command -v cargo)
UDP_SOURCE=$TMP/zmosh-udp-source
UDP_PREFIX=$TMP/zmosh-udp-prefix
UDP_CACHE=$TMP/zmosh-udp-cache
UDP_GLOBAL_CACHE=$TMP/zmosh-udp-global-cache

# BEGIN ISOLATED CARGO BUILD
(
    cd "$SOURCE"
    /usr/bin/env -i PATH="$PATH" HOME="$HOME" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}" \
    CARGO_HOME="$STREAM_CARGO_HOME" CARGO_TARGET_DIR="$ROOT_TARGET" CARGO_PROFILE_RELEASE_LTO=fat \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_PROFILE_RELEASE_OPT_LEVEL=3 \
    RUSTFLAGS='' CARGO_ENCODED_RUSTFLAGS='' "$CARGO_EXECUTABLE" build --locked --release \
    --manifest-path "$SOURCE/Cargo.toml" -p everudp \
    --no-default-features --features "$FLOOR_FEATURES" --example everudp-stream-floor \
    >"$OUTDIR/logs/everudp-stream-floor-build.stdout" \
    2>"$OUTDIR/logs/everudp-stream-floor-build.stderr"
)
# END ISOLATED CARGO BUILD
install -m 0755 "$ROOT_TARGET/release/examples/everudp-stream-floor" \
    "$OUTDIR/artifacts/bin/everudp-stream-floor"

/usr/bin/cc -std=c11 -O3 -Wall -Wextra -Werror \
    "$SOURCE_NET/pty-bench.c" -o "$OUTDIR/artifacts/bin/pty-bench" -lutil \
    >"$OUTDIR/logs/pty-bench-build.stdout" 2>"$OUTDIR/logs/pty-bench-build.stderr"
/usr/bin/cc -std=c11 -O3 -Wall -Wextra -Werror \
    "$SOURCE_NET/pty-echo.c" -o "$OUTDIR/artifacts/bin/pty-echo" \
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

[[ $(git -C "$ROOT" rev-parse HEAD) == "$HEAD_SHA" \
    && -z $(git -C "$ROOT" status --porcelain=v1 --untracked-files=all) ]] || {
    echo "source changed during exact stream build" >&2; exit 1;
}
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
import shutil
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

artifact_names = ("everudp-stream-floor", "zmosh-udp", "pty-bench", "pty-echo")
input_names = ("pty-bench.c", "pty-echo.c")
provenance = {
    "schema_version": 1,
    "purpose": "matched-noq-reliable-stream-floor",
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
    "tool_binaries": {
        name: {"path": str(Path(path).resolve()), "sha256": digest(Path(path).resolve())}
        for name, path in {"cargo": shutil.which("cargo"), "rustc": shutil.which("rustc"),
                           "cc": "/usr/bin/cc", "git": "/usr/bin/git"}.items()
    },
    "isolation": {
        "fresh_detached_zmosh_clone": True,
        "isolated_cargo_target": True,
        "archived_eversh_source": True,
        "empty_cargo_home": True,
        "cleared_cargo_environment": True,
        "isolated_zig_local_cache": True,
        "isolated_zig_global_cache": True,
    },
    "everudp_build": {
        "cargo_features": features.split(","),
        "default_features": False,
        "runtime_modes": ["ordinary", "native"],
        "diagnostic_build": False,
        "target": "example everudp-stream-floor",
        "profile": {"lto": "fat", "codegen_units": 1, "panic": "unwind", "opt_level": 3, "rustflags": "", "target_cpu": "portable default"},
    },
    "inputs": {
        "Cargo.lock": digest(root / "Cargo.lock"),
        "everudp-stream-floor.rs": digest(root / "crates/everudp/examples/everudp-stream-floor.rs"),
        "builder": digest(net / "build-stream-floor.sh"),
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
        f"env -i PATH HOME RUSTUP_HOME CARGO_HOME=(empty isolated directory) CARGO_TARGET_DIR=(isolated) CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_PROFILE_RELEASE_OPT_LEVEL=3 RUSTFLAGS='' CARGO_ENCODED_RUSTFLAGS='' cargo build --locked --release -p everudp --no-default-features --features {features} --example everudp-stream-floor (cwd=archived source)",
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
