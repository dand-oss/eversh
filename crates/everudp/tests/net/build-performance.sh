#!/usr/bin/env bash
# Build the production candidate, both frozen zmosh baselines, and every
# timed-path fixture from exact source into one immutable artifact directory.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
OUTDIR=${1:?usage: build-performance.sh OUTDIR}
OUTDIR=$(realpath -m -- "$OUTDIR")
ZMOSH_REPOSITORY=${ZMOSH_SOURCE_REPO:-/home/appsmith/asv/ports/repo/zmosh}
ZMOSH_UDP_COMMIT=dfc8395b5edcd237bf82712fbde879c6e8be7dfa
ZMOSH_UDP_TREE=1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514
ZMOSH_QUIC_COMMIT=21db4a4de6040b254531f2131b6f1c0cd146a7a1
ZMOSH_QUIC_TREE=38ea33069ce480a1b6465d4c49eafc59c3b6edd8
ZIG_0152=${EVERUDP_ZIG_0152:-}
ZIG_0160=${EVERUDP_ZIG_0160:-$(command -v zig || true)}
EVERUDP_FEATURES=${EVERUDP_CARGO_FEATURES:-cli}
EVERUDP_ENGINE=${EVERUDP_ENGINE:-noq}

# The normal build is the workspace's vendored NoQ engine.  Quinn is an
# explicitly named, isolated comparison package; it may never be selected by
# accident or combined with an experiment feature.
case "$EVERUDP_ENGINE" in
    noq)
        ENGINE_MANIFEST="$ROOT/Cargo.toml"
        ENGINE_MANIFEST_REL="Cargo.toml"
        ENGINE_PACKAGE=everudp
        ENGINE_FEATURES="$EVERUDP_FEATURES"
        ENGINE_LOCK="$ROOT/Cargo.lock"
        ;;
    quinn-eval)
        [[ "$EVERUDP_FEATURES" == cli ]] || {
            echo "quinn-eval engine accepts only EVERUDP_CARGO_FEATURES=cli" >&2
            exit 2
        }
        ENGINE_MANIFEST="$ROOT/spikes/everudp-quinn-eval/Cargo.toml"
        ENGINE_MANIFEST_REL="spikes/everudp-quinn-eval/Cargo.toml"
        ENGINE_PACKAGE=everudp-quinn-eval
        ENGINE_FEATURES=cli
        ENGINE_LOCK="$ROOT/spikes/everudp-quinn-eval/Cargo.lock"
        ;;
    *)
        echo "EVERUDP_ENGINE must be noq or quinn-eval" >&2
        exit 2
        ;;
esac

case "$EVERUDP_FEATURES" in
    cli,discarded-space-spike) ;;
    cli,input-ack-hold-spike) ;;
    cli,single-path-scheduling-spike|cli,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike,single-path-scheduling-spike|cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike,single-path-scheduling-spike) ;;
    cli,pty-ready-spike|cli,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike,pty-ready-spike|cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike,pty-ready-spike) ;;
    cli,quic-ack-threshold-spike|cli,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike|cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike,quic-ack-threshold-spike) ;;
    cli,quic-ack-coalescing-spike|cli,application-task-spike,stream-delivery-spike,quic-ack-coalescing-spike|cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike,quic-ack-coalescing-spike) ;;
    cli,packet-preparation-spike|cli,application-task-spike,stream-delivery-spike,packet-preparation-spike|cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike,packet-preparation-spike) ;;
    cli,application-task-spike|cli,application-task-spike,stream-delivery-spike|cli,path-packet-diagnostics,application-task-spike|cli,path-packet-diagnostics,application-task-spike,stream-delivery-spike) ;;
    cli|cli,datagram-spike|cli,stream-flush-spike|cli,stream-receive-spike|cli,stream-pump-spike|cli,path-diagnostics|cli,path-io-diagnostics|cli,path-packet-diagnostics|cli,stream-delivery-spike|cli,path-packet-diagnostics,stream-delivery-spike) ;;
    *)
        echo "EVERUDP_CARGO_FEATURES must be cli or a listed isolated experiment; application-task-spike permits stream-delivery-spike and/or preceding path-packet-diagnostics, with no other scheduling features" >&2
        exit 2
        ;;
esac

ENGINE_COMMAND_TEXT="CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_PROFILE_RELEASE_OPT_LEVEL=3 RUSTFLAGS='' CARGO_ENCODED_RUSTFLAGS='' cargo build --locked --release --manifest-path $ENGINE_MANIFEST_REL -p $ENGINE_PACKAGE --features $ENGINE_FEATURES"

[[ ! -e $OUTDIR ]] || { echo "refusing to overwrite exact build: $OUTDIR" >&2; exit 1; }
[[ -x $ZIG_0152 ]] || { echo "set EVERUDP_ZIG_0152 to the Zig 0.15.2 executable" >&2; exit 1; }
[[ -x $ZIG_0160 ]] || { echo "set EVERUDP_ZIG_0160 to the Zig 0.16.0 executable" >&2; exit 1; }
[[ $($ZIG_0152 version) == 0.15.2 ]] || { echo "old zmosh requires Zig 0.15.2" >&2; exit 1; }
[[ $($ZIG_0160 version) == 0.16.0 ]] || { echo "QUIC zmosh requires Zig 0.16.0" >&2; exit 1; }
for executable in /usr/bin/git /usr/bin/cc "$(command -v cargo)" "$(command -v rustc)"; do
    [[ -x $executable ]] || { echo "missing build executable: $executable" >&2; exit 1; }
done
for source in "$NET/pty-bench.c" "$NET/pty-echo.c" \
    "$NET/zmosh-quic-bridge.zig" "$NET/zmosh-quic-bench-build.zig"; do
    [[ -f $source ]] || { echo "missing build input: $source" >&2; exit 1; }
done
[[ -d $ZMOSH_REPOSITORY ]] || { echo "missing zmosh repository: $ZMOSH_REPOSITORY" >&2; exit 1; }
[[ -f $ENGINE_MANIFEST && -f $ENGINE_LOCK ]] || {
    echo "missing $EVERUDP_ENGINE engine manifest or lockfile" >&2
    exit 1
}

HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(git -C "$ROOT" rev-parse 'HEAD^{tree}')
[[ -z $(git -C "$ROOT" status --porcelain=v1 --untracked-files=all) ]] || {
    echo "refusing exact build from a dirty eversh worktree" >&2
    exit 1
}
for identity in "$ZMOSH_UDP_COMMIT:$ZMOSH_UDP_TREE" "$ZMOSH_QUIC_COMMIT:$ZMOSH_QUIC_TREE"; do
    commit=${identity%%:*}
    tree=${identity#*:}
    [[ $(git -C "$ZMOSH_REPOSITORY" cat-file -t "$commit") == commit ]] || {
        echo "missing frozen zmosh commit: $commit" >&2
        exit 1
    }
    [[ $(git -C "$ZMOSH_REPOSITORY" rev-parse "$commit^{tree}") == "$tree" ]] || {
        echo "frozen zmosh tree mismatch: $commit" >&2
        exit 1
    }
done

mkdir -p "$OUTDIR/artifacts/bin" "$OUTDIR/logs"
TMP=$(mktemp -d /tmp/everudp-exact-build.XXXXXX)
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
QUIC_SOURCE=$TMP/zmosh-quic-source
QUIC_PREFIX=$TMP/zmosh-quic-prefix
QUIC_CACHE=$TMP/zmosh-quic-cache
QUIC_ADAPTER_CACHE=$TMP/zmosh-quic-adapter-cache
QUIC_GLOBAL_CACHE=$TMP/zmosh-quic-global-cache

CARGO_TARGET_DIR=$ROOT_TARGET CARGO_PROFILE_RELEASE_LTO=fat \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_PANIC=unwind \
    CARGO_PROFILE_RELEASE_OPT_LEVEL=3 RUSTFLAGS='' CARGO_ENCODED_RUSTFLAGS='' \
    cargo build --locked --release \
    --manifest-path "${ENGINE_MANIFEST:-$ROOT/Cargo.toml}" \
    -p "${ENGINE_PACKAGE:-everudp}" \
    --features "${ENGINE_FEATURES:-$EVERUDP_FEATURES}" \
    >"$OUTDIR/logs/everudp-build.stdout" 2>"$OUTDIR/logs/everudp-build.stderr"
install -m 0755 "$ROOT_TARGET/release/everudp" "$OUTDIR/artifacts/bin/everudp"

if [[ -n ${EVERUDP_CONTROL_BUILD:-} ]]; then
    /usr/bin/python3 -B "$NET/reuse_performance_controls.py" \
        "$EVERUDP_CONTROL_BUILD" "$OUTDIR" "$NET"
else
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
    echo "old zmosh clone is not the frozen clean source" >&2
    exit 1
}
(
    cd "$UDP_SOURCE"
    "$ZIG_0152" build -Doptimize=ReleaseFast -p "$UDP_PREFIX" \
        --cache-dir "$UDP_CACHE" --global-cache-dir "$UDP_GLOBAL_CACHE"
) >"$OUTDIR/logs/zmosh-udp-build.stdout" 2>"$OUTDIR/logs/zmosh-udp-build.stderr"
install -m 0755 "$UDP_PREFIX/bin/zmosh" "$OUTDIR/artifacts/bin/zmosh-udp"

git clone --shared --no-checkout "$ZMOSH_REPOSITORY" "$QUIC_SOURCE" \
    >"$OUTDIR/logs/zmosh-quic-clone.stdout" 2>"$OUTDIR/logs/zmosh-quic-clone.stderr"
git -C "$QUIC_SOURCE" checkout --detach "$ZMOSH_QUIC_COMMIT" \
    >"$OUTDIR/logs/zmosh-quic-checkout.stdout" 2>"$OUTDIR/logs/zmosh-quic-checkout.stderr"
[[ $(git -C "$QUIC_SOURCE" rev-parse HEAD) == "$ZMOSH_QUIC_COMMIT" \
    && $(git -C "$QUIC_SOURCE" rev-parse 'HEAD^{tree}') == "$ZMOSH_QUIC_TREE" \
    && -z $(git -C "$QUIC_SOURCE" status --porcelain=v1 --untracked-files=all) ]] || {
    echo "QUIC zmosh clone is not the frozen clean source" >&2
    exit 1
}
(
    cd "$QUIC_SOURCE"
    "$ZIG_0160" build -Doptimize=ReleaseFast -p "$QUIC_PREFIX" \
        --cache-dir "$QUIC_CACHE" --global-cache-dir "$QUIC_GLOBAL_CACHE"
) >"$OUTDIR/logs/zmosh-quic-build.stdout" 2>"$OUTDIR/logs/zmosh-quic-build.stderr"
install -m 0755 "$QUIC_PREFIX/bin/zmosh" "$OUTDIR/artifacts/bin/zmosh-quic"

# These two untracked files are benchmark adapter inputs, not modifications to
# the frozen baseline. Tracked source remains byte-for-byte at the pinned tree.
install -m 0644 "$NET/zmosh-quic-bridge.zig" "$QUIC_SOURCE/zmosh-quic-bridge.zig"
install -m 0644 "$NET/zmosh-quic-bench-build.zig" "$QUIC_SOURCE/zmosh-quic-bench-build.zig"
[[ -z $(git -C "$QUIC_SOURCE" status --porcelain=v1 --untracked-files=no) ]] || {
    echo "QUIC adapter changed tracked baseline source" >&2
    exit 1
}
(
    cd "$QUIC_SOURCE"
    "$ZIG_0160" build --build-file zmosh-quic-bench-build.zig \
        -Doptimize=ReleaseFast -p "$QUIC_PREFIX" \
        --cache-dir "$QUIC_ADAPTER_CACHE" --global-cache-dir "$QUIC_GLOBAL_CACHE"
) >"$OUTDIR/logs/zmosh-quic-adapter-build.stdout" \
    2>"$OUTDIR/logs/zmosh-quic-adapter-build.stderr"
install -m 0755 "$QUIC_PREFIX/bin/zmosh-quic-bridge" \
    "$OUTDIR/artifacts/bin/zmosh-quic-bridge"
fi

FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CARGO_VERSION=$(cargo --version)
RUSTC_VERSION=$(rustc --version)
CC_VERSION=$(/usr/bin/cc --version | head -1)
GIT_VERSION=$(git --version)
ZIG_0152_VERSION=$($ZIG_0152 version)
ZIG_0160_VERSION=$($ZIG_0160 version)
ZIG_0152_SHA=$(sha256sum "$ZIG_0152" | awk '{print $1}')
ZIG_0160_SHA=$(sha256sum "$ZIG_0160" | awk '{print $1}')

/usr/bin/python3 - "$OUTDIR" "$ROOT" "$NET" "$HEAD_SHA" "$TREE_SHA" \
    "$ZMOSH_UDP_COMMIT" "$ZMOSH_UDP_TREE" "$ZMOSH_QUIC_COMMIT" \
    "$ZMOSH_QUIC_TREE" "$STARTED_UTC" "$FINISHED_UTC" "$CARGO_VERSION" \
    "$RUSTC_VERSION" "$CC_VERSION" "$GIT_VERSION" "$ZIG_0152_VERSION" \
    "$ZIG_0160_VERSION" "$ZIG_0152_SHA" "$ZIG_0160_SHA" \
    "$EVERUDP_FEATURES" "$EVERUDP_ENGINE" "$ENGINE_MANIFEST_REL" "$ENGINE_PACKAGE" \
    "$ENGINE_COMMAND_TEXT" "$(sha256sum "$ENGINE_LOCK" | awk '{print $1}')" <<'PY'
import hashlib
import json
import platform
import tomllib
import sys
from pathlib import Path

(
    out_raw, root_raw, net_raw, head, tree, udp_commit, udp_tree,
    quic_commit, quic_tree, started, finished, cargo_version,
    rustc_version, cc_version, git_version, zig_old_version,
    zig_new_version, zig_old_sha, zig_new_sha, everudp_features,
    engine, engine_manifest, engine_package, engine_command, engine_lock_sha,
) = sys.argv[1:]
out = Path(out_raw)
root = Path(root_raw)
net = Path(net_raw)

# Derive engine identities from the sealed lock, not a label copied from the
# selected option. Fail rather than publishing stale version claims.
pinned_dependencies = {}
if engine == "quinn-eval":
    packages = tomllib.loads((root / "spikes/everudp-quinn-eval/Cargo.lock").read_text())["package"]
    for name, version in (("quinn", "0.11.11"), ("quinn-proto", "0.11.15")):
        matches = [package for package in packages if package["name"] == name]
        if len(matches) != 1 or matches[0]["version"] != version:
            raise SystemExit(f"unexpected pinned {name} identity")
        package = matches[0]
        pinned_dependencies[name] = {
            "package": name, "version": package["version"],
            "source": package["source"], "checksum": package["checksum"],
        }

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

artifact_names = (
    "everudp", "zmosh-udp", "zmosh-quic", "zmosh-quic-bridge",
    "pty-bench", "pty-echo",
)
input_names = (
    "pty-bench.c", "pty-echo.c", "zmosh-quic-bridge.zig",
    "zmosh-quic-bench-build.zig",
)
provenance = {
    "schema_version": 1,
    "source": {"head_sha": head, "tree_sha": tree, "clean": True},
    "zmosh_sources": {
        "udp": {"commit": udp_commit, "tree": udp_tree, "clean": True},
        "quic": {"commit": quic_commit, "tree": quic_tree, "clean": True},
    },
    "started_utc": started,
    "finished_utc": finished,
    "host": {"platform": platform.platform()},
    "tools": {
        "cargo": cargo_version,
        "rustc": rustc_version,
        "cc": cc_version,
        "git": git_version,
        "zig_0_15_2": {"version": zig_old_version, "sha256": zig_old_sha},
        "zig_0_16_0": {"version": zig_new_version, "sha256": zig_new_sha},
    },
    "isolation": {
        "fresh_detached_zmosh_clones": True,
        "isolated_cargo_target": True,
        "isolated_zig_local_caches": True,
        "isolated_zig_global_caches_per_baseline": True,
        "quic_adapter_changes_tracked_baseline": False,
    },
    "everudp_build": {
        "engine": engine,
        "manifest": engine_manifest,
        "package": engine_package,
        "cargo_lock_sha256": engine_lock_sha,
        "command": engine_command,
        "pinned_dependencies": pinned_dependencies,
        "cargo_features": everudp_features.split(","),
        "profile": {"lto": "fat", "codegen_units": 1, "panic": "unwind",
                    "opt_level": 3, "rustflags": "", "encoded_rustflags": "",
                    "target_cpu": "portable default"},
    },
    "inputs": {
        "Cargo.lock": digest(root / "Cargo.lock"),
        "engine_Cargo.lock": engine_lock_sha,
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
        engine_command,
        "zig-0.15.2 build -Doptimize=ReleaseFast (zmosh UDP)",
        "zig-0.16.0 build -Doptimize=ReleaseFast (zmosh QUIC)",
        "zig-0.16.0 build --build-file zmosh-quic-bench-build.zig -Doptimize=ReleaseFast",
        "cc -std=c11 -O3 -Wall -Wextra -Werror pty-bench.c -lutil",
        "cc -std=c11 -O3 -Wall -Wextra -Werror pty-echo.c",
    ],
}
control_path = out / "provenance-inputs/control.json"
if control_path.exists():
    control = json.loads(control_path.read_text(encoding="utf-8"))
    if control["tools"] != provenance["tools"]:
        raise ValueError("reused control toolchain identity differs from current build")
    control_names = artifact_names[1:]
    for name in control_names:
        if provenance["artifacts"][name] != control["artifacts"][name]:
            raise ValueError(f"copied control artifact mismatch: {name}")
    provenance["control_reuse"] = {
        "provenance_path": "provenance-inputs/control.json",
        "provenance_sha256": digest(control_path),
        "source": control["source"],
        "artifacts": {name: control["artifacts"][name] for name in control_names},
    }
    provenance["isolation"].update(
        fresh_detached_zmosh_clones=False,
        isolated_zig_local_caches=False,
        isolated_zig_global_caches_per_baseline=False,
        sealed_control_reuse=True,
    )
    provenance["commands"] = [provenance["commands"][0],
        "reuse_performance_controls.py: verify sealed ordinary control bundle and copy five controls"]
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
echo "exact performance build PASS: $OUTDIR"
