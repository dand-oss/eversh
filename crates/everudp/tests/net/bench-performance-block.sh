#!/usr/bin/env bash
# One frozen-order, one-loss-cell performance block. Production qualification
# uses three candidates; the v4 stage-zero cutoff uses the authenticated floor
# and frozen zmosh UDP in the same compiled local PTY driver.
set -Eeuo pipefail
export PYTHONDONTWRITEBYTECODE=1

COUNTER_CAPTURE=${EVERUDP_COUNTER_CAPTURE:-0}
[[ $COUNTER_CAPTURE == 0 || $COUNTER_CAPTURE == 1 ]] || {
    echo "counter capture must be 0 or 1" >&2; exit 2;
}
if [[ $COUNTER_CAPTURE == 1 ]]; then
    for option in EVERUDP_PATH_TRACE EVERUDP_PATH_IO_TRACE EVERUDP_PATH_PACKET_TRACE \
        EVERUDP_FLOOR_TRACE EVERUDP_FLOOR_NATIVE_TRACE EVERUDP_FLOOR_REACTOR_TRACE \
        EVERUDP_FLOOR_PARTITION_TRACE; do
        [[ ${!option:-0} == 0 ]] || {
            echo "counter capture cannot be combined with tracing" >&2; exit 2;
        }
    done
fi

PATH_TRACE=${EVERUDP_PATH_TRACE:-0}
IO_TRACE=${EVERUDP_PATH_IO_TRACE:-0}
PACKET_TRACE=${EVERUDP_PATH_PACKET_TRACE:-0}
[[ $PACKET_TRACE == 0 || $PACKET_TRACE == 1 ]] &&
    [[ $PACKET_TRACE == 0 || $IO_TRACE == 1 ]] || {
    echo "production packet tracing requires boolean options and I/O tracing" >&2; exit 2;
}
[[ $IO_TRACE == 0 || $IO_TRACE == 1 ]] || {
    echo "production I/O tracing must be 0 or 1" >&2; exit 2;
}
[[ $IO_TRACE == 0 || $PATH_TRACE == 1 ]] || {
    echo "production I/O tracing requires production path tracing" >&2; exit 2;
}
[[ $PATH_TRACE == 0 || $PATH_TRACE == 1 ]] || {
    echo "production path tracing must be 0 or 1" >&2; exit 2;
}
if [[ $PATH_TRACE == 1 && ( ${EVERUDP_FLOOR_TRACE:-0} != 0 || ${EVERUDP_FLOOR_NATIVE_TRACE:-0} != 0 || ${EVERUDP_FLOOR_REACTOR_TRACE:-0} != 0 || ${EVERUDP_FLOOR_PARTITION_TRACE:-0} != 0 ) ]]; then
    echo "production path tracing cannot be combined with floor tracing" >&2; exit 2
fi

NATIVE_TRACE=${EVERUDP_FLOOR_NATIVE_TRACE:-0}
PARTITION_TRACE=${EVERUDP_FLOOR_PARTITION_TRACE:-0}
[[ $PARTITION_TRACE == 0 || $PARTITION_TRACE == 1 ]] || {
    echo "EVERUDP_FLOOR_PARTITION_TRACE must be 0 or 1" >&2; exit 2;
}
if [[ $PARTITION_TRACE == 1 && ( $NATIVE_TRACE == 1 || ${EVERUDP_FLOOR_TRACE:-0} == 1 || ${EVERUDP_FLOOR_REACTOR_TRACE:-0} == 1 ) ]]; then
    echo "partition tracing cannot be combined with other tracing" >&2; exit 2
fi
REACTOR_TRACE=${EVERUDP_FLOOR_REACTOR_TRACE:-0}
[[ $REACTOR_TRACE == 0 || $REACTOR_TRACE == 1 ]] || {
    echo "EVERUDP_FLOOR_REACTOR_TRACE must be 0 or 1" >&2; exit 2;
}
[[ $NATIVE_TRACE == 0 || $NATIVE_TRACE == 1 ]] || {
    echo "EVERUDP_FLOOR_NATIVE_TRACE must be 0 or 1" >&2; exit 2;
}
if [[ $NATIVE_TRACE == 1 && ${EVERUDP_FLOOR_TRACE:-0} == 1 ]]; then
    echo "native and legacy tracing cannot be combined" >&2
    exit 2
fi
if [[ $REACTOR_TRACE == 1 && ( $NATIVE_TRACE == 1 || ${EVERUDP_FLOOR_TRACE:-0} == 1 ) ]]; then
    echo "reactor work tracing cannot be combined with other tracing" >&2
    exit 2
fi

if (( EUID != 0 )); then
    echo "everudp performance blocks require root network-namespace privileges" >&2
    exit 77
fi

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$NET/counter-capture.sh"
TRIALS=${1:?usage: bench-performance-block.sh TRIALS LOSS SEED OUTDIR ORDER}
LOSS=${2:?usage: bench-performance-block.sh TRIALS LOSS SEED OUTDIR ORDER}
BLOCK_SEED=${3:?usage: bench-performance-block.sh TRIALS LOSS SEED OUTDIR ORDER}
OUTDIR=${4:?usage: bench-performance-block.sh TRIALS LOSS SEED OUTDIR ORDER}
ORDER=${5:?usage: bench-performance-block.sh TRIALS LOSS SEED OUTDIR ORDER}
BUILD=${EVERUDP_PERF_BUILD:?set EVERUDP_PERF_BUILD to an exact performance build}
OUTDIR=$(realpath -m -- "$OUTDIR")
BUILD=$(realpath -m -- "$BUILD")
ARTIFACTS=$BUILD/artifacts/bin

if ! [[ $TRIALS =~ ^[0-9]+$ && $BLOCK_SEED =~ ^[0-9]+$ ]]; then
    echo "trials and seed must be positive integers" >&2
    exit 2
fi
if (( TRIALS < 200 )) && [[ ${EVERUDP_ALLOW_SHORT:-0} != 1 ]]; then
    echo "final blocks require 200 trials; EVERUDP_ALLOW_SHORT=1 is smoke-only" >&2
    exit 2
fi
if (( BLOCK_SEED < 1 || BLOCK_SEED > 2147483646 )); then
    echo "seed must be in [1, 2147483646]" >&2
    exit 2
fi
[[ $LOSS == 0 || $LOSS == 5 ]] || { echo "loss cell must be 0 or 5" >&2; exit 2; }

IFS=, read -r -a CANDIDATES <<<"$ORDER"
# shellcheck source=benchmark-candidates.sh
source "$NET/benchmark-candidates.sh"
COMPARISON_MODE=$(benchmark_candidate_mode "$ORDER")
if [[ $COUNTER_CAPTURE == 1 && $COMPARISON_MODE != production ]]; then
    echo "counter capture requires production candidates" >&2; exit 2
fi
FLOOR_MODE=0
STREAM_MODE=0
[[ $COMPARISON_MODE != datagram-floor ]] || FLOOR_MODE=1
[[ $COMPARISON_MODE != stream-floor ]] || STREAM_MODE=1
if (( FLOOR_MODE == 1 )); then
    [[ $PATH_TRACE == 0 ]] || { echo "production path tracing requires production candidates" >&2; exit 2; }
fi
if (( STREAM_MODE == 1 )); then
    [[ $PATH_TRACE == 0 && $NATIVE_TRACE == 0 && $REACTOR_TRACE == 0 && $PARTITION_TRACE == 0 && ${EVERUDP_FLOOR_TRACE:-0} == 0 && ! -v EVERUDP_STREAM_PROFILE_DIR ]] || {
        echo "stream timing cannot include tracing or preflight profile capture" >&2
        exit 2
    }
fi

EVERUDP_BIN=$ARTIFACTS/everudp
EVERUDP_FLOOR_BIN=$ARTIFACTS/everudp-floor
EVERUDP_STREAM_BIN=$ARTIFACTS/everudp-stream-floor
ZMOSH_UDP_BIN=$ARTIFACTS/zmosh-udp
ZMOSH_QUIC_BIN=$ARTIFACTS/zmosh-quic
ZMOSH_QUIC_BRIDGE=$ARTIFACTS/zmosh-quic-bridge
PTY_BENCH=$ARTIFACTS/pty-bench
PTY_ECHO=$ARTIFACTS/pty-echo
candidate_executables=("$ZMOSH_UDP_BIN" "$PTY_BENCH" "$PTY_ECHO")
if (( FLOOR_MODE == 1 )); then
    candidate_executables+=("$EVERUDP_FLOOR_BIN")
elif (( STREAM_MODE == 1 )); then
    candidate_executables+=("$EVERUDP_STREAM_BIN")
else
    candidate_executables+=("$EVERUDP_BIN" "$ZMOSH_QUIC_BIN" "$ZMOSH_QUIC_BRIDGE")
fi
for executable in "${candidate_executables[@]}" /usr/bin/ip \
    /usr/sbin/tc /usr/bin/ssh /usr/bin/ssh-keygen /usr/bin/ssh-keyscan \
    /usr/sbin/sshd /usr/bin/sudo /usr/bin/taskset /usr/bin/time \
    /usr/bin/python3 /usr/bin/jq /usr/bin/sha256sum; do
    [[ -x $executable ]] || { echo "missing executable: $executable" >&2; exit 1; }
done
for helper in "$NET/ssh-wrapper.sh" "$NET/remote-everudp.sh" \
    "$NET/remote-zmosh.sh" "$NET/launch-zmosh-quic.sh"; do
    [[ -f $helper ]] || { echo "missing benchmark helper: $helper" >&2; exit 1; }
done
if [[ ! -f $BUILD/provenance.json && ${EVERUDP_ALLOW_UNSEALED_BUILD:-0} != 1 ]]; then
    echo "performance build has no provenance.json" >&2
    exit 1
fi
[[ ! -e $OUTDIR ]] || { echo "refusing to overwrite performance block: $OUTDIR" >&2; exit 1; }
if [[ $PATH_TRACE == 1 ]]; then
    /usr/bin/jq -e --arg io "$IO_TRACE" --arg packet "$PACKET_TRACE" '
        .everudp_build.cargo_features as $features |
        ($packet == "1" and ($features == ["cli", "path-packet-diagnostics"] or
            $features == ["cli", "path-packet-diagnostics", "stream-delivery-spike"] or
            $features == ["cli", "path-packet-diagnostics", "application-task-spike"] or
            $features == ["cli", "path-packet-diagnostics", "application-task-spike", "stream-delivery-spike"] or
            $features == ["cli", "path-packet-diagnostics", "application-task-spike", "stream-delivery-spike", "quic-ack-coalescing-spike"] or
            $features == ["cli", "path-packet-diagnostics", "application-task-spike", "stream-delivery-spike", "quic-ack-threshold-spike"])) or
        ($packet == "0" and ($features == ["cli", "path-io-diagnostics"] or
        ($io == "0" and $features == ["cli", "path-diagnostics"])))' \
        "$BUILD/provenance.json" >/dev/null || {
        echo "production path tracing requires a matching isolated diagnostic build" >&2; exit 2;
    }
fi

HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(git -C "$ROOT" rev-parse 'HEAD^{tree}')
DIRTY=$(git -C "$ROOT" status --porcelain=v1 --untracked-files=all)
if [[ -n $DIRTY && ${EVERUDP_ALLOW_DIRTY:-0} != 1 ]]; then
    echo "refusing exact-SHA performance block from a dirty worktree" >&2
    exit 1
fi
DIRTY_JSON=false
[[ -z $DIRTY ]] || DIRTY_JSON=true

RUN_USER=${SUDO_USER:-$(stat -c %U "$ROOT")}
RUN_HOME=$(getent passwd "$RUN_USER" | cut -d: -f6)
[[ -n $RUN_HOME ]] || { echo "cannot resolve home for $RUN_USER" >&2; exit 1; }

allowed=$(taskset -pc $$ | sed 's/.*: //')
CPU_SET=${EVERUDP_BENCH_CPUSET:-$(/usr/bin/python3 - "$allowed" <<'PY'
import sys

cpus = []
for part in sys.argv[1].split(","):
    if "-" in part:
        lo, hi = map(int, part.split("-", 1))
        cpus.extend(range(lo, hi + 1))
    else:
        cpus.append(int(part))
preferred = [cpu for cpu in cpus if cpu % 2 == 0]
chosen = (preferred or cpus)[-4:]
print(",".join(map(str, chosen)))
PY
)}
[[ -n $CPU_SET ]] || { echo "empty CPU affinity" >&2; exit 1; }

TMP=$(mktemp -d /tmp/everudp-perf-block.XXXXXX)
TAG=p$(printf '%05x' $(((RANDOM << 1 ^ BLOCK_SEED) & 1048575)))
SERVER_NS=${TAG}s
CLIENT_NS=${TAG}c
SSHD_PID=
CLEANED=0
GOVERNORS_CHANGED=0
mkdir -p "$OUTDIR" "$TMP/client-bin" "$TMP/server-state" \
    "$TMP/remote-everudp/state" "$TMP/remote-zmosh-udp/state" \
    "$TMP/remote-zmosh-quic/state" "$TMP/remote-everudp-floor/state" "$TMP/remote-everudp-stream/state"
chmod 0755 "$TMP"
chmod 0700 "$TMP/server-state" "$TMP"/remote-*/state

record_governors() {
    local phase=$1 cpu file value
    : >"$OUTDIR/governors-$phase.txt"
    for cpu in ${CPU_SET//,/ }; do
        file=/sys/devices/system/cpu/cpu${cpu}/cpufreq/scaling_governor
        if [[ -r $file ]]; then
            value=$(<"$file")
            printf 'cpu%s %s\n' "$cpu" "$value" >>"$OUTDIR/governors-$phase.txt"
        else
            printf 'cpu%s unavailable\n' "$cpu" >>"$OUTDIR/governors-$phase.txt"
        fi
    done
}

pin_governors() {
    local cpu file value
    record_governors before
    for cpu in ${CPU_SET//,/ }; do
        file=/sys/devices/system/cpu/cpu${cpu}/cpufreq/scaling_governor
        [[ -w $file ]] || continue
        value=$(<"$file")
        printf '%s\n' "$value" >"$TMP/governor-$cpu"
        printf 'performance\n' >"$file"
        GOVERNORS_CHANGED=1
    done
    record_governors pinned
}

restore_governors() {
    local cpu file
    (( GOVERNORS_CHANGED == 1 )) || return 0
    for cpu in ${CPU_SET//,/ }; do
        file=/sys/devices/system/cpu/cpu${cpu}/cpufreq/scaling_governor
        [[ -f $TMP/governor-$cpu && -w $file ]] || continue
        command /usr/bin/tee "$file" <"$TMP/governor-$cpu" >/dev/null || true
    done
}

cleanup() {
    local status=$?
    (( CLEANED == 0 )) || exit "$status"
    CLEANED=1
    set +e
    trap - EXIT INT TERM HUP
    [[ -z ${SSHD_PID:-} ]] || kill -TERM "$SSHD_PID" 2>/dev/null
    for ns in "$CLIENT_NS" "$SERVER_NS"; do
        mapfile -t pids < <(/usr/bin/ip netns pids "$ns" 2>/dev/null)
        ((${#pids[@]} == 0)) || kill -KILL "${pids[@]}" 2>/dev/null
        /usr/bin/ip netns del "$ns" 2>/dev/null
    done
    if (( GOVERNORS_CHANGED == 1 )); then
        restore_governors
        record_governors after 2>/dev/null || true
    fi
    rm -rf -- "$TMP"
    if [[ -d $OUTDIR ]] && ! chown -R -- "$RUN_USER" "$OUTDIR"; then
        echo "could not return performance block artifacts to $RUN_USER" >&2
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

pin_governors

/usr/bin/ssh-keygen -q -t ed25519 -N '' -f "$TMP/host" >/dev/null
/usr/bin/ssh-keygen -q -t ed25519 -N '' -f "$TMP/client" >/dev/null
install -m 0644 "$TMP/client.pub" "$TMP/authorized_keys"
install -m 0755 "$NET/ssh-wrapper.sh" "$TMP/client-bin/ssh"
install -m 0755 "$NET/remote-everudp.sh" "$TMP/remote-everudp/remote-everudp"
if [[ $PATH_TRACE == 1 ]]; then
    touch "$TMP/remote-everudp/path-trace.enabled"
fi
if [[ $IO_TRACE == 1 ]]; then
    touch "$TMP/remote-everudp/path-io-trace.enabled"
fi
install -m 0755 "$NET/remote-everudp.sh" "$TMP/remote-everudp-floor/remote-everudp-floor"
install -m 0755 "$NET/remote-everudp.sh" "$TMP/remote-everudp-stream/remote-everudp-stream"
install -m 0755 "$NET/remote-zmosh.sh" "$TMP/remote-zmosh-udp/remote-zmosh"
install -m 0755 "$NET/remote-zmosh.sh" "$TMP/remote-zmosh-quic/remote-zmosh"
ln -s "$EVERUDP_BIN" "$TMP/remote-everudp/everudp"
ln -s "$EVERUDP_FLOOR_BIN" "$TMP/remote-everudp-floor/everudp"
ln -s "$EVERUDP_STREAM_BIN" "$TMP/remote-everudp-stream/everudp"
ln -s "$ZMOSH_UDP_BIN" "$TMP/remote-zmosh-udp/zmosh"
ln -s "$ZMOSH_QUIC_BIN" "$TMP/remote-zmosh-quic/zmosh"
chown -R "$RUN_USER" "$OUTDIR" "$TMP/client" "$TMP/client.pub" \
    "$TMP/client-bin" "$TMP/remote-everudp" "$TMP/remote-zmosh-udp" \
    "$TMP/remote-zmosh-quic" "$TMP/remote-everudp-floor" "$TMP/remote-everudp-stream"

/usr/bin/ip netns add "$SERVER_NS"
/usr/bin/ip netns add "$CLIENT_NS"
/usr/bin/ip link add "${TAG}s0" type veth peer name "${TAG}c0"
/usr/bin/ip link set "${TAG}s0" netns "$SERVER_NS"
/usr/bin/ip link set "${TAG}c0" netns "$CLIENT_NS"
/usr/bin/ip -n "$SERVER_NS" link set "${TAG}s0" name s0
/usr/bin/ip -n "$CLIENT_NS" link set "${TAG}c0" name c0
/usr/bin/ip -n "$SERVER_NS" link set lo up
/usr/bin/ip -n "$CLIENT_NS" link set lo up
/usr/bin/ip -n "$SERVER_NS" addr add 10.246.0.1/24 dev s0
/usr/bin/ip -n "$CLIENT_NS" addr add 10.246.0.2/24 dev c0
/usr/bin/ip -n "$SERVER_NS" link set s0 up
/usr/bin/ip -n "$CLIENT_NS" link set c0 up
/usr/bin/ip -j -n "$SERVER_NS" address show >"$OUTDIR/topology-server.json"
/usr/bin/ip -j -n "$CLIENT_NS" address show >"$OUTDIR/topology-client.json"

cat >"$TMP/sshd_config" <<EOF
Port 22461
ListenAddress 10.246.0.1
HostKey $TMP/host
AuthorizedKeysFile $TMP/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
UseDNS no
PermitUserEnvironment no
PermitUserRC no
LogLevel ERROR
EOF
/usr/bin/taskset -c "$CPU_SET" /usr/bin/ip netns exec "$SERVER_NS" \
    /usr/sbin/sshd -D -e -f "$TMP/sshd_config" 2>"$OUTDIR/sshd.stderr" &
SSHD_PID=$!
for _ in $(seq 1 100); do
    /usr/bin/ip netns exec "$CLIENT_NS" /usr/bin/ssh-keyscan -T 1 -p 22461 \
        10.246.0.1 >"$TMP/known" 2>/dev/null || true
    grep -q ssh-ed25519 "$TMP/known" && break
    sleep 0.05
done
grep -q ssh-ed25519 "$TMP/known" || { cat "$OUTDIR/sshd.stderr" >&2; exit 1; }
cat >"$TMP/client_config" <<EOF
Host target 10.246.0.1
    HostName 10.246.0.1
    AddressFamily inet
    Port 22461
    User $RUN_USER
    IdentityFile $TMP/client
    IdentitiesOnly yes
    UserKnownHostsFile $TMP/known
    GlobalKnownHostsFile /dev/null
    StrictHostKeyChecking yes
    HostKeyAlgorithms ssh-ed25519
    BatchMode yes
    ConnectTimeout 3
    ConnectionAttempts 1
EOF
chmod 0644 "$TMP/client_config" "$TMP/known"
chown "$RUN_USER" "$TMP/client_config" "$TMP/known"

reset_netem() {
    local label=$1
    /usr/bin/ip netns exec "$CLIENT_NS" /usr/sbin/tc qdisc replace dev c0 root netem \
        loss random "${LOSS}%" seed "$BLOCK_SEED"
    /usr/bin/ip netns exec "$SERVER_NS" /usr/sbin/tc qdisc replace dev s0 root netem \
        loss random "${LOSS}%" seed "$((BLOCK_SEED + 1000003))"
}

record_netem_before() {
    local label=$1
    /usr/bin/ip netns exec "$CLIENT_NS" /usr/sbin/tc -s qdisc show dev c0 \
        >"$OUTDIR/netem-$label-client-before.txt"
    /usr/bin/ip netns exec "$SERVER_NS" /usr/sbin/tc -s qdisc show dev s0 \
        >"$OUTDIR/netem-$label-server-before.txt"
}

wait_measurement_barrier() {
    local marker=$1 runner=$2 budget=$3
    local deadline=$((SECONDS + budget))
    while [[ ! -f $marker ]]; do
        if ! kill -0 "$runner" 2>/dev/null || (( SECONDS >= deadline )); then
            echo "measurement barrier unavailable: $marker" >&2
            return 1
        fi
        sleep 0.01
    done
}

record_netem_after() {
    local label=$1
    /usr/bin/ip netns exec "$CLIENT_NS" /usr/sbin/tc -s qdisc show dev c0 \
        >"$OUTDIR/netem-$label-client-after.txt"
    /usr/bin/ip netns exec "$SERVER_NS" /usr/sbin/tc -s qdisc show dev s0 \
        >"$OUTDIR/netem-$label-server-after.txt"
}

clean_candidate_processes() {
    local pid
    while read -r pid; do
        [[ -n $pid && $pid != "$SSHD_PID" ]] || continue
        kill -KILL "$pid" 2>/dev/null || true
    done < <(/usr/bin/ip netns pids "$SERVER_NS" 2>/dev/null)
    while read -r pid; do
        [[ -n $pid ]] || continue
        kill -KILL "$pid" 2>/dev/null || true
    done < <(/usr/bin/ip netns pids "$CLIENT_NS" 2>/dev/null)
    sleep 0.1
}

run_as_user() {
    /usr/bin/ip netns exec "$CLIENT_NS" /usr/bin/sudo -n -H -u "$RUN_USER" "$@"
}

host_snapshot() {
    /usr/bin/python3 -B "$NET/host_snapshot.py" "$CPU_SET" "$CLIENT_NS" "$SERVER_NS" \
        >"$candidate_dir/host-$1.json"
}

run_candidate() {
    local label=$1
    shift
    local candidate_dir=$OUTDIR/$label
    mkdir -p "$candidate_dir/window"
    chown -R "$RUN_USER" "$candidate_dir"
    reset_netem "$label"
    /usr/bin/ip netns exec "$CLIENT_NS" /usr/sbin/tc -s qdisc show dev c0 \
        >"$candidate_dir/netem-client-start.txt"
    run_as_user /usr/bin/time -v -o "$candidate_dir/resources.txt" \
        /usr/bin/env PTY_BENCH_WINDOW_DIR="$candidate_dir/window" \
        /usr/bin/taskset -c "$CPU_SET" "$PTY_BENCH" "$TRIALS" 100 \
        "$candidate_dir/result.json" "$candidate_dir/candidate.stderr" -- "$@" &
    local runner=$!
    wait_measurement_barrier "$candidate_dir/window/start.ready" "$runner" 90
    record_netem_before "$label"
    host_snapshot before
    counter_capture_barrier "$candidate_dir/window" start "$runner"
    touch "$candidate_dir/window/start.go"
    wait_measurement_barrier "$candidate_dir/window/finish.ready" "$runner" "$((TRIALS * 11 + 60))"
    counter_capture_barrier "$candidate_dir/window" stop "$runner"
    host_snapshot after
    record_netem_after "$label"
    touch "$candidate_dir/window/finish.go"
    wait "$runner"
    if [[ $PATH_TRACE == 1 && $label == everudp ]]; then
        # An authenticated client detach exports the persistent gateway's
        # trace. Require complete JSON before the ordinary SIGKILL cleanup.
        local exported=0 role
        for ((attempt = 0; attempt < 100; attempt++)); do
            if /usr/bin/jq -e '.schema_version == 1 and (.events | type) == "array"' \
                "$TMP/remote-everudp/path-trace.json" >/dev/null 2>&1 &&
                { [[ $IO_TRACE == 0 ]] || /usr/bin/jq -e \
                    '.trace_kind == "quic_io" and (.events | type) == "array"' \
                    "$TMP/remote-everudp/path-trace.json.io.json" >/dev/null 2>&1; } &&
                { [[ $PACKET_TRACE == 0 ]] || /usr/bin/jq -e \
                    '.trace_kind == "quic_packets" and (.events | type) == "array"' \
                    "$TMP/remote-everudp/path-trace.json.packets.json" >/dev/null 2>&1; }; then
                exported=1
                break
            fi
            sleep 0.05
        done
        (( exported == 1 )) || { echo "gateway path trace did not export valid JSON" >&2; return 1; }
        install -m 0600 "$TMP/remote-everudp/path-trace.json" "$candidate_dir/gateway-path-trace.json"
        if [[ $IO_TRACE == 1 ]]; then
            install -m 0600 "$TMP/remote-everudp/path-trace.json.io.json" \
                "$candidate_dir/gateway-path-trace.json.io.json"
            for role in client gateway; do
                /usr/bin/python3 -B "$NET/validate_io_trace.py" \
                    "$candidate_dir/$role-path-trace.json.io.json" \
                    "$candidate_dir/$role-path-trace.json" "$role" \
                    >"$candidate_dir/$role-io-validation.json"
            done
        fi
        /usr/bin/jq -e '.schema_version == 1 and .valid == true and .overflow == false and (.events | length) > 0' \
            "$candidate_dir/client-path-trace.json" >/dev/null
        /usr/bin/python3 -B "$NET/analyze_path_trace.py" \
            "$candidate_dir/client-path-trace.json" "$candidate_dir/gateway-path-trace.json" \
            "$candidate_dir/result.json" >"$candidate_dir/path-analysis.json"
        if [[ $PACKET_TRACE == 1 ]]; then
            install -m 0600 "$TMP/remote-everudp/path-trace.json.packets.json" \
                "$candidate_dir/gateway-path-trace.json.packets.json"
            /usr/bin/python3 -B "$NET/analyze_packet_trace.py" \
                "$candidate_dir/client-path-trace.json" "$candidate_dir/gateway-path-trace.json" \
                "$candidate_dir/result.json" \
                "$candidate_dir/client-path-trace.json.packets.json" \
                "$candidate_dir/gateway-path-trace.json.packets.json" \
                >"$candidate_dir/packet-analysis.json"
        fi
    fi
    /usr/bin/jq -e --argjson trials "$TRIALS" \
        '.trials == $trials and .transcript_failures == 0
         and (.samples_us | length) == $trials
         and all(.samples_us[]; . > 0)' "$candidate_dir/result.json" >/dev/null
    clean_candidate_processes
}

run_named_candidate() {
    local label=$1 ordinal=$2
    local session="perf-${TAG}-${ordinal}-${label//-/_}"
    local candidate_dir=$OUTDIR/$label
    local trace_args=()
    if [[ ${EVERUDP_FLOOR_TRACE:-0} == 1 ]]; then
        trace_args=(--trace-json "$candidate_dir/client-trace.json")
    elif [[ $NATIVE_TRACE == 1 ]]; then
        trace_args=(--native-trace-json "$candidate_dir/native-stage-trace.json")
    elif [[ $REACTOR_TRACE == 1 ]]; then
        trace_args=(--reactor-trace-json "$candidate_dir/reactor-work-trace.json")
    elif [[ $PARTITION_TRACE == 1 ]]; then
        trace_args=(--partition-trace-json "$candidate_dir/reactor-partition-trace.json")
    fi
    case "$label" in
        everudp-stream-native|everudp-stream-ordinary)
            run_candidate "$label" /usr/bin/env TERM=xterm-256color \
                "$EVERUDP_STREAM_BIN" client target --runtime "${label##*-}" --session "$session" \
                --remote-program "$TMP/remote-everudp-stream/remote-everudp-stream" \
                "--ssh-option=-F$TMP/client_config"
            ;;
        everudp-floor)
            run_candidate "$label" /usr/bin/env TERM=xterm-256color \
                "$EVERUDP_FLOOR_BIN" client "${trace_args[@]}" target --session "$session" \
                --remote-program "$TMP/remote-everudp-floor/remote-everudp-floor" \
                --ssh-option "-F$TMP/client_config"
            if [[ ${EVERUDP_FLOOR_TRACE:-0} == 1 ]]; then
                /usr/bin/jq -e '.diagnostic_only == true and .run_succeeded == true
                    and .trace.valid == true and .trace.overflow == false' \
                    "$candidate_dir/client-trace.json" >/dev/null
                /usr/bin/jq -e '.valid == true and .overflow == false
                    and (.events | length) > 0' \
                    "$candidate_dir/client-trace.json.server.json" >/dev/null
            elif [[ $NATIVE_TRACE == 1 ]]; then
                /usr/bin/jq -e '.diagnostic_only == true and .run_succeeded == true
                    and .valid == true and .overflow == false and (.events | length) > 0
                    and .wall_clock == "CLOCK_MONOTONIC"
                    and .cpu_clock == "CLOCK_THREAD_CPUTIME_ID"' \
                    "$candidate_dir/native-stage-trace.json" >/dev/null
            elif [[ $REACTOR_TRACE == 1 ]]; then
                /usr/bin/jq -e '.schema_version == 1
                    and .protocol == "everudp-reactor-work-v1"
                    and .diagnostic_only == true and .run_succeeded == true
                    and .valid == true and .overflow == false and (.events | length) > 0
                    and .wall_clock == "CLOCK_MONOTONIC"
                    and .cpu_clock == "CLOCK_THREAD_CPUTIME_ID"' \
                    "$candidate_dir/reactor-work-trace.json" >/dev/null
            elif [[ $PARTITION_TRACE == 1 ]]; then
                /usr/bin/jq -e '.schema_version == 2
                    and .protocol == "everudp-reactor-partitions-v2"
                    and .diagnostic_only == true and .run_succeeded == true
                    and .valid == true and .overflow == false and (.events | length) > 0
                    and .wall_clock == "CLOCK_MONOTONIC"
                    and .cpu_clock == "CLOCK_THREAD_CPUTIME_ID"' \
                    "$candidate_dir/reactor-partition-trace.json" >/dev/null
            fi
            ;;
        everudp)
            mkdir -p "$candidate_dir/client-state"
            chown -R "$RUN_USER" "$candidate_dir/client-state"
            local path_trace_args=()
            if [[ $PATH_TRACE == 1 ]]; then
                path_trace_args=("EVERUDP_CLIENT_PATH_TRACE=$candidate_dir/client-path-trace.json")
            fi
            if [[ $IO_TRACE == 1 ]]; then
                path_trace_args+=("EVERUDP_PATH_IO_TRACE=1")
            fi
            run_candidate "$label" /usr/bin/env \
                -u EVERUDP_CLIENT_PATH_TRACE \
                -u EVERUDP_PATH_IO_TRACE \
                "${path_trace_args[@]}" \
                EVERSH_STATE_DIR="$candidate_dir/client-state" TERM=xterm-256color \
                "$EVERUDP_BIN" --remote-program "$TMP/remote-everudp/remote-everudp" \
                connect target --session "$session" \
                --ssh-option "-F$TMP/client_config" \
                --status-file "$candidate_dir/status.log" -- "$PTY_ECHO"
            ;;
        zmosh-udp)
            mkdir -p "$candidate_dir/client-state"
            chown -R "$RUN_USER" "$candidate_dir/client-state"
            run_candidate "$label" /usr/bin/env \
                EVERUDP_BENCH_SSH_CONFIG="$TMP/client_config" \
                ZMX_DIR="$candidate_dir/client-state" \
                ZMOSH_REMOTE_BIN="$TMP/remote-zmosh-udp/remote-zmosh" \
                TERM=xterm-256color PATH="$TMP/client-bin:/usr/bin:/bin" \
                "$ZMOSH_UDP_BIN" attach -r 10.246.0.1 "$session" "$PTY_ECHO"
            ;;
        zmosh-quic)
            run_candidate "$label" "$NET/launch-zmosh-quic.sh" \
                target 10.246.0.1 "$TMP/client_config" \
                "$TMP/remote-zmosh-quic/remote-zmosh" "$session" "$PTY_ECHO" \
                "$ZMOSH_QUIC_BRIDGE" "$candidate_dir/connect.log" \
                "$candidate_dir/server.stderr"
            ;;
    esac
}

STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ordinal=0
for candidate in "${CANDIDATES[@]}"; do
    ordinal=$((ordinal + 1))
    echo "performance block candidate $ordinal/${#CANDIDATES[@]}: $candidate"
    run_named_candidate "$candidate" "$ordinal"
done
FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
restore_governors
GOVERNORS_CHANGED=0
record_governors after

BUILD_PROVENANCE_SHA=null
if [[ -f $BUILD/provenance.json ]]; then
    BUILD_PROVENANCE_SHA=\"$(sha256sum "$BUILD/provenance.json" | awk '{print $1}')\"
fi
KERNEL=$(uname -srmo)
CPU_MODEL=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1)

/usr/bin/python3 - "$OUTDIR" "$ROOT" "$BUILD" "$HEAD_SHA" "$TREE_SHA" \
    "$DIRTY_JSON" "$TRIALS" "$LOSS" "$BLOCK_SEED" "$ORDER" "$CPU_SET" \
    "$STARTED_UTC" "$FINISHED_UTC" "$KERNEL" "$CPU_MODEL" \
    "$BUILD_PROVENANCE_SHA" "$COUNTER_CAPTURE" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

(
    out_raw, root_raw, build_raw, head, tree, dirty, trials, loss, seed,
    order, cpu_set, started, finished, kernel, cpu_model, provenance_sha, counter_capture,
) = sys.argv[1:]
sys.path.insert(0, str(Path(root_raw) / "crates/everudp/tests/net"))
from packet_accounting import account_packet_attempts
out = Path(out_raw)
build = Path(build_raw)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

candidates = order.split(",")
results = {}
loss_evidence = {}
for name in candidates:
    result_path = out / name / "result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    before_c = out / f"netem-{name}-client-before.txt"
    after_c = out / f"netem-{name}-client-after.txt"
    before_s = out / f"netem-{name}-server-before.txt"
    after_s = out / f"netem-{name}-server-after.txt"
    accounting = account_packet_attempts(*(path.read_text(encoding="utf-8")
        for path in (before_c, after_c, before_s, after_s)))
    client_delta = accounting.client.dropped_packets
    server_delta = accounting.server.dropped_packets
    client_packets = accounting.client.sent_packets
    server_packets = accounting.server.sent_packets
    if int(loss) == 5 and (client_delta == 0 or server_delta == 0):
        raise SystemExit(f"{name} did not observe configured symmetric loss")
    results[name] = {
        "path": f"{name}/result.json",
        "sha256": digest(result_path),
        "samples": len(result["samples_us"]),
        "transcript_failures": result["transcript_failures"],
        "stderr_sha256": digest(out / name / "candidate.stderr"),
        "resources_sha256": digest(out / name / "resources.txt"),
    }
    loss_evidence[name] = {
        "client_egress_drop_delta": client_delta,
        "server_egress_drop_delta": server_delta,
        "client_egress_packet_delta": client_packets,
        "server_egress_packet_delta": server_packets,
        "summed_egress_packet_delta": client_packets + server_packets,
        "summed_egress_attempt_delta": accounting.total_attempts,
        "measurement_window": "post-warmup-start-barrier-to-pre-teardown-finish-barrier",
        "packet_definition": (
            "summed root-netem sent-plus-drop attempts in both directions; "
            "sent-only legacy field excludes netem drops"
        ),
        "receipts": {
            path.name: digest(path)
            for path in (before_c, after_c, before_s, after_s)
        },
    }

artifact_names = ["zmosh-udp", "pty-bench", "pty-echo"]
if "everudp-floor" in candidates:
    artifact_names.append("everudp-floor")
elif "everudp-stream-native" in candidates:
    artifact_names.append("everudp-stream-floor")
else:
    artifact_names.extend(("everudp", "zmosh-quic", "zmosh-quic-bridge"))
artifacts = {
    name: {
        "path": str(build / "artifacts" / "bin" / name),
        "sha256": digest(build / "artifacts" / "bin" / name),
    }
    for name in artifact_names
}

manifest = {
    "schema_version": 1,
    "source": {"head_sha": head, "tree_sha": tree, "dirty": dirty == "true"},
    "build": {
        "path": str(build),
        "provenance_sha256": None if provenance_sha == "null" else provenance_sha.strip('"'),
    },
    "started_utc": started,
    "finished_utc": finished,
    "trials_per_candidate": int(trials),
    "hardware_counter_capture": counter_capture == "1",
    "diagnostic_tracing": (counter_capture == "1" or (out / "everudp-floor/client-trace.json").exists()
                           or (out / "everudp/client-path-trace.json").exists()
                           or (out / "everudp/client-path-trace.json.io.json").exists()
                           or (out / "everudp-floor/native-stage-trace.json").exists()
                           or (out / "everudp-floor/reactor-work-trace.json").exists()
                           or (out / "everudp-floor/reactor-partition-trace.json").exists()),
    "native_stage_tracing": (out / "everudp-floor/native-stage-trace.json").exists(),
    "production_path_tracing": (out / "everudp/client-path-trace.json").exists(),
    "production_io_tracing": (out / "everudp/client-path-trace.json.io.json").exists(),
    "production_packet_tracing": (out / "everudp/client-path-trace.json.packets.json").exists(),
    "reactor_work_tracing": (out / "everudp-floor/reactor-work-trace.json").exists(),
    "reactor_partition_tracing": (out / "everudp-floor/reactor-partition-trace.json").exists(),
    "gap_ms": 100,
    "loss_percent_each_direction": int(loss),
    "seeds": {"client": int(seed), "server": int(seed) + 1_000_003},
    "order": candidates,
    "workload": (
        "rotating printable byte through authenticated reliable QUIC STREAM echo floor; "
        "matched ordinary/native runtime modes; zmosh uses compiled raw remote PTY echo"
        if "everudp-stream-native" in candidates else
        "rotating printable byte through authenticated QUIC DATAGRAM echo floor; "
        "zmosh control uses the compiled raw remote PTY echo fixture"
        if "everudp-floor" in candidates else
        "rotating printable byte through one compiled raw-mode PTY echo process"
    ),
    "timer": "immediately before PTY public send; after exact byte accepted by /dev/null sink",
    "topology": "two isolated Linux network namespaces joined by one veth pair",
    "affinity": cpu_set,
    "governors": {
        phase: {
            "path": f"governors-{phase}.txt",
            "sha256": digest(out / f"governors-{phase}.txt"),
        }
        for phase in ("before", "pinned", "after")
    },
    "host": {"kernel": kernel, "cpu_model": cpu_model},
    "artifacts": artifacts,
    "results": results,
    "loss_evidence": loss_evidence,
}
(out / "manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

(
    cd "$OUTDIR"
    find . -type f ! -name SHA256SUMS -printf '%P\0' \
        | sort -z | xargs -0 sha256sum >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
chown -R "$RUN_USER" "$OUTDIR"
echo "performance block PASS: $OUTDIR"
