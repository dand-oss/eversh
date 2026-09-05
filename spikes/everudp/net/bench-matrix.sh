#!/usr/bin/env bash
# Stage D latency matrix over one isolated netns/veth path.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SPIKE=$ROOT/spikes/everudp/target/release
EVERSSH_BIN=$ROOT/target/release/eversh
ZMOSH_PREFIX=${ZMOSH_PREFIX:-/tmp/zmosh-059-out}
ZMOSH_BIN=${ZMOSH_BIN:-$ZMOSH_PREFIX/bin/zmosh}
ZMOSH_SOURCE_COMMIT=${ZMOSH_SOURCE_COMMIT:-dfc8395b5edcd237bf82712fbde879c6e8be7dfa}
ZMOSH_SOURCE_TREE=${ZMOSH_SOURCE_TREE:-1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514}
TRIALS=${1:?trials}
LOSS=${2:-0}
OUTDIR=${3:-$ROOT/target/qualification/everudp}
DELAY_MS=${4:-0}
REORDER_PCT=${5:-0}
RUN_USER=${SUDO_USER:-$(stat -c %U "$ROOT")}
TIME=/usr/bin/time
TIME_FORMAT=$'user_seconds=%U\nsystem_seconds=%S\nmax_rss_kib=%M\nexit_status=%x'
if (( EUID != 0 )); then
    echo "benchmark matrix requires root network-namespace privileges" >&2
    exit 2
fi
for value in "$TRIALS" "$LOSS" "$DELAY_MS" "$REORDER_PCT"; do
    [[ $value =~ ^[0-9]+$ ]] || { echo "matrix parameters must be nonnegative integers" >&2; exit 2; }
done
if (( TRIALS < 30 )) && [[ ${EVERUDP_ALLOW_SHORT:-0} != 1 ]]; then
    echo "at least 30 trials are required" >&2
    exit 2
fi
(( LOSS <= 100 && REORDER_PCT <= 100 )) || {
    echo "loss and reorder percentages must be at most 100" >&2
    exit 2
}
for executable in "$SPIKE/everudp-spike" "$EVERSSH_BIN" "$ZMOSH_BIN" \
    /usr/bin/mosh-server /usr/bin/mosh-client /usr/bin/ssh /usr/sbin/sshd \
    /usr/bin/python3 /usr/bin/cc /usr/bin/tcpdump "$TIME"; do
    [[ -x $executable ]] || { echo "missing executable: $executable" >&2; exit 1; }
done
for required in "$ZMOSH_PREFIX/include/zmosh/zmosh.h" \
    "$ZMOSH_PREFIX/lib/libzmosh.a" "$NET/zmosh-bench.c" "$NET/echo1.py"; do
    [[ -f $required ]] || { echo "missing input: $required" >&2; exit 1; }
done

run_user() {
    /usr/bin/sudo -n -H -u "$RUN_USER" "$@"
}

HEAD_SHA=$(run_user git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(run_user git -C "$ROOT" rev-parse HEAD^{tree})
DIRTY_STATE=$(run_user git -C "$ROOT" status --porcelain=v1)
if [[ -n $DIRTY_STATE && ${EVERUDP_ALLOW_DIRTY:-0} != 1 ]]; then
    echo "refusing exact-SHA matrix from a dirty worktree" >&2
    exit 1
fi
[[ ! -e $OUTDIR ]] || { echo "refusing to overwrite matrix output: $OUTDIR" >&2; exit 1; }
CELL="loss${LOSS}"
if (( DELAY_MS > 0 )); then
    CELL="$CELL-jitter${DELAY_MS}"
fi
if (( REORDER_PCT > 0 )); then
    CELL="$CELL-reorder${REORDER_PCT}"
fi
mkdir -p "$OUTDIR"
STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TAG=u$((RANDOM & 32767))
SERVER_NS=${TAG}s
CLIENT_NS=${TAG}c
IP=/usr/bin/ip
TC=/usr/sbin/tc
TMP=$(mktemp -d)
chmod 755 "$TMP"
/usr/bin/cc -O3 -Wall -Wextra -Werror -no-pie \
    -I "$ZMOSH_PREFIX/include" "$NET/zmosh-bench.c" \
    "$ZMOSH_PREFIX/lib/libzmosh.a" -o "$TMP/zmosh-bench" -lpthread
SERVER_PID=
cleaned=0
cleanup() {
    (( cleaned )) && return
    cleaned=1
    set +e
    [[ -z $SERVER_PID ]] || kill -KILL "$SERVER_PID" 2>/dev/null
    for ns in "$CLIENT_NS" "$SERVER_NS"; do
        "$IP" netns exec "$ns" "$TC" qdisc del dev c0 root 2>/dev/null
        "$IP" netns exec "$ns" "$TC" qdisc del dev s0 root 2>/dev/null
        "$IP" netns pids "$ns" 2>/dev/null | xargs -r kill -KILL 2>/dev/null
        "$IP" netns del "$ns" 2>/dev/null
    done
    "$IP" link del "${TAG}c" 2>/dev/null
    rm -rf -- "$TMP"
}
trap cleanup EXIT

$IP netns add "$SERVER_NS"
$IP netns add "$CLIENT_NS"
$IP link add "${TAG}s" type veth peer name "${TAG}c"
$IP link set "${TAG}s" netns "$SERVER_NS"
$IP link set "${TAG}c" netns "$CLIENT_NS"
$IP -n "$SERVER_NS" link set "${TAG}s" name s0
$IP -n "$CLIENT_NS" link set "${TAG}c" name c0
$IP -n "$SERVER_NS" link set lo up
$IP -n "$CLIENT_NS" link set lo up
$IP -n "$SERVER_NS" addr add 10.241.0.1/24 dev s0
$IP -n "$CLIENT_NS" addr add 10.241.0.2/24 dev c0
$IP -n "$SERVER_NS" link set s0 up
$IP -n "$CLIENT_NS" link set c0 up

$IP -j -n "$CLIENT_NS" address show >"$OUTDIR/topology-client-addresses.json"
$IP -j -n "$SERVER_NS" address show >"$OUTDIR/topology-server-addresses.json"
$IP -j -n "$CLIENT_NS" route show table all >"$OUTDIR/topology-client-routes.json"
$IP -j -n "$SERVER_NS" route show table all >"$OUTDIR/topology-server-routes.json"

CLIENT_SEED=$((9015 + LOSS * 1000 + DELAY_MS * 10 + REORDER_PCT))
SERVER_SEED=$((CLIENT_SEED + 1000003))

candidate_begin() {
    local label=$1
    local delay_arg=() reorder_arg=() seed_arg=()
    if (( DELAY_MS > 0 )); then
        delay_arg=(delay "${DELAY_MS}ms" 5ms)
    elif (( REORDER_PCT > 0 )); then
        delay_arg=(delay 1ms)
    fi
    (( REORDER_PCT == 0 )) || reorder_arg=(reorder "${REORDER_PCT}%")
    (( LOSS == 0 )) || seed_arg=(seed "$CLIENT_SEED")
    $IP netns exec "$CLIENT_NS" $TC qdisc replace dev c0 root netem \
        loss random "${LOSS}%" "${seed_arg[@]}" "${delay_arg[@]}" "${reorder_arg[@]}"
    (( LOSS == 0 )) || seed_arg=(seed "$SERVER_SEED")
    $IP netns exec "$SERVER_NS" $TC qdisc replace dev s0 root netem \
        loss random "${LOSS}%" "${seed_arg[@]}" "${delay_arg[@]}" "${reorder_arg[@]}"
    $IP netns exec "$CLIENT_NS" $TC -s qdisc show dev c0 \
        | sed 's/[[:space:]]*$//' >"$OUTDIR/netem-$label-client-before.txt"
    $IP netns exec "$SERVER_NS" $TC -s qdisc show dev s0 \
        | sed 's/[[:space:]]*$//' >"$OUTDIR/netem-$label-server-before.txt"
    $IP -s -j -n "$CLIENT_NS" link show dev c0 >"$OUTDIR/network-$label-client-before.json"
    $IP -s -j -n "$SERVER_NS" link show dev s0 >"$OUTDIR/network-$label-server-before.json"
}

candidate_end() {
    local label=$1
    $IP netns exec "$CLIENT_NS" $TC -s qdisc show dev c0 \
        | sed 's/[[:space:]]*$//' >"$OUTDIR/netem-$label-client-after.txt"
    $IP netns exec "$SERVER_NS" $TC -s qdisc show dev s0 \
        | sed 's/[[:space:]]*$//' >"$OUTDIR/netem-$label-server-after.txt"
    $IP -s -j -n "$CLIENT_NS" link show dev c0 >"$OUTDIR/network-$label-client-after.json"
    $IP -s -j -n "$SERVER_NS" link show dev s0 >"$OUTDIR/network-$label-server-after.json"
}

clear_impairment() {
    $IP netns exec "$CLIENT_NS" $TC qdisc del dev c0 root 2>/dev/null || true
    $IP netns exec "$SERVER_NS" $TC qdisc del dev s0 root 2>/dev/null || true
}

wait_for_ready() {
    local label=$1 pid=$2 ready=$3
    for _ in $(seq 1 6000); do
        [[ ! -s $ready ]] || return 0
        if ! kill -0 "$pid" 2>/dev/null; then
            set +e
            wait "$pid"
            local code=$?
            set -e
            echo "$label exited before its measurement barrier (status $code)" >&2
            return 1
        fi
        sleep 0.01
    done
    echo "$label did not reach its measurement barrier" >&2
    return 1
}

snapshot_process() {
    local label=$1 phase=$2 pid=$3
    [[ -r /proc/$pid/status && -r /proc/$pid/stat ]] || {
        echo "process $pid disappeared before $label $phase snapshot" >&2
        return 1
    }
    {
        printf 'pid=%s\n' "$pid"
        sed -n -E '/^(Name|VmPeak|VmHWM|VmRSS|Threads):/p' "/proc/$pid/status"
        awk '{printf "user_ticks=%s\nsystem_ticks=%s\n", $14, $15}' "/proc/$pid/stat"
    } >"$OUTDIR/resource-$label-server-$phase.txt"
}

ssh-keygen -q -t ed25519 -N '' -f "$TMP/host" >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$TMP/client" >/dev/null
cp "$TMP/client.pub" "$TMP/authorized_keys"
chmod 644 "$TMP/authorized_keys"
PORT=${EVERUDP_SSH_PORT:-22}
[[ $PORT =~ ^[0-9]+$ ]] && (( PORT > 0 && PORT <= 65535 )) || {
    echo "invalid EVERUDP_SSH_PORT" >&2
    exit 2
}
cat >"$TMP/sshd_config" <<EOF
Port $PORT
ListenAddress 10.241.0.1
ListenAddress 127.0.0.1
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
AcceptEnv EVERSSH_DEBUG_SERVER
LogLevel ERROR
EOF
$IP netns exec "$SERVER_NS" /usr/sbin/sshd -D -e -f "$TMP/sshd_config" 2>"$TMP/sshd.err" &
SERVER_PID=$!
for _ in $(seq 1 50); do
    $IP netns exec "$CLIENT_NS" /usr/bin/ssh-keyscan -T 1 -p "$PORT" 10.241.0.1 >"$TMP/known" 2>/dev/null || true
    grep -q ssh-ed25519 "$TMP/known" && break
    sleep 0.1
done
grep -q ssh-ed25519 "$TMP/known" || { cat "$TMP/sshd.err" >&2; exit 1; }
cat >"$TMP/client_config" <<EOF
Host bench 10.241.0.1
    HostName 10.241.0.1
    Port $PORT
    User $USER
    IdentityFile $TMP/client
    IdentitiesOnly yes
    UserKnownHostsFile $TMP/known
    GlobalKnownHostsFile /dev/null
    StrictHostKeyChecking yes
    HostKeyAlgorithms ssh-ed25519
    BatchMode yes
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PreferredAuthentications publickey
    ConnectTimeout 30
    ConnectionAttempts 1
    ControlMaster no
    ControlPath none
    ControlPersist no
    ClearAllForwardings yes
    ForwardAgent no
    ForwardX11 no
    Tunnel no
    ServerAliveInterval 60
    ServerAliveCountMax 12
    UpdateHostKeys no
    ProxyCommand none
    ProxyJump none
    RequestTTY auto
    SendEnv EVERSSH_DEBUG_SERVER
EOF

run_ssh_control() {
    local mode=$1
    local ready="$TMP/$mode.ready" go="$TMP/$mode.go"
    local remote_command="/bin/sh -c 'printf EVERUDP_READY; stty raw -echo; exec /usr/bin/python3 -u $NET/echo1.py'"
    local command=(ssh -F "$TMP/client_config" -tt bench "$remote_command")
    if [[ $mode == everssh ]]; then
        command=(
            "$EVERSSH_BIN" ssh
            --remote-eversh "$EVERSSH_BIN"
            bench -- "-F$TMP/client_config" -tt -- "$remote_command"
        )
    fi
    clear_impairment
    $IP netns exec "$CLIENT_NS" /usr/bin/env \
        EVERUDP_BENCH_READY_FILE="$ready" EVERUDP_BENCH_GO_FILE="$go" \
        "$TIME" -f "$TIME_FORMAT" \
        -o "$OUTDIR/resource-$mode-client.txt" \
        /usr/bin/python3 "$NET/drive-ssh.py" \
        "$OUTDIR/${mode}-${CELL}.json" "$TRIALS" 0.10 \
        "${command[@]}" 2>"$OUTDIR/$mode-client.stderr" &
    local client_pid=$!
    wait_for_ready "$mode" "$client_pid" "$ready"
    candidate_begin "$mode"
    snapshot_process "$mode" before "$SERVER_PID"
    touch "$go"
    wait "$client_pid"
    snapshot_process "$mode" after "$SERVER_PID"
    candidate_end "$mode"
    python3 - "$OUTDIR/${mode}-${CELL}.json" "$TRIALS" <<'PY'
import json, math, sys
path = sys.argv[1]
expected = int(sys.argv[2])
events = json.load(open(path, encoding="utf-8"))
if not isinstance(events, list) or len(events) != expected:
    raise SystemExit(f"expected {expected} events, got {len(events) if isinstance(events, list) else 'invalid'}")
samples = sorted((e["echo_t"] - e["t"]) // 1000 for e in events if e.get("echo_t"))
if len(samples) != expected or any(value <= 0 for value in samples):
    raise SystemExit(f"expected {expected} positive samples, got {len(samples)}")
def pick(q):
    return samples[max(0, math.ceil(q * len(samples)) - 1)]
json.dump({
    "schema_version": 1,
    "summary": {
        "trials": len(events),
        "nonzero": len(samples),
        "median_us": pick(0.5),
        "p95_us": pick(0.95),
        "max_us": samples[-1] if samples else 0,
    },
    "events": events,
    "samples": samples,
}, open(path, "w", encoding="utf-8"), separators=(",", ":"))
with open(path, "a", encoding="utf-8") as stream:
    stream.write("\n")
PY
}

run_everudp_udp() {
    local prediction=$1
    local label="everudp-udp-$([[ $prediction == on ]] && echo pred || echo nopred)"
    local name="$label-$CELL"
    local ready="$TMP/$label.ready" go="$TMP/$label.go"
    clear_impairment
    $IP netns exec "$SERVER_NS" "$SPIKE/everudp-spike" udp-pty-server \
        --bind 10.241.0.1:60200 --key-hex 62bc8275e2d0fa1d11abb04d07d7e47731c70879c2d343bc47deb577df13ee7d \
        --echo-command "/usr/bin/python3 -u $NET/echo1.py" \
        >"$OUTDIR/$label-server.stdout" 2>"$OUTDIR/$label-server.stderr" &
    local udp_server=$!
    SERVER_PID=$udp_server
    sleep 0.3
    kill -0 "$udp_server" 2>/dev/null || { cat "$OUTDIR/$label-server.stderr" >&2; exit 1; }
    $IP netns exec "$CLIENT_NS" /usr/bin/env \
        EVERUDP_BENCH_READY_FILE="$ready" EVERUDP_BENCH_GO_FILE="$go" \
        "$TIME" -f "$TIME_FORMAT" -o "$OUTDIR/resource-$label-client.txt" \
        "$SPIKE/everudp-spike" bench \
        --transport udp --prediction "$prediction" --trials "$TRIALS" \
        --server 10.241.0.1:60200 >"$OUTDIR/$name.json" \
        2>"$OUTDIR/$name.err" &
    local client_pid=$!
    wait_for_ready "$label" "$client_pid" "$ready"
    candidate_begin "$label"
    snapshot_process "$label" before "$udp_server"
    touch "$go"
    wait "$client_pid"
    candidate_end "$label"
    kill "$udp_server" 2>/dev/null || true
    wait "$udp_server" 2>/dev/null || true
    SERVER_PID=
}

run_everudp_quic() {
    local prediction=$1
    local label="everudp-quic-$([[ $prediction == on ]] && echo pred || echo nopred)"
    local name="$label-$CELL"
    local ready="$TMP/$label.ready" go="$TMP/$label.go"
    clear_impairment
    $IP netns exec "$SERVER_NS" "$SPIKE/everudp-spike" quic-pty-server \
        --bind 10.241.0.1:60201 \
        --echo-command "/usr/bin/python3 -u $NET/echo1.py" \
        >"$OUTDIR/$label-server.stdout" 2>"$OUTDIR/$label-server.stderr" &
    local quic_server=$!
    SERVER_PID=$quic_server
    for _ in $(seq 1 30); do
        grep -q '^spki=' "$OUTDIR/$label-server.stdout" && break
        sleep 0.1
    done
    local spki
    spki=$(sed -n 's/^spki=//p' "$OUTDIR/$label-server.stdout")
    [[ ${#spki} == 64 ]] || { cat "$OUTDIR/$label-server.stderr" >&2; exit 1; }
    $IP netns exec "$CLIENT_NS" /usr/bin/env \
        EVERUDP_BENCH_READY_FILE="$ready" EVERUDP_BENCH_GO_FILE="$go" \
        "$TIME" -f "$TIME_FORMAT" -o "$OUTDIR/resource-$label-client.txt" \
        "$SPIKE/everudp-spike" bench \
        --transport quic --prediction "$prediction" --trials "$TRIALS" \
        --server 10.241.0.1:60201 --spki-hex "$spki" \
        >"$OUTDIR/$name.json" 2>"$OUTDIR/$name.err" &
    local client_pid=$!
    wait_for_ready "$label" "$client_pid" "$ready"
    candidate_begin "$label"
    snapshot_process "$label" before "$quic_server"
    touch "$go"
    wait "$client_pid"
    candidate_end "$label"
    kill "$quic_server" 2>/dev/null || true
    wait "$quic_server" 2>/dev/null || true
    SERVER_PID=
}

run_mosh() {
    local label=mosh
    local out="$OUTDIR/mosh-$CELL.json"
    local port=60100
    local ready="$TMP/mosh.ready" go="$TMP/mosh.go"
    local mosh_output
    clear_impairment
    mosh_output=$($IP netns exec "$SERVER_NS" mosh-server new -p $port \
        -- /usr/bin/python3 -u "$NET/echo1.py" 2>"$OUTDIR/mosh-server.stderr")
    read -r _ _ actual_port key <<<"$mosh_output"
    [[ -n ${key:-} ]] || { cat "$OUTDIR/mosh-server.stderr" >&2; exit 1; }
    $IP netns exec "$CLIENT_NS" /usr/bin/tcpdump -i c0 -nn -U \
        -w "$OUTDIR/mosh.pcap" "udp port $actual_port" \
        2>"$OUTDIR/mosh-tcpdump.stderr" &
    local tdump=$!
    sleep 0.3
    MOSH_BENCH_KEY=$key $IP netns exec "$CLIENT_NS" /usr/bin/env \
        EVERUDP_BENCH_READY_FILE="$ready" EVERUDP_BENCH_GO_FILE="$go" \
        "$TIME" -f "$TIME_FORMAT" \
        -o "$OUTDIR/resource-mosh-client.txt" \
        /usr/bin/python3 "$NET/drive-mosh.py" \
        "$actual_port" - "$TRIALS" "$OUTDIR/mosh-events.json" \
        0.10 10.241.0.1 2>"$OUTDIR/mosh-client.stderr" &
    local client_pid=$!
    wait_for_ready "$label" "$client_pid" "$ready"
    candidate_begin "$label"
    touch "$go"
    wait "$client_pid"
    sleep 0.2
    candidate_end "$label"
    kill "$tdump" 2>/dev/null || true
    wait "$tdump" 2>/dev/null || true
    python3 "$NET/parse-pcap.py" "$OUTDIR/mosh.pcap" \
        "$OUTDIR/mosh-events.json" "$out" "$actual_port"
    local pid cmdline
    while read -r pid; do
        [[ -r /proc/$pid/cmdline ]] || continue
        cmdline=$(tr '\0' ' ' <"/proc/$pid/cmdline")
        if [[ $cmdline == *mosh-server* && $cmdline == *"$actual_port"* ]]; then
            kill "$pid" 2>/dev/null || true
        fi
    done < <($IP netns pids "$SERVER_NS")
}

run_zmosh() {
    local label=zmosh
    local out="$OUTDIR/zmosh-$CELL.json"
    local zdir="$TMP/zmx"
    local ready="$TMP/zmosh.ready" go="$TMP/zmosh.go"
    mkdir -p "$zdir"
    clear_impairment
    $IP netns exec "$SERVER_NS" /usr/bin/env \
        -u ZMX_SESSION TERM=xterm-256color ZMX_DIR="$zdir" \
        "$ZMOSH_BIN" run everudp-zmosh \
        /usr/bin/python3 -u "$NET/echo1.py" >/dev/null
    sleep 0.3
    $IP netns exec "$SERVER_NS" /usr/bin/env \
        -u ZMX_SESSION TERM=xterm-256color ZMX_DIR="$zdir" \
        "$ZMOSH_BIN" serve everudp-zmosh \
        >"$TMP/zmosh-connect.txt" 2>"$OUTDIR/zmosh-server.stderr" &
    local zserve=$!
    for _ in $(seq 1 50); do
        grep -q '^ZMX_CONNECT' "$TMP/zmosh-connect.txt" && break
        sleep 0.1
    done
    read -r _ _ zport zkey <"$TMP/zmosh-connect.txt"
    [[ -n ${zkey:-} ]] || { cat "$OUTDIR/zmosh-server.stderr" >&2; exit 1; }
    ZMOSH_BENCH_KEY=$zkey $IP netns exec "$CLIENT_NS" /usr/bin/env \
        EVERUDP_BENCH_READY_FILE="$ready" EVERUDP_BENCH_GO_FILE="$go" \
        "$TIME" -f "$TIME_FORMAT" \
        -o "$OUTDIR/resource-zmosh-client.txt" \
        "$TMP/zmosh-bench" 10.241.0.1 "$zport" - "$TRIALS" 100 \
        >"$TMP/zmosh-samples.json" 2>"$OUTDIR/zmosh-client.stderr" &
    local client_pid=$!
    wait_for_ready "$label" "$client_pid" "$ready"
    candidate_begin "$label"
    touch "$go"
    wait "$client_pid"
    local samples
    samples=$(<"$TMP/zmosh-samples.json")
    candidate_end "$label"
    kill "$zserve" 2>/dev/null || true
    wait "$zserve" 2>/dev/null || true
    python3 - "$out" "$samples" "$TRIALS" <<'PY'
import json, math, sys
out, raw, trials = sys.argv[1], sys.argv[2], int(sys.argv[3])
samples = json.loads(raw)
if len(samples) != trials:
    raise SystemExit(f"expected {trials} samples, got {len(samples)}")
ordered = sorted(value for value in samples if value > 0)
if len(ordered) != trials:
    raise SystemExit(f"expected {trials} positive samples, got {len(ordered)}")
def pick(q):
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]
json.dump({
    "schema_version": 1,
    "summary": {
        "trials": trials,
        "nonzero": len(ordered),
        "median_us": pick(0.5),
        "p95_us": pick(0.95),
        "max_us": ordered[-1] if ordered else 0,
    },
    "samples": samples,
}, open(out, "w", encoding="utf-8"), separators=(",", ":"))
with open(out, "a", encoding="utf-8") as stream:
    stream.write("\n")
PY
    $IP netns exec "$SERVER_NS" /usr/bin/env -u ZMX_SESSION ZMX_DIR="$zdir" \
        "$ZMOSH_BIN" kill everudp-zmosh >/dev/null 2>&1 || true
}

run_ssh_control ssh
run_ssh_control everssh
run_mosh
run_zmosh
run_everudp_udp on
run_everudp_udp off
run_everudp_quic on
run_everudp_quic off
cp "$TMP/sshd.err" "$OUTDIR/sshd.stderr"

FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DIRTY_JSON=false
[[ -z $DIRTY_STATE ]] || DIRTY_JSON=true

python3 - "$OUTDIR" "$CELL" "$TRIALS" <<'PY'
import json
import sys
from pathlib import Path

outdir, cell, expected = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
candidates = (
    "ssh", "everssh", "mosh", "zmosh", "everudp-udp-pred",
    "everudp-udp-nopred", "everudp-quic-pred", "everudp-quic-nopred",
)
for candidate in candidates:
    path = outdir / f"{candidate}-{cell}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    samples = data.get("samples")
    if not isinstance(samples, list) or len(samples) != expected:
        raise SystemExit(f"{path}: expected {expected} raw samples")
    if any(not isinstance(value, (int, float)) or value <= 0 for value in samples):
        raise SystemExit(f"{path}: every sample must be positive")
PY

python3 - "$OUTDIR" "$HEAD_SHA" "$TREE_SHA" "$DIRTY_JSON" \
    "$TRIALS" "$LOSS" "$DELAY_MS" "$REORDER_PCT" "$CELL" \
    "$STARTED_UTC" "$FINISHED_UTC" "$CLIENT_SEED" "$SERVER_SEED" \
    "$SPIKE/everudp-spike" "$EVERSSH_BIN" "$ZMOSH_BIN" "$TMP/zmosh-bench" \
    "$ZMOSH_SOURCE_COMMIT" "$ZMOSH_SOURCE_TREE" <<'PY'
import hashlib
import json
import platform
import sys
from pathlib import Path

(
    outdir_raw, head, tree, dirty_raw, trials, loss, delay, reorder, cell,
    started, finished, client_seed, server_seed, everudp, everssh, zmosh,
    zmosh_bench, zmosh_commit, zmosh_tree,
) = sys.argv[1:]
outdir = Path(outdir_raw)

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

receipt_files = {}
for path in sorted(outdir.iterdir()):
    if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}:
        receipt_files[path.name] = digest(path)

artifacts = {
    "everudp": {"path": everudp, "sha256": digest(everudp)},
    "everssh": {"path": everssh, "sha256": digest(everssh)},
    "zmosh": {
        "path": zmosh,
        "sha256": digest(zmosh),
        "source_commit": zmosh_commit,
        "source_tree": zmosh_tree,
    },
    "zmosh_bench": {
        "source": "spikes/everudp/net/zmosh-bench.c",
        "sha256": digest(zmosh_bench),
    },
    "mosh_client": {"path": "/usr/bin/mosh-client", "sha256": digest("/usr/bin/mosh-client")},
    "mosh_server": {"path": "/usr/bin/mosh-server", "sha256": digest("/usr/bin/mosh-server")},
    "openssh": {"path": "/usr/bin/ssh", "sha256": digest("/usr/bin/ssh")},
}

manifest = {
    "schema_version": 3,
    "source": {"head_sha": head, "tree_sha": tree, "dirty": dirty_raw == "true"},
    "command": [
        "spikes/everudp/net/bench-matrix.sh", int(trials), int(loss),
        str(outdir), int(delay), int(reorder),
    ],
    "started_utc": started,
    "finished_utc": finished,
    "cell": cell,
    "topology": "two Linux network namespaces joined by one veth pair; identical qdisc reset before every candidate",
    "workload": "single printable byte through the same Python echo1.py real-PTY endpoint",
    "quantile": "empirical nearest-rank ceil(p*n)-1",
    "trials_per_candidate": int(trials),
    "inter_trial_ms": {"ssh": 100, "mosh": 100, "zmosh": 100, "everudp": 100},
    "impairment": {
        "symmetric_loss_percent": int(loss),
        "delay_ms": int(delay),
        "delay_jitter_ms": 5 if int(delay) else 0,
        "reorder_percent": int(reorder),
        "client_seed": int(client_seed),
        "server_seed": int(server_seed),
    },
    "candidates": [
        "ssh", "everssh", "mosh", "zmosh", "everudp-udp-pred",
        "everudp-udp-nopred", "everudp-quic-pred", "everudp-quic-nopred",
    ],
    "resource_scope": "GNU time maximum RSS and CPU for each full client process tree; post-association interface byte/packet counters for the impaired trial window on both directions; server point snapshots where a stable PID exists",
    "host": {"kernel": platform.release(), "machine": platform.machine()},
    "artifacts": artifacts,
    "receipt_files": receipt_files,
}
(outdir / "manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

(
    cd "$OUTDIR"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\0' \
        | sort -z | xargs -0 sha256sum >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)

python3 - "$OUTDIR" "$CELL" <<'PY'
import glob, json, sys
outdir, cell = sys.argv[1], sys.argv[2]
for path in sorted(glob.glob(f"{outdir}/*-{cell}.json")):
    try:
        data = json.load(open(path))
    except Exception:
        continue
    summary = data.get("summary") or {
        "median_us": data.get("median_us"),
        "p95_us": data.get("p95_us"),
    }
    print(path, json.dumps(summary))
PY
echo "matrix cell complete: $CELL ($OUTDIR)"
