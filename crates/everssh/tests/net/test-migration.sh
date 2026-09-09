#!/usr/bin/env bash
# Root-required production-process Slice 4 migration/path-loss gate.
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "everssh migration gate requires root" >&2
    exit 77
fi

ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
BIN="$ROOT/target/debug/everssh"
IP=/usr/bin/ip
TC=/usr/sbin/tc
PY=/usr/bin/python3
DD=/usr/bin/dd
TIMEOUT=/usr/bin/timeout
for tool in "$IP" "$TC" "$PY" "$DD" "$TIMEOUT" /usr/bin/env /usr/bin/cmp /usr/bin/find /usr/bin/stat; do
    [[ -x "$tool" ]] || { echo "missing required tool: $tool" >&2; exit 1; }
done
[[ -x "$BIN" ]] || { echo "missing production binary: $BIN" >&2; exit 1; }
[[ ! "$ROOT/crates/everssh/Cargo.toml" -nt "$BIN" ]] \
    && [[ -z $(/usr/bin/find "$ROOT/crates/everssh/src" -type f -name '*.rs' -newer "$BIN" -print -quit) ]] || {
    echo "stale production binary; run the cargo test gate first" >&2
    exit 1
}
API_BIN=
for candidate in "$ROOT"/target/debug/deps/slice4_api-*; do
    [[ -x "$candidate" ]] || continue
    [[ -z "$API_BIN" || "$candidate" -nt "$API_BIN" ]] && API_BIN=$candidate
done
[[ -n "$API_BIN" && "$API_BIN" -nt "$ROOT/crates/everssh/tests/slice4_api.rs" ]] \
    && [[ ! "$ROOT/crates/everssh/Cargo.toml" -nt "$API_BIN" ]] \
    && [[ -z $(/usr/bin/find "$ROOT/crates/everssh/src" -type f -name '*.rs' -newer "$API_BIN" -print -quit) ]] || {
    echo "missing current slice4_api test binary; run the cargo test gate first" >&2
    exit 1
}

TMP=$(mktemp -d /tmp/everssh-slice4.XXXXXX)
TAG=e$(printf '%04x' $((RANDOM & 65535)))
NS_ALL=()
PID_ALL=()
LINK_ALL=()
CURRENT_S=
CURRENT_C=
CURRENT_TAG=
CLEANED=0

wait_process() {
    local pid=$1 timeout_seconds=$2 deadline state
    deadline=$((SECONDS + timeout_seconds))
    while [[ -e /proc/$pid/stat ]]; do
        state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
        [[ "$state" = Z ]] && return 0
        ((SECONDS < deadline)) || { echo "process $pid exceeded ${timeout_seconds}s" >&2; return 1; }
        sleep 0.05
    done
}

cleanup() {
    local status=$?
    [[ $CLEANED -eq 0 ]] || exit "$status"
    CLEANED=1
    set +e
    trap - EXIT INT TERM HUP
    exec 9>&- || true
    for pid in "${PID_ALL[@]}"; do
        kill -TERM "$pid" 2>/dev/null
    done
    sleep 0.1
    for pid in "${PID_ALL[@]}"; do
        kill -KILL "$pid" 2>/dev/null
        if wait_process "$pid" 2; then
            wait "$pid" 2>/dev/null
        fi
    done
    for ns in "${NS_ALL[@]}"; do
        for dev in c0 c1 s0 s1; do
            "$IP" netns exec "$ns" "$TC" qdisc del dev "$dev" root 2>/dev/null
        done
        mapfile -t pids < <("$IP" netns pids "$ns" 2>/dev/null)
        ((${#pids[@]} == 0)) || kill -KILL "${pids[@]}" 2>/dev/null
    done
    sleep 0.1
    for ns in "${NS_ALL[@]}"; do
        "$IP" netns del "$ns" 2>/dev/null
    done
    for link in "${LINK_ALL[@]}"; do
        "$IP" link del "$link" 2>/dev/null
    done
    rm -rf "$TMP"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

cat >"$TMP/ssh" <<'SH'
#!/bin/sh
query=no
for argument in "$@"; do
    [ "$argument" = "-G" ] && query=yes
done
if [ "$query" = yes ]; then
    printf 'hostname everssh-netns\n'
    exit 0
fi
exec /usr/bin/ip netns exec "$EL_SERVER_NS" /usr/bin/env -i \
    SSH_CONNECTION="$EL_SSH_CONNECTION" "$EL_BIN" __bootstrap-parent-v1
SH
chmod 0700 "$TMP/ssh"

cat >"$TMP/target.py" <<'PY'
import hashlib, os, socket, sys
family, port, ready, report, expected = sys.argv[1:]
af = socket.AF_INET if family == "4" else socket.AF_INET6
host = "127.0.0.1" if family == "4" else "::1"
s = socket.socket(af, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, int(port)))
s.listen(1)
with open(ready, "w", encoding="ascii") as out:
    out.write("ready\n")
c, _ = s.accept()
c.settimeout(400)
data = bytearray()
while True:
    try:
        chunk = c.recv(65536)
    except (ConnectionResetError, TimeoutError, OSError):
        break
    if not chunk:
        break
    data.extend(chunk)
    try:
        c.sendall(chunk)
    except (BrokenPipeError, ConnectionResetError, OSError):
        break
try:
    c.shutdown(socket.SHUT_WR)
except OSError:
    pass
c.close(); s.close()
match = None
if expected != "-":
    with open(expected, "rb") as source:
        match = source.read() == data
with open(report, "w", encoding="ascii") as out:
    out.write(f"accepts=1 bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()} match={match}\n")
PY

cat >"$TMP/frames.py" <<'PY'
import sys
path, count, salt = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
with open(path, "wb") as out:
    for index in range(count):
        frame = bytearray(1024)
        frame[:8] = index.to_bytes(8, "big")
        for offset in range(8, len(frame)):
            frame[offset] = (index * 193 + offset + salt) & 255
        out.write(frame)
PY

wait_path() {
    local path=$1 timeout_seconds=$2 deadline
    deadline=$((SECONDS + timeout_seconds))
    while [[ ! -e "$path" ]]; do
        ((SECONDS < deadline)) || { echo "timeout waiting for $path" >&2; return 1; }
        sleep 0.02
    done
}

write_frames() {
    local frames=$1 skip=$2 count=$3
    "$TIMEOUT" --kill-after=1s 10s "$DD" \
        if="$frames" bs=1024 skip="$skip" count="$count" status=none >&9
}

wait_bytes() {
    local path=$1 wanted=$2 timeout_seconds=$3 deadline size=0
    deadline=$((SECONDS + timeout_seconds))
    while ((size < wanted)); do
        [[ -e "$path" ]] && size=$(/usr/bin/stat -c %s "$path")
        ((SECONDS < deadline)) || {
            echo "timeout waiting for $wanted bytes in $path (got $size)" >&2
            [[ -n ${CURRENT_C:-} ]] && "$IP" netns exec "$CURRENT_C" /usr/bin/ss -uapn >&2 || true
            [[ -n ${CURRENT_S:-} ]] && "$IP" netns exec "$CURRENT_S" /usr/bin/ss -uapn >&2 || true
            [[ -n ${CURRENT_C:-} ]] && "$IP" -s -n "$CURRENT_C" link show >&2 || true
            [[ -n ${CURRENT_S:-} ]] && "$IP" -s -n "$CURRENT_S" link show >&2 || true
            [[ -n ${PROXY_ERROR:-} && -e ${PROXY_ERROR:-} ]] && cat "$PROXY_ERROR" >&2 || true
            return 1
        }
        sleep 0.02
    done
}

assert_namespace_empty() {
    local ns=$1 pids
    pids=$("$IP" netns pids "$ns" 2>/dev/null || true)
    [[ -z "$pids" ]] || { echo "owned processes survived in $ns: $pids" >&2; return 1; }
}

setup_topology() {
    local family=$1 label=$2
    CURRENT_TAG="${TAG}${label}"
    CURRENT_S="${CURRENT_TAG}s"
    CURRENT_C="${CURRENT_TAG}c"
    NS_ALL+=("$CURRENT_S" "$CURRENT_C")
    LINK_ALL+=(
        "${CURRENT_TAG}s0" "${CURRENT_TAG}c0"
        "${CURRENT_TAG}s1" "${CURRENT_TAG}c1"
    )
    "$IP" netns add "$CURRENT_S"
    "$IP" netns add "$CURRENT_C"
    "$IP" link add "${CURRENT_TAG}s0" type veth peer name "${CURRENT_TAG}c0"
    "$IP" link add "${CURRENT_TAG}s1" type veth peer name "${CURRENT_TAG}c1"
    "$IP" link set "${CURRENT_TAG}s0" netns "$CURRENT_S"
    "$IP" link set "${CURRENT_TAG}s1" netns "$CURRENT_S"
    "$IP" link set "${CURRENT_TAG}c0" netns "$CURRENT_C"
    "$IP" link set "${CURRENT_TAG}c1" netns "$CURRENT_C"
    "$IP" -n "$CURRENT_S" link set "${CURRENT_TAG}s0" name s0
    "$IP" -n "$CURRENT_S" link set "${CURRENT_TAG}s1" name s1
    "$IP" -n "$CURRENT_C" link set "${CURRENT_TAG}c0" name c0
    "$IP" -n "$CURRENT_C" link set "${CURRENT_TAG}c1" name c1
    "$IP" -n "$CURRENT_S" link set lo up
    "$IP" -n "$CURRENT_C" link set lo up
    if [[ $family = 4 ]]; then
        "$IP" -n "$CURRENT_S" addr add 10.241.0.1/24 dev s0
        "$IP" -n "$CURRENT_S" addr add 10.241.1.1/24 dev s1
        "$IP" -n "$CURRENT_C" addr add 10.241.0.2/24 dev c0
        "$IP" -n "$CURRENT_C" addr add 10.241.1.2/24 dev c1
    else
        "$IP" -n "$CURRENT_S" -6 addr add fd42:241::1/64 dev s0 nodad
        "$IP" -n "$CURRENT_S" -6 addr add fd42:242::1/64 dev s1 nodad
        "$IP" -n "$CURRENT_C" -6 addr add fd42:241::2/64 dev c0 nodad
        "$IP" -n "$CURRENT_C" -6 addr add fd42:242::2/64 dev c1 nodad
    fi
    "$IP" -n "$CURRENT_S" link set s0 up
    "$IP" -n "$CURRENT_S" link set s1 up
    "$IP" -n "$CURRENT_C" link set c0 up
    "$IP" -n "$CURRENT_C" link set c1 up
}

teardown_topology() {
    for ns in "$CURRENT_C" "$CURRENT_S"; do
        for dev in c0 c1 s0 s1; do
            "$IP" netns exec "$ns" "$TC" qdisc del dev "$dev" root 2>/dev/null || true
        done
        local deadline=$((SECONDS + 10))
        while [[ -n $("$IP" netns pids "$ns" 2>/dev/null || true) ]] && ((SECONDS < deadline)); do
            sleep 0.1
        done
        assert_namespace_empty "$ns"
        "$IP" netns del "$ns"
    done
    CURRENT_S= CURRENT_C= CURRENT_TAG=
}

start_target() {
    local family=$1 port=$2 stem=$3 expected=$4
    TARGET_READY="$TMP/$stem.ready"
    TARGET_REPORT="$TMP/$stem.report"
    "$IP" netns exec "$CURRENT_S" "$PY" "$TMP/target.py" \
        "$family" "$port" "$TARGET_READY" "$TARGET_REPORT" "$expected" &
    TARGET_PID=$!
    PID_ALL+=("$TARGET_PID")
    wait_path "$TARGET_READY" 3
}

start_proxy() {
    local family=$1 port=$2 stem=$3 status_file=${4-}
    PROXY_FIFO="$TMP/$stem.fifo"
    PROXY_OUTPUT="$TMP/$stem.out"
    PROXY_ERROR="$TMP/$stem.err"
    PROXY_STATUS=${status_file:-}
    local -a status_args=()
    if [[ -n $status_file ]]; then
        : >"$status_file"
        status_args=(--status-file "$status_file")
    fi
    mkfifo "$PROXY_FIFO"
    exec 9<>"$PROXY_FIFO"
    local ssh_connection
    if [[ $family = 4 ]]; then
        ssh_connection="10.241.0.2 50000 10.241.0.1 $port"
    else
        ssh_connection="fd42:241::2 50000 fd42:241::1 $port"
    fi
    "$IP" netns exec "$CURRENT_C" /usr/bin/env \
        PATH="$TMP:/usr/bin:/bin" EL_SERVER_NS="$CURRENT_S" \
        EL_SSH_CONNECTION="$ssh_connection" EL_BIN="$BIN" \
        "$BIN" ssh-proxy alias "$port" \
        "${status_args[@]}" \
        <"$PROXY_FIFO" >"$PROXY_OUTPUT" 2>"$PROXY_ERROR" 9>&- &
    PROXY_PID=$!
    PID_ALL+=("$PROXY_PID")
    sleep 0.2
    kill -0 "$PROXY_PID"
}

finish_normal_proxy() {
    local frames=$1
    exec 9>&-
    wait_process "$PROXY_PID" 15
    wait_process "$TARGET_PID" 15
    set +e
    wait "$PROXY_PID"
    local proxy_status=$?
    wait "$TARGET_PID"
    local target_status=$?
    set -e
    [[ $proxy_status -eq 0 ]] || { cat "$PROXY_ERROR" >&2; echo "proxy failed: $proxy_status" >&2; return 1; }
    [[ $target_status -eq 0 ]] || { echo "target failed: $target_status" >&2; return 1; }
    [[ ! -s "$PROXY_ERROR" ]] || { cat "$PROXY_ERROR" >&2; return 1; }
    /usr/bin/cmp "$frames" "$PROXY_OUTPUT" || {
        echo "resume output mismatch: expected=$(stat -c %s "$frames") actual=$(stat -c %s "$PROXY_OUTPUT")" >&2
        return 1
    }
    grep -q 'accepts=1 .* match=True' "$TARGET_REPORT" || {
        echo "resume target report mismatch: $(cat "$TARGET_REPORT")" >&2
        return 1
    }
}

run_api_source_migration() {
    local family=$1 label=$2
    local stem=api$family shared="$TMP/api$family"
    setup_topology "$family" "$label"
    mkdir -m 0700 "$shared"

    "$IP" netns exec "$CURRENT_S" /usr/bin/env \
        EVERSSH_SLICE4_API_ROLE=server EVERSSH_SLICE4_API_FAMILY="$family" \
        EVERSSH_SLICE4_API_DIR="$shared" \
        "$API_BIN" --exact netns_api_server_helper --nocapture \
        >"$TMP/$stem.server.log" 2>&1 &
    local server_pid=$!
    PID_ALL+=("$server_pid")
    wait_path "$shared/bootstrap" 5

    "$IP" netns exec "$CURRENT_C" /usr/bin/env \
        EVERSSH_SLICE4_API_ROLE=client EVERSSH_SLICE4_API_FAMILY="$family" \
        EVERSSH_SLICE4_API_DIR="$shared" \
        "$API_BIN" --exact netns_api_client_helper --nocapture \
        >"$TMP/$stem.client.log" 2>&1 &
    local client_pid=$!
    PID_ALL+=("$client_pid")
    wait_path "$shared/old-route-ready" 8
    kill -STOP "$client_pid"
    if [[ $family = 4 ]]; then
        "$IP" -n "$CURRENT_C" addr del 10.241.0.2/24 dev c0
        "$IP" -n "$CURRENT_C" route replace 10.241.0.1/32 via 10.241.1.1 dev c1 src 10.241.1.2
        "$IP" -n "$CURRENT_C" route get 10.241.0.1 | grep -q 'dev c1 .*src 10.241.1.2'
    else
        "$IP" -n "$CURRENT_C" -6 addr del fd42:241::2/64 dev c0
        "$IP" -n "$CURRENT_C" -6 route replace fd42:241::1/128 via fd42:242::1 dev c1 src fd42:242::2
        "$IP" -n "$CURRENT_C" -6 route get fd42:241::1 | grep -q 'dev c1 .*src fd42:242::2'
    fi
    sleep 0.7
    kill -CONT "$client_pid"
    printf 'changed\n' >"$shared/route-changed"

    if ! wait_process "$client_pid" 30; then
        cat "$TMP/$stem.client.log" "$TMP/$stem.server.log" >&2
        return 1
    fi
    if ! wait_process "$server_pid" 30; then
        cat "$TMP/$stem.client.log" "$TMP/$stem.server.log" >&2
        return 1
    fi
    set +e
    wait "$client_pid"
    local client_status=$?
    wait "$server_pid"
    local server_status=$?
    set -e
    if [[ $client_status -ne 0 || $server_status -ne 0 ]]; then
        cat "$TMP/$stem.client.log" "$TMP/$stem.server.log" >&2
        echo "IPv$family API migration failed: client=$client_status server=$server_status" >&2
        return 1
    fi
    grep -q 'stable_id=.* rebinds=1 .* frames=400' "$shared/client-report"
    grep -q '^frames=400 target_closed=true$' "$shared/server-report"
    teardown_topology
    echo "everssh IPv$family API source-address migration: PASS"
}

run_migration() {
    local family=$1 label=$2 port=$3
    local stem=migrate$family frames="$TMP/migrate$family.frames"
    setup_topology "$family" "$label"
    "$PY" "$TMP/frames.py" "$frames" 600 "$family"
    start_target "$family" "$port" "$stem" "$frames"
    start_proxy "$family" "$port" "$stem"

    write_frames "$frames" 0 150
    wait_bytes "$PROXY_OUTPUT" $((150 * 1024)) 8

    "$IP" netns exec "$CURRENT_C" "$TC" qdisc replace dev c0 root netem \
        delay 20ms 5ms 25% duplicate 2% reorder 5% 50%
    write_frames "$frames" 150 50
    wait_bytes "$PROXY_OUTPUT" $((200 * 1024)) 8
    # Queue a few old-path packets long enough that they become stale after
    # rebind; duplication/reordering remains below QUIC, not in the framing.
    "$IP" netns exec "$CURRENT_C" "$TC" qdisc replace dev c0 root netem \
        delay 1200ms 40ms 25% duplicate 12% reorder 20% 50%
    write_frames "$frames" 200 4
    kill -STOP "$PROXY_PID"
    if [[ $family = 4 ]]; then
        "$IP" -n "$CURRENT_C" addr del 10.241.0.2/24 dev c0
        "$IP" -n "$CURRENT_C" route replace 10.241.0.1/32 via 10.241.1.1 dev c1 src 10.241.1.2
        "$IP" -n "$CURRENT_C" route get 10.241.0.1 | grep -q 'dev c1 .*src 10.241.1.2'
    else
        "$IP" -n "$CURRENT_C" -6 addr del fd42:241::2/64 dev c0
        "$IP" -n "$CURRENT_C" -6 route replace fd42:241::1/128 via fd42:242::1 dev c1 src fd42:242::2
        "$IP" -n "$CURRENT_C" -6 route get fd42:241::1 | grep -q 'dev c1 .*src fd42:242::2'
    fi
    sleep 0.7
    kill -CONT "$PROXY_PID"

    write_frames "$frames" 204 150
    wait_bytes "$PROXY_OUTPUT" $((354 * 1024)) 12
    "$IP" netns exec "$CURRENT_C" "$TC" qdisc replace dev c0 root netem loss 100%
    write_frames "$frames" 354 46
    wait_bytes "$PROXY_OUTPUT" $((400 * 1024)) 8

    "$IP" netns exec "$CURRENT_C" "$TC" qdisc del dev c0 root
    kill -STOP "$PROXY_PID"
    if [[ $family = 4 ]]; then
        "$IP" -n "$CURRENT_C" route del 10.241.0.1/32 2>/dev/null || true
        "$IP" -n "$CURRENT_C" addr del 10.241.1.2/24 dev c1
        "$IP" -n "$CURRENT_C" addr add 10.241.0.2/24 dev c0
        "$IP" -n "$CURRENT_C" route replace 10.241.0.1/32 dev c0 src 10.241.0.2
        "$IP" -n "$CURRENT_C" route get 10.241.0.1 | grep -q 'dev c0 .*src 10.241.0.2'
    else
        "$IP" -n "$CURRENT_C" -6 route del fd42:241::1/128 2>/dev/null || true
        "$IP" -n "$CURRENT_C" -6 addr del fd42:242::2/64 dev c1
        "$IP" -n "$CURRENT_C" -6 addr add fd42:241::2/64 dev c0 nodad
        "$IP" -n "$CURRENT_C" -6 route replace fd42:241::1/128 dev c0 src fd42:241::2
        "$IP" -n "$CURRENT_C" -6 route get fd42:241::1 | grep -q 'dev c0 .*src fd42:241::2'
    fi
    sleep 0.7
    kill -CONT "$PROXY_PID"
    write_frames "$frames" 400 200
    wait_bytes "$PROXY_OUTPUT" $((600 * 1024)) 12
    finish_normal_proxy "$frames"
    teardown_topology
    echo "everssh IPv$family production migration: PASS"
}

run_loss() {
    local mode=$1 label=$2 port=$3
    local stem=$mode frames="$TMP/$mode.frames" status="$TMP/$mode.status"
    setup_topology 4 "$label"
    "$PY" "$TMP/frames.py" "$frames" 64 77
    start_target 4 "$port" "$stem" -
    start_proxy 4 "$port" "$stem" "$status"
    write_frames "$frames" 0 8
    wait_bytes "$PROXY_OUTPUT" $((8 * 1024)) 8

    if [[ $mode = same-route ]]; then
        # The kernel route remains c0/10.241.0.2 while all packets fail. The
        # QUIC read stall is the production path-failure trigger.
        "$IP" netns exec "$CURRENT_C" "$TC" qdisc replace dev c0 root netem loss 100%
        "$IP" -n "$CURRENT_C" route get 10.241.0.1 | grep -q 'dev c0 .*src 10.241.0.2'
    else
        "$IP" -n "$CURRENT_C" link del c0
        "$IP" -n "$CURRENT_C" link del c1
    fi
    write_frames "$frames" 8 32 || true
    # v2 semantics revise the old one-shot contract: sustained loss no longer
    # ends a live association quickly. The proxy must still be reconnecting
    # well past the former 45s termination window; lease-bounded failure is
    # proven at actor scale with tiny configured leases.
    local held_deadline=$((SECONDS + 50))
    while (( SECONDS < held_deadline )); do
        kill -0 "$PROXY_PID" 2>/dev/null || {
            echo "$mode association did not hold through loss" >&2
            cat "$PROXY_ERROR" >&2 || true
            return 1
        }
        sleep 1
    done
    grep -q '^everssh-status-v1 reconnecting$' "$status" || {
        echo "$mode did not publish its reconnecting state" >&2
        return 1
    }
    # The user gives up: end the local association, then the released server,
    # which would otherwise correctly wait out its long renewed lease.
    kill -TERM "$PROXY_PID" 2>/dev/null || true
    wait_process "$PROXY_PID" 10
    local server_pid
    for server_pid in $("$IP" netns pids "$CURRENT_S" 2>/dev/null); do
        [[ $(cat "/proc/$server_pid/comm" 2>/dev/null) == everssh ]] || continue
        kill -TERM "$server_pid" 2>/dev/null || true
    done
    wait_process "$TARGET_PID" 15
    set +e
    wait "$TARGET_PID"
    local target_status=$?
    set -e
    [[ $target_status -eq 0 ]] || { echo "$mode target failed: $target_status" >&2; return 1; }
    grep -q '^accepts=1 ' "$TARGET_REPORT"
    teardown_topology
    echo "everssh $mode sustained association hold: PASS"
}

run_terminal_expiry() {
    local mode=$1 label=$2 port=$3
    local stem="expire-$mode" frames="$TMP/expire-$mode.frames" status="$TMP/expire-$mode.status"
    setup_topology 4 "$label"
    "$PY" "$TMP/frames.py" "$frames" 32 177
    start_target 4 "$port" "$stem" -
    start_proxy 4 "$port" "$stem" "$status"
    write_frames "$frames" 0 8
    wait_bytes "$PROXY_OUTPUT" $((8 * 1024)) 8

    if [[ $mode = same-route ]]; then
        "$IP" netns exec "$CURRENT_C" "$TC" qdisc replace dev c0 root netem loss 100%
        "$IP" -n "$CURRENT_C" route get 10.241.0.1 | grep -q 'dev c0 .*src 10.241.0.2'
    else
        "$IP" -n "$CURRENT_C" link del c0
        "$IP" -n "$CURRENT_C" link del c1
    fi
    write_frames "$frames" 8 24 || true

    # Default-bound expiry: 20s remote stall + 350s reconnect budget, plus
    # close/finalize and observer slack. The proxy must terminate itself.
    wait_process "$PROXY_PID" 400
    exec 9>&-
    # The released server independently waits out its 360s renewed lease from
    # the start of resume acceptance; cover that whole bounded window.
    wait_process "$TARGET_PID" 45
    set +e
    wait "$PROXY_PID"
    local proxy_status=$?
    wait "$TARGET_PID"
    local target_status=$?
    set -e
    [[ $proxy_status -ne 0 ]] || { echo "$mode unexpectedly exited successfully" >&2; return 1; }
    [[ $target_status -eq 0 ]] || { echo "$mode target failed: $target_status" >&2; return 1; }
    grep -q '^everssh-status-v1 reconnecting$' "$status" || {
        echo "$mode did not publish reconnecting before expiry" >&2
        return 1
    }
    grep -q '^everssh-status-v1 cause transport-failure carried=1$' "$status" || {
        echo "$mode did not publish its terminal association failure" >&2
        cat "$status" >&2
        return 1
    }
    grep -q '^accepts=1 ' "$TARGET_REPORT"
    teardown_topology
    echo "everssh $mode default-bound terminal expiry: PASS"
}

run_total_loss_resume() {
    local family=$1 label=$2 port=$3 outage_seconds=${4:-22}
    local stem="resume$family" frames="$TMP/resume$family.frames" status="$TMP/resume$family.status"
    setup_topology "$family" "$label"
    "$PY" "$TMP/frames.py" "$frames" 96 "$family"
    start_target "$family" "$port" "$stem" "$frames"
    start_proxy "$family" "$port" "$stem" "$status"

    write_frames "$frames" 0 24
    wait_bytes "$PROXY_OUTPUT" $((24 * 1024)) 8

    # Kill the only path after a healthy prefix. The 20s remote stall ends
    # connection 1; frames written here remain queued for replay while the
    # bounded client reconnect loop waits out total loss.
    "$IP" netns exec "$CURRENT_C" "$TC" qdisc replace dev c0 root netem loss 100%
    write_frames "$frames" 24 24
    local outage_deadline=$((SECONDS + outage_seconds))
    while (( SECONDS < outage_deadline )); do
        kill -0 "$PROXY_PID" 2>/dev/null || {
            echo "IPv$family association died during the ${outage_seconds}s outage" >&2
            cat "$PROXY_ERROR" >&2 || true
            return 1
        }
        sleep 1
    done
    grep -q '^everssh-status-v1 reconnecting$' "$status" || {
        echo "IPv$family did not publish reconnecting during the outage" >&2
        return 1
    }
    "$IP" netns exec "$CURRENT_C" "$TC" qdisc del dev c0 root

    # The first reconnect attempt is still inside its handshake deadline when
    # the path returns; replay plus new traffic must be byte-exact.
    write_frames "$frames" 48 48
    wait_bytes "$PROXY_OUTPUT" $((96 * 1024)) 15
    finish_normal_proxy "$frames"
    grep -q '^everssh-status-v1 reconnecting$' "$status" || {
        echo "resume status missing reconnecting: $(cat "$status")" >&2
        return 1
    }
    grep -q '^everssh-status-v1 cause clean-close carried=1$' "$status" || {
        echo "resume status missing clean close: $(cat "$status")" >&2
        return 1
    }
    teardown_topology
    echo "everssh IPv$family production total-loss resume: PASS"
}

run_fresh_no_replay() {
    local frames="$TMP/fresh.frames" port=22994
    setup_topology 4 f
    "$PY" "$TMP/frames.py" "$frames" 12 199
    start_target 4 "$port" fresh "$frames"
    start_proxy 4 "$port" fresh
    write_frames "$frames" 0 12
    wait_bytes "$PROXY_OUTPUT" $((12 * 1024)) 8
    finish_normal_proxy "$frames"
    teardown_topology
    echo "everssh fresh connection no-replay boundary: PASS"
}

run_api_source_migration 4 u
# IPv6 is a required supported-host branch, not a silent skip.
[[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6) = 0 ]] || {
    echo "IPv6 is disabled; required IPv6 migration cannot run" >&2
    exit 1
}
run_api_source_migration 6 v
run_migration 4 a 22990
[[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6) = 0 ]] || {
    echo "IPv6 is disabled; required IPv6 migration cannot run" >&2
    exit 1
}
run_migration 6 b 22991
run_loss same-route c 22992
run_loss total-loss d 22993
run_terminal_expiry same-route g 22997
run_terminal_expiry total-loss h 22998
run_total_loss_resume 4 e 22995 302
run_total_loss_resume 6 f 22996
run_fresh_no_replay

echo "everssh Slice 4 production netns/veth gate: PASS"
