#!/usr/bin/env bash
# Root-required, full-product everudp reliability gate. OpenSSH is used only
# for bootstrap/recovery; every measured terminal byte travels over QUIC/UDP.
set -Eeuo pipefail

if (( EUID != 0 )); then
    echo "everudp reliability gate requires root" >&2
    exit 77
fi

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
BIN=${EVERUDP_BIN:-$ROOT/target/release/everudp}
OUTDIR=${1:?usage: test-reliability.sh OUTDIR}
OUTDIR=$(realpath -m -- "$OUTDIR")
SMOKE=${EVERUDP_SMOKE:-0}
ONLY=${EVERUDP_ONLY:-}
RUN_USER=${SUDO_USER:-$(stat -c %U "$ROOT")}
RUN_HOME=$(getent passwd "$RUN_USER" | cut -d: -f6)
IP=/usr/bin/ip
TC=/usr/sbin/tc
SS=/usr/bin/ss
PY=/usr/bin/python3
TCPDUMP=/usr/bin/tcpdump
TIMEOUT=/usr/bin/timeout

for tool in "$BIN" "$IP" "$TC" "$SS" "$PY" "$TCPDUMP" "$TIMEOUT" \
    /usr/bin/ssh /usr/bin/ssh-keygen /usr/bin/ssh-keyscan /usr/sbin/sshd \
    /usr/bin/sudo /usr/bin/jq /usr/bin/sha256sum /usr/bin/strace \
    /usr/bin/find /usr/bin/wc; do
    [[ -x $tool ]] || { echo "missing required executable: $tool" >&2; exit 1; }
done
[[ -f $NET/drive-session.py ]] || { echo "missing PTY driver" >&2; exit 1; }
[[ -f $NET/verify-process-traces.py ]] || { echo "missing process-trace verifier" >&2; exit 1; }
[[ $SMOKE == 0 || $SMOKE == 1 ]] || { echo "EVERUDP_SMOKE must be 0 or 1" >&2; exit 2; }
[[ ! -e $OUTDIR ]] || { echo "refusing to overwrite reliability output: $OUTDIR" >&2; exit 1; }

HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(git -C "$ROOT" rev-parse 'HEAD^{tree}')
DIRTY=$(git -C "$ROOT" status --porcelain=v1 --untracked-files=all)
if [[ -n $DIRTY && ${EVERUDP_ALLOW_DIRTY:-0} != 1 ]]; then
    echo "refusing exact-SHA reliability gate from a dirty worktree" >&2
    exit 1
fi

TMP=$(mktemp -d /tmp/everudp-reliability.XXXXXX)
TAG=u$(printf '%04x' $((RANDOM & 65535)))
SERVER_NS=${TAG}s
CLIENT_NS=${TAG}c
SSHD_PID=
DRIVER_PID=
CAPTURE_PID=
GATEWAY_TRACE_PID=
CLIENT_TRACE_PID=
TRACE_BEFORE_GO_UTC=
CLEANED=0
mkdir -p "$OUTDIR" "$OUTDIR/scenarios" "$TMP/server-state"
chmod 0755 "$TMP"
chmod 0700 "$TMP/server-state"
chown -R "$RUN_USER" "$OUTDIR" "$TMP/server-state"

wait_process() {
    local pid=$1 seconds=$2 deadline state
    deadline=$((SECONDS + seconds))
    while [[ -e /proc/$pid/stat ]]; do
        state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
        [[ $state == Z ]] && return 0
        (( SECONDS < deadline )) || return 1
        sleep 0.05
    done
}

cleanup() {
    local status=$?
    (( CLEANED == 0 )) || exit "$status"
    CLEANED=1
    set +e
    trap - EXIT INT TERM HUP
    [[ -z ${CAPTURE_PID:-} ]] || kill -INT "$CAPTURE_PID" 2>/dev/null
    [[ -z ${CLIENT_TRACE_PID:-} ]] || kill -INT "$CLIENT_TRACE_PID" 2>/dev/null
    [[ -z ${GATEWAY_TRACE_PID:-} ]] || kill -INT "$GATEWAY_TRACE_PID" 2>/dev/null
    [[ -z ${DRIVER_PID:-} ]] || kill -TERM "$DRIVER_PID" 2>/dev/null
    [[ -z ${SSHD_PID:-} ]] || kill -TERM "$SSHD_PID" 2>/dev/null
    for ns in "$CLIENT_NS" "$SERVER_NS"; do
        for dev in c0 c1 s0 s1; do
            "$IP" netns exec "$ns" "$TC" qdisc del dev "$dev" root 2>/dev/null
        done
        mapfile -t pids < <("$IP" netns pids "$ns" 2>/dev/null)
        ((${#pids[@]} == 0)) || kill -KILL "${pids[@]}" 2>/dev/null
    done
    sleep 0.1
    "$IP" netns del "$CLIENT_NS" 2>/dev/null
    "$IP" netns del "$SERVER_NS" 2>/dev/null
    rm -rf -- "$TMP"
    if [[ -d $OUTDIR ]] && ! chown -R -- "$RUN_USER" "$OUTDIR"; then
        echo "could not return reliability artifacts to $RUN_USER" >&2
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

wait_path() {
    local path=$1 seconds=$2 deadline
    deadline=$((SECONDS + seconds))
    while [[ ! -e $path ]]; do
        if [[ -n ${DRIVER_PID:-} ]] && ! kill -0 "$DRIVER_PID" 2>/dev/null; then
            wait "$DRIVER_PID" || true
            echo "driver exited before $path" >&2
            [[ -f ${CURRENT_DIR:-}/driver.stderr ]] && tail -n 40 "${CURRENT_DIR}/driver.stderr" >&2
            [[ -f ${CURRENT_DIR:-}/result.json ]] && cat "${CURRENT_DIR}/result.json" >&2
            return 1
        fi
        (( SECONDS < deadline )) || { echo "timeout waiting for $path" >&2; return 1; }
        sleep 0.05
    done
}

trace_is_attached() {
    local tracer_pid=$1 tracee_pid=$2 trace_file=$3 actual_tracer
    kill -0 "$tracer_pid" 2>/dev/null || return 1
    [[ -r /proc/$tracee_pid/status && -s $trace_file ]] || return 1
    actual_tracer=$(awk '$1 == "TracerPid:" { print $2 }' "/proc/$tracee_pid/status")
    [[ $actual_tracer == "$tracer_pid" ]]
}

wait_trace_attached() {
    local label=$1 tracer_pid=$2 tracee_pid=$3 trace_file=$4 deadline
    deadline=$((SECONDS + 10))
    until trace_is_attached "$tracer_pid" "$tracee_pid" "$trace_file"; do
        if ! kill -0 "$tracer_pid" 2>/dev/null; then
            echo "$label tracer exited before attaching to everudp pid $tracee_pid" >&2
            return 1
        fi
        (( SECONDS < deadline )) || {
            echo "$label tracer did not attach to everudp pid $tracee_pid" >&2
            return 1
        }
        sleep 0.02
    done
}

stop_expected_tracer() {
    local label=$1 tracer_pid=$2 stderr_path=$3 stdout_path=$4 status_name=$5
    local wait_status stderr_bytes stdout_bytes
    kill -INT "$tracer_pid" 2>/dev/null || {
        echo "$label tracer could not receive its expected SIGINT shutdown" >&2
        return 1
    }
    if wait "$tracer_pid"; then
        wait_status=0
    else
        wait_status=$?
    fi
    stderr_bytes=$(/usr/bin/wc -c <"$stderr_path")
    stdout_bytes=$(/usr/bin/wc -c <"$stdout_path")
    if (( wait_status != 130 || stderr_bytes != 0 || stdout_bytes != 0 )); then
        echo "$label tracer shutdown was noncanonical: status=$wait_status stderr-bytes=$stderr_bytes stdout-bytes=$stdout_bytes" >&2
        return 1
    fi
    printf -v "$status_name" '%s' "$wait_status"
}

stop_process_traces_at_driver_done() {
    local client_pid gateway_pid client_trace_pid gateway_trace_pid
    local client_status gateway_status driver_done_utc stopped_utc
    client_pid=$(/usr/bin/jq -r '.client_pid' "$CURRENT_DIR/process-trace-phase.json")
    gateway_pid=$(/usr/bin/jq -r '.gateway_pid' "$CURRENT_DIR/process-trace-phase.json")
    client_trace_pid=$CLIENT_TRACE_PID
    gateway_trace_pid=$GATEWAY_TRACE_PID
    trace_is_attached "$client_trace_pid" "$client_pid" \
        "$CURRENT_DIR/client-strace.$client_pid" || {
        echo "client tracer was not attached at driver-done" >&2
        return 1
    }
    trace_is_attached "$gateway_trace_pid" "$gateway_pid" \
        "$CURRENT_DIR/gateway-strace.$gateway_pid" || {
        echo "gateway tracer was not attached at driver-done" >&2
        return 1
    }
    driver_done_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    stop_expected_tracer client "$client_trace_pid" \
        "$CURRENT_DIR/client-strace.stderr" "$CURRENT_DIR/client-strace.stdout" \
        client_status
    CLIENT_TRACE_PID=
    stop_expected_tracer gateway "$gateway_trace_pid" \
        "$CURRENT_DIR/gateway-strace.stderr" "$CURRENT_DIR/gateway-strace.stdout" \
        gateway_status
    GATEWAY_TRACE_PID=
    stopped_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    /usr/bin/jq -n \
        --arg before_go "$TRACE_BEFORE_GO_UTC" \
        --arg driver_done "$driver_done_utc" --arg stopped "$stopped_utc" \
        --argjson client_pid "$client_pid" --argjson gateway_pid "$gateway_pid" \
        --argjson client_tracer "$client_trace_pid" \
        --argjson gateway_tracer "$gateway_trace_pid" \
        --argjson client_status "$client_status" \
        --argjson gateway_status "$gateway_status" \
        '{schema_version: 1,
          window: {begin: "before-control-go", end: "driver-done",
                   attached_before_go_utc: $before_go,
                   attached_at_driver_done_utc: $driver_done,
                   tracers_stopped_utc: $stopped},
          client: {tracee_pid: $client_pid, tracer_pid: $client_tracer,
                   attached_before_go: true, attached_at_driver_done: true,
                   shutdown_signal: "SIGINT", wait_status: $client_status,
                   stderr_bytes: 0, stdout_bytes: 0},
          gateway: {tracee_pid: $gateway_pid, tracer_pid: $gateway_tracer,
                    attached_before_go: true, attached_at_driver_done: true,
                    shutdown_signal: "SIGINT", wait_status: $gateway_status,
                    stderr_bytes: 0, stdout_bytes: 0}}' \
        >"$CURRENT_DIR/process-trace-lifecycle.json"
}

setup_topology() {
    "$IP" netns add "$SERVER_NS"
    "$IP" netns add "$CLIENT_NS"
    "$IP" link add "${TAG}s0" type veth peer name "${TAG}c0"
    "$IP" link add "${TAG}s1" type veth peer name "${TAG}c1"
    "$IP" link set "${TAG}s0" netns "$SERVER_NS"
    "$IP" link set "${TAG}s1" netns "$SERVER_NS"
    "$IP" link set "${TAG}c0" netns "$CLIENT_NS"
    "$IP" link set "${TAG}c1" netns "$CLIENT_NS"
    "$IP" -n "$SERVER_NS" link set "${TAG}s0" name s0
    "$IP" -n "$SERVER_NS" link set "${TAG}s1" name s1
    "$IP" -n "$CLIENT_NS" link set "${TAG}c0" name c0
    "$IP" -n "$CLIENT_NS" link set "${TAG}c1" name c1
    "$IP" -n "$SERVER_NS" link set lo up
    "$IP" -n "$CLIENT_NS" link set lo up
    "$IP" -n "$SERVER_NS" addr add 10.253.0.1/24 dev s0
    "$IP" -n "$CLIENT_NS" addr add 10.253.0.2/24 dev c0
    "$IP" -n "$SERVER_NS" -6 addr add fd42:253::1/64 dev s0 nodad
    "$IP" -n "$CLIENT_NS" -6 addr add fd42:253::2/64 dev c0 nodad
    "$IP" -n "$SERVER_NS" link set s0 up
    "$IP" -n "$CLIENT_NS" link set c0 up
    "$IP" -n "$SERVER_NS" link set s1 up
    "$IP" -n "$CLIENT_NS" link set c1 up
    "$IP" -j -n "$SERVER_NS" address show >"$OUTDIR/topology-server.json"
    "$IP" -j -n "$CLIENT_NS" address show >"$OUTDIR/topology-client.json"
}

setup_ssh() {
    /usr/bin/ssh-keygen -q -t ed25519 -N '' -f "$TMP/host" >/dev/null
    /usr/bin/ssh-keygen -q -t ed25519 -N '' -f "$TMP/client" >/dev/null
    cp "$TMP/client.pub" "$TMP/authorized_keys"
    chmod 0600 "$TMP/client"
    chmod 0644 "$TMP/authorized_keys"
    chown "$RUN_USER" "$TMP/client" "$TMP/client.pub"
    cat >"$TMP/sshd_config" <<EOF
Port 22453
ListenAddress 10.253.0.1
ListenAddress fd42:253::1
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
    cat >"$TMP/remote-everudp" <<EOF
#!/bin/sh
export EVERSH_STATE_DIR='$TMP/server-state'
export PATH='/usr/bin:/bin'
export SHELL='/bin/sh'
exec '$BIN' "\$@"
EOF
    chmod 0755 "$TMP/remote-everudp"
    "$IP" netns exec "$SERVER_NS" /usr/sbin/sshd -D -e -f "$TMP/sshd_config" \
        2>"$OUTDIR/sshd.stderr" &
    SSHD_PID=$!
    local known4="$TMP/known4" known6="$TMP/known6"
    for _ in $(seq 1 100); do
        "$IP" netns exec "$CLIENT_NS" /usr/bin/ssh-keyscan -T 1 -p 22453 \
            10.253.0.1 >"$known4" 2>/dev/null || true
        grep -q ssh-ed25519 "$known4" && break
        sleep 0.05
    done
    grep -q ssh-ed25519 "$known4" || { cat "$OUTDIR/sshd.stderr" >&2; return 1; }
    "$IP" netns exec "$CLIENT_NS" /usr/bin/ssh-keyscan -T 2 -p 22453 \
        fd42:253::1 >"$known6" 2>/dev/null
    grep -q ssh-ed25519 "$known6"
    cat "$known4" "$known6" >"$TMP/known"
    cat >"$TMP/client_config" <<EOF
Host target4
    HostName 10.253.0.1
    AddressFamily inet
    Port 22453
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
Host target6
    HostName fd42:253::1
    AddressFamily inet6
    Port 22453
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
}

clear_netem() {
    "$IP" netns exec "$CLIENT_NS" "$TC" qdisc del dev c0 root 2>/dev/null || true
    "$IP" netns exec "$SERVER_NS" "$TC" qdisc del dev s0 root 2>/dev/null || true
}

apply_netem() {
    local loss=$1 delay=$2 reorder=$3 duplicate=$4 seed=$5
    local delay_args=() reorder_args=() duplicate_args=()
    if (( delay > 0 )); then
        delay_args=(delay "${delay}ms" 5ms)
    elif (( reorder > 0 )); then
        delay_args=(delay 1ms)
    fi
    (( reorder == 0 )) || reorder_args=(reorder "${reorder}%" 50%)
    (( duplicate == 0 )) || duplicate_args=(duplicate "${duplicate}%")
    "$IP" netns exec "$CLIENT_NS" "$TC" qdisc replace dev c0 root netem \
        loss random "${loss}%" seed "$seed" "${delay_args[@]}" \
        "${reorder_args[@]}" "${duplicate_args[@]}"
    "$IP" netns exec "$SERVER_NS" "$TC" qdisc replace dev s0 root netem \
        loss random "${loss}%" seed "$((seed + 100003))" "${delay_args[@]}" \
        "${reorder_args[@]}" "${duplicate_args[@]}"
}

snapshot_network() {
    local phase=$1
    "$IP" netns exec "$CLIENT_NS" "$TC" -s qdisc show dev c0 >"$CURRENT_DIR/netem-client-$phase.txt"
    "$IP" netns exec "$SERVER_NS" "$TC" -s qdisc show dev s0 >"$CURRENT_DIR/netem-server-$phase.txt"
    "$IP" -s -j -n "$CLIENT_NS" link show dev c0 >"$CURRENT_DIR/link-client-$phase.json"
    "$IP" -s -j -n "$SERVER_NS" link show dev s0 >"$CURRENT_DIR/link-server-$phase.json"
}

start_driver() {
    local label=$1 mode=$2 destination=${3:-target4}
    local -a trace_window_args=()
    CURRENT_DIR="$OUTDIR/scenarios/$label"
    mkdir -p "$CURRENT_DIR/control"
    chown -R "$RUN_USER" "$CURRENT_DIR"
    local messages=200
    local client_binary=$BIN
    (( SMOKE == 0 )) || messages=24
    if [[ ${EVERUDP_TRACE_CLIENT:-0} == 1 && ${EVERUDP_TRACE_GATEWAY:-0} == 1 ]]; then
        trace_window_args=(--hold-at-driver-done)
    fi
    "$IP" netns exec "$CLIENT_NS" /usr/bin/sudo -n -H -u "$RUN_USER" \
        /usr/bin/env PYTHONDONTWRITEBYTECODE=1 PATH=/usr/bin:/bin HOME="$RUN_HOME" \
        "$PY" "$NET/drive-session.py" \
        --binary "$client_binary" --remote-program "$TMP/remote-everudp" \
        --ssh-config "$TMP/client_config" --destination "$destination" \
        --session "$label" --mode "$mode" --control-dir "$CURRENT_DIR/control" \
        --status "$CURRENT_DIR/status.log" --transcript "$CURRENT_DIR/transcript.bin" \
        --stderr "$CURRENT_DIR/client.stderr" --result "$CURRENT_DIR/result.json" \
        --messages "$messages" --timeout 2400 "${trace_window_args[@]}" \
        >"$CURRENT_DIR/driver.stdout" 2>"$CURRENT_DIR/driver.stderr" &
    DRIVER_PID=$!
    wait_path "$CURRENT_DIR/control/ready" 40
    local client_pid= gateway_pid= pid command
    if [[ ${EVERUDP_TRACE_CLIENT:-0} == 1 ]]; then
        client_pid=$(<"$CURRENT_DIR/control/client-pid")
        [[ $client_pid =~ ^[1-9][0-9]*$ && -r /proc/$client_pid/status ]] \
            || { echo "could not locate client process" >&2; return 1; }
        /usr/bin/strace -qq -ff -tt -yy \
            -e trace=clone,clone3,fork,vfork,execve,execveat,exit,exit_group,wait4,waitid,kill,tgkill,socket,socketpair,bind,connect,listen,accept,accept4,getsockname,getpeername,shutdown,close,epoll_wait,epoll_pwait,epoll_pwait2,poll,ppoll,select,pselect6 \
            -o "$CURRENT_DIR/client-strace" -p "$client_pid" \
            >"$CURRENT_DIR/client-strace.stdout" 2>"$CURRENT_DIR/client-strace.stderr" &
        CLIENT_TRACE_PID=$!
    fi
    if [[ ${EVERUDP_TRACE_GATEWAY:-0} == 1 ]]; then
        [[ -x /usr/bin/strace ]] || { echo "missing /usr/bin/strace" >&2; return 1; }
        for pid in $("$IP" netns pids "$SERVER_NS"); do
            command=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
            if [[ $command == *"__gateway-v1"* ]]; then
                gateway_pid=$pid
                break
            fi
        done
        [[ -n $gateway_pid ]] || { echo "could not locate gateway process" >&2; return 1; }
        /usr/bin/strace -qq -ff -tt -yy \
            -e trace=clone,clone3,fork,vfork,execve,execveat,exit,exit_group,wait4,waitid,kill,tgkill,socket,socketpair,bind,connect,listen,accept,accept4,getsockname,getpeername,shutdown,close,epoll_wait,epoll_pwait,epoll_pwait2,poll,ppoll,select,pselect6 \
            -o "$CURRENT_DIR/gateway-strace" \
            -p "$gateway_pid" >"$CURRENT_DIR/gateway-strace.stdout" \
            2>"$CURRENT_DIR/gateway-strace.stderr" &
        GATEWAY_TRACE_PID=$!
    fi
    if [[ ${EVERUDP_TRACE_CLIENT:-0} == 1 && ${EVERUDP_TRACE_GATEWAY:-0} == 1 ]]; then
        wait_trace_attached client "$CLIENT_TRACE_PID" "$client_pid" \
            "$CURRENT_DIR/client-strace.$client_pid"
        wait_trace_attached gateway "$GATEWAY_TRACE_PID" "$gateway_pid" \
            "$CURRENT_DIR/gateway-strace.$gateway_pid"
        TRACE_BEFORE_GO_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        /usr/bin/jq -n --argjson client "$client_pid" --argjson gateway "$gateway_pid" \
            '{schema_version: 1, phase: "post-bootstrap-terminal",
              client_pid: $client, gateway_pid: $gateway}' \
            >"$CURRENT_DIR/process-trace-phase.json"
        /usr/bin/grep -E '^(Name|Pid|PPid|NSpid):' "/proc/$client_pid/status" \
            >"$CURRENT_DIR/client-process.txt"
        /usr/bin/grep -E '^(Name|Pid|PPid|NSpid):' "/proc/$gateway_pid/status" \
            >"$CURRENT_DIR/gateway-process.txt"
    fi
    sleep 0.2
}

finish_driver() {
    local timeout_seconds=$1
    if [[ -n ${CLIENT_TRACE_PID:-} || -n ${GATEWAY_TRACE_PID:-} ]]; then
        echo "process tracers must be verified and stopped before finish_driver" >&2
        return 1
    fi
    wait_process "$DRIVER_PID" "$timeout_seconds" || {
        echo "driver $DRIVER_PID exceeded ${timeout_seconds}s" >&2
        return 1
    }
    wait "$DRIVER_PID"
    DRIVER_PID=
    /usr/bin/jq -e '.verdict == "PASS"' "$CURRENT_DIR/result.json" >/dev/null
}

run_stream() {
    local label=$1 loss=$2 delay=$3 reorder=$4 duplicate=$5 destination=${6:-target4}
    start_driver "$label" stream "$destination"
    apply_netem "$loss" "$delay" "$reorder" "$duplicate" "$((900000 + SCENARIO_INDEX * 2003))"
    snapshot_network before
    touch "$CURRENT_DIR/control/go"
    finish_driver 300
    snapshot_network after
    clear_netem
    SCENARIO_INDEX=$((SCENARIO_INDEX + 1))
    echo "everudp reliability $label: PASS"
}

run_outage() {
    local label=$1 seconds=$2
    start_driver "$label" outage target4
    apply_netem 100 0 0 0 "$((910000 + SCENARIO_INDEX * 2003))"
    snapshot_network before
    local began=$(date +%s)
    touch "$CURRENT_DIR/control/go"
    sleep "$seconds"
    local ended=$(date +%s)
    (( ended - began >= seconds ))
    snapshot_network outage
    clear_netem
    touch "$CURRENT_DIR/control/restore"
    finish_driver 180
    "$PY" - "$CURRENT_DIR/result.json" "$seconds" <<'PY'
import json, pathlib, sys
path, seconds = pathlib.Path(sys.argv[1]), int(sys.argv[2])
value = json.loads(path.read_text(encoding="utf-8"))
value["required_outage_seconds"] = seconds
value["observed_outage_seconds"] = seconds
path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
PY
    SCENARIO_INDEX=$((SCENARIO_INDEX + 1))
    echo "everudp reliability $label (${seconds}s): PASS"
}

run_overrun() {
    local label=forced-overrun
    start_driver "$label" overrun target4
    apply_netem 100 0 0 0 930001
    snapshot_network before
    touch "$CURRENT_DIR/control/go"
    wait_path "$CURRENT_DIR/control/burst-done" 120
    snapshot_network overrun
    clear_netem
    touch "$CURRENT_DIR/control/restore"
    finish_driver 180
    SCENARIO_INDEX=$((SCENARIO_INDEX + 1))
    echo "everudp reliability forced overrun: PASS"
}

run_pause() {
    local label=sleep-wake
    start_driver "$label" pause target4
    local client_pid
    client_pid=$(<"$CURRENT_DIR/control/client-pid")
    kill -STOP "$client_pid"
    touch "$CURRENT_DIR/control/go"
    sleep 5
    kill -CONT "$client_pid"
    touch "$CURRENT_DIR/control/restore"
    finish_driver 120
    SCENARIO_INDEX=$((SCENARIO_INDEX + 1))
    echo "everudp reliability sleep/wake: PASS"
}

run_cancel_outage() {
    local label=cancel-outage
    start_driver "$label" cancel target4
    apply_netem 100 0 0 0 925001
    snapshot_network before
    touch "$CURRENT_DIR/control/go"
    finish_driver 60
    clear_netem
    /usr/bin/jq -e \
        '.verdict == "PASS" and .exit_code == 143 and .terminal_restored == true
         and .saw_reconnecting == true and .cancellation_ms <= 3000' \
        "$CURRENT_DIR/result.json" >/dev/null
    SCENARIO_INDEX=$((SCENARIO_INDEX + 1))
    echo "everudp reliability local cancellation during outage: PASS"
}

run_packet_proof() {
    local label=udp-only-proof
    EVERUDP_TRACE_CLIENT=1 EVERUDP_TRACE_GATEWAY=1 start_driver "$label" stream target4
    local client_pid gateway_pid
    client_pid=$(/usr/bin/jq -r '.client_pid' "$CURRENT_DIR/process-trace-phase.json")
    gateway_pid=$(/usr/bin/jq -r '.gateway_pid' "$CURRENT_DIR/process-trace-phase.json")
    "$IP" netns exec "$CLIENT_NS" "$SS" -atupn >"$CURRENT_DIR/client-sockets-after-bootstrap.txt"
    "$IP" netns exec "$SERVER_NS" "$SS" -atupn >"$CURRENT_DIR/gateway-sockets-after-bootstrap.txt"
    if ! grep -Eq "^udp.*pid=$client_pid," "$CURRENT_DIR/client-sockets-after-bootstrap.txt" \
        || ! grep -Eq "^udp.*pid=$gateway_pid," \
            "$CURRENT_DIR/gateway-sockets-after-bootstrap.txt"; then
        echo "post-bootstrap everudp UDP socket identity is missing" >&2
        return 1
    fi
    if grep -Eq "^tcp.*pid=($client_pid|$gateway_pid)," \
        "$CURRENT_DIR/client-sockets-after-bootstrap.txt" \
        "$CURRENT_DIR/gateway-sockets-after-bootstrap.txt"; then
        echo "post-bootstrap everudp process owns a TCP socket" >&2
        return 1
    fi
    "$IP" netns exec "$CLIENT_NS" "$TCPDUMP" --immediate-mode -U -n -i c0 \
        -w "$CURRENT_DIR/terminal.pcap" 'host 10.253.0.1 and (udp or tcp)' \
        >"$CURRENT_DIR/tcpdump.stdout" 2>"$CURRENT_DIR/tcpdump.stderr" &
    CAPTURE_PID=$!
    sleep 0.3
    touch "$CURRENT_DIR/control/go"
    wait_path "$CURRENT_DIR/control/driver-done" 180
    stop_process_traces_at_driver_done
    touch "$CURRENT_DIR/control/trace-window-verified"
    sleep 0.3
    kill -INT "$CAPTURE_PID"
    wait "$CAPTURE_PID" || true
    CAPTURE_PID=
    finish_driver 60
    "$PY" "$NET/verify-process-traces.py" --self-test
    "$PY" "$NET/verify-process-traces.py" \
        --phase "$CURRENT_DIR/process-trace-phase.json" \
        --lifecycle "$CURRENT_DIR/process-trace-lifecycle.json" \
        --client-prefix "$CURRENT_DIR/client-strace" \
        --gateway-prefix "$CURRENT_DIR/gateway-strace" \
        --client-identity "$CURRENT_DIR/client-process.txt" \
        --gateway-identity "$CURRENT_DIR/gateway-process.txt" \
        --marker pre-udp-only-proof --marker udp-only-proof-000000 \
        --marker post-udp-only-proof \
        --output "$CURRENT_DIR/process-trace-verification.json"
    local client_trace_count gateway_trace_count
    client_trace_count=$(/usr/bin/jq -r '.client.files' \
        "$CURRENT_DIR/process-trace-verification.json")
    gateway_trace_count=$(/usr/bin/jq -r '.gateway.files' \
        "$CURRENT_DIR/process-trace-verification.json")
    printf '%s\n' \
        'phase=post-bootstrap-terminal' \
        'events=process,socket,readiness-metadata-only' \
        'payload-syscalls=disabled' \
        'fd-decoding=endpoint-metadata' >"$CURRENT_DIR/process-trace-profile.txt"
    "$TCPDUMP" -n -r "$CURRENT_DIR/terminal.pcap" >"$CURRENT_DIR/terminal-packets.txt" 2>/dev/null
    local udp_count tcp_count
    udp_count=$(grep -c ' UDP' "$CURRENT_DIR/terminal-packets.txt" || true)
    tcp_count=$(grep -c 'Flags \[' "$CURRENT_DIR/terminal-packets.txt" || true)
    (( udp_count > 0 && tcp_count == 0 )) || {
        echo "terminal capture was not UDP-only: udp=$udp_count tcp=$tcp_count" >&2
        return 1
    }
    /usr/bin/jq --argjson udp "$udp_count" --argjson tcp "$tcp_count" \
        --argjson client_traces "$client_trace_count" \
        --argjson gateway_traces "$gateway_trace_count" \
        '. + {captured_udp_packets: $udp, captured_tcp_packets: $tcp,
              client_process_trace_files: $client_traces,
              gateway_process_trace_files: $gateway_traces,
              process_trace_verified: true,
              trace_phase: "post-bootstrap-terminal",
              socket_snapshot_verified: true}' \
        "$CURRENT_DIR/result.json" >"$CURRENT_DIR/result.tmp"
    mv "$CURRENT_DIR/result.tmp" "$CURRENT_DIR/result.json"
    SCENARIO_INDEX=$((SCENARIO_INDEX + 1))
    echo "everudp reliability UDP-only data plane: PASS"
}

run_mtu() {
    local label=mtu1200
    start_driver "$label" stream target4
    "$IP" -n "$SERVER_NS" link set s0 mtu 1200
    "$IP" -n "$CLIENT_NS" link set c0 mtu 1200
    apply_netem 5 0 0 0 940001
    snapshot_network before
    touch "$CURRENT_DIR/control/go"
    finish_driver 300
    snapshot_network after
    clear_netem
    "$IP" -n "$SERVER_NS" link set s0 mtu 1500
    "$IP" -n "$CLIENT_NS" link set c0 mtu 1500
    SCENARIO_INDEX=$((SCENARIO_INDEX + 1))
    echo "everudp reliability 1200-byte MTU: PASS"
}

run_migration() {
    local label=interface-migration
    start_driver "$label" stream target4
    "$IP" -n "$CLIENT_NS" addr add 10.253.0.3/24 dev c1
    "$IP" -n "$SERVER_NS" addr del 10.253.0.1/24 dev s0
    "$IP" -n "$SERVER_NS" addr add 10.253.0.1/24 dev s1
    "$IP" -n "$CLIENT_NS" addr del 10.253.0.2/24 dev c0
    "$IP" -n "$SERVER_NS" link set s0 down
    "$IP" -n "$CLIENT_NS" link set c0 down
    "$IP" -j -n "$SERVER_NS" address show >"$CURRENT_DIR/server-after.json"
    "$IP" -j -n "$CLIENT_NS" address show >"$CURRENT_DIR/client-after.json"
    touch "$CURRENT_DIR/control/go"
    finish_driver 180
    SCENARIO_INDEX=$((SCENARIO_INDEX + 1))
    echo "everudp reliability address/interface migration: PASS"
}

setup_topology
setup_ssh
STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SCENARIO_INDEX=0

if [[ -n $ONLY ]]; then
    case $ONLY in
        forced-overrun) run_overrun ;;
        outage-smoke) run_outage outage-smoke 35 ;;
        sleep-wake) run_pause ;;
        cancel-outage) run_cancel_outage ;;
        udp-only-proof) run_packet_proof ;;
        ipv6-loss5) run_stream ipv6-loss5 5 0 0 0 target6 ;;
        interface-migration) run_migration ;;
        mtu1200) run_mtu ;;
        loss0) run_stream loss0 0 0 0 0 ;;
        loss5-jitter25) run_stream loss5-jitter25 5 25 0 0 ;;
        loss5-reorder2-duplicate2) run_stream loss5-reorder2-duplicate2 5 10 2 2 ;;
        *) echo "unknown EVERUDP_ONLY scenario: $ONLY" >&2; exit 2 ;;
    esac
elif (( SMOKE == 1 )); then
    run_stream loss0 0 0 0 0
    run_stream loss5-jitter25 5 25 0 0
    run_outage outage-smoke 35
    run_overrun
    run_pause
    run_cancel_outage
    run_packet_proof
    run_stream ipv6-loss5 5 0 0 0 target6
    run_migration
else
    run_stream loss0 0 0 0 0
    run_stream loss1 1 0 0 0
    run_stream loss5 5 0 0 0
    run_stream loss10 10 0 0 0
    run_stream loss25 25 0 0 0
    run_stream loss5-jitter25 5 25 0 0
    run_stream loss5-jitter50 5 50 0 0
    run_stream loss5-reorder2-duplicate2 5 10 2 2
    run_packet_proof
    run_stream ipv6-loss5 5 0 0 0 target6
    run_mtu
    run_pause
    run_cancel_outage
    run_outage outage-5m 300
    run_outage outage-30m 1800
    run_overrun
    if [[ ${EVERUDP_RUN_12H_SOAK:-0} == 1 ]]; then
        run_outage outage-12h 43200
        SOAK_STATUS=PASS
    else
        SOAK_STATUS=NOT_RUN
    fi
    run_migration
fi

COMPLETED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SOAK_STATUS=${SOAK_STATUS:-NOT_RUN}
/usr/bin/jq -s \
    --arg head "$HEAD_SHA" --arg tree "$TREE_SHA" --arg started "$STARTED" \
    --arg completed "$COMPLETED" --arg soak "$SOAK_STATUS" --argjson smoke "$SMOKE" \
    '{schema_version: 1, verdict: "PASS", source: {head: $head, tree: $tree},
      started_utc: $started, completed_utc: $completed, smoke: ($smoke == 1),
      twelve_hour_soak: $soak, scenarios: .}' \
    "$OUTDIR"/scenarios/*/result.json >"$OUTDIR/receipt.json"
(cd "$OUTDIR" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS)
echo "everudp production reliability gate: PASS ($OUTDIR)"
