#!/usr/bin/bash
# Root-required composed M4 outage gate: real eversh + everssh + everpty +
# isolated system sshd under netns/veth total path loss.
set -Eeuo pipefail

if [[ ${1-} != b1 && ${1-} != b2 ]]; then
    printf 'usage: test-composed-netns.sh b1|b2\n' >&2
    exit 2
fi
MODE=$1
TIMEOUT=/usr/bin/timeout
WATCHDOG_SECONDS=700
SCRIPT_PATH=$(readlink -f -- "${BASH_SOURCE[0]}") || exit 1
if [[ ${2-} != --watchdog-child ]]; then
    exec "$TIMEOUT" --signal=TERM --kill-after=3s \
        "${WATCHDOG_SECONDS}s" "$SCRIPT_PATH" "$MODE" --watchdog-child
fi

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    printf 'composed outage gate requires root\n' >&2
    exit 77
fi

ROOT=$(cd -- "$(dirname -- "$0")/../../../.." && pwd -P)
EVERSH_BIN="$ROOT/target/debug/eversh"
IP=/usr/bin/ip
TC=/usr/sbin/tc
SSH=/usr/bin/ssh
SSHD=/usr/sbin/sshd
SSHKEYGEN=/usr/bin/ssh-keygen
SSHKEYSCAN=/usr/bin/ssh-keyscan
SCRIPT=/usr/bin/script
TIMEOUT=/usr/bin/timeout
BASH=/usr/bin/bash
CAT=/usr/bin/cat
CHMOD=/usr/bin/chmod
GREP=/usr/bin/grep
MKDIR=/usr/bin/mkdir
MKTEMP=/usr/bin/mktemp
PRINTF=/usr/bin/printf
SLEEP=/usr/bin/sleep
STAT=/usr/bin/stat
STTY=/usr/bin/stty
AWK=/usr/bin/awk
TAIL=/usr/bin/tail
GIT=/usr/bin/git
for tool in "$IP" "$TC" "$SSH" "$SSHD" "$SSHKEYGEN" "$SSHKEYSCAN" "$GIT" \
    "$SCRIPT" "$TIMEOUT" "$BASH" "$CAT" "$CHMOD" "$GREP" "$MKDIR" \
    "$MKTEMP" "$PRINTF" "$SLEEP" "$STAT" "$STTY" "$AWK" "$TAIL"; do
    [[ -x $tool ]] || { printf 'missing tool: %s\n' "$tool" >&2; exit 1; }
done
[[ -x $EVERSH_BIN ]] || { printf 'missing eversh binary\n' >&2; exit 1; }

TMP=$("$MKTEMP" -d /tmp/eversh-composed-netns.XXXXXX)
TAG=c$("$PRINTF" '%04x' $((RANDOM & 65535)))
SERVER_NS=${TAG}s
CLIENT_NS=${TAG}c
PID_ALL=()
FD9=
CLEANED=0

cleanup() {
    local status=$?
    (( CLEANED )) && exit "$status"
    CLEANED=1
    set +e
    trap - EXIT INT TERM HUP
    [[ -z $FD9 ]] || exec 9>&-
    local pid ns
    for pid in "${PID_ALL[@]}"; do kill -KILL "$pid" 2>/dev/null || :; done
    # The transcript annotator owns a private session because `tail -f`
    # and its reader never exit when the pipeline leader is killed. Kill
    # the whole process group so no diagnostic follower outlives the gate.
    if [[ -n ${LOG_TS_PID:-} ]]; then
        kill -KILL -- -"$LOG_TS_PID" 2>/dev/null || :
    fi
    for ns in "$CLIENT_NS" "$SERVER_NS"; do
        [[ -n $ns ]] || continue
        "$IP" netns exec "$ns" "$TC" qdisc del dev c0 root 2>/dev/null || :
        "$IP" netns exec "$ns" "$TC" qdisc del dev s0 root 2>/dev/null || :
        "$IP" netns pids "$ns" 2>/dev/null | xargs -r kill -KILL 2>/dev/null || :
        "$IP" netns del "$ns" 2>/dev/null || :
    done
    "$IP" link del "${TAG}c0" 2>/dev/null || :
    "$IP" link del "${TAG}s0" 2>/dev/null || :
    if [[ ${EVERSSH_COMPOSED_KEEP:-0} != 1 ]]; then
        rm -rf -- "$TMP"
    else
        printf 'composed diagnostics preserved at %s\n' "$TMP" >&2
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

die() { printf '%s\n' "$1" >&2; exit 1; }

"$IP" netns add "$SERVER_NS"
"$IP" netns add "$CLIENT_NS"
"$IP" link add "${TAG}s0" type veth peer name "${TAG}c0"
"$IP" link set "${TAG}s0" netns "$SERVER_NS"
"$IP" link set "${TAG}c0" netns "$CLIENT_NS"
"$IP" -n "$SERVER_NS" link set "${TAG}s0" name s0
"$IP" -n "$CLIENT_NS" link set "${TAG}c0" name c0
"$IP" -n "$SERVER_NS" link set lo up
"$IP" -n "$CLIENT_NS" link set lo up
"$IP" -n "$SERVER_NS" addr add 10.241.0.1/24 dev s0
"$IP" -n "$CLIENT_NS" addr add 10.241.0.2/24 dev c0
"$IP" -n "$SERVER_NS" link set s0 up
"$IP" -n "$CLIENT_NS" link set c0 up

"$MKDIR" -m 700 "$TMP/sshd" "$TMP/state" "$TMP/client-state" "$TMP/bin"
SERVER_KEY="$TMP/sshd/host_ed25519"
CLIENT_KEY="$TMP/sshd/client_ed25519"
KNOWN_HOSTS="$TMP/sshd/known_hosts"
AUTHORIZED="$TMP/sshd/authorized_keys"
CLIENT_CONFIG="$TMP/client_config"
COUNT="$TMP/ssh.count"
WRAPPER="$TMP/connect.wrap.sh"
FIFO="$TMP/input.fifo"
LOG="$TMP/session.log"
STATUS_ROOT="$TMP/client-state/link-status"
"$SSHKEYGEN" -q -t ed25519 -N '' -f "$SERVER_KEY" >/dev/null 2>&1
"$SSHKEYGEN" -q -t ed25519 -N '' -f "$CLIENT_KEY" >/dev/null 2>&1
"$CAT" "$CLIENT_KEY.pub" >"$AUTHORIZED"
"$CHMOD" 600 "$AUTHORIZED" "$CLIENT_KEY" "$SERVER_KEY"

SSHD_CONFIG="$TMP/sshd/sshd_config"
{
    "$PRINTF" '%s\n' \
        'Port 22' \
        'ListenAddress 10.241.0.1' \
        'ListenAddress 127.0.0.1' \
        "HostKey $SERVER_KEY" \
        "PidFile $TMP/sshd/sshd.pid" \
        "AuthorizedKeysFile $AUTHORIZED" \
        'PermitRootLogin yes' \
        'AllowUsers root' \
        'AuthenticationMethods publickey' \
        'PubkeyAuthentication yes' \
        'PasswordAuthentication no' \
        'KbdInteractiveAuthentication no' \
        'StrictModes no' \
        'UsePAM no' \
        'X11Forwarding no' \
        'AllowAgentForwarding no' \
        'AllowTcpForwarding no' \
        'PermitTunnel no' \
        'UseDNS no' \
        'PermitUserEnvironment no' \
        'PermitUserRC no' \
        "SetEnv EVERSH_STATE_DIR=$TMP/state" \
        'Subsystem sftp internal-sftp'
} >"$SSHD_CONFIG"
"$CHMOD" 600 "$SSHD_CONFIG"
"$IP" netns exec "$SERVER_NS" "$SSHD" -t -f "$SSHD_CONFIG"
"$IP" netns exec "$SERVER_NS" "$SSHD" -D -f "$SSHD_CONFIG" &
SSHD_PID=$!
PID_ALL+=("$SSHD_PID")

for scan_attempt in $(seq 1 20); do
    kill -0 "$SSHD_PID" 2>/dev/null || die 'isolated sshd exited during startup'
    "$IP" netns exec "$CLIENT_NS" "$SSHKEYSCAN" -4 -T 1 -p 22 -t ed25519 10.241.0.1 \
        >"$KNOWN_HOSTS" 2>/dev/null || :
    "$GREP" -q 'ssh-ed25519' "$KNOWN_HOSTS" && break
    "$SLEEP" 0.2
done
"$GREP" -q 'ssh-ed25519' "$KNOWN_HOSTS" || die 'host key scan failed'
{
    "$PRINTF" '%s\n' \
        'Host composed' \
        '    HostName 10.241.0.1' \
        '    Port 22' \
        '    User root' \
        "    IdentityFile $CLIENT_KEY" \
        '    IdentitiesOnly yes' \
        "    UserKnownHostsFile $KNOWN_HOSTS" \
        '    GlobalKnownHostsFile /dev/null' \
        '    StrictHostKeyChecking yes' \
        '    HostKeyAlgorithms ssh-ed25519' \
        '    ProxyCommand none' \
        '    ProxyJump none' \
        '    BatchMode yes' \
        '    PubkeyAuthentication yes' \
        '    PasswordAuthentication no' \
        '    KbdInteractiveAuthentication no' \
        '    PreferredAuthentications publickey' \
        '    ConnectTimeout 5' \
        '    ConnectionAttempts 1' \
        '    ControlMaster no' \
        '    ControlPath none' \
        '    ControlPersist no' \
        '    ClearAllForwardings yes' \
        '    ForwardAgent no' \
        '    ForwardX11 no' \
        '    Tunnel no' \
        '    ServerAliveInterval 60' \
        '    ServerAliveCountMax 12' \
        '    UpdateHostKeys no'
} >"$CLIENT_CONFIG"
"$CHMOD" 600 "$CLIENT_CONFIG"

SSH_SHIM="$TMP/bin/ssh"
{
    printf '#!/usr/bin/bash\n'
    printf 'read -r uptime_now _ < /proc/uptime\n'
    printf 'printf "%%s %%s %%s\\\\n" "$uptime_now" "$PPID" "$$" >> %q\n' "$COUNT"
    printf 'exec %q "$@"\n' "$SSH"
} >"$SSH_SHIM"
"$CHMOD" 700 "$SSH_SHIM"
: >"$COUNT"
"$CHMOD" 600 "$COUNT"

READER_SCRIPT='printf "READY\\n"; while IFS= read -r line; do printf "R:%s\\n" "$line"; done'
{
    printf '#!/usr/bin/bash\nset -Eeuo pipefail\n'
    printf 'export PATH=%q:/usr/bin:/bin\n' "$TMP/bin"
    printf 'export EVERSH_STATE_DIR=%q\n' "$TMP/client-state"
    printf '%q rows 24 cols 80 -echo -echoctl 2>/dev/null || :\n' "$STTY"
    printf 'exec %q connect composed --session outage --remote-eversh %q --ssh-option -F%q -- /bin/sh -c %q\n' \
        "$EVERSH_BIN" "$EVERSH_BIN" "$CLIENT_CONFIG" "$READER_SCRIPT"
} >"$WRAPPER"
"$CHMOD" 700 "$WRAPPER"
mkfifo "$FIFO"
exec 9<>"$FIFO"
FD9=1
: >"$LOG"
"$CHMOD" 600 "$LOG"
LOG_TS="$TMP/session.log.ts"
: >"$LOG_TS"
setsid "$BASH" -c '
    "$3" -n +1 -f "$1" | while IFS= read -r line; do
        read -r stamp_now _ < /proc/uptime
        printf "%s %s\n" "$stamp_now" "$line"
    done >"$2"
' gate-transcript "$LOG" "$LOG_TS" "$TAIL" &
LOG_TS_PID=$!
PID_ALL+=("$LOG_TS_PID")

"$IP" netns exec "$CLIENT_NS" "$SCRIPT" -qefc "$WRAPPER" /dev/null <"$FIFO" >"$LOG" 2>&1 &
SESSION_PID=$!
PID_ALL+=("$SESSION_PID")

wait_log() {
    local needle=$1 timeout_seconds=$2 deadline
    deadline=$((SECONDS + timeout_seconds))
    while (( SECONDS < deadline )); do
        "$GREP" -q -F -- "$needle" "$LOG" && return 0
        kill -0 "$SESSION_PID" 2>/dev/null || {
            "$CAT" "$LOG" >&2
            die 'session exited before readiness'
        }
        "$SLEEP" 0.1
    done
    "$CAT" "$LOG" >&2
    die "timeout waiting for $needle"
}

count_lines() { "$CAT" "$COUNT" | "$AWK" 'END { print NR + 0 }'; }
HEAD_SHA=$("$GIT" -C "$ROOT" rev-parse HEAD)
TREE_SHA=$("$GIT" -C "$ROOT" rev-parse 'HEAD^{tree}')
if [[ -z $("$GIT" -C "$ROOT" status --porcelain) ]]; then
    TREE_DIRTY=false
else
    TREE_DIRTY=true
fi
ms_from_epoch() {
    local value=$1 seconds fraction
    seconds=${value%%.*}
    fraction=${value#*.}
    fraction=${fraction:0:3}
    while ((${#fraction} < 3)); do
        fraction="${fraction}0"
    done
    "$PRINTF" '%s%s\n' "$seconds" "$fraction"
}
now_ms() {
    local value
    read -r value _ < /proc/uptime
    ms_from_epoch "$value"
}
first_ssh_after_ms() {
    local threshold=$1 line timestamp_ms min=0
    while read -r timestamp_ms _; do
        [[ $timestamp_ms =~ ^[0-9]+\.?[0-9]*$ ]] || continue
        timestamp_ms=$(ms_from_epoch "$timestamp_ms")
        if ((timestamp_ms >= threshold && (min == 0 || timestamp_ms < min))); then
            min=$timestamp_ms
        fi
    done <"$COUNT"
    "$PRINTF" '%d\n' "$min"
}
ssh_count_between_ms() {
    local start=$1 end=$2 line timestamp_ms count=0
    while read -r timestamp_ms _; do
        [[ $timestamp_ms =~ ^[0-9]+\.?[0-9]*$ ]] || continue
        timestamp_ms=$(ms_from_epoch "$timestamp_ms")
        ((timestamp_ms >= start && timestamp_ms < end)) && count=$((count + 1))
    done <"$COUNT"
    "$PRINTF" '%d\n' "$count"
}
composed_server_alive() {
    local pid
    for pid in $("$IP" netns pids "$SERVER_NS" 2>/dev/null); do
        if "$GREP" -aq -- '__server-v1' "/proc/$pid/cmdline" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}
timestamped_line_ms() {
    local needle=$1
    local line
    line=$("$GREP" -F -m1 -- "$needle" "$LOG_TS" 2>/dev/null || true)
    [[ -n $line ]] || return 0
    ms_from_epoch "${line%% *}"
}
broker_pid() {
    local output
    output=$("$IP" netns exec "$CLIENT_NS" "$SSH" -F "$CLIENT_CONFIG" -- \
        composed "$EVERSH_BIN" __everpty v1 list json 2>"$TMP/broker-list.err")
    "$PRINTF" '%s\n' "$output" >"$TMP/broker-list.json"
    "$PRINTF" '%s\n' "$output" \
        | "$GREP" -oE '"name":"outage","broker":\{"pid":[0-9]+' \
        | "$GREP" -oE '[0-9]+$'
}

wait_log 'READY' 20
"$PRINTF" 'PRE1\n' >&9
wait_log 'R:PRE1' 10
BASELINE=$(count_lines)
(( BASELINE >= 1 )) || die 'no ssh invocations recorded'
MARK_BEFORE=$("$GREP" -c -E '^R:' "$LOG" || :)
broker_pid >"$TMP/broker-before.json.raw" || :
BROKER_BEFORE=$("$CAT" "$TMP/broker-before.json.raw")
[[ $BROKER_BEFORE =~ ^[0-9]+$ ]] || die 'could not read pre-outage broker pid'

# Snapshot link-status files every second: the supervisor legitimately
# deletes each per-spawn file after classification, so snapshots preserve
# the terminal record for gate diagnostics.
SNAP_DIR="$TMP/status-snapshots"
"$MKDIR" -m 700 -- "$SNAP_DIR"
(
    while :; do
        for status_file in "$STATUS_ROOT"/*.status; do
            [[ -e $status_file ]] || continue
            "$CAT" "$status_file" \
                >"$SNAP_DIR/$(basename "$status_file").snap" 2>/dev/null || :
        done
        "$SLEEP" 1
    done
) &
SNAP_PID=$!
PID_ALL+=("$SNAP_PID")

"$IP" netns exec "$CLIENT_NS" "$TC" qdisc replace dev c0 root netem loss 100%
T_LOSS=$(now_ms)
"$PRINTF" '%s\n' "$([[ $MODE == b1 ]] && printf QUEUED || printf OLD)" >&9

RECONNECTING=0
loss_guard() {
    kill -0 "$SESSION_PID" 2>/dev/null || {
        "$CAT" "$LOG" >&2
        die "$MODE session exited during path loss"
    }
    if [[ -d $STATUS_ROOT ]] && "$GREP" -R -q -F \
        'everssh-status-v1 reconnecting' "$STATUS_ROOT" 2>/dev/null; then
        RECONNECTING=1
    fi
    NOW_LINES=$(count_lines)
    (( NOW_LINES == BASELINE )) || {
        "$CAT" "$LOG" >&2
        die "$MODE spawned ssh during association outage ($BASELINE -> $NOW_LINES)"
    }
}

stop_transcript_annotator() {
    [[ -n ${LOG_TS_PID:-} ]] || return 0
    kill -TERM -- -"$LOG_TS_PID" 2>/dev/null || :
    local attempt
    for attempt in $(seq 1 50); do
        kill -0 -- -"$LOG_TS_PID" 2>/dev/null || return 0
        "$SLEEP" 0.1
    done
    kill -KILL -- -"$LOG_TS_PID" 2>/dev/null || :
    "$SLEEP" 0.2
    kill -0 -- -"$LOG_TS_PID" 2>/dev/null \
        && die 'transcript annotator process group leaked'
}

T_BUDGET=0
T_DEATH=0
T_RELEASE=0
T_RESTORE=0
if [[ $MODE == b1 ]]; then
    DEADLINE=$((SECONDS + 95))
    while (( SECONDS < DEADLINE )); do
        loss_guard
        "$SLEEP" 1
    done
else
    composed_server_alive \
        || die 'b2 everssh server role was not live before loss'
    BUDGET_SEEN=0
    DEATH_SEEN=0
    RELEASE_SEEN=0
    DEADLINE=$((SECONDS + 520))
    while (( SECONDS < DEADLINE )); do
        loss_guard
        # The timestamped transcript observes the outer ssh's own terminal
        # line (its stderr marker can be interleaved mid-word, so the ssh
        # close line is the durable budget-exhaustion oracle). The event
        # time comes from the transcript annotator's own monotonic stamp,
        # not from when this poll first notices the line.
        if (( ! BUDGET_SEEN )) && "$GREP" -q -F -- \
            'Connection to 10.241.0.1 closed.' "$LOG_TS" 2>/dev/null; then
            BUDGET_SEEN=1
            T_BUDGET=$(timestamped_line_ms 'Connection to 10.241.0.1 closed.')
            [[ $T_BUDGET =~ ^[1-9][0-9]*$ ]] \
                || die 'b2 terminal transcript line lacked its monotonic stamp'
        fi
        if (( ! DEATH_SEEN )) && (( RECONNECTING == 1 )); then
            DEATH_SEEN=1
            T_DEATH=$(now_ms)
        fi
        if (( ! RELEASE_SEEN )) && ! composed_server_alive; then
            RELEASE_SEEN=1
            T_RELEASE=$(now_ms)
        fi
        (( BUDGET_SEEN && RELEASE_SEEN )) && break
        "$SLEEP" 1
    done
    (( BUDGET_SEEN )) || die 'b2 never observed client budget exhaustion'
    (( DEATH_SEEN )) || die 'b2 never observed connection-death detection'
    (( RELEASE_SEEN )) || die 'b2 never observed server association release'
    # B2 restores only at least ten seconds after the OBSERVED release, not
    # at a predicted constant.
    RESTORE_AT=$((T_RELEASE + 10000))
    while (( $(now_ms) < RESTORE_AT )); do
        "$SLEEP" 1
    done
fi
(( RECONNECTING == 1 )) || {
    find "$TMP/client-state" -type f -maxdepth 3 -print -exec "$CAT" {} \; >&2
    die "$MODE never published reconnecting"
}

"$IP" netns exec "$CLIENT_NS" "$TC" qdisc del dev c0 root
T_RESTORE=$(now_ms)
if [[ $MODE == b1 ]]; then
    "$GREP" -q -F -- 'R:QUEUED' "$LOG" && die 'b1 delivered queued input through total loss'
    "$PRINTF" 'AFTER1\n' >&9
    deadline=$((SECONDS + 40))
    while (( SECONDS < deadline )); do
        "$GREP" -q -F -- 'R:AFTER1' "$LOG" && break
        "$SLEEP" 0.2
    done
    "$GREP" -q -F -- 'R:AFTER1' "$LOG" || {
        "$CAT" "$LOG" >&2
        die 'b1 did not resume the same byte stream'
    }
    MARK_AFTER=$("$GREP" -c -E '^R:' "$LOG" || :)
    (( MARK_AFTER == MARK_BEFORE + 2 )) || {
        die "b1 marker count mismatch ($MARK_BEFORE -> $MARK_AFTER)"
    }
    QUEUED_COUNT=$("$GREP" -c -F -- 'R:QUEUED' "$LOG" || :)
    (( QUEUED_COUNT == 1 )) || die 'b1 queued marker was not delivered exactly once'
    kill -0 "$SESSION_PID" 2>/dev/null || die 'b1 local terminal process changed'
    "$GREP" -q -F -- 'R:PRE1' "$LOG" || die 'b1 local scrollback was not preserved'
    BROKER_AFTER=$(broker_pid)
    [[ $BROKER_AFTER == "$BROKER_BEFORE" ]] \
        || die "b1 broker changed ($BROKER_BEFORE -> $BROKER_AFTER)"
    kill -TERM "$SESSION_PID" 2>/dev/null || :
    "$TIMEOUT" 15s "$BASH" -c 'while kill -0 "$1" 2>/dev/null; do sleep 0.1; done' _ "$SESSION_PID"
    stop_transcript_annotator
    "$MKDIR" -p -- "$ROOT/target/qualification"
    {
        "$PRINTF" 'clock\t/proc/uptime (CLOCK_MONOTONIC-derived)\n'
        "$PRINTF" 'head_sha\t%s\n' "$HEAD_SHA"
        "$PRINTF" 'tree_sha\t%s\n' "$TREE_SHA"
        "$PRINTF" 'tree_dirty\t%s\n' "$TREE_DIRTY"
        "$PRINTF" 't_loss_ms\t%d\n' "$T_LOSS"
        "$PRINTF" 't_restore_ms\t%d\n' "$T_RESTORE"
        "$PRINTF" 'ssh_invocations\t%d\n' "$(count_lines)"
    } >"$ROOT/target/qualification/eversh-composed-b1-latest-events.tsv"
    "$PRINTF" 'eversh composed B1 outage continuity: PASS\n'
else
    "$GREP" -q -F -- 'R:OLD' "$LOG" && die 'b2 delivered old input before terminal transition'
    # Observed-timeline contract: the supervisor must spend no ssh attempt
    # during the configured 30 s association drain, and its first fresh
    # attempt must wait that drain out. One polling-second tolerance is
    # allowed on the observed lower bound.
    FIRST_FRESH=0
    deadline=$((SECONDS + 60))
    while (( SECONDS < deadline )); do
        FIRST_FRESH=$(first_ssh_after_ms "$T_BUDGET")
        [[ $FIRST_FRESH =~ ^[1-9][0-9]*$ ]] && break
        "$SLEEP" 1
    done
    [[ $FIRST_FRESH =~ ^[1-9][0-9]*$ ]] || {
        "$CAT" "$COUNT" >&2
        find "$TMP/client-state" -type f -maxdepth 3 -print -exec "$CAT" {} \; >&2
        "$CAT" "$LOG" >&2
        die 'b2 supervisor never spent a fresh ssh attempt'
    }
    # The wait above proves the full drain window has elapsed; only now is
    # the zero-attempt observation complete.
    DRAIN_INVOCATIONS=$(ssh_count_between_ms "$T_BUDGET" "$((T_BUDGET + 29000))")
    (( DRAIN_INVOCATIONS == 0 )) || {
        "$CAT" "$COUNT" >&2
        die "b2 spent $DRAIN_INVOCATIONS ssh attempts during the association drain"
    }
    (( FIRST_FRESH - T_BUDGET >= 29000 )) || {
        "$CAT" "$COUNT" >&2
        find "$TMP/client-state" -type f -maxdepth 3 -print -exec "$CAT" {} \; >&2
        "$CAT" "$LOG" >&2
        die "b2 first fresh attempt preceded the drain (budget=$T_BUDGET first=$FIRST_FRESH)"
    }
    T_BACKOFF=$(timestamped_line_ms 'reconnect attempt 1 in')
    [[ $T_BACKOFF =~ ^[1-9][0-9]*$ ]] || {
        "$CAT" "$LOG_TS" >&2
        die 'b2 supervisor never published its post-drain reconnect attempt'
    }
    (( T_BACKOFF - T_BUDGET >= 29000 )) || {
        "$CAT" "$LOG_TS" >&2
        die "b2 supervisor skipped the association drain (budget=$T_BUDGET backoff=$T_BACKOFF)"
    }
    "$PRINTF" 'NEW1\n' >&9
    deadline=$((SECONDS + 90))
    while (( SECONDS < deadline )); do
        "$GREP" -q -F -- 'R:NEW1' "$LOG" && break
        "$SLEEP" 0.2
    done
    "$GREP" -q -F -- 'R:NEW1' "$LOG" || {
        "$CAT" "$LOG" >&2
        die 'b2 fresh SSH did not reattach the live broker'
    }
    OLD_COUNT=$("$GREP" -c -F -- 'R:OLD' "$LOG" || :)
    (( OLD_COUNT == 0 )) || die 'b2 delivered an old-association byte after terminal transition'
    kill -0 "$SESSION_PID" 2>/dev/null || die 'b2 local terminal process changed'
    "$GREP" -q -F -- 'R:PRE1' "$LOG" || die 'b2 local scrollback was not preserved'
    PROBE_COUNT=$("$GREP" -c -F -- \
        "probing session 'outage' (attempt 1)" "$LOG" || :)
    REATTACH_COUNT=$("$GREP" -c -F -- \
        "reattaching session 'outage' (attempt 1)" "$LOG" || :)
    (( PROBE_COUNT == 1 )) || {
        "$CAT" "$LOG" >&2
        die "b2 expected exactly one first-attempt probe, observed $PROBE_COUNT"
    }
    (( REATTACH_COUNT == 1 )) || {
        "$CAT" "$LOG" >&2
        die "b2 expected exactly one first-attempt reattach, observed $REATTACH_COUNT"
    }
    BROKER_AFTER=$(broker_pid)
    [[ $BROKER_AFTER == "$BROKER_BEFORE" ]] \
        || die "b2 broker changed ($BROKER_BEFORE -> $BROKER_AFTER)"
    FINAL_LINES=$(count_lines)
    # The bounded fresh path is one probe plus one reattach; each structured
    # spawn contributes its outer ssh, effective-config query, and bootstrap
    # ssh, so at most six entries may follow the baseline.
    (( FINAL_LINES > BASELINE && FINAL_LINES <= BASELINE + 6 )) || {
        die "b2 unexpected ssh invocation count ($BASELINE -> $FINAL_LINES)"
    }
    kill -TERM "$SESSION_PID" 2>/dev/null || :
    "$TIMEOUT" 15s "$BASH" -c 'while kill -0 "$1" 2>/dev/null; do sleep 0.1; done' _ "$SESSION_PID"
    DRAIN_BACKOFF_DELTA=$((T_BACKOFF - T_BUDGET))
    FIRST_FRESH_DELTA=$((FIRST_FRESH - T_BUDGET))
    RELEASE_AFTER_LOSS_DELTA=$((T_RELEASE - T_LOSS))
    LEASE_START_UPPER=$((T_RELEASE - 360000))
    "$MKDIR" -p -- "$ROOT/target/qualification"
    B2_RECEIPT="$ROOT/target/qualification/eversh-composed-b2-latest-events.tsv"
    {
        "$PRINTF" 'clock\t/proc/uptime (CLOCK_MONOTONIC-derived)\n'
        "$PRINTF" 'head_sha\t%s\n' "$HEAD_SHA"
        "$PRINTF" 'tree_sha\t%s\n' "$TREE_SHA"
        "$PRINTF" 'tree_dirty\t%s\n' "$TREE_DIRTY"
        "$PRINTF" 't_loss_ms\t%d\n' "$T_LOSS"
        "$PRINTF" 't_connection_death_detection_ms\t%d\n' "$T_DEATH"
        "$PRINTF" 't_client_budget_exhaustion_ms\t%d\n' "$T_BUDGET"
        # The server's private resume-acceptance entry is not exposed on
        # its process boundary; these monotonic observations bound it.
        "$PRINTF" 'renewed_lease_start_bound_ms\t%d..%d\n' "$T_DEATH" "$LEASE_START_UPPER"
        "$PRINTF" 't_server_association_release_ms\t%d\n' "$T_RELEASE"
        "$PRINTF" 't_restore_ms\t%d\n' "$T_RESTORE"
        "$PRINTF" 't_post_drain_backoff_ms\t%d\n' "$T_BACKOFF"
        "$PRINTF" 't_first_fresh_ssh_ms\t%d\n' "$FIRST_FRESH"
        "$PRINTF" 'delta_release_after_loss_ms\t%d\n' "$RELEASE_AFTER_LOSS_DELTA"
        "$PRINTF" 'delta_drain_backoff_ms\t%d\n' "$DRAIN_BACKOFF_DELTA"
        "$PRINTF" 'delta_first_fresh_ms\t%d\n' "$FIRST_FRESH_DELTA"
        "$PRINTF" 'drain_window_attempts\t0\n'
        "$PRINTF" 'probe_attempts\t1\nreattach_attempts\t1\n'
        "$PRINTF" 'ssh_invocations\t%d..%d\n' "$FINAL_LINES" "$((BASELINE + 6))"
    } >"$B2_RECEIPT"
    stop_transcript_annotator
    "$PRINTF" 'everssh composed B2 terminal fallback: PASS (release-after-loss=%dms drain-backoff=%dms first-fresh=%dms attempts=1/1 invocations=%d/%d events=%s)\n' \
        "$RELEASE_AFTER_LOSS_DELTA" "$DRAIN_BACKOFF_DELTA" "$FIRST_FRESH_DELTA" \
        "$FINAL_LINES" "$((BASELINE + 6))" "$B2_RECEIPT"
fi
