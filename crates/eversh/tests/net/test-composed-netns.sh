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
WATCHDOG_SECONDS=600
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
for tool in "$IP" "$TC" "$SSH" "$SSHD" "$SSHKEYGEN" "$SSHKEYSCAN" \
    "$SCRIPT" "$TIMEOUT" "$BASH" "$CAT" "$CHMOD" "$GREP" "$MKDIR" \
    "$MKTEMP" "$PRINTF" "$SLEEP" "$STAT" "$STTY" "$AWK"; do
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
    printf 'printf %%s\\\\n "$PPID" >> %q\n' "$COUNT"
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

"$IP" netns exec "$CLIENT_NS" "$TC" qdisc replace dev c0 root netem loss 100%
"$PRINTF" '%s\n' "$([[ $MODE == b1 ]] && printf QUEUED || printf OLD)" >&9

OUTAGE_SECONDS=95
if [[ $MODE == b2 ]]; then OUTAGE_SECONDS=405; fi
DEADLINE=$((SECONDS + OUTAGE_SECONDS))
RECONNECTING=0
while (( SECONDS < DEADLINE )); do
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
    "$SLEEP" 1
done
(( RECONNECTING == 1 )) || {
    find "$TMP/client-state" -type f -maxdepth 3 -print -exec "$CAT" {} \; >&2
    die "$MODE never published reconnecting"
}

"$IP" netns exec "$CLIENT_NS" "$TC" qdisc del dev c0 root
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
    "$PRINTF" 'eversh composed B1 outage continuity: PASS\n'
else
    "$GREP" -q -F -- 'R:OLD' "$LOG" && die 'b2 delivered old input before terminal transition'
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
    BROKER_AFTER=$(broker_pid)
    [[ $BROKER_AFTER == "$BROKER_BEFORE" ]] \
        || die "b2 broker changed ($BROKER_BEFORE -> $BROKER_AFTER)"
    FINAL_LINES=$(count_lines)
    (( FINAL_LINES > BASELINE && FINAL_LINES <= BASELINE + 6 )) || {
        die "b2 unexpected ssh invocation count ($BASELINE -> $FINAL_LINES)"
    }
    kill -TERM "$SESSION_PID" 2>/dev/null || :
    "$TIMEOUT" 15s "$BASH" -c 'while kill -0 "$1" 2>/dev/null; do sleep 0.1; done' _ "$SESSION_PID"
    "$PRINTF" 'everssh composed B2 terminal fallback: PASS\n'
fi
