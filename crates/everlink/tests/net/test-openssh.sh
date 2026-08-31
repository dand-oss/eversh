#!/usr/bin/bash
set -Eeuo pipefail

# Slice 5A exercises two production OpenSSH ProxyCommand sessions (status 0,
# then status 42) while keeping every process, key, and diagnostic artifact
# owned by this bounded harness.

readonly BASH_TOOL=/usr/bin/bash
readonly CHMOD_TOOL=/usr/bin/chmod
readonly CMP_TOOL=/usr/bin/cmp
readonly ID_TOOL=/usr/bin/id
readonly IP_TOOL=/usr/sbin/ip
readonly MKDIR_TOOL=/usr/bin/mkdir
readonly PRINTF_TOOL=/usr/bin/printf
readonly MKtemp_TOOL=/usr/bin/mktemp
readonly READLINK_TOOL=/usr/bin/readlink
readonly RM_TOOL=/usr/bin/rm
readonly SLEEP_TOOL=/usr/bin/sleep
readonly SORT_TOOL=/usr/bin/sort
readonly SS_TOOL=/usr/bin/ss
readonly SSH_TOOL=/usr/bin/ssh
readonly SSHD_EXE=/usr/sbin/sshd
readonly SSHKEYGEN_TOOL=/usr/bin/ssh-keygen
readonly SSHKEYSCAN_TOOL=/usr/bin/ssh-keyscan
readonly STAT_TOOL=/usr/bin/stat
readonly SETSID_TOOL=/usr/bin/setsid
readonly TIMEOUT_TOOL=/usr/bin/timeout
readonly AWK_TOOL=/usr/bin/awk
readonly CAT_TOOL=/usr/bin/cat
readonly DD_TOOL=/usr/bin/dd
readonly HEAD_TOOL=/usr/bin/head
readonly LN_TOOL=/usr/bin/ln
readonly MV_TOOL=/usr/bin/mv
readonly ENV_TOOL=/usr/bin/env
# 2*15s SSH sessions + 2*35s server polls + startup/health checks and
# bounded failure cleanup, with finite headroom for the two-session run.
readonly WATCHDOG_SECONDS=150
readonly POLL_SECONDS=5
readonly SERVER_POLL_SECONDS=35
readonly READINESS_POLL_ATTEMPTS=60
readonly OPERATION_TIMEOUT_SECONDS=4
readonly SSH_SESSION_TIMEOUT_SECONDS=15

for tool in "$BASH_TOOL" "$CHMOD_TOOL" "$CMP_TOOL" "$ID_TOOL" "$IP_TOOL" \
    "$MKDIR_TOOL" "$MKtemp_TOOL" "$PRINTF_TOOL" "$READLINK_TOOL" "$RM_TOOL" \
    "$SLEEP_TOOL" "$SORT_TOOL" "$SS_TOOL" "$SSH_TOOL" "$SSHD_EXE" \
    "$SSHKEYGEN_TOOL" "$SSHKEYSCAN_TOOL" "$STAT_TOOL" "$SETSID_TOOL" \
    "$TIMEOUT_TOOL" "$AWK_TOOL" "$CAT_TOOL" "$DD_TOOL" "$HEAD_TOOL" \
    "$LN_TOOL" "$MV_TOOL" "$ENV_TOOL"; do
    [[ -x "$tool" ]] || {
        printf 'missing required executable\n' >&2
        exit 1
    }
done

SCRIPT_PATH=$("$READLINK_TOOL" -e -- "${BASH_SOURCE[0]}") || {
    printf 'cannot resolve test script\n' >&2
    exit 1
}
[[ -x "$SCRIPT_PATH" ]] || {
    printf 'test script is not executable\n' >&2
    exit 1
}

WATCHDOG_CHILD=0
if [[ ${1-} == --watchdog-child ]]; then
    WATCHDOG_CHILD=1
    shift
fi

MODE=parent
if [[ ${1-} == --signal-probe ]]; then
    MODE=child
    [[ $# -eq 3 ]] || {
        printf 'invalid signal probe arguments\n' >&2
        exit 1
    }
    PROBE_REPORT=$2
    PROBE_RELEASE=$3
elif [[ $# -ne 0 ]]; then
    printf 'unexpected arguments\n' >&2
    exit 1
fi

# These variables are initialized before traps so a signal during startup is safe.
CLEANUP_DONE=0
TMP_ROOT=
OWN_PID=
OWN_START=
OWN_EXE=
OWN_PGRP=
OWN_ROLE=
CHILD_PID=
CHILD_START=
CHILD_EXE=
CHILD_PGRP=
CHILD_ROLE=
CHILD_FINISHED=0
CHILD_ROOT=
CHILD_SLEEP_PID=
CHILD_SLEEP_START=
CHILD_SLEEP_EXE=
CHILD_SLEEP_PGRP=
BASELINE_PIDS=()
ISOLATED_ADDR=
ISOLATED_PORT=
ISOLATED_SERVER=0
SSHD_CONFIG=
SSHD_LOG=
SSHD_PID_FILE=
SSHD_HOST_KEY=
SSHD_CLIENT_KEY=
SSHD_AUTHORIZED_KEYS=
SSHD_KNOWN_HOSTS=
SSHD_EXPECTED_OUTPUT=
SSHD_REMOTE_BIN=
CURRENT_USER=
WORKSPACE_ROOT=
EVERLINK_EXE=
SSHD_HOST_BLOB=
SERVER_PID=
SERVER_START=
SERVER_EXE=
SERVER_PGRP=
SERVER_ROLE=
SSH_ALIAS=everlink-slice5a-alias
SSH_SHIM_DIR=
SSH_SHIM=
SSH_QUERY_ARGV=
SSH_BOOTSTRAP_ARGV=
SSH_QUERY_OUTPUT=
SSH_INNER_CONFIG=
SSH_OUTER_CONFIG=
SSH_SERVER_IDENTITY=
BASELINE_STARTS=()
BASELINE_EXES=()
BASELINE_PGRPS=()

capture_identity() {
    local pid=$1 line suffix state ppid pgrp session tty_nr tpgid flags minflt
    local cminflt majflt cmajflt utime stime cutime cstime priority nice
    local num_threads itrealvalue starttime remainder

    CAP_STATE=
    CAP_START=
    CAP_EXE=
    CAP_PGRP=
    [[ $pid =~ ^[0-9]+$ ]] || return 1
    [[ -r "/proc/$pid/stat" ]] || return 1
    if ! IFS= read -r line 2>/dev/null < "/proc/$pid/stat"; then
        return 1
    fi
    suffix=${line##*) }
    [[ $suffix != "$line" ]] || return 1
    read -r state ppid pgrp session tty_nr tpgid flags minflt cminflt \
        majflt cmajflt utime stime cutime cstime priority nice num_threads \
        itrealvalue starttime remainder <<< "$suffix" || return 1
    [[ $state =~ ^[[:alpha:]]$ ]] || return 1
    [[ $pgrp =~ ^[0-9]+$ && $starttime =~ ^[0-9]+$ ]] || return 1
    CAP_STATE=$state
    CAP_START=$starttime
    CAP_PGRP=$pgrp
    CAP_EXE=$("$READLINK_TOOL" -e -- "/proc/$pid/exe" 2>/dev/null) || return 1
    [[ -n $CAP_EXE ]] || return 1
}

# Return 0 for an exact owned tuple, 2 for disappearance, and 1 for mismatch.
validate_owned() {
    local pid=$1 expected_start=$2 expected_exe=$3 expected_pgrp=$4
    local expected_role=$5
    if ! capture_identity "$pid"; then
        if [[ ! -e "/proc/$pid/stat" || ${CAP_STATE:-} == Z ]]; then
            return 2
        fi
        return 1
    fi
    [[ $CAP_START == "$expected_start" ]] || return 1
    [[ $CAP_EXE == "$expected_exe" ]] || return 1
    [[ $CAP_PGRP == "$expected_pgrp" ]] || return 1
    [[ $expected_role != '' ]] || return 1
    [[ $CAP_STATE != Z ]] || return 2
    return 0
}

validate_temp_target() {
    local path=$1 canonical mode
    [[ -n $path && $path == /tmp/everlink-slice5a.* && -d $path ]] || return 1
    canonical=$("$READLINK_TOOL" -e -- "$path") || return 1
    [[ $canonical == "$path" && $canonical != /tmp && $canonical != / ]] || return 1
    mode=$("$STAT_TOOL" -c '%a' -- "$path") || return 1
    [[ $mode == 700 ]]
}

remove_temp_root() {
    local path=$1 rc=0
    if [[ -z $path ]]; then
        return 0
    fi
    if ! validate_temp_target "$path"; then
        [[ ! -e $path ]] || rc=1
    fi
    if [[ $rc -eq 0 && -e $path ]]; then
        "$RM_TOOL" -rf -- "$path" || rc=1
    fi
    [[ ! -e $path ]] || rc=1
    return "$rc"
}

run_bounded() {
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=1s "${OPERATION_TIMEOUT_SECONDS}s" "$@"
}

verify_current_binary() {
    local binary_mtime input input_mtime
    WORKSPACE_ROOT=${SCRIPT_PATH%/crates/everlink/tests/net/test-openssh.sh}
    EVERLINK_EXE="$WORKSPACE_ROOT/target/debug/everlink"
    [[ "$SCRIPT_PATH" == "$WORKSPACE_ROOT/crates/everlink/tests/net/test-openssh.sh" ]] || return 1
    [[ -x "$EVERLINK_EXE" ]] || return 1
    [[ "$($READLINK_TOOL -e -- "$EVERLINK_EXE")" == "$EVERLINK_EXE" ]] || return 1
    binary_mtime=$($STAT_TOOL -c '%Y' -- "$EVERLINK_EXE") || return 1
    for input in "$WORKSPACE_ROOT/Cargo.toml" \
        "$WORKSPACE_ROOT/Cargo.lock" "$WORKSPACE_ROOT/crates/everlink/Cargo.toml" \
        "$WORKSPACE_ROOT/crates/everpty/Cargo.toml" "$WORKSPACE_ROOT/crates/eversh/Cargo.toml" \
        "$WORKSPACE_ROOT"/crates/everlink/src/*.rs; do
        [[ -f "$input" ]] || return 1
        input_mtime=$($STAT_TOOL -c '%Y' -- "$input") || return 1
        (( binary_mtime > input_mtime )) || return 1
    done
}

valid_ipv4_literal() {
    local value=$1 part number
    local -a octets=()
    IFS=. read -r -a octets <<< "$value"
    [[ ${#octets[@]} -eq 4 ]] || return 1
    for part in "${octets[@]}"; do
        [[ $part =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
        number=$((10#$part))
        (( number <= 255 )) || return 1
    done
}

select_nonloopback_address() {
    local records record cidr candidate broadcast route_output
    IP_RECORDS=$(run_bounded "$IP_TOOL" -o -4 addr show scope global \
        | "$AWK_TOOL" '{ broadcast=""; for (i=1; i<=NF; i++) if ($i == "brd") broadcast=$(i+1); print $4 "|" broadcast }' \
        | "$SORT_TOOL" -t '|' -k1,1) || return 1
    [[ -n $IP_RECORDS ]] || return 1
    while IFS='|' read -r record broadcast; do
        cidr=$record
        candidate=${cidr%/*}
        [[ $candidate != "$cidr" ]] || continue
        valid_ipv4_literal "$candidate" || continue
        local -a octets=()
        IFS=. read -r -a octets <<< "$candidate"
        (( 10#${octets[0]} != 0 && 10#${octets[0]} != 127 && 10#${octets[0]} < 224 )) || continue
        [[ $candidate != 255.255.255.255 && $candidate != "$broadcast" ]] || continue
        route_output=$(run_bounded "$IP_TOOL" route get "$candidate") || return 1
        [[ " $route_output " == *" src $candidate "* ]] || return 1
        ISOLATED_ADDR=$candidate
        return 0
    done <<< "$IP_RECORDS"
    return 1
}

listener_conflict() {
    local address=$1 port=$2
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=1s 2s "$SS_TOOL" -H -4 -ltn \
        | "$AWK_TOOL" -v exact="$address:$port" -v wildcard="0.0.0.0:$port" \
            -v any="*:$port" '$4 == exact || $4 == wildcard || $4 == any { found=1 } END { exit !found }'
}

listener_exact() {
    local address=$1 port=$2
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=1s 2s "$SS_TOOL" -H -4 -ltn \
        | "$AWK_TOOL" -v exact="$address:$port" '$4 == exact { found=1 } END { exit !found }'
}

port_free_for_both() {
    local port=$1
    ! listener_conflict "$ISOLATED_ADDR" "$port" \
        && ! listener_conflict 127.0.0.1 "$port"
}

select_free_port() {
    local attempt port
    for ((attempt = 0; attempt < 100; attempt++)); do
        port=$((40000 + RANDOM % 20000))
        if port_free_for_both "$port"; then
            ISOLATED_PORT=$port
            return 0
        fi
    done
    return 1
}

tcp_connect() {
    local address=$1 port=$2
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=1s 3s "$BASH_TOOL" -c \
        'set -e; exec 3<>"/dev/tcp/$1/$2"; exec 3>&-' -- "$address" "$port" \
        >/dev/null 2>&1
}

listeners_gone() {
    ! listener_conflict "$ISOLATED_ADDR" "$ISOLATED_PORT" \
        && ! listener_conflict 127.0.0.1 "$ISOLATED_PORT" \
        && ! tcp_connect 127.0.0.1 "$ISOLATED_PORT"
}

poll_listeners_gone() {
    local deadline=$((SECONDS + POLL_SECONDS))
    while (( SECONDS < deadline )); do
        listeners_gone && return 0
        "$TIMEOUT_TOOL" 1s "$SLEEP_TOOL" 0.05
    done
    return 1
}

group_empty() {
    local wanted=$1 proc pid line suffix state ppid pgrp rest
    [[ $wanted =~ ^[0-9]+$ ]] || return 1
    for proc in /proc/[0-9]*; do
        [[ -r "$proc/stat" ]] || continue
        pid=${proc##*/}
        if ! IFS= read -r line < "$proc/stat"; then
            continue
        fi
        suffix=${line##*) }
        [[ $suffix != "$line" ]] || continue
        read -r state ppid pgrp rest <<< "$suffix" || continue
        [[ $pgrp == "$wanted" ]] || continue
        # A member remaining in the group is a leak, regardless of its name.
        return 1
    done
    return 0
}

poll_owned_gone() {
    local pid=$1 start=$2 exe=$3 pgrp=$4 role=$5
    local deadline=$((SECONDS + POLL_SECONDS)) result
    while (( SECONDS < deadline )); do
        if validate_owned "$pid" "$start" "$exe" "$pgrp" "$role"; then
            "$SLEEP_TOOL" 0.05
            continue
        else
            result=$?
        fi
        [[ $result -eq 2 ]] && return 0
        return 1
    done
    return 1
}

poll_server_gone() {
    local pid=$1 start=$2 exe=$3 pgrp=$4 role=$5
    local deadline=$((SECONDS + SERVER_POLL_SECONDS)) result
    while (( SECONDS < deadline )); do
        if validate_owned "$pid" "$start" "$exe" "$pgrp" "$role"; then
            "$SLEEP_TOOL" 0.05
            continue
        else
            result=$?
        fi
        [[ $result -eq 2 ]] && return 0
        return 1
    done
    return 1
}

poll_group_empty() {
    local pgrp=$1 deadline=$((SECONDS + POLL_SECONDS))
    while (( SECONDS < deadline )); do
        group_empty "$pgrp" && return 0
        "$SLEEP_TOOL" 0.05
    done
    return 1
}

# Reap only a known background child after a fresh terminal-identity check.
reap_owned_child() {
    local pid=$1 start=$2 exe=$3 pgrp=$4 role=$5 result
    if validate_owned "$pid" "$start" "$exe" "$pgrp" "$role"; then
        return 1
    else
        result=$?
    fi
    [[ $result -eq 2 ]] || return 1
    if ! builtin wait "$pid" 2>/dev/null; then
        :
    fi
}

# Signal and reap only after validating the complete recorded tuple.
cleanup_owned() {
    local pid=$1 start=$2 exe=$3 pgrp=$4 role=$5
    local result rc=0 term_sent=0
    [[ -n $pid ]] || return 0

    if validate_owned "$pid" "$start" "$exe" "$pgrp" "$role"; then
        if builtin kill -TERM "$pid" 2>/dev/null; then
            term_sent=1
        elif validate_owned "$pid" "$start" "$exe" "$pgrp" "$role"; then
            rc=1
        else
            result=$?
            [[ $result -eq 2 ]] || rc=1
        fi
    else
        result=$?
        [[ $result -eq 2 ]] || rc=1
    fi

    if (( term_sent )); then
        if ! poll_owned_gone "$pid" "$start" "$exe" "$pgrp" "$role"; then
            if validate_owned "$pid" "$start" "$exe" "$pgrp" "$role"; then
                if builtin kill -KILL "$pid" 2>/dev/null; then
                    if ! poll_owned_gone "$pid" "$start" "$exe" "$pgrp" "$role"; then
                        rc=1
                    fi
                elif validate_owned "$pid" "$start" "$exe" "$pgrp" "$role"; then
                    rc=1
                else
                    result=$?
                    [[ $result -eq 2 ]] || rc=1
                fi
            else
                result=$?
                [[ $result -eq 2 ]] || rc=1
            fi
        fi
    fi

    if ! reap_owned_child "$pid" "$start" "$exe" "$pgrp" "$role"; then
        rc=1
    fi
    poll_group_empty "$pgrp" || rc=1
    return "$rc"
}

start_sleep() {
    local role=$1 pid i
    "$SETSID_TOOL" "$SLEEP_TOOL" 30 &
    pid=$!
    for ((i = 0; i < READINESS_POLL_ATTEMPTS; i++)); do
        if capture_identity "$pid" && [[ $CAP_EXE == "$SLEEP_TOOL" ]]; then
            # setsid can briefly expose the exec transition before installing
            # the new group; wait for the complete isolated identity.
            OWN_PID=$pid
            OWN_START=$CAP_START
            OWN_EXE=$CAP_EXE
            OWN_PGRP=$CAP_PGRP
            OWN_ROLE=$role
            [[ $CAP_PGRP == "$pid" ]] && return 0
        fi
        "$SLEEP_TOOL" 0.05
    done
    return 1
}

snapshot_baseline() {
    local proc pid
    BASELINE_PIDS=()
    BASELINE_STARTS=()
    BASELINE_EXES=()
    BASELINE_PGRPS=()
    for proc in /proc/[0-9]*; do
        [[ -r "$proc/stat" ]] || continue
        pid=${proc##*/}
        if capture_identity "$pid" && [[ $CAP_EXE == "$SSHD_EXE" ]]; then
            BASELINE_PIDS+=("$pid")
            BASELINE_STARTS+=("$CAP_START")
            BASELINE_EXES+=("$CAP_EXE")
            BASELINE_PGRPS+=("$CAP_PGRP")
        fi
    done
}

verify_baseline() {
    local i result
    for ((i = 0; i < ${#BASELINE_PIDS[@]}; i++)); do
        if validate_owned "${BASELINE_PIDS[i]}" "${BASELINE_STARTS[i]}" \
            "${BASELINE_EXES[i]}" "${BASELINE_PGRPS[i]}" baseline-sshd; then
            :
        else
            result=$?
            printf 'baseline sshd identity changed or disappeared\n' >&2
            return "$result"
        fi
    done
}

run_child_probe() {
    local i result child_status
    PROBE_REPORT="$TMP_ROOT/signal-report"
    PROBE_RELEASE="$TMP_ROOT/signal-release"
    "$BASH_TOOL" "$SCRIPT_PATH" --watchdog-child --signal-probe "$PROBE_REPORT" "$PROBE_RELEASE" &
    CHILD_PID=$!
    for ((i = 0; i < READINESS_POLL_ATTEMPTS; i++)); do
        if capture_identity "$CHILD_PID"; then
            CHILD_START=$CAP_START
            CHILD_EXE=$CAP_EXE
            CHILD_PGRP=$CAP_PGRP
            CHILD_ROLE=signal-probe
            break
        fi
        "$SLEEP_TOOL" 0.05
    done
    [[ -n $CHILD_START && $CHILD_EXE == "$BASH_TOOL" ]] || return 1
    for ((i = 0; i < READINESS_POLL_ATTEMPTS; i++)); do
        [[ -s $PROBE_REPORT ]] && break
        "$SLEEP_TOOL" 0.05
    done
    [[ -s $PROBE_REPORT ]] || return 1
    mapfile -t probe_lines < "$PROBE_REPORT"
    [[ ${#probe_lines[@]} -eq 5 ]] || return 1
    CHILD_SLEEP_PID=${probe_lines[0]}
    CHILD_SLEEP_START=${probe_lines[1]}
    CHILD_SLEEP_EXE=${probe_lines[2]}
    CHILD_SLEEP_PGRP=${probe_lines[3]}
    CHILD_ROOT=${probe_lines[4]}
    [[ $CHILD_SLEEP_PID =~ ^[0-9]+$ && $CHILD_SLEEP_START =~ ^[0-9]+$ ]] || return 1
    [[ $CHILD_SLEEP_EXE == "$SLEEP_TOOL" && $CHILD_SLEEP_PGRP == "$CHILD_SLEEP_PID" ]] || return 1
    [[ $CHILD_ROOT == /tmp/everlink-slice5a.* ]] || return 1

    # Release the child only after the parent has recorded and checked its tuple.
    if ! validate_owned "$CHILD_PID" "$CHILD_START" "$CHILD_EXE" "$CHILD_PGRP" "$CHILD_ROLE"; then
        return 1
    fi
    printf 'release\n' > "$PROBE_RELEASE"
    if ! poll_owned_gone "$CHILD_PID" "$CHILD_START" "$CHILD_EXE" "$CHILD_PGRP" "$CHILD_ROLE"; then
        printf 'signal probe child did not exit in time\n' >&2
        return 1
    fi
    if validate_owned "$CHILD_PID" "$CHILD_START" "$CHILD_EXE" "$CHILD_PGRP" "$CHILD_ROLE"; then
        printf 'signal probe child is still live\n' >&2
        return 1
    else
        result=$?
        [[ $result -eq 2 ]] || return 1
    fi
    child_status=0
    builtin wait "$CHILD_PID" 2>/dev/null || child_status=$?
    [[ $child_status -eq 143 ]] || return 1
    CHILD_FINISHED=1
    [[ ! -e /proc/$CHILD_PID/stat ]] || return 1
    [[ ! -e /proc/$CHILD_SLEEP_PID/stat ]] || return 1
    poll_group_empty "$CHILD_SLEEP_PGRP" || return 1
    [[ ! -e $CHILD_ROOT ]] || return 1
}

clear_owned() {
    OWN_PID=
    OWN_START=
    OWN_EXE=
    OWN_PGRP=
    OWN_ROLE=
}

clear_server_tuple() {
    SERVER_PID=
    SERVER_START=
    SERVER_EXE=
    SERVER_PGRP=
    SERVER_ROLE=
}

prepare_isolated_sshd() {
    local host_blob derived_blob
    (( EUID != 0 )) || return 1
    CURRENT_USER=$(run_bounded "$ID_TOOL" -un) || return 1
    [[ $CURRENT_USER =~ ^[A-Za-z0-9._-]+$ ]] || return 1
    SSHD_CONFIG="$TMP_ROOT/sshd/sshd_config"
    SSHD_LOG="$TMP_ROOT/sshd/sshd.log"
    SSHD_PID_FILE="$TMP_ROOT/sshd/sshd.pid"
    SSHD_HOST_KEY="$TMP_ROOT/sshd/host_ed25519"
    SSHD_CLIENT_KEY="$TMP_ROOT/sshd/client_ed25519"
    SSHD_AUTHORIZED_KEYS="$TMP_ROOT/sshd/authorized_keys"
    SSHD_KNOWN_HOSTS="$TMP_ROOT/sshd/known_hosts"
    SSHD_EXPECTED_OUTPUT="$TMP_ROOT/sshd/expected-output"
    SSHD_REMOTE_BIN="$TMP_ROOT/remote-bin"
    "$MKDIR_TOOL" -m 700 -- "$TMP_ROOT/sshd" "$SSHD_REMOTE_BIN" || return 1
    "$LN_TOOL" -s -- "$EVERLINK_EXE" "$SSHD_REMOTE_BIN/everlink" || return 1
    [[ "$($READLINK_TOOL -e -- "$SSHD_REMOTE_BIN/everlink")" == "$EVERLINK_EXE" ]] || return 1
    : > "$SSHD_LOG"
    "$CHMOD_TOOL" 600 -- "$SSHD_LOG" || return 1
    run_bounded "$SSHKEYGEN_TOOL" -q -t ed25519 -N '' -f "$SSHD_HOST_KEY" >/dev/null 2>&1 || return 1
    run_bounded "$SSHKEYGEN_TOOL" -q -t ed25519 -N '' -f "$SSHD_CLIENT_KEY" >/dev/null 2>&1 || return 1
    "$CHMOD_TOOL" 600 -- "$SSHD_HOST_KEY" "$SSHD_CLIENT_KEY" \
        "$SSHD_HOST_KEY.pub" "$SSHD_CLIENT_KEY.pub" || return 1
    "$CHMOD_TOOL" 600 -- "$SSHD_CLIENT_KEY.pub" || return 1
    "$RM_TOOL" -f -- "$SSHD_AUTHORIZED_KEYS" || return 1
    "$BASH_TOOL" -c 'printf "%s\\n" "$(<"$1")" > "$2"' -- \
        "$SSHD_CLIENT_KEY.pub" "$SSHD_AUTHORIZED_KEYS" || return 1
    "$CHMOD_TOOL" 600 -- "$SSHD_AUTHORIZED_KEYS" || return 1
    host_blob=$("$AWK_TOOL" 'NF >= 2 { print $2; exit }' "$SSHD_HOST_KEY.pub") || return 1
    derived_blob=$(run_bounded "$SSHKEYGEN_TOOL" -y -f "$SSHD_HOST_KEY" \
        | "$AWK_TOOL" 'NF >= 2 { print $2; exit }') || return 1
    [[ -n $host_blob && $host_blob == "$derived_blob" ]] || return 1
    SSHD_HOST_BLOB=$derived_blob
    select_free_port || return 1

    # The validated mode-0700 root and mode-0600 files are beneath /tmp,
    # whose required sticky mode makes StrictModes reject the path itself.
    printf '%s\n' \
        "Port $ISOLATED_PORT" \
        "ListenAddress $ISOLATED_ADDR:$ISOLATED_PORT" \
        "ListenAddress 127.0.0.1:$ISOLATED_PORT" \
        "HostKey $SSHD_HOST_KEY" \
        "PidFile $SSHD_PID_FILE" \
        "AuthorizedKeysFile $SSHD_AUTHORIZED_KEYS" \
        "AllowUsers $CURRENT_USER" \
        "SetEnv PATH=$SSHD_REMOTE_BIN:/usr/bin:/bin" \
        'AuthenticationMethods publickey' \
        'PubkeyAuthentication yes' \
        'PasswordAuthentication no' \
        'KbdInteractiveAuthentication no' \
        'ChallengeResponseAuthentication no' \
        'PermitEmptyPasswords no' \
        'PermitRootLogin no' \
        'UsePAM no' \
        'StrictModes no' \
        'X11Forwarding no' \
        'AllowAgentForwarding no' \
        'PermitTunnel no' \
        'PermitTTY no' \
        'AllowTcpForwarding local' \
        'PermitOpen 127.0.0.1:*' \
        'GatewayPorts no' \
        'UseDNS no' \
        'PermitUserEnvironment no' \
        'PermitUserRC no' > "$SSHD_CONFIG"
    "$CHMOD_TOOL" 600 -- "$SSHD_CONFIG" || return 1
    run_bounded "$SSHD_EXE" -t -f "$SSHD_CONFIG" >/dev/null 2>"$SSHD_LOG" || return 1
}

record_captured_identity() {
    local pid=$1 role=$2
    OWN_PID=$pid
    OWN_START=$CAP_START
    OWN_EXE=$CAP_EXE
    OWN_PGRP=$CAP_PGRP
    OWN_ROLE=$role
}

process_terminal() {
    local pid=$1 line suffix state ppid pgrp rest
    [[ -e "/proc/$pid/stat" ]] || return 0
    [[ -r "/proc/$pid/stat" ]] || return 1
    if ! IFS= read -r line < "/proc/$pid/stat"; then
        return 1
    fi
    suffix=${line##*) }
    [[ $suffix != "$line" ]] || return 1
    read -r state ppid pgrp rest <<< "$suffix" || return 1
    [[ $state == Z ]]
}

# The PID is a known background child; only reap it after it is absent or a
# zombie, never an unverified live process.
reap_terminal_child() {
    local pid=$1
    process_terminal "$pid" || return 1
    if ! builtin wait "$pid" 2>/dev/null; then
        :
    fi
    [[ ! -e "/proc/$pid/stat" ]]
}

# A failed exec/readiness path still owns the exact spawned PID.  Capture a
# final complete tuple when it is live; otherwise prove terminality and reap it.
settle_failed_sshd() {
    local pid=$1 deadline=$((SECONDS + POLL_SECONDS))
    while (( SECONDS < deadline )); do
        if capture_identity "$pid"; then
            record_captured_identity "$pid" isolated-sshd-startup
            if [[ $CAP_STATE == Z ]]; then
                if reap_owned_child "$OWN_PID" "$OWN_START" "$OWN_EXE" \
                    "$OWN_PGRP" "$OWN_ROLE"; then
                    clear_owned
                    return 0
                fi
                return 1
            fi
            # Do not accept an unexpected live executable as sshd.  It is
            # nevertheless owned by its exact PID/start/group tuple for EXIT.
            return 1
        fi
        if reap_terminal_child "$pid"; then
            return 0
        fi
        "$SLEEP_TOOL" 0.05
    done
    if capture_identity "$pid"; then
        record_captured_identity "$pid" isolated-sshd-startup
        return 1
    fi
    reap_terminal_child "$pid"
}

wait_for_sshd() {
    local i pid=$1
    for ((i = 0; i < READINESS_POLL_ATTEMPTS; i++)); do
        if capture_identity "$pid" && [[ $CAP_EXE == "$SSHD_EXE" ]]; then
            record_captured_identity "$pid" isolated-sshd
            ISOLATED_SERVER=1
            if [[ $CAP_STATE != Z && $CAP_PGRP == "$pid" && -f $SSHD_PID_FILE ]] \
                && [[ $(<"$SSHD_PID_FILE") == "$pid" ]]; then
                return 0
            fi
        fi
        "$TIMEOUT_TOOL" 1s "$SLEEP_TOOL" 0.05
    done
    return 1
}

start_isolated_sshd() {
    local pid
    : > "$SSHD_PID_FILE"
    "$CHMOD_TOOL" 600 -- "$SSHD_PID_FILE" || return 1
    port_free_for_both "$ISOLATED_PORT" || return 1
    "$SETSID_TOOL" "$SSHD_EXE" -D -e -f "$SSHD_CONFIG" -E "$SSHD_LOG" \
        </dev/null >/dev/null 2>>"$SSHD_LOG" &
    pid=$!
    if wait_for_sshd "$pid"; then
        return 0
    fi
    [[ -n $OWN_PID ]] || settle_failed_sshd "$pid"
    return 1
}

wait_for_listeners() {
    local i
    for ((i = 0; i < 8; i++)); do
        if listener_exact "$ISOLATED_ADDR" "$ISOLATED_PORT" \
            && listener_exact 127.0.0.1 "$ISOLATED_PORT" \
            && tcp_connect "$ISOLATED_ADDR" "$ISOLATED_PORT"; then
            return 0
        fi
        "$TIMEOUT_TOOL" 1s "$SLEEP_TOOL" 0.05
    done
    return 1
}

make_known_hosts() {
    local output keyscan_status keyscan_blob expected count address
    KEYSCAN_ERR="$TMP_ROOT/sshd/keyscan.stderr"
    : > "$KEYSCAN_ERR"
    "$CHMOD_TOOL" 600 -- "$KEYSCAN_ERR" || return 1
    set +e
    output=$(run_bounded "$SSHKEYSCAN_TOOL" -4 -T 2 -p "$ISOLATED_PORT" \
        -t ed25519 127.0.0.1 "$ISOLATED_ADDR" 2>"$KEYSCAN_ERR")
    keyscan_status=$?
    set -e
    (( keyscan_status == 0 )) || return 1
    [[ -n $output && ! -s $KEYSCAN_ERR ]] || return 1
    printf '%s\n' "$output" > "$SSHD_KNOWN_HOSTS"
    "$CHMOD_TOOL" 600 -- "$SSHD_KNOWN_HOSTS" || return 1
    count=$(printf '%s\n' "$output" \
        | "$AWK_TOOL" '$2 == "ssh-ed25519" { count++ } END { print count + 0 }') || return 1
    [[ $count == 2 ]] || return 1
    for address in 127.0.0.1 "$ISOLATED_ADDR"; do
        expected="[$address]:$ISOLATED_PORT"
        keyscan_blob=$(printf '%s\n' "$output" \
            | "$AWK_TOOL" -v expected="$expected" \
                '$1 == expected && $2 == "ssh-ed25519" { print $3; exit }') || return 1
        [[ -n $keyscan_blob && $keyscan_blob == "$SSHD_HOST_BLOB" ]] || return 1
    done
}

write_ssh_configs_and_shim() {
    local session_number=$1
    SSH_SHIM_DIR="$TMP_ROOT/ssh-shim-$session_number"
    SSH_SHIM="$SSH_SHIM_DIR/ssh"
    SSH_QUERY_ARGV="$SSH_SHIM_DIR/query.argv"
    SSH_BOOTSTRAP_ARGV="$SSH_SHIM_DIR/bootstrap.argv"
    SSH_QUERY_OUTPUT="$SSH_SHIM_DIR/query.stdout"
    SSH_INNER_CONFIG="$SSH_SHIM_DIR/inner_config"
    SSH_OUTER_CONFIG="$SSH_SHIM_DIR/outer_config"
    SSH_SERVER_IDENTITY="$SSH_SHIM_DIR/server.identity"
    "$MKDIR_TOOL" -m 700 -- "$SSH_SHIM_DIR" || return 1

    {
        printf '%s\n' '#!/usr/bin/bash' "readonly SHIM_DIR=$SSH_SHIM_DIR"
        "$CAT_TOOL" <<'SHIM'
set -Eeuo pipefail

readonly REAL_SSH=/usr/bin/ssh
readonly CAT_TOOL=/usr/bin/cat
readonly CHMOD_TOOL=/usr/bin/chmod
readonly DD_TOOL=/usr/bin/dd
readonly HEAD_TOOL=/usr/bin/head
readonly MV_TOOL=/usr/bin/mv
readonly READLINK_TOOL=/usr/bin/readlink
readonly RM_TOOL=/usr/bin/rm
readonly STAT_TOOL=/usr/bin/stat
readonly QUERY_ARGV="$SHIM_DIR/query.argv"
readonly BOOTSTRAP_ARGV="$SHIM_DIR/bootstrap.argv"
readonly QUERY_OUTPUT="$SHIM_DIR/query.stdout"
readonly SERVER_IDENTITY="$SHIM_DIR/server.identity"
readonly BOOTSTRAP_COMMAND='everlink __bootstrap-parent-v1'

write_argv() {
    local path=$1 tmp
    shift
    tmp="${path}.tmp.$$"
    [[ ! -e $path && ! -e $tmp ]] || exit 1
    umask 077
    printf '%s\0' "$@" > "$tmp" || exit 1
    "$CHMOD_TOOL" 600 -- "$tmp" || exit 1
    "$MV_TOOL" -f -- "$tmp" "$path" || exit 1
}

capture_server_identity() {
    local pid=$1 line suffix state ppid pgrp session tty_nr tpgid flags minflt
    local cminflt majflt cmajflt utime stime cutime cstime priority nice
    local num_threads itrealvalue starttime remainder exe tmp
    [[ $pid =~ ^[1-9][0-9]*$ && -r "/proc/$pid/stat" ]] || exit 1
    IFS= read -r line < "/proc/$pid/stat" || exit 1
    suffix=${line##*) }
    [[ $suffix != "$line" ]] || exit 1
    read -r state ppid pgrp session tty_nr tpgid flags minflt cminflt \
        majflt cmajflt utime stime cutime cstime priority nice num_threads \
        itrealvalue starttime remainder <<< "$suffix" || exit 1
    [[ $state != Z && $pgrp =~ ^[1-9][0-9]*$ && $starttime =~ ^[1-9][0-9]*$ ]] || exit 1
    exe=$("$READLINK_TOOL" -e -- "/proc/$pid/exe") || exit 1
    [[ -n $exe ]] || exit 1
    tmp="${SERVER_IDENTITY}.tmp.$$"
    printf '%s\n%s\n%s\n%s\ndetached-everlink-server\n' \
        "$pid" "$starttime" "$exe" "$pgrp" > "$tmp" || exit 1
    "$CHMOD_TOOL" 600 -- "$tmp" || exit 1
    "$MV_TOOL" -f -- "$tmp" "$SERVER_IDENTITY" || exit 1
}

g_count=0
bootstrap_count=0
for argument in "$@"; do
    [[ $argument == -G ]] && ((g_count += 1))
    [[ $argument == "$BOOTSTRAP_COMMAND" ]] && ((bootstrap_count += 1))
done
if (( g_count == 1 )); then
    (( bootstrap_count == 0 )) || exit 1
    write_argv "$QUERY_ARGV" "$@"
    output_tmp="${QUERY_OUTPUT}.tmp.$$"
    [[ ! -e $QUERY_OUTPUT && ! -e $output_tmp ]] || exit 1
    umask 077
    : > "$output_tmp"
    "$CHMOD_TOOL" 600 -- "$output_tmp" || exit 1
    set +e
    "$REAL_SSH" "$@" | "$DD_TOOL" bs=1 count=65537 status=none > "$output_tmp"
    pipeline_status=$?
    set -e
    output_size=$("$STAT_TOOL" -c '%s' -- "$output_tmp") || exit 1
    (( pipeline_status == 0 && output_size <= 65536 )) || {
        "$RM_TOOL" -f -- "$output_tmp"
        exit 1
    }
    "$MV_TOOL" -f -- "$output_tmp" "$QUERY_OUTPUT" || exit 1
    "$CHMOD_TOOL" 600 -- "$QUERY_OUTPUT" || exit 1
    exec "$CAT_TOOL" "$QUERY_OUTPUT"
fi

(( g_count == 0 && bootstrap_count == 1 )) || exit 1
[[ ${!#} == "$BOOTSTRAP_COMMAND" ]] || exit 1
write_argv "$BOOTSTRAP_ARGV" "$@"
set +e
bootstrap_capture=$(
    "$REAL_SSH" "$@" | "$HEAD_TOOL" -c 201
    printf '%s\n' "${PIPESTATUS[0]}"
)
capture_status=$?
set -e
(( capture_status == 0 )) || exit 1
bootstrap_lines=()
mapfile -t bootstrap_lines <<< "$bootstrap_capture"
[[ ${#bootstrap_lines[@]} -eq 2 && ${bootstrap_lines[1]} == 0 ]] || exit 1
pattern='^everlink v1 [^[:space:]]+ [0-9]+ [0-9a-f]{64} [0-9a-f]{64} [1-9][0-9]*$'
[[ ${bootstrap_lines[0]} =~ $pattern ]] || exit 1
server_pid=${bootstrap_lines[0]##* }
capture_server_identity "$server_pid"
printf '%s\n' "${bootstrap_lines[0]}"
SHIM
    } > "$SSH_SHIM" || return 1
    "$CHMOD_TOOL" 700 -- "$SSH_SHIM" || return 1

    printf '%s\n' \
        "Host $SSH_ALIAS" \
        "    HostName $ISOLATED_ADDR" \
        "    Port $ISOLATED_PORT" \
        "    User $CURRENT_USER" \
        "    IdentityFile $SSHD_CLIENT_KEY" \
        '    IdentitiesOnly yes' \
        '    IdentityAgent none' \
        "    UserKnownHostsFile $SSHD_KNOWN_HOSTS" \
        '    GlobalKnownHostsFile /dev/null' \
        '    StrictHostKeyChecking yes' \
        '    HostKeyAlgorithms ssh-ed25519' \
        '    ProxyCommand none' \
        '    ProxyJump none' \
        '    PubkeyAuthentication yes' \
        '    PasswordAuthentication no' \
        '    KbdInteractiveAuthentication no' \
        '    ChallengeResponseAuthentication no' \
        '    PreferredAuthentications publickey' \
        '    NumberOfPasswordPrompts 0' \
        '    ConnectTimeout 2' \
        '    ConnectionAttempts 1' \
        '    RequestTTY no' \
        '    UpdateHostKeys no' \
        '    ControlMaster no' \
        '    ControlPath none' \
        '    ControlPersist no' \
        '    ForkAfterAuthentication no' \
        '    PermitLocalCommand no' \
        '    LocalCommand none' \
        '    RemoteCommand none' \
        '    SessionType default' \
        '    ClearAllForwardings yes' \
        '    ForwardAgent no' \
        '    ForwardX11 no' \
        '    ForwardX11Trusted no' \
        '    Tunnel no' \
        '    StdinNull yes' > "$SSH_INNER_CONFIG" || return 1
    "$CHMOD_TOOL" 600 -- "$SSH_INNER_CONFIG" || return 1

    printf '%s\n' \
        "Host $SSH_ALIAS" \
        '    HostName 127.0.0.1' \
        "    Port $ISOLATED_PORT" \
        "    User $CURRENT_USER" \
        "    IdentityFile $SSHD_CLIENT_KEY" \
        '    IdentitiesOnly yes' \
        '    IdentityAgent none' \
        "    UserKnownHostsFile $SSHD_KNOWN_HOSTS" \
        '    GlobalKnownHostsFile /dev/null' \
        '    StrictHostKeyChecking yes' \
        '    HostKeyAlgorithms ssh-ed25519' \
        "    ProxyCommand $ENV_TOOL PATH=$SSH_SHIM_DIR:/usr/bin:/bin EVERLINK_SHIM_DIR=$SSH_SHIM_DIR $EVERLINK_EXE ssh-proxy %n %p --ssh-option=-F$SSH_INNER_CONFIG" \
        '    BatchMode yes' \
        '    PubkeyAuthentication yes' \
        '    PasswordAuthentication no' \
        '    KbdInteractiveAuthentication no' \
        '    ChallengeResponseAuthentication no' \
        '    PreferredAuthentications publickey' \
        '    NumberOfPasswordPrompts 0' \
        '    ConnectTimeout 2' \
        '    ConnectionAttempts 1' \
        '    RequestTTY no' \
        '    UpdateHostKeys no' \
        '    ControlMaster no' \
        '    ControlPath none' \
        '    ControlPersist no' \
        '    ClearAllForwardings yes' \
        '    ForwardAgent no' \
        '    ForwardX11 no' \
        '    ForwardX11Trusted no' \
        '    Tunnel no' \
        '    LogLevel QUIET' > "$SSH_OUTER_CONFIG" || return 1
    "$CHMOD_TOOL" 600 -- "$SSH_OUTER_CONFIG" || return 1
}

read_nul_argv() {
    local path=$1 name=$2 value
    local -n result=$name
    result=()
    [[ -f $path && $("$STAT_TOOL" -c '%a' -- "$path") == 600 ]] || return 1
    while IFS= read -r -d '' value; do
        result+=("$value")
    done < "$path"
    ((${#result[@]} > 0))
}

assert_no_batch_mode() {
    local path=$1 value
    local -a actual=()
    read_nul_argv "$path" actual || return 1
    for value in "${actual[@]}"; do
        [[ $value != *BatchMode* ]] || return 1
        [[ $value != *'BEGIN OPENSSH PRIVATE KEY'* ]] || return 1
    done
}

assert_effective_config() {
    local output=$1 name=$2 value=$3
    "$AWK_TOOL" -v wanted_name="$name" -v wanted_value="$value" \
        '$1 == wanted_name && $2 == wanted_value { found=1 } END { exit !found }' "$output"
}

assert_no_effective_value() {
    local output=$1 name=$2 value=$3
    "$AWK_TOOL" -v wanted_name="$name" -v wanted_value="$value" \
        '$1 == wanted_name && $2 == wanted_value { found=1 } END { exit found }' "$output"
}

assert_effective_none() {
    local output=$1 name=$2 config_name=$3
    "$AWK_TOOL" -v wanted_name="$name" \
        '$1 == wanted_name && tolower($2) != "none" { found=1 } END { exit found }' "$output" || return 1
    "$AWK_TOOL" -v wanted_name="$config_name" \
        '$1 == wanted_name && tolower($2) == "none" { found=1 } END { exit !found }' "$SSH_INNER_CONFIG"
}

assert_no_private_key_lines() {
    local output=$1
    "$AWK_TOOL" 'NR == FNR { secret[$0] = 1; next } $0 in secret { found=1 } END { exit found }' \
        "$SSHD_CLIENT_KEY" "$output"
}

load_server_identity() {
    local -a server_lines=()
    local line server_pid server_start server_exe server_pgrp server_role
    SERVER_PID=
    SERVER_START=
    SERVER_EXE=
    SERVER_PGRP=
    SERVER_ROLE=
    [[ -f $SSH_SERVER_IDENTITY && $("$STAT_TOOL" -c '%a' -- "$SSH_SERVER_IDENTITY") == 600 ]] || return 1
    while IFS= read -r line; do
        server_lines+=("$line")
    done < "$SSH_SERVER_IDENTITY"
    [[ ${#server_lines[@]} -eq 5 ]] || return 1
    server_pid=${server_lines[0]}
    server_start=${server_lines[1]}
    server_exe=${server_lines[2]}
    server_pgrp=${server_lines[3]}
    server_role=${server_lines[4]}
    [[ $server_pid =~ ^[1-9][0-9]*$ && $server_start =~ ^[1-9][0-9]*$ ]] || return 1
    [[ $server_pgrp =~ ^[1-9][0-9]*$ && $server_exe == "$EVERLINK_EXE" ]] || return 1
    [[ $server_role == detached-everlink-server ]] || return 1
    SERVER_PID=$server_pid
    SERVER_START=$server_start
    SERVER_EXE=$server_exe
    SERVER_PGRP=$server_pgrp
    SERVER_ROLE=$server_role
}

verify_proxy_evidence() {
    local -a query_expected=(
        -G
        -o ControlMaster=no -o ControlPath=none -o ControlPersist=no
        -o ForkAfterAuthentication=no -o PermitLocalCommand=no
        -o LocalCommand=none -o RemoteCommand=none -o SessionType=default
        -o RequestTTY=no -o ClearAllForwardings=yes -o ForwardAgent=no
        -o ForwardX11=no -o ForwardX11Trusted=no -o Tunnel=no -o StdinNull=yes
        -p "$ISOLATED_PORT" "-F$SSH_INNER_CONFIG" -- "$SSH_ALIAS"
    )
    local -a bootstrap_expected=(
        -o ProxyCommand=none -o ControlMaster=no -o ControlPath=none
        -o ControlPersist=no -o ForkAfterAuthentication=no
        -o PermitLocalCommand=no -o LocalCommand=none -o RemoteCommand=none
        -o SessionType=default -o RequestTTY=no -o ClearAllForwardings=yes
        -o ForwardAgent=no -o ForwardX11=no -o ForwardX11Trusted=no
        -o Tunnel=no -o StdinNull=yes -p "$ISOLATED_PORT"
        "-F$SSH_INNER_CONFIG" -- "$SSH_ALIAS" 'everlink __bootstrap-parent-v1'
    )
    local -a actual=()
    local query_size
    read_nul_argv "$SSH_QUERY_ARGV" actual || return 1
    [[ ${#actual[@]} -eq ${#query_expected[@]} ]] || return 1
    for ((query_size = 0; query_size < ${#actual[@]}; query_size++)); do
        [[ ${actual[query_size]} == "${query_expected[query_size]}" ]] || return 1
    done
    read_nul_argv "$SSH_BOOTSTRAP_ARGV" actual || return 1
    [[ ${#actual[@]} -eq ${#bootstrap_expected[@]} ]] || return 1
    for ((query_size = 0; query_size < ${#actual[@]}; query_size++)); do
        [[ ${actual[query_size]} == "${bootstrap_expected[query_size]}" ]] || return 1
    done
    assert_no_batch_mode "$SSH_QUERY_ARGV" || return 1
    assert_no_batch_mode "$SSH_BOOTSTRAP_ARGV" || return 1
    [[ -f $SSH_QUERY_OUTPUT && $("$STAT_TOOL" -c '%a' -- "$SSH_QUERY_OUTPUT") == 600 ]] || return 1
    query_size=$("$STAT_TOOL" -c '%s' -- "$SSH_QUERY_OUTPUT") || return 1
    (( query_size > 0 && query_size <= 65536 )) || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" hostname "$ISOLATED_ADDR" || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" port "$ISOLATED_PORT" || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" user "$CURRENT_USER" || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" identityfile "$SSHD_CLIENT_KEY" || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" userknownhostsfile "$SSHD_KNOWN_HOSTS" || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" globalknownhostsfile /dev/null || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" stricthostkeychecking true || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" identitiesonly yes || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" identityagent none || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" pubkeyauthentication true || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" passwordauthentication no || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" kbdinteractiveauthentication no || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" preferredauthentications publickey || return 1
    assert_effective_none "$SSH_QUERY_OUTPUT" proxycommand ProxyCommand || return 1
    assert_effective_none "$SSH_QUERY_OUTPUT" proxyjump ProxyJump || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" requesttty false || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" clearallforwardings yes || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" forwardagent no || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" forwardx11 no || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" tunnel false || return 1
    assert_no_effective_value "$SSH_QUERY_OUTPUT" remotecommand 'everlink __bootstrap-parent-v1' || return 1
    assert_no_effective_value "$SSH_QUERY_OUTPUT" 'everlink' 'v1' || return 1
    assert_no_private_key_lines "$SSH_QUERY_OUTPUT" || return 1
    load_server_identity || return 1
}

run_outer_ssh() {
    local session_number=$1 expected_status=$2 expected=$3 status remote_command
    local output="$TMP_ROOT/outer-$session_number.stdout" error="$TMP_ROOT/outer-$session_number.stderr"
    printf '%s\n' "$expected" > "$SSHD_EXPECTED_OUTPUT"
    "$CHMOD_TOOL" 600 -- "$SSHD_EXPECTED_OUTPUT" || return 1
    remote_command="$PRINTF_TOOL '%s\\n' '$expected'"
    if [[ $expected_status == 42 ]]; then
        remote_command+='; exit 42'
    fi
    set +e
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=1s \
        "${SSH_SESSION_TIMEOUT_SECONDS}s" "$ENV_TOOL" \
        "PATH=$SSH_SHIM_DIR:/usr/bin:/bin" \
        "EVERLINK_SHIM_DIR=$SSH_SHIM_DIR" \
        "$SSH_TOOL" -4 -F "$SSH_OUTER_CONFIG" -n -T -- "$SSH_ALIAS" \
        "$remote_command" > "$output" 2> "$error"
    status=$?
    set -e
    (( status == expected_status )) || return 1
    "$CMP_TOOL" -s -- "$SSHD_EXPECTED_OUTPUT" "$output" || return 1
    [[ ! -s $error ]]
}

run_direct_ssh() {
    local number=$1 expected="EverLink isolated direct connection $1" status
    local output="$TMP_ROOT/sshd/direct-$number.stdout"
    local error="$TMP_ROOT/sshd/direct-$number.stderr"
    printf '%s\n' "$expected" > "$SSHD_EXPECTED_OUTPUT"
    set +e
    run_bounded "$SSH_TOOL" -4 -F /dev/null -n -T -i "$SSHD_CLIENT_KEY" \
        -p "$ISOLATED_PORT" \
        -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
        -o UserKnownHostsFile="$SSHD_KNOWN_HOSTS" \
        -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes \
        -o ProxyCommand=none -o ProxyJump=none -o ControlMaster=no \
        -o ControlPath=none -o ControlPersist=no -o ForwardAgent=no \
        -o ForwardX11=no -o Tunnel=no -o ClearAllForwardings=yes \
        -o PubkeyAuthentication=yes -o PasswordAuthentication=no \
        -o KbdInteractiveAuthentication=no -o PreferredAuthentications=publickey \
        -o ConnectTimeout=2 -o ConnectionAttempts=1 -o RequestTTY=no \
        -o UpdateHostKeys=no -- "$CURRENT_USER@127.0.0.1" \
        "$PRINTF_TOOL '%s\\n' '$expected'" >"$output" 2>"$error"
    status=$?
    set -e
    (( status == 0 )) || return 1
    "$CMP_TOOL" -s -- "$SSHD_EXPECTED_OUTPUT" "$output" || return 1
    [[ ! -s $error ]]
}

run_production_session() {
    local session_number=$1 expected_status=$2 expected=$3
    clear_server_tuple
    write_ssh_configs_and_shim "$session_number" || return 1
    run_outer_ssh "$session_number" "$expected_status" "$expected" || return 1
    verify_proxy_evidence || return 1
    poll_server_gone "$SERVER_PID" "$SERVER_START" "$SERVER_EXE" "$SERVER_PGRP" \
        "$SERVER_ROLE" || return 1
    listener_exact "$ISOLATED_ADDR" "$ISOLATED_PORT" \
        && listener_exact 127.0.0.1 "$ISOLATED_PORT"
}

cleanup_detached_server() {
    local pid=$1 start=$2 exe=$3 pgrp=$4 role=$5
    local result rc=0 term_sent=0
    [[ -n $pid && -n $start && -n $exe && -n $pgrp && -n $role ]] || return 1

    if validate_owned "$pid" "$start" "$exe" "$pgrp" "$role"; then
        if builtin kill -TERM "$pid" 2>/dev/null; then
            term_sent=1
        elif validate_owned "$pid" "$start" "$exe" "$pgrp" "$role"; then
            rc=1
        else
            result=$?
            [[ $result -eq 2 ]] || rc=1
        fi
    else
        result=$?
        [[ $result -eq 2 ]] || rc=1
    fi

    if (( term_sent )); then
        if ! poll_owned_gone "$pid" "$start" "$exe" "$pgrp" "$role"; then
            if validate_owned "$pid" "$start" "$exe" "$pgrp" "$role"; then
                if builtin kill -KILL "$pid" 2>/dev/null; then
                    poll_owned_gone "$pid" "$start" "$exe" "$pgrp" "$role" || rc=1
                elif validate_owned "$pid" "$start" "$exe" "$pgrp" "$role"; then
                    rc=1
                else
                    result=$?
                    [[ $result -eq 2 ]] || rc=1
                fi
            else
                result=$?
                [[ $result -eq 2 ]] || rc=1
            fi
        fi
    fi

    # The server is deliberately detached from this shell.  Its PID tuple is
    # checked, but it is never group-signalled and never reaped here.
    poll_owned_gone "$pid" "$start" "$exe" "$pgrp" "$role" || rc=1
    return "$rc"
}

run_signal_child() {
    local i
    TMP_ROOT=$("$MKtemp_TOOL" -d -- /tmp/everlink-slice5a.XXXXXX)
    "$CHMOD_TOOL" 700 -- "$TMP_ROOT"
    validate_temp_target "$TMP_ROOT" || return 1
    start_sleep signal-probe-sleep
    printf '%s\n%s\n%s\n%s\n%s\n' "$OWN_PID" "$OWN_START" "$OWN_EXE" \
        "$OWN_PGRP" "$TMP_ROOT" > "$PROBE_REPORT"
    for ((i = 0; i < 400; i++)); do
        [[ -e $PROBE_RELEASE ]] && break
        "$SLEEP_TOOL" 0.05
    done
    # The bounded timeout is also a safe fallback if the parent is interrupted.
    builtin kill -TERM "$$"
}

cleanup() {
    local original_status=$? rc=0 result identity_loaded=0
    if (( CLEANUP_DONE )); then
        exit "$original_status"
    fi
    CLEANUP_DONE=1
    trap - EXIT INT TERM HUP
    set +e

    if [[ $MODE == child ]]; then
        if [[ -n $OWN_PID ]]; then
            cleanup_owned "$OWN_PID" "$OWN_START" "$OWN_EXE" "$OWN_PGRP" "$OWN_ROLE" || rc=1
        fi
        remove_temp_root "$TMP_ROOT" || rc=1
    else
        if [[ -z $SERVER_PID && -f $SSH_SERVER_IDENTITY ]]; then
            if load_server_identity; then
                identity_loaded=1
            else
                rc=1
            fi
        elif [[ -n $SERVER_PID ]]; then
            identity_loaded=1
        fi
        if (( identity_loaded )); then
            cleanup_detached_server "$SERVER_PID" "$SERVER_START" "$SERVER_EXE" \
                "$SERVER_PGRP" "$SERVER_ROLE" || rc=1
        fi
        if [[ -n $OWN_PID ]]; then
            cleanup_owned "$OWN_PID" "$OWN_START" "$OWN_EXE" "$OWN_PGRP" "$OWN_ROLE" || rc=1
        fi
        if (( ISOLATED_SERVER )); then
            poll_listeners_gone || rc=1
        fi
        if [[ $CHILD_FINISHED -eq 0 && -n $CHILD_PID ]]; then
            printf 'release\n' > "$PROBE_RELEASE" 2>/dev/null || true
            if validate_owned "$CHILD_PID" "$CHILD_START" "$CHILD_EXE" "$CHILD_PGRP" "$CHILD_ROLE"; then
                poll_owned_gone "$CHILD_PID" "$CHILD_START" "$CHILD_EXE" "$CHILD_PGRP" "$CHILD_ROLE" || rc=1
            else
                result=$?
                [[ $result -eq 2 ]] || rc=1
            fi
            if ! reap_owned_child "$CHILD_PID" "$CHILD_START" "$CHILD_EXE" \
                "$CHILD_PGRP" "$CHILD_ROLE"; then
                rc=1
            fi
        fi
        verify_baseline || rc=1
        remove_temp_root "$TMP_ROOT" || rc=1
    fi

    if (( original_status != 0 )); then
        exit "$original_status"
    fi
    if (( rc != 0 )); then
        exit 1
    fi
    if [[ $MODE == parent ]]; then
        printf 'EverLink Slice 5A production OpenSSH path: PASS\n'
    fi
    exit 0
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if (( WATCHDOG_CHILD == 0 )); then
    exec "$TIMEOUT_TOOL" --signal=TERM --kill-after=2s "${WATCHDOG_SECONDS}s" \
        "$BASH_TOOL" "$SCRIPT_PATH" --watchdog-child "$@"
fi

if [[ $MODE == child ]]; then
    run_signal_child
    exit 0
fi

verify_current_binary || {
    printf 'target/debug/everlink is stale or invalid\n' >&2
    exit 1
}

TMP_ROOT=$("$MKtemp_TOOL" -d -- /tmp/everlink-slice5a.XXXXXX)
"$CHMOD_TOOL" 700 -- "$TMP_ROOT"
validate_temp_target "$TMP_ROOT" || {
    printf 'invalid temporary root\n' >&2
    exit 1
}
snapshot_baseline
start_sleep ordinary-sleep
validate_owned "$OWN_PID" "$OWN_START" "$OWN_EXE" "$OWN_PGRP" "$OWN_ROLE" || {
    printf 'ordinary owned identity validation failed\n' >&2
    exit 1
}
FORGED_START=$((OWN_START + 1))
if cleanup_owned "$OWN_PID" "$FORGED_START" "$OWN_EXE" "$OWN_PGRP" "$OWN_ROLE"; then
    printf 'forged ordinary identity was accepted\n' >&2
    exit 1
fi
validate_owned "$OWN_PID" "$OWN_START" "$OWN_EXE" "$OWN_PGRP" "$OWN_ROLE" || {
    printf 'forged identity affected ordinary sleep\n' >&2
    exit 1
}
run_child_probe
verify_baseline
if ! cleanup_owned "$OWN_PID" "$OWN_START" "$OWN_EXE" "$OWN_PGRP" "$OWN_ROLE"; then
    printf 'ordinary owned process cleanup failed\n' >&2
    exit 1
fi
clear_owned
select_nonloopback_address || {
    printf 'no usable non-loopback IPv4 address\n' >&2
    exit 1
}
prepare_isolated_sshd || {
    printf 'isolated sshd preparation failed\n' >&2
    exit 1
}
start_isolated_sshd || {
    printf 'isolated sshd failed to start\n' >&2
    exit 1
}
wait_for_listeners || {
    printf 'isolated sshd listeners were not ready\n' >&2
    exit 1
}
make_known_hosts || {
    printf 'isolated sshd host key scan failed\n' >&2
    exit 1
}
run_direct_ssh 1 || {
    printf 'first direct ssh health check failed\n' >&2
    exit 1
}
run_production_session 1 0 'EverLink isolated production connection' || {
    printf 'first production ProxyCommand session failed\n' >&2
    exit 1
}
run_direct_ssh 2 || {
    printf 'second direct ssh health check failed\n' >&2
    exit 1
}
run_production_session 2 42 'EverLink isolated production connection 2' || {
    printf 'second production ProxyCommand session failed\n' >&2
    exit 1
}
run_direct_ssh 3 || {
    printf 'third direct ssh health check failed\n' >&2
    exit 1
}
clear_server_tuple
exit 0
