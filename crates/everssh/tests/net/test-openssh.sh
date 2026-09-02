#!/usr/bin/bash
set -Eeuo pipefail

# Slice 5A exercises eight production OpenSSH ProxyCommand sessions (status 0,
# status 42, one 1 MiB binary session, one forced-PTY session, one SFTP batch,
# one modern SCP download, one Unix-socket local/remote forward, and one
# isolated-agent user-certificate session)
# while keeping every process, key, and diagnostic artifact owned by this bounded harness.

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
readonly SSHAGENT_TOOL=/usr/bin/ssh-agent
readonly SSHADD_TOOL=/usr/bin/ssh-add
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
readonly SHA256SUM_TOOL=/usr/bin/sha256sum
readonly STTY_TOOL=/usr/bin/stty
readonly SFTP_TOOL=/usr/bin/sftp
readonly SCP_TOOL=/usr/bin/scp
readonly NC_TOOL=/usr/bin/nc
# Existing sessions and server polls (~420s) plus bounded forwarding, health,
# startup, and cleanup work fit below 600s without weakening nested timeouts.
readonly WATCHDOG_SECONDS=600
readonly FORWARD_READY_SECONDS=15
readonly FORWARD_CLIENT_TIMEOUT_SECONDS=15
readonly FORWARD_REMOTE_WAIT_ATTEMPTS=300
readonly POLL_SECONDS=5
# A killed ProxyCommand is indistinguishable from total loss, so the released
# v2 server holds its association for the 20s remote stall, the renewed 30s
# resume lease, and bounded finalize. The /proc observer adds five seconds;
# this does not extend any production deadline.
readonly SERVER_POLL_SECONDS=60
readonly READINESS_POLL_ATTEMPTS=60
readonly OPERATION_TIMEOUT_SECONDS=4
readonly SSH_SESSION_TIMEOUT_SECONDS=15
readonly SSH_BINARY_SESSION_TIMEOUT_SECONDS=30
readonly SFTP_SESSION_TIMEOUT_SECONDS=30
readonly SCP_SESSION_TIMEOUT_SECONDS=30
readonly BINARY_BYTES=1048576

for tool in "$BASH_TOOL" "$CHMOD_TOOL" "$CMP_TOOL" "$ID_TOOL" "$IP_TOOL" \
    "$MKDIR_TOOL" "$MKtemp_TOOL" "$PRINTF_TOOL" "$READLINK_TOOL" "$RM_TOOL" \
    "$SLEEP_TOOL" "$SORT_TOOL" "$SS_TOOL" "$SSH_TOOL" "$SSHAGENT_TOOL" \
    "$SSHADD_TOOL" "$SSHD_EXE" "$SSHKEYGEN_TOOL" "$SSHKEYSCAN_TOOL" \
    "$STAT_TOOL" "$SETSID_TOOL" \
    "$TIMEOUT_TOOL" "$AWK_TOOL" "$CAT_TOOL" "$DD_TOOL" "$HEAD_TOOL" \
    "$LN_TOOL" "$MV_TOOL" "$ENV_TOOL" "$SHA256SUM_TOOL" "$STTY_TOOL" \
    "$SFTP_TOOL" "$SCP_TOOL" "$NC_TOOL"; do
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
FORWARD_PID=
FORWARD_START=
FORWARD_EXE=
FORWARD_PGRP=
FORWARD_ROLE=
FORWARD_SOCK=
FORWARD_REMOTE_SOCK=
FORWARD_RELEASE=
AGENT_PID= AGENT_START= AGENT_EXE= AGENT_PGRP= AGENT_ROLE=
SSH_AGENT_SOCK= SSH_AGENT_KEY_DIR= SSH_AGENT_CERT_DIR= SSH_AGENT_OUTPUT_DIR= SSH_AGENT_PRIVATE= SSH_AGENT_PUBLIC= SSH_AGENT_CERT=
BASELINE_PIDS=()
ISOLATED_ADDR=
ISOLATED_PORT=
ISOLATED_SERVER=0
SSHD_CONFIG=
SSHD_LOG=
SSHD_PID_FILE=
SSHD_HOST_KEY=
SSHD_CLIENT_KEY=
SSHD_CA_KEY= SSHD_CA_PUBLIC=
SSHD_AUTHORIZED_KEYS=
SSHD_KNOWN_HOSTS=
SSHD_EXPECTED_OUTPUT=
SSHD_REMOTE_BIN=
CURRENT_USER=
WORKSPACE_ROOT=
EVERSSH_EXE=
SSHD_HOST_BLOB=
SERVER_PID=
SERVER_START=
SERVER_EXE=
SERVER_PGRP=
SERVER_ROLE=
SSH_ALIAS=everssh-slice5a-alias
readonly PTY_TERM_VALUE=everssh-m3s5-pty
readonly PTY_INPUT_LINE=everssh-pty-canonical-input-v1
readonly PTY_MARKER=EVERSSH-PTY-SESSION-OK
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
    local pid=$1 role=${2-} line suffix state ppid pgrp session tty_nr tpgid flags minflt
    local cminflt majflt cmajflt utime stime cutime cstime priority nice
    local num_threads itrealvalue starttime remainder proc_uid comm argument; local -a argv=()

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
    if CAP_EXE=$("$READLINK_TOOL" -e -- "/proc/$pid/exe" 2>/dev/null); then
        [[ -n $CAP_EXE ]] || return 1
    elif [[ $role == isolated-ssh-agent* ]]; then
        proc_uid=$("$STAT_TOOL" -c '%u' -- "/proc/$pid" 2>/dev/null) || return 1; IFS= read -r comm 2>/dev/null < "/proc/$pid/comm" || return 1
        while IFS= read -r -d '' argument; do argv+=("$argument"); done 2>/dev/null < "/proc/$pid/cmdline"
        [[ $proc_uid == "$EUID" && $ppid == "$BASHPID" && $comm == ssh-agent && ${#argv[@]} -eq 4 ]] || return 1
        [[ ${argv[0]} == "$SSHAGENT_TOOL" && ${argv[1]} == -D && ${argv[2]} == -a && ${argv[3]} == "$SSH_AGENT_SOCK" ]] || return 1
        CAP_EXE=$SSHAGENT_TOOL
    else
        return 1
    fi
}

# Return 0 for an exact owned tuple, 2 for disappearance, and 1 for mismatch.
validate_owned() {
    local pid=$1 expected_start=$2 expected_exe=$3 expected_pgrp=$4
    local expected_role=$5
    if ! capture_identity "$pid" "$expected_role"; then
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
    [[ -n $path && $path == /tmp/everssh-slice5a.* && -d $path ]] || return 1
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
    WORKSPACE_ROOT=${SCRIPT_PATH%/crates/everssh/tests/net/test-openssh.sh}
    EVERSSH_EXE="$WORKSPACE_ROOT/target/debug/everssh"
    [[ "$SCRIPT_PATH" == "$WORKSPACE_ROOT/crates/everssh/tests/net/test-openssh.sh" ]] || return 1
    [[ -x "$EVERSSH_EXE" ]] || return 1
    [[ "$($READLINK_TOOL -e -- "$EVERSSH_EXE")" == "$EVERSSH_EXE" ]] || return 1
    binary_mtime=$($STAT_TOOL -c '%Y' -- "$EVERSSH_EXE") || return 1
    for input in "$WORKSPACE_ROOT/Cargo.toml" \
        "$WORKSPACE_ROOT/Cargo.lock" "$WORKSPACE_ROOT/crates/everssh/Cargo.toml" \
        "$WORKSPACE_ROOT/crates/everpty/Cargo.toml" "$WORKSPACE_ROOT/crates/eversh/Cargo.toml" \
        "$WORKSPACE_ROOT"/crates/everssh/src/*.rs; do
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
    [[ $CHILD_ROOT == /tmp/everssh-slice5a.* ]] || return 1

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

clear_forward() {
    FORWARD_PID=
    FORWARD_START=
    FORWARD_EXE=
    FORWARD_PGRP=
    FORWARD_ROLE=
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
    SSHD_CA_KEY="$TMP_ROOT/ca/user_ca_ed25519"
    SSHD_CA_PUBLIC="$SSHD_CA_KEY.pub"
    SSHD_AUTHORIZED_KEYS="$TMP_ROOT/sshd/authorized_keys"
    SSHD_KNOWN_HOSTS="$TMP_ROOT/sshd/known_hosts"
    SSHD_EXPECTED_OUTPUT="$TMP_ROOT/sshd/expected-output"
    SSHD_REMOTE_BIN="$TMP_ROOT/remote-bin"
    "$MKDIR_TOOL" -m 700 -- "$TMP_ROOT/sshd" "$TMP_ROOT/ca" \
        "$SSHD_REMOTE_BIN" || return 1
    "$LN_TOOL" -s -- "$EVERSSH_EXE" "$SSHD_REMOTE_BIN/everssh" || return 1
    [[ "$($READLINK_TOOL -e -- "$SSHD_REMOTE_BIN/everssh")" == "$EVERSSH_EXE" ]] || return 1
    : > "$SSHD_LOG"
    "$CHMOD_TOOL" 600 -- "$SSHD_LOG" || return 1
    run_bounded "$SSHKEYGEN_TOOL" -q -t ed25519 -N '' -f "$SSHD_HOST_KEY" >/dev/null 2>&1 || return 1
    run_bounded "$SSHKEYGEN_TOOL" -q -t ed25519 -N '' -f "$SSHD_CLIENT_KEY" >/dev/null 2>&1 || return 1
    ( umask 077
      run_bounded "$SSHKEYGEN_TOOL" -q -t ed25519 -N '' -f "$SSHD_CA_KEY" \
        >"$TMP_ROOT/ca/keygen.stdout" 2>"$TMP_ROOT/ca/keygen.stderr" ) || return 1
    "$CHMOD_TOOL" 600 -- "$SSHD_HOST_KEY" "$SSHD_CLIENT_KEY" \
        "$SSHD_HOST_KEY.pub" "$SSHD_CLIENT_KEY.pub" "$SSHD_CA_KEY" \
        "$SSHD_CA_PUBLIC" || return 1
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
        "TrustedUserCAKeys $SSHD_CA_PUBLIC" \
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
        'AllowTcpForwarding yes' \
        'PermitOpen 127.0.0.1:*' \
        'GatewayPorts no' \
        'AllowStreamLocalForwarding remote' \
        'StreamLocalBindMask 0177' \
        'StreamLocalBindUnlink no' \
        'UseDNS no' \
        'Subsystem sftp internal-sftp' \
        'PermitUserEnvironment no' \
        'PermitUserRC no' \
        'Match LocalAddress 127.0.0.1' \
        '    PermitTTY yes' \
        'Match all' \
        '    PermitTTY no' > "$SSHD_CONFIG"
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

record_forward_identity() {
    local pid=$1 role=$2
    FORWARD_PID=$pid
    FORWARD_START=$CAP_START
    FORWARD_EXE=$CAP_EXE
    FORWARD_PGRP=$CAP_PGRP
    FORWARD_ROLE=$role
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

write_ssh_shim() {
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
readonly BOOTSTRAP_COMMAND='everssh __bootstrap-parent-v1'

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
    printf '%s\n%s\n%s\n%s\ndetached-everssh-server\n' \
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
    "$REAL_SSH" "$@" | "$HEAD_TOOL" -c 233
    printf '%s\n' "${PIPESTATUS[0]}"
)
capture_status=$?
set -e
(( capture_status == 0 )) || exit 1
bootstrap_lines=()
mapfile -t bootstrap_lines <<< "$bootstrap_capture"
[[ ${#bootstrap_lines[@]} -eq 2 && ${bootstrap_lines[1]} == 0 ]] || exit 1
pattern='^everssh v2 [^[:space:]]+ [0-9]+ [0-9a-f]{64} [0-9a-f]{64} [0-9a-f]{32} [1-9][0-9]*$'
[[ ${bootstrap_lines[0]} =~ $pattern ]] || exit 1
server_pid=${bootstrap_lines[0]##* }
capture_server_identity "$server_pid"
printf '%s\n' "${bootstrap_lines[0]}"
SHIM
    } > "$SSH_SHIM" || return 1
    "$CHMOD_TOOL" 700 -- "$SSH_SHIM" || return 1
}

prepare_ssh_shim_dir() {
    local session_number=$1
    SSH_SHIM_DIR="$TMP_ROOT/ssh-shim-$session_number"
    SSH_SHIM="$SSH_SHIM_DIR/ssh"
    SSH_QUERY_ARGV="$SSH_SHIM_DIR/query.argv"
    SSH_BOOTSTRAP_ARGV="$SSH_SHIM_DIR/bootstrap.argv"
    SSH_QUERY_OUTPUT="$SSH_SHIM_DIR/query.stdout"
    SSH_INNER_CONFIG="$SSH_SHIM_DIR/inner_config"
    SSH_OUTER_CONFIG="$SSH_SHIM_DIR/outer_config"
    SSH_SERVER_IDENTITY="$SSH_SHIM_DIR/server.identity"
    "$MKDIR_TOOL" -m 700 -- "$SSH_SHIM_DIR"
}

write_ssh_configs() {
    local identity_file=$1 identity_agent=$2 certificate_file=${3-}
    local -a certificate_line=()
    [[ -z $certificate_file ]] || certificate_line=("    CertificateFile $certificate_file")

    printf '%s\n' \
        "Host $SSH_ALIAS" \
        "    HostName $ISOLATED_ADDR" \
        "    Port $ISOLATED_PORT" \
        "    User $CURRENT_USER" \
        "    IdentityFile $identity_file" \
        "${certificate_line[@]}" \
        '    IdentitiesOnly yes' \
        "    IdentityAgent $identity_agent" \
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
        "    IdentityFile $identity_file" \
        "${certificate_line[@]}" \
        '    IdentitiesOnly yes' \
        "    IdentityAgent $identity_agent" \
        "    UserKnownHostsFile $SSHD_KNOWN_HOSTS" \
        '    GlobalKnownHostsFile /dev/null' \
        '    StrictHostKeyChecking yes' \
        '    HostKeyAlgorithms ssh-ed25519' \
        "    ProxyCommand $ENV_TOOL PATH=$SSH_SHIM_DIR:/usr/bin:/bin EVERSSH_SHIM_DIR=$SSH_SHIM_DIR $EVERSSH_EXE ssh-proxy %n %p --ssh-option=-F$SSH_INNER_CONFIG" \
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

write_ssh_configs_and_shim() {
    prepare_ssh_shim_dir "$1" || return 1
    write_ssh_shim || return 1
    write_ssh_configs "$SSHD_CLIENT_KEY" none
}

write_agent_configs_and_shim() {
    [[ $1 == 8 ]] || return 1
    prepare_ssh_shim_dir "$1" || return 1
    write_ssh_shim || return 1
    write_ssh_configs "$SSH_AGENT_PUBLIC" "$SSH_AGENT_SOCK" "$SSH_AGENT_CERT"
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
    local output=$1 private_key=${2:-$SSHD_CLIENT_KEY}
    "$AWK_TOOL" 'NR == FNR { secret[$0] = 1; next } $0 in secret { found=1 } END { exit found }' \
        "$private_key" "$output"
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
    [[ $server_pgrp =~ ^[1-9][0-9]*$ && $server_exe == "$EVERSSH_EXE" ]] || return 1
    [[ $server_role == detached-everssh-server ]] || return 1
    SERVER_PID=$server_pid
    SERVER_START=$server_start
    SERVER_EXE=$server_exe
    SERVER_PGRP=$server_pgrp
    SERVER_ROLE=$server_role
}

assert_shim_argv_evidence() {
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
        "-F$SSH_INNER_CONFIG" -- "$SSH_ALIAS" 'everssh __bootstrap-parent-v1'
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
    (( query_size > 0 && query_size <= 65536 ))
}

assert_common_proxy_effective() {
    assert_effective_config "$SSH_QUERY_OUTPUT" hostname "$ISOLATED_ADDR" || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" port "$ISOLATED_PORT" || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" user "$CURRENT_USER" || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" userknownhostsfile "$SSHD_KNOWN_HOSTS" || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" globalknownhostsfile /dev/null || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" stricthostkeychecking true || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" identitiesonly yes || return 1
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
    assert_no_effective_value "$SSH_QUERY_OUTPUT" remotecommand \
        'everssh __bootstrap-parent-v1' || return 1
    assert_no_effective_value "$SSH_QUERY_OUTPUT" 'everssh' 'v1'
}

verify_proxy_evidence() {
    assert_shim_argv_evidence || return 1
    assert_common_proxy_effective || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" identityfile "$SSHD_CLIENT_KEY" || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" identityagent none || return 1
    assert_no_private_key_lines "$SSH_QUERY_OUTPUT" || return 1
    load_server_identity
}

verify_agent_proxy_evidence() {
    local path value
    local -a actual=()
    assert_shim_argv_evidence || return 1
    assert_common_proxy_effective || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" identityfile "$SSH_AGENT_PUBLIC" || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" certificatefile "$SSH_AGENT_CERT" || return 1
    assert_effective_config "$SSH_QUERY_OUTPUT" identityagent "$SSH_AGENT_SOCK" || return 1
    assert_no_effective_value "$SSH_QUERY_OUTPUT" identityfile "$SSH_AGENT_PRIVATE" || return 1
    assert_no_private_key_lines "$SSH_QUERY_OUTPUT" "$SSH_AGENT_PRIVATE" || return 1
    for path in "$SSH_QUERY_ARGV" "$SSH_BOOTSTRAP_ARGV"; do
        read_nul_argv "$path" actual || return 1
        for value in "${actual[@]}"; do
            [[ $value != *"$SSH_AGENT_PRIVATE"* ]] || return 1
        done
    done
    load_server_identity || return 1
    validate_owned "$AGENT_PID" "$AGENT_START" "$AGENT_EXE" \
        "$AGENT_PGRP" "$AGENT_ROLE" || return 1
    [[ $SERVER_PID != "$AGENT_PID" && $SERVER_PGRP != "$AGENT_PGRP" && \
        $SERVER_ROLE != "$AGENT_ROLE" ]]
}

clear_agent_tuple() {
    AGENT_PID= AGENT_START= AGENT_EXE= AGENT_PGRP= AGENT_ROLE=
}

agent_artifact_cleanup() {
    local path rc=0
    validate_temp_target "$TMP_ROOT" || return 1
    for path in "$SSH_AGENT_SOCK" "$SSH_AGENT_KEY_DIR" "$SSH_AGENT_CERT_DIR" "$SSH_AGENT_OUTPUT_DIR"; do
        [[ -n $path ]] || continue
        case $path in
            "$TMP_ROOT/agent.sock"|"$TMP_ROOT/agent-key"|"$TMP_ROOT/agent-cert"|"$TMP_ROOT/agent-output") ;;
            *) rc=1; continue ;;
        esac
        "$RM_TOOL" -rf -- "$path" || rc=1
        [[ ! -e $path && ! -L $path ]] || rc=1
    done
    return "$rc"
}

stop_isolated_agent() {
    local rc=0
    if [[ -n $AGENT_PID ]]; then
        if [[ -z $AGENT_START || -z $AGENT_EXE || -z $AGENT_PGRP ]]; then
            if capture_identity "$AGENT_PID" "$AGENT_ROLE"; then
                AGENT_START=$CAP_START AGENT_EXE=$CAP_EXE AGENT_PGRP=$CAP_PGRP
            elif reap_terminal_child "$AGENT_PID"; then
                clear_agent_tuple
            else
                rc=1
            fi
        fi
        if [[ -n $AGENT_PID ]]; then
            if cleanup_owned "$AGENT_PID" "$AGENT_START" "$AGENT_EXE" \
                "$AGENT_PGRP" "$AGENT_ROLE"; then
                clear_agent_tuple
            else
                rc=1
            fi
        fi
    fi
    if (( rc == 0 )); then
        agent_artifact_cleanup || rc=1
    fi
    return "$rc"
}

start_isolated_agent() {
    local i mode stdout="$SSH_AGENT_OUTPUT_DIR/agent.stdout" stderr="$SSH_AGENT_OUTPUT_DIR/agent.stderr"
    umask 077
    : > "$stdout"; : > "$stderr"
    "$CHMOD_TOOL" 600 -- "$stdout" "$stderr" || return 1
    [[ $SSH_AGENT_SOCK == "$TMP_ROOT/agent.sock" && ! -e $SSH_AGENT_SOCK ]] || return 1
    "$SETSID_TOOL" "$ENV_TOOL" -u SSH_AUTH_SOCK "$SSHAGENT_TOOL" -D -a "$SSH_AGENT_SOCK" \
        </dev/null >"$stdout" 2>"$stderr" &
    AGENT_PID=$! AGENT_ROLE=isolated-ssh-agent-startup
    for ((i = 0; i < READINESS_POLL_ATTEMPTS; i++)); do
        if capture_identity "$AGENT_PID" "$AGENT_ROLE"; then
            AGENT_START=$CAP_START AGENT_EXE=$CAP_EXE AGENT_PGRP=$CAP_PGRP
            mode=$($STAT_TOOL -c '%a' -- "$SSH_AGENT_SOCK" 2>/dev/null) || mode=
            if [[ $CAP_STATE != Z && $AGENT_EXE == "$SSHAGENT_TOOL" && \
                $AGENT_PGRP == "$AGENT_PID" && -S $SSH_AGENT_SOCK && \
                ! -L $SSH_AGENT_SOCK && $mode == 600 ]]; then
                AGENT_ROLE=isolated-ssh-agent
                [[ $AGENT_PID != "$OWN_PID" && $AGENT_PGRP != "$OWN_PGRP" ]] || break
                [[ $AGENT_PID != "$SERVER_PID" && $AGENT_PGRP != "$SERVER_PGRP" ]] || break
                [[ $AGENT_PID != "$FORWARD_PID" && $AGENT_PGRP != "$FORWARD_PGRP" ]] || break
                return 0
            fi
        elif reap_terminal_child "$AGENT_PID"; then
            clear_agent_tuple
            break
        fi
        "$TIMEOUT_TOOL" 1s "$SLEEP_TOOL" 0.05
    done
    stop_isolated_agent || :
    return 1
}

run_isolated_ssh_add() {
    run_bounded "$ENV_TOOL" -u SSH_AUTH_SOCK "SSH_AUTH_SOCK=$SSH_AGENT_SOCK" "$SSHADD_TOOL" "$@"
}

load_isolated_agent_key() {
    local path status prefix="$SSH_AGENT_OUTPUT_DIR/ssh-add"
    validate_owned "$AGENT_PID" "$AGENT_START" "$AGENT_EXE" \
        "$AGENT_PGRP" "$AGENT_ROLE" || return 1
    [[ ! -e "${SSH_AGENT_PRIVATE}-cert.pub" ]] || return 1
    set +e
    run_isolated_ssh_add -l >"$prefix.empty.stdout" 2>"$prefix.empty.stderr"
    status=$?
    set -e
    (( status == 1 )) || return 1
    run_isolated_ssh_add "$SSH_AGENT_PRIVATE" \
        >"$prefix.load.stdout" 2>"$prefix.load.stderr" || return 1
    run_bounded "$SSHKEYGEN_TOOL" -lf "$SSH_AGENT_PUBLIC" \
        >"$prefix.expected" 2>"$prefix.expected.stderr" || return 1
    run_isolated_ssh_add -l >"$prefix.actual" 2>"$prefix.actual.stderr" || return 1
    "$CMP_TOOL" -s -- "$prefix.expected" "$prefix.actual" || return 1
    run_isolated_ssh_add -L >"$prefix.public" 2>"$prefix.public.stderr" || return 1
    "$CMP_TOOL" -s -- "$SSH_AGENT_PUBLIC" "$prefix.public" || return 1
    for path in "$SSH_AGENT_OUTPUT_DIR"/*; do
        [[ -f $path && $($STAT_TOOL -c '%a' -- "$path") == 600 ]] || return 1
    done
    validate_owned "$AGENT_PID" "$AGENT_START" "$AGENT_EXE" "$AGENT_PGRP" "$AGENT_ROLE"
}

run_outer_ssh() {
    local session_number=$1 expected_status=$2 expected=$3 status remote_command agent_mode=${4-}
    local output="$TMP_ROOT/outer-$session_number.stdout" error="$TMP_ROOT/outer-$session_number.stderr"
    local -a env_options=()
    [[ -z $agent_mode ]] || { [[ $agent_mode == isolated-agent ]] || return 1; env_options=(-u SSH_AUTH_SOCK); }
    printf '%s\n' "$expected" > "$SSHD_EXPECTED_OUTPUT"
    "$CHMOD_TOOL" 600 -- "$SSHD_EXPECTED_OUTPUT" || return 1
    remote_command="$PRINTF_TOOL '%s\\n' '$expected'"
    if [[ $expected_status == 42 ]]; then
        remote_command+='; exit 42'
    fi
    set +e
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=1s \
        "${SSH_SESSION_TIMEOUT_SECONDS}s" "$ENV_TOOL" "${env_options[@]}" \
        "PATH=$SSH_SHIM_DIR:/usr/bin:/bin" \
        "EVERSSH_SHIM_DIR=$SSH_SHIM_DIR" \
        "$SSH_TOOL" -4 -F "$SSH_OUTER_CONFIG" -n -T -- "$SSH_ALIAS" \
        "$remote_command" > "$output" 2> "$error"
    status=$?
    set -e
    (( status == expected_status )) || return 1
    "$CMP_TOOL" -s -- "$SSHD_EXPECTED_OUTPUT" "$output" || return 1
    [[ ! -s $error ]]
}

run_direct_ssh() {
    local number=$1 expected="EverSSH isolated direct connection $1" status
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

run_agent_certificate_production_session() {
    local session_number=$1 cert_source agent_blob client_blob ca_blob ca_fingerprint
    [[ $session_number == 8 ]] || return 1
    SSH_AGENT_KEY_DIR="$TMP_ROOT/agent-key" SSH_AGENT_CERT_DIR="$TMP_ROOT/agent-cert" SSH_AGENT_OUTPUT_DIR="$TMP_ROOT/agent-output" SSH_AGENT_SOCK="$TMP_ROOT/agent.sock"
    SSH_AGENT_PRIVATE="$SSH_AGENT_KEY_DIR/id_ed25519"
    SSH_AGENT_PUBLIC="$SSH_AGENT_PRIVATE.pub"
    cert_source="$SSH_AGENT_CERT_DIR/id_ed25519.pub" SSH_AGENT_CERT="$SSH_AGENT_CERT_DIR/id_ed25519-cert.pub"
    umask 077
    if ! { "$MKDIR_TOOL" -m 700 -- "$SSH_AGENT_KEY_DIR" "$SSH_AGENT_CERT_DIR" \
        "$SSH_AGENT_OUTPUT_DIR" && run_bounded "$SSHKEYGEN_TOOL" -q -t ed25519 \
        -N '' -f "$SSH_AGENT_PRIVATE" >"$SSH_AGENT_OUTPUT_DIR/keygen.stdout" \
        2>"$SSH_AGENT_OUTPUT_DIR/keygen.stderr" && "$CHMOD_TOOL" 600 -- \
        "$SSH_AGENT_PRIVATE" "$SSH_AGENT_PUBLIC" && "$CAT_TOOL" \
        "$SSH_AGENT_PUBLIC" > "$cert_source" && "$CHMOD_TOOL" 600 -- "$cert_source" && \
        run_bounded "$SSHKEYGEN_TOOL" -q -s "$SSHD_CA_KEY" \
        -I everssh-slice5a-cert -n "$CURRENT_USER" -V +10m "$cert_source" \
        >"$SSH_AGENT_OUTPUT_DIR/sign.stdout" 2>"$SSH_AGENT_OUTPUT_DIR/sign.stderr" && \
        "$CHMOD_TOOL" 600 -- "$SSH_AGENT_CERT" && run_bounded "$SSHKEYGEN_TOOL" \
        -Lf "$SSH_AGENT_CERT" >"$SSH_AGENT_OUTPUT_DIR/cert.info" \
        2>"$SSH_AGENT_OUTPUT_DIR/cert.stderr" && run_bounded "$SSHKEYGEN_TOOL" \
        -lf "$SSHD_CA_PUBLIC" >"$SSH_AGENT_OUTPUT_DIR/ca.fingerprint" \
        2>"$SSH_AGENT_OUTPUT_DIR/ca.stderr"; }; then
        report_session_failure 8 agent-setup; return 1
    fi
    ca_fingerprint=$($AWK_TOOL 'NR == 1 { print $2 }' "$SSH_AGENT_OUTPUT_DIR/ca.fingerprint") || { report_session_failure 8 cert-fingerprint; return 1; }
    if ! "$AWK_TOOL" -v principal="$CURRENT_USER" -v ca="$ca_fingerprint" '
        $1 == "Key" && $2 == "ID:" && $3 == "\"everssh-slice5a-cert\"" { id=1 }; $1 == "Signing" && $2 == "CA:" && $4 == ca { signer=1 }; $1 == "Valid:" && $2 == "from" && $4 == "to" { valid=1 }; $1 == "Principals:" { in_principals=1; next }; in_principals && $1 == principal && NF == 1 { named=1 }; $1 == "Critical" { in_principals=0 }
        END { exit !(id && signer && valid && named) }' \
        "$SSH_AGENT_OUTPUT_DIR/cert.info"; then
        report_session_failure 8 cert-evidence; return 1
    fi
    agent_blob=$($AWK_TOOL 'NF >= 2 { print $2; exit }' "$SSH_AGENT_PUBLIC") || { report_session_failure 8 agent-key-blob; return 1; }
    client_blob=$($AWK_TOOL 'NF >= 2 { print $2; exit }' "$SSHD_CLIENT_KEY.pub") || { report_session_failure 8 client-key-blob; return 1; }
    ca_blob=$($AWK_TOOL 'NF >= 2 { print $2; exit }' "$SSHD_CA_PUBLIC") || { report_session_failure 8 ca-key-blob; return 1; }
    if [[ -z $agent_blob || -z $client_blob || -z $ca_blob || \
        $agent_blob == "$client_blob" || $agent_blob == "$ca_blob" ]] || \
        ! "$AWK_TOOL" -v direct="$client_blob" -v agent="$agent_blob" \
        'NF { lines++; direct_count += ($2 == direct); agent_count += ($2 == agent) }
         END { exit !(lines == 1 && direct_count == 1 && agent_count == 0) }' \
        "$SSHD_AUTHORIZED_KEYS" || ! "$RM_TOOL" -f -- "$SSHD_CA_KEY" || \
        [[ -e $SSHD_CA_KEY || -L $SSHD_CA_KEY ]]; then
        report_session_failure 8 authorization-evidence; return 1
    fi
    start_isolated_agent || { report_session_failure 8 agent-start; return 1; }
    load_isolated_agent_key || { report_session_failure 8 agent-load; return 1; }
    clear_server_tuple
    write_agent_configs_and_shim 8 || { report_session_failure 8 config; return 1; }
    : > "$TMP_ROOT/outer-8.stdout"; : > "$TMP_ROOT/outer-8.stderr"
    "$CHMOD_TOOL" 600 -- "$TMP_ROOT/outer-8.stdout" "$TMP_ROOT/outer-8.stderr" || return 1
    run_outer_ssh 8 0 'EverSSH isolated production connection 8' isolated-agent || \
        { report_session_failure 8 command; return 1; }
    verify_agent_proxy_evidence || { report_session_failure 8 proxy-evidence; return 1; }
    poll_server_gone "$SERVER_PID" "$SERVER_START" "$SERVER_EXE" "$SERVER_PGRP" \
        "$SERVER_ROLE" || { report_session_failure 8 server-exit; return 1; }
    stop_isolated_agent || { report_session_failure 8 agent-stop; return 1; }
    listener_exact "$ISOLATED_ADDR" "$ISOLATED_PORT" && listener_exact \
        127.0.0.1 "$ISOLATED_PORT" || { report_session_failure 8 listeners; return 1; }
}

run_binary_production_session() {
    local session_number=$1 input="$TMP_ROOT/binary-$1.input"
    local output="$TMP_ROOT/binary-$1.stdout" error="$TMP_ROOT/binary-$1.stderr"
    local status input_size output_size input_mode output_mode
    local input_digest output_digest

    clear_server_tuple
    write_ssh_configs_and_shim "$session_number" || return 1
    umask 077
    run_bounded "$DD_TOOL" if=/dev/urandom of="$input" \
        bs="$BINARY_BYTES" count=1 status=none || return 1
    "$CHMOD_TOOL" 600 -- "$input" || return 1
    input_size=$("$STAT_TOOL" -c '%s' -- "$input") || return 1
    input_mode=$("$STAT_TOOL" -c '%a' -- "$input") || return 1
    [[ $input_size == "$BINARY_BYTES" && $input_mode == 600 ]] || return 1

    : > "$output"
    : > "$error"
    "$CHMOD_TOOL" 600 -- "$output" "$error" || return 1
    set +e
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=1s \
        "${SSH_BINARY_SESSION_TIMEOUT_SECONDS}s" "$ENV_TOOL" \
        "PATH=$SSH_SHIM_DIR:/usr/bin:/bin" \
        "EVERSSH_SHIM_DIR=$SSH_SHIM_DIR" \
        "$SSH_TOOL" -4 -F "$SSH_OUTER_CONFIG" -T -- "$SSH_ALIAS" \
        /usr/bin/cat < "$input" > "$output" 2> "$error"
    status=$?
    set -e
    (( status == 0 )) || return 1
    [[ ! -s $error ]] || return 1

    input_size=$("$STAT_TOOL" -c '%s' -- "$input") || return 1
    output_size=$("$STAT_TOOL" -c '%s' -- "$output") || return 1
    input_mode=$("$STAT_TOOL" -c '%a' -- "$input") || return 1
    output_mode=$("$STAT_TOOL" -c '%a' -- "$output") || return 1
    [[ $input_size == "$BINARY_BYTES" && $input_mode == 600 ]] || return 1
    [[ $output_size == "$BINARY_BYTES" && $output_mode == 600 ]] || return 1

    input_digest=$("$SHA256SUM_TOOL" -- "$input") || return 1
    output_digest=$("$SHA256SUM_TOOL" -- "$output") || return 1
    input_digest=${input_digest%% *}
    output_digest=${output_digest%% *}
    [[ $input_digest =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ $output_digest =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ $input_digest == "$output_digest" ]] || return 1
    "$CMP_TOOL" -s -- "$input" "$output" || return 1
    verify_proxy_evidence || return 1
    poll_server_gone "$SERVER_PID" "$SERVER_START" "$SERVER_EXE" "$SERVER_PGRP" \
        "$SERVER_ROLE" || return 1
    listener_exact "$ISOLATED_ADDR" "$ISOLATED_PORT" \
        && listener_exact 127.0.0.1 "$ISOLATED_PORT"
}

validate_sftp_path() {
    local path=$1 relative
    validate_temp_target "$TMP_ROOT" || return 1
    [[ $path == /* && $path == "$TMP_ROOT/"* ]] || return 1
    relative=${path#"$TMP_ROOT/"}
    [[ -n $relative && $relative != */* ]] || return 1
    [[ $relative != . && $relative != .. ]] || return 1
    [[ $relative =~ ^[A-Za-z0-9._-]+$ ]] || return 1
    [[ $path == "$TMP_ROOT/$relative" ]]
}

report_session_failure() {
    local session_number=$1 stage=$2 detail=${3-}
    [[ $session_number =~ ^[4-8]$ ]] || return 1
    [[ $stage =~ ^[a-z][a-z0-9-]{0,31}$ ]] || return 1
    if [[ -n $detail ]]; then
        [[ $detail =~ ^[0-9]{1,12}$ ]] || return 1
        printf 'everssh-slice5a session=%s stage=%s detail=%s\n' \
            "$session_number" "$stage" "$detail" >&2
    else
        printf 'everssh-slice5a session=%s stage=%s\n' \
            "$session_number" "$stage" >&2
    fi
}

sftp_report_failure() {
    local session_number=$1 remote=$2 stage=$3 detail=${4-}
    if [[ -e $remote || -L $remote ]]; then
        "$RM_TOOL" -f -- "$remote" 2>/dev/null || :
    fi
    [[ ! -e $remote && ! -L $remote ]] || return 1
    report_session_failure "$session_number" "$stage" "$detail"
    return 1
}

run_pty_production_session() {
    local session_number=$1
    local input="$TMP_ROOT/pty-$session_number.input"
    local expected="$TMP_ROOT/pty-$session_number.expected"
    local output="$TMP_ROOT/pty-$session_number.stdout"
    local error="$TMP_ROOT/pty-$session_number.stderr"
    local remote_command status input_size expected_size output_size error_size cmp_status
    local input_mode expected_mode output_mode error_mode

    [[ $PTY_TERM_VALUE =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || return 1
    [[ $PTY_INPUT_LINE =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || return 1
    [[ $PTY_MARKER =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || return 1
    clear_server_tuple
    write_ssh_configs_and_shim "$session_number" || return 1
    umask 077
    "$PRINTF_TOOL" '%s\n' "$PTY_INPUT_LINE" > "$input" || return 1
    "$PRINTF_TOOL" '%s\r\n%s\r\n' "$PTY_INPUT_LINE" "$PTY_MARKER" > "$expected" || return 1
    : > "$output"
    : > "$error"
    "$CHMOD_TOOL" 600 -- "$input" "$expected" "$output" "$error" || return 1

    input_size=$($STAT_TOOL -c '%s' -- "$input") || return 1
    expected_size=$($STAT_TOOL -c '%s' -- "$expected") || return 1
    input_mode=$($STAT_TOOL -c '%a' -- "$input") || return 1
    expected_mode=$($STAT_TOOL -c '%a' -- "$expected") || return 1
    [[ $input_size == $(( ${#PTY_INPUT_LINE} + 1 )) && \
        $expected_size == $(( ${#PTY_INPUT_LINE} + ${#PTY_MARKER} + 4 )) && \
        $input_mode == 600 && $expected_mode == 600 ]] || return 1

    remote_command="$STTY_TOOL icanon echo opost onlcr && test -t 0 && test -t 1 && test -t 2 && [ \"\$TERM\" = '$PTY_TERM_VALUE' ] && IFS= read -r line && [ \"\$line\" = '$PTY_INPUT_LINE' ] && printf '%s\\n' '$PTY_MARKER'"
    set +e
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=1s \
        "${SSH_SESSION_TIMEOUT_SECONDS}s" "$ENV_TOOL" \
        "PATH=$SSH_SHIM_DIR:/usr/bin:/bin" \
        "EVERSSH_SHIM_DIR=$SSH_SHIM_DIR" \
        "TERM=$PTY_TERM_VALUE" \
        "$SSH_TOOL" -4 -F "$SSH_OUTER_CONFIG" -tt -- "$SSH_ALIAS" \
        "$remote_command" < "$input" > "$output" 2> "$error"
    status=$?
    set -e
    if (( status != 0 )); then
        report_session_failure "$session_number" pty-command "$status"
        return 1
    fi
    if [[ -s $error ]]; then
        error_size=$($STAT_TOOL -c '%s' -- "$error") || return 1
        report_session_failure "$session_number" stderr-size "$error_size"
        return 1
    fi

    input_size=$($STAT_TOOL -c '%s' -- "$input") || return 1
    expected_size=$($STAT_TOOL -c '%s' -- "$expected") || return 1
    output_size=$($STAT_TOOL -c '%s' -- "$output") || return 1
    input_mode=$($STAT_TOOL -c '%a' -- "$input") || return 1
    expected_mode=$($STAT_TOOL -c '%a' -- "$expected") || return 1
    output_mode=$($STAT_TOOL -c '%a' -- "$output") || return 1
    error_mode=$($STAT_TOOL -c '%a' -- "$error") || return 1
    if [[ $input_size != $(( ${#PTY_INPUT_LINE} + 1 )) || \
        $expected_size != $(( ${#PTY_INPUT_LINE} + ${#PTY_MARKER} + 4 )) || \
        $output_size != "$expected_size" || $input_mode != 600 || \
        $expected_mode != 600 || $output_mode != 600 || $error_mode != 600 ]]; then
        report_session_failure "$session_number" artifact-mismatch "$output_size"
        return 1
    fi
    cmp_status=0
    "$CMP_TOOL" -s -- "$expected" "$output" || cmp_status=$?
    if (( cmp_status != 0 )); then
        report_session_failure "$session_number" transcript-mismatch "$cmp_status"
        return 1
    fi

    if ! verify_proxy_evidence; then
        report_session_failure "$session_number" proxy-evidence
        return 1
    fi
    if ! poll_server_gone "$SERVER_PID" "$SERVER_START" "$SERVER_EXE" "$SERVER_PGRP" \
        "$SERVER_ROLE"; then
        report_session_failure "$session_number" server-exit
        return 1
    fi
    if listener_exact "$ISOLATED_ADDR" "$ISOLATED_PORT" \
        && listener_exact 127.0.0.1 "$ISOLATED_PORT"; then
        :
    else
        report_session_failure "$session_number" listeners
        return 1
    fi
}

run_sftp_production_session() {
    local session_number=$1
    local input="$TMP_ROOT/sftp-$session_number.input"
    local batch="$TMP_ROOT/sftp-$session_number.batch"
    local remote="$TMP_ROOT/sftp-$session_number.remote.$RANDOM"
    local download="$TMP_ROOT/sftp-$session_number.download"
    local output="$TMP_ROOT/sftp-$session_number.stdout"
    local error="$TMP_ROOT/sftp-$session_number.stderr"
    local path status input_size download_size input_mode download_mode
    local batch_mode output_mode error_mode input_digest download_digest
    local error_size cmp_status

    [[ $session_number == 5 ]] || return 1
    clear_server_tuple
    write_ssh_configs_and_shim "$session_number" || return 1
    for path in "$input" "$batch" "$remote" "$download" "$output" "$error"; do
        validate_sftp_path "$path" || return 1
        [[ ! -e $path && ! -L $path ]] || return 1
    done

    umask 077
    run_bounded "$DD_TOOL" if=/dev/urandom of="$input" \
        bs="$BINARY_BYTES" count=1 status=none || return 1
    : > "$download" || return 1
    : > "$output" || return 1
    : > "$error" || return 1
    "$PRINTF_TOOL" '%s\n' \
        "put \"$input\" \"$remote\"" \
        "get \"$remote\" \"$download\"" \
        "rm \"$remote\"" > "$batch" || return 1
    "$CHMOD_TOOL" 600 -- "$input" "$batch" "$download" "$output" "$error" || return 1

    input_size=$($STAT_TOOL -c '%s' -- "$input") || return 1
    input_mode=$($STAT_TOOL -c '%a' -- "$input") || return 1
    batch_mode=$($STAT_TOOL -c '%a' -- "$batch") || return 1
    download_mode=$($STAT_TOOL -c '%a' -- "$download") || return 1
    output_mode=$($STAT_TOOL -c '%a' -- "$output") || return 1
    error_mode=$($STAT_TOOL -c '%a' -- "$error") || return 1
    [[ $input_size == "$BINARY_BYTES" && $input_mode == 600 && \
        $batch_mode == 600 && $download_mode == 600 && \
        $output_mode == 600 && $error_mode == 600 ]] || return 1

    set +e
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=1s \
        "${SFTP_SESSION_TIMEOUT_SECONDS}s" "$ENV_TOOL" \
        "PATH=$SSH_SHIM_DIR:/usr/bin:/bin" \
        "EVERSSH_SHIM_DIR=$SSH_SHIM_DIR" \
        "$SFTP_TOOL" -q -4 -F "$SSH_OUTER_CONFIG" -S "$SSH_TOOL" \
        -b "$batch" "$SSH_ALIAS" < /dev/null > "$output" 2> "$error"
    status=$?
    set -e
    if (( status != 0 )); then
        sftp_report_failure "$session_number" "$remote" sftp-command "$status"
        return 1
    fi

    cmp_status=0
    "$CMP_TOOL" -s -- \
        <("$PRINTF_TOOL" '%s\n' \
            "sftp> put \"$input\" \"$remote\"" \
            "sftp> get \"$remote\" \"$download\"" \
            "sftp> rm \"$remote\"") "$output" || cmp_status=$?
    if (( cmp_status != 0 )); then
        output_size=$($STAT_TOOL -c '%s' -- "$output") || {
            sftp_report_failure "$session_number" "$remote" output-size
            return 1
        }
        sftp_report_failure "$session_number" "$remote" transcript-mismatch "$output_size"
        return 1
    fi
    if [[ -s $error ]]; then
        error_size=$($STAT_TOOL -c '%s' -- "$error") || {
            sftp_report_failure "$session_number" "$remote" stderr-size
            return 1
        }
        sftp_report_failure "$session_number" "$remote" stderr-size "$error_size"
        return 1
    fi

    input_size=$($STAT_TOOL -c '%s' -- "$input") || {
        sftp_report_failure "$session_number" "$remote" input-size
        return 1
    }
    download_size=$($STAT_TOOL -c '%s' -- "$download") || {
        sftp_report_failure "$session_number" "$remote" download-size
        return 1
    }
    input_mode=$($STAT_TOOL -c '%a' -- "$input") || {
        sftp_report_failure "$session_number" "$remote" input-mode
        return 1
    }
    download_mode=$($STAT_TOOL -c '%a' -- "$download") || {
        sftp_report_failure "$session_number" "$remote" download-mode
        return 1
    }
    batch_mode=$($STAT_TOOL -c '%a' -- "$batch") || {
        sftp_report_failure "$session_number" "$remote" batch-mode
        return 1
    }
    output_mode=$($STAT_TOOL -c '%a' -- "$output") || {
        sftp_report_failure "$session_number" "$remote" output-mode
        return 1
    }
    error_mode=$($STAT_TOOL -c '%a' -- "$error") || {
        sftp_report_failure "$session_number" "$remote" stderr-mode
        return 1
    }
    if [[ $input_size != "$BINARY_BYTES" || $download_size != "$BINARY_BYTES" || \
        $input_mode != 600 || $download_mode != 600 || $batch_mode != 600 || \
        $output_mode != 600 || $error_mode != 600 ]]; then
        sftp_report_failure "$session_number" "$remote" artifact-mismatch "$download_size"
        return 1
    fi

    input_digest=$($SHA256SUM_TOOL -- "$input") || {
        sftp_report_failure "$session_number" "$remote" input-digest
        return 1
    }
    download_digest=$($SHA256SUM_TOOL -- "$download") || {
        sftp_report_failure "$session_number" "$remote" download-digest
        return 1
    }
    input_digest=${input_digest%% *}
    download_digest=${download_digest%% *}
    if [[ ! $input_digest =~ ^[0-9a-f]{64}$ || \
        ! $download_digest =~ ^[0-9a-f]{64}$ || \
        $input_digest != "$download_digest" ]]; then
        sftp_report_failure "$session_number" "$remote" digest-mismatch 1
        return 1
    fi
    cmp_status=0
    "$CMP_TOOL" -s -- "$input" "$download" || cmp_status=$?
    if (( cmp_status != 0 )); then
        sftp_report_failure "$session_number" "$remote" bytes-mismatch "$cmp_status"
        return 1
    fi
    if [[ -e $remote || -L $remote ]]; then
        sftp_report_failure "$session_number" "$remote" artifact-mismatch 1
        return 1
    fi

    if ! verify_proxy_evidence; then
        sftp_report_failure "$session_number" "$remote" proxy-evidence
        return 1
    fi
    if ! poll_server_gone "$SERVER_PID" "$SERVER_START" "$SERVER_EXE" \
        "$SERVER_PGRP" "$SERVER_ROLE"; then
        sftp_report_failure "$session_number" "$remote" server-exit
        return 1
    fi
    if listener_exact "$ISOLATED_ADDR" "$ISOLATED_PORT" \
        && listener_exact 127.0.0.1 "$ISOLATED_PORT"; then
        return 0
    fi
    sftp_report_failure "$session_number" "$remote" listeners
}

scp_report_failure() {
    local session_number=$1 source=$2 stage=$3 detail=${4-}
    if [[ -e $source || -L $source ]]; then
        "$RM_TOOL" -f -- "$source" 2>/dev/null || :
    fi
    if [[ -e $source || -L $source ]]; then
        report_session_failure "$session_number" source-remove 1
    else
        report_session_failure "$session_number" "$stage" "$detail"
    fi
    return 1
}

run_scp_production_session() {
    local session_number=$1
    local source="$TMP_ROOT/scp-$1.source"
    local download="$TMP_ROOT/scp-$1.download"
    local output="$TMP_ROOT/scp-$1.stdout"
    local error="$TMP_ROOT/scp-$1.stderr"
    local path status source_size download_size source_mode download_mode
    local output_size error_size cmp_status
    local source_digest download_digest

    [[ $session_number == 6 ]] || return 1
    clear_server_tuple
    write_ssh_configs_and_shim "$session_number" || return 1
    for path in "$source" "$download" "$output" "$error"; do
        validate_sftp_path "$path" || return 1
        [[ ! -e $path && ! -L $path ]] || return 1
    done

    umask 077
    set +e
    run_bounded "$DD_TOOL" if=/dev/urandom of="$source" \
        bs="$BINARY_BYTES" count=1 status=none
    status=$?
    set -e
    if (( status != 0 )); then
        scp_report_failure "$session_number" "$source" scp-source "$status"
        return 1
    fi
    if ! "$CHMOD_TOOL" 600 -- "$source"; then
        scp_report_failure "$session_number" "$source" source-mode 1
        return 1
    fi
    if ! { : > "$download" && : > "$output" && : > "$error"; }; then
        scp_report_failure "$session_number" "$source" artifact-create 1
        return 1
    fi
    if ! "$CHMOD_TOOL" 600 -- "$download" "$output" "$error"; then
        scp_report_failure "$session_number" "$source" artifact-mode 1
        return 1
    fi

    source_size=$($STAT_TOOL -c '%s' -- "$source") || {
        scp_report_failure "$session_number" "$source" source-size
        return 1
    }
    source_mode=$($STAT_TOOL -c '%a' -- "$source") || {
        scp_report_failure "$session_number" "$source" source-mode
        return 1
    }
    [[ $source_size == "$BINARY_BYTES" && $source_mode == 600 ]] || {
        scp_report_failure "$session_number" "$source" source-artifact "$source_size"
        return 1
    }

    set +e
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=1s \
        "${SCP_SESSION_TIMEOUT_SECONDS}s" "$ENV_TOOL" \
        "PATH=$SSH_SHIM_DIR:/usr/bin:/bin" \
        "EVERSSH_SHIM_DIR=$SSH_SHIM_DIR" \
        "$SCP_TOOL" -q -4 -F "$SSH_OUTER_CONFIG" -S "$SSH_TOOL" -- \
        "$SSH_ALIAS:$source" "$download" < /dev/null > "$output" 2> "$error"
    status=$?
    set -e
    if (( status != 0 )); then
        scp_report_failure "$session_number" "$source" scp-command "$status"
        return 1
    fi

    output_size=$($STAT_TOOL -c '%s' -- "$output") || { scp_report_failure "$session_number" "$source" stdout-size; return 1; }
    (( output_size == 0 )) || { scp_report_failure "$session_number" "$source" stdout-size "$output_size"; return 1; }
    error_size=$($STAT_TOOL -c '%s' -- "$error") || { scp_report_failure "$session_number" "$source" stderr-size; return 1; }
    (( error_size == 0 )) || { scp_report_failure "$session_number" "$source" stderr-size "$error_size"; return 1; }

    source_size=$($STAT_TOOL -c '%s' -- "$source") || {
        scp_report_failure "$session_number" "$source" source-size
        return 1
    }
    download_size=$($STAT_TOOL -c '%s' -- "$download") || {
        scp_report_failure "$session_number" "$source" download-size
        return 1
    }
    source_mode=$($STAT_TOOL -c '%a' -- "$source") || {
        scp_report_failure "$session_number" "$source" source-mode
        return 1
    }
    download_mode=$($STAT_TOOL -c '%a' -- "$download") || {
        scp_report_failure "$session_number" "$source" download-mode
        return 1
    }
    if [[ $source_size != "$BINARY_BYTES" || $download_size != "$BINARY_BYTES" || \
        $source_mode != 600 || $download_mode != 600 ]]; then
        scp_report_failure "$session_number" "$source" artifact-mismatch "$download_size"
        return 1
    fi

    source_digest=$($SHA256SUM_TOOL -- "$source") || {
        scp_report_failure "$session_number" "$source" source-digest
        return 1
    }
    download_digest=$($SHA256SUM_TOOL -- "$download") || {
        scp_report_failure "$session_number" "$source" download-digest
        return 1
    }
    source_digest=${source_digest%% *}
    download_digest=${download_digest%% *}
    if [[ ! $source_digest =~ ^[0-9a-f]{64}$ || \
        ! $download_digest =~ ^[0-9a-f]{64}$ || \
        $source_digest != "$download_digest" ]]; then
        scp_report_failure "$session_number" "$source" digest-mismatch 1
        return 1
    fi
    cmp_status=0
    "$CMP_TOOL" -s -- "$source" "$download" || cmp_status=$?
    if (( cmp_status != 0 )); then
        scp_report_failure "$session_number" "$source" bytes-mismatch "$cmp_status"
        return 1
    fi

    "$RM_TOOL" -f -- "$source" 2>/dev/null || :
    if [[ -e $source || -L $source ]]; then
        report_session_failure "$session_number" source-remove 1
        return 1
    fi
    if ! verify_proxy_evidence; then
        report_session_failure "$session_number" proxy-evidence
        return 1
    fi
    if ! poll_server_gone "$SERVER_PID" "$SERVER_START" "$SERVER_EXE" \
        "$SERVER_PGRP" "$SERVER_ROLE"; then
        report_session_failure "$session_number" server-exit
        return 1
    fi
    if listener_exact "$ISOLATED_ADDR" "$ISOLATED_PORT" \
        && listener_exact 127.0.0.1 "$ISOLATED_PORT"; then
        return 0
    fi
    report_session_failure "$session_number" listeners
    return 1
}

forward_artifact_cleanup() {
    local path rc=0
    for path in "$FORWARD_SOCK" "$FORWARD_REMOTE_SOCK" "$FORWARD_RELEASE"; do
        [[ -n $path ]] || continue
        "$RM_TOOL" -f -- "$path" 2>/dev/null || rc=1
        [[ ! -e $path && ! -L $path ]] || rc=1
    done
    (( rc == 0 )) && { FORWARD_SOCK=; FORWARD_REMOTE_SOCK=; FORWARD_RELEASE=; }
    return "$rc"
}

forward_report_failure() {
    local stage=$1 detail=${2-}
    case $stage in
        identity|start|listener|remote-listener|client|remote-client|release|exit-status|output-clean|\
        group-empty|artifact-remove|proxy-evidence|server-exit|listeners) ;;
        *) return 1 ;;
    esac
    [[ -z $detail || $detail =~ ^[0-9]{1,12}$ ]] || return 1
    if [[ -n $detail ]]; then
        printf 'everssh-slice5a session=7 stage=%s detail=%s\n' \
            "$stage" "$detail" >&2
    else
        printf 'everssh-slice5a session=7 stage=%s\n' "$stage" >&2
    fi
}

forward_fail() {
    local stage=$1 detail=${2-}
    if [[ -n $FORWARD_PID ]]; then
        if cleanup_owned "$FORWARD_PID" "$FORWARD_START" "$FORWARD_EXE" \
            "$FORWARD_PGRP" "$FORWARD_ROLE"; then
            clear_forward
        fi
    fi
    forward_artifact_cleanup || :
    forward_report_failure "$stage" "$detail" || :
    return 1
}

run_forward_nested_client() {
    local socket=$1 expected=$2 expected_file=$3 output=$4 error=$5
    local status mode cmp_status size path
    set +e
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=1s \
        "${FORWARD_CLIENT_TIMEOUT_SECONDS}s" "$SSH_TOOL" -4 -F /dev/null -n -T \
        -i "$SSHD_CLIENT_KEY" -p "$ISOLATED_PORT" \
        -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
        -o UserKnownHostsFile="$SSHD_KNOWN_HOSTS" -o GlobalKnownHostsFile=/dev/null \
        -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519 \
        -o ProxyCommand="$NC_TOOL -U $socket" -o ProxyJump=none \
        -o ControlMaster=no -o ControlPath=none -o ControlPersist=no \
        -o ForwardAgent=no -o ForwardX11=no -o ForwardX11Trusted=no -o Tunnel=no \
        -o ClearAllForwardings=yes -o PubkeyAuthentication=yes \
        -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
        -o PreferredAuthentications=publickey -o ConnectTimeout=2 \
        -o ConnectionAttempts=1 -o RequestTTY=no -o UpdateHostKeys=no \
        -- "$CURRENT_USER@127.0.0.1" "$PRINTF_TOOL '%s\\n' '$expected'" \
        > "$output" 2> "$error"
    status=$?
    set -e
    (( status == 0 )) || return "$status"
    for path in "$output" "$error"; do
        mode=$("$STAT_TOOL" -c '%a' -- "$path") || return 1
        [[ $mode == 600 ]] || return 1
    done
    cmp_status=0
    "$CMP_TOOL" -s -- "$expected_file" "$output" || cmp_status=$?
    (( cmp_status == 0 )) || return "$cmp_status"
    size=$("$STAT_TOOL" -c '%s' -- "$error") || return 1
    (( size == 0 ))
}

run_forward_production_session() {
    local session_number=$1
    local primary_output="$TMP_ROOT/forward-7.stdout"
    local primary_error="$TMP_ROOT/forward-7.stderr"
    local client_output="$TMP_ROOT/forward-7.client.stdout"
    local client_error="$TMP_ROOT/forward-7.client.stderr"
    local remote_client_output="$TMP_ROOT/forward-7.remote-client.stdout"
    local remote_client_error="$TMP_ROOT/forward-7.remote-client.stderr"
    local expected_output="$TMP_ROOT/forward-7.expected"
    local remote_expected_output="$TMP_ROOT/forward-7.remote.expected"
    local expected='EverSSH isolated forwarded connection 7'
    local remote_expected='EverSSH isolated remote-forwarded connection 7'
    local remote_command path status result i deadline cmp_status size mode pid

    [[ $session_number == 7 ]] || return 1
    clear_forward
    clear_server_tuple
    FORWARD_SOCK="$TMP_ROOT/forward-7.sock"
    FORWARD_REMOTE_SOCK="$TMP_ROOT/forward-7.remote.sock"
    FORWARD_RELEASE="$TMP_ROOT/forward-7.release"
    write_ssh_configs_and_shim 7 || { forward_fail identity; return 1; }
    for path in "$FORWARD_SOCK" "$FORWARD_REMOTE_SOCK" "$FORWARD_RELEASE" \
        "$primary_output" "$primary_error" "$client_output" "$client_error" \
        "$expected_output" "$remote_client_output" "$remote_client_error" \
        "$remote_expected_output"; do
        validate_sftp_path "$path" || { forward_fail identity; return 1; }
        [[ ! -e $path && ! -L $path ]] || { forward_fail identity; return 1; }
    done

    umask 077
    if ! { : > "$primary_output" && : > "$primary_error" && \
        : > "$client_output" && : > "$client_error" && \
        : > "$remote_client_output" && : > "$remote_client_error" && \
        "$PRINTF_TOOL" '%s\n' "$expected" > "$expected_output" && \
        "$PRINTF_TOOL" '%s\n' "$remote_expected" > "$remote_expected_output"; }; then
        forward_fail identity
        return 1
    fi
    "$CHMOD_TOOL" 600 -- "$primary_output" "$primary_error" \
        "$client_output" "$client_error" "$expected_output" \
        "$remote_client_output" "$remote_client_error" \
        "$remote_expected_output" || {
        forward_fail identity
        return 1
    }
    remote_command="i=0; while [ ! -e '$FORWARD_RELEASE' ] && [ \"\$i\" -lt $FORWARD_REMOTE_WAIT_ATTEMPTS ]; do i=\$((i + 1)); /usr/bin/sleep 0.1; done; [ -e '$FORWARD_RELEASE' ]"
    "$SETSID_TOOL" "$ENV_TOOL" PATH="$SSH_SHIM_DIR:/usr/bin:/bin" \
        EVERSSH_SHIM_DIR="$SSH_SHIM_DIR" "$SSH_TOOL" -4 -F "$SSH_OUTER_CONFIG" \
        -n -T -o ClearAllForwardings=no -o ExitOnForwardFailure=yes \
        -o StreamLocalBindMask=0077 \
        -L "$FORWARD_SOCK:127.0.0.1:$ISOLATED_PORT" \
        -R "$FORWARD_REMOTE_SOCK:127.0.0.1:$ISOLATED_PORT" -- "$SSH_ALIAS" \
        "$remote_command" > "$primary_output" 2> "$primary_error" &
    pid=$!
    for ((i = 0; i < READINESS_POLL_ATTEMPTS; i++)); do
        if capture_identity "$pid"; then
            if [[ $CAP_STATE != Z && $CAP_EXE == "$SSH_TOOL" && \
                $CAP_PGRP == "$pid" ]]; then
                record_forward_identity "$pid" forward-ssh
                break
            fi
        elif [[ ! -e "/proc/$pid/stat" ]]; then
            status=0
            builtin wait "$pid" 2>/dev/null || status=$?
            forward_fail start "$status"
            return 1
        fi
        "$TIMEOUT_TOOL" 1s "$SLEEP_TOOL" 0.05
    done
    if [[ -z $FORWARD_PID ]]; then
        if capture_identity "$pid"; then
            record_forward_identity "$pid" forward-ssh
        elif reap_terminal_child "$pid"; then
            forward_fail start 1
            return 1
        else
            forward_fail identity
            return 1
        fi
        forward_fail identity
        return 1
    fi
    validate_owned "$FORWARD_PID" "$FORWARD_START" "$FORWARD_EXE" "$FORWARD_PGRP" "$FORWARD_ROLE" || {
        result=$?
        forward_fail identity "$result"
        return 1
    }

    deadline=$((SECONDS + FORWARD_READY_SECONDS))
    while (( SECONDS < deadline )); do
        if validate_owned "$FORWARD_PID" "$FORWARD_START" "$FORWARD_EXE" "$FORWARD_PGRP" "$FORWARD_ROLE"; then
            if [[ -S $FORWARD_SOCK && ! -L $FORWARD_SOCK ]]; then
                mode=$("$STAT_TOOL" -c '%a' -- "$FORWARD_SOCK") || mode=
                [[ $mode == 700 ]] && break
            fi
        else
            status=0
            builtin wait "$FORWARD_PID" 2>/dev/null || status=$?
            forward_fail listener "$status"
            return 1
        fi
        "$TIMEOUT_TOOL" 1s "$SLEEP_TOOL" 0.05
    done
    mode=$("$STAT_TOOL" -c '%a' -- "$FORWARD_SOCK") 2>/dev/null || mode=
    [[ -S $FORWARD_SOCK && ! -L $FORWARD_SOCK && $mode == 700 ]] || {
        forward_fail listener
        return 1
    }

    deadline=$((SECONDS + FORWARD_READY_SECONDS))
    while (( SECONDS < deadline )); do
        if validate_owned "$FORWARD_PID" "$FORWARD_START" "$FORWARD_EXE" "$FORWARD_PGRP" "$FORWARD_ROLE"; then
            if [[ -S $FORWARD_REMOTE_SOCK && ! -L $FORWARD_REMOTE_SOCK ]]; then
                mode=$("$STAT_TOOL" -c '%a' -- "$FORWARD_REMOTE_SOCK") || mode=
                [[ $mode == 600 ]] && break
            fi
        else
            status=0
            builtin wait "$FORWARD_PID" 2>/dev/null || status=$?
            forward_fail remote-listener "$status"
            return 1
        fi
        "$TIMEOUT_TOOL" 1s "$SLEEP_TOOL" 0.05
    done
    mode=$("$STAT_TOOL" -c '%a' -- "$FORWARD_REMOTE_SOCK") 2>/dev/null || mode=
    [[ -S $FORWARD_REMOTE_SOCK && ! -L $FORWARD_REMOTE_SOCK && $mode == 600 ]] || {
        forward_fail remote-listener
        return 1
    }

    run_forward_nested_client "$FORWARD_SOCK" "$expected" "$expected_output" \
        "$client_output" "$client_error" || {
        status=$?
        forward_fail client "$status"
        return 1
    }
    run_forward_nested_client "$FORWARD_REMOTE_SOCK" "$remote_expected" \
        "$remote_expected_output" "$remote_client_output" "$remote_client_error" || {
        status=$?
        forward_fail remote-client "$status"
        return 1
    }

    "$PRINTF_TOOL" 'release\n' > "$FORWARD_RELEASE" || {
        forward_fail release 1
        return 1
    }
    "$CHMOD_TOOL" 600 -- "$FORWARD_RELEASE" || { forward_fail release 1; return 1; }
    mode=$("$STAT_TOOL" -c '%a' -- "$FORWARD_RELEASE") || { forward_fail release 1; return 1; }
    [[ $mode == 600 ]] || { forward_fail release 1; return 1; }
    poll_owned_gone "$FORWARD_PID" "$FORWARD_START" "$FORWARD_EXE" "$FORWARD_PGRP" "$FORWARD_ROLE" || {
        forward_fail release
        return 1
    }
    if validate_owned "$FORWARD_PID" "$FORWARD_START" "$FORWARD_EXE" "$FORWARD_PGRP" "$FORWARD_ROLE"; then
        forward_fail release 1
        return 1
    else
        result=$?
        (( result == 2 )) || { forward_fail release "$result"; return 1; }
    fi
    status=0
    builtin wait "$FORWARD_PID" 2>/dev/null || status=$?
    (( status == 0 )) || { forward_fail exit-status "$status"; return 1; }
    [[ ! -e "/proc/$FORWARD_PID/stat" ]] || { forward_fail exit-status 1; return 1; }
    mode=$("$STAT_TOOL" -c '%a' -- "$primary_output") || { forward_fail output-clean 1; return 1; }
    [[ $mode == 600 ]] || { forward_fail output-clean 1; return 1; }
    size=$("$STAT_TOOL" -c '%s' -- "$primary_output") || { forward_fail output-clean 1; return 1; }
    (( size == 0 )) || { forward_fail output-clean "$size"; return 1; }
    mode=$("$STAT_TOOL" -c '%a' -- "$primary_error") || { forward_fail output-clean 1; return 1; }
    [[ $mode == 600 ]] || { forward_fail output-clean 1; return 1; }
    size=$("$STAT_TOOL" -c '%s' -- "$primary_error") || { forward_fail output-clean 1; return 1; }
    (( size == 0 )) || { forward_fail output-clean "$size"; return 1; }
    poll_group_empty "$FORWARD_PGRP" || { forward_fail group-empty 1; return 1; }
    clear_forward
    forward_artifact_cleanup || { forward_fail artifact-remove 1; return 1; }
    verify_proxy_evidence || { forward_fail proxy-evidence; return 1; }
    poll_server_gone "$SERVER_PID" "$SERVER_START" "$SERVER_EXE" \
        "$SERVER_PGRP" "$SERVER_ROLE" || { forward_fail server-exit; return 1; }
    listener_exact "$ISOLATED_ADDR" "$ISOLATED_PORT" && \
        listener_exact 127.0.0.1 "$ISOLATED_PORT" || { forward_fail listeners; return 1; }
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
    TMP_ROOT=$("$MKtemp_TOOL" -d -- /tmp/everssh-slice5a.XXXXXX)
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
        if [[ -n $FORWARD_PID ]]; then
            if cleanup_owned "$FORWARD_PID" "$FORWARD_START" "$FORWARD_EXE" \
                "$FORWARD_PGRP" "$FORWARD_ROLE"; then
                clear_forward
            else
                rc=1
            fi
        fi
        if [[ -n $OWN_PID ]]; then
            if cleanup_owned "$OWN_PID" "$OWN_START" "$OWN_EXE" "$OWN_PGRP" "$OWN_ROLE"; then
                clear_owned
            else
                rc=1
            fi
        fi
        if [[ -n $AGENT_PID || -n $SSH_AGENT_SOCK || -n $SSH_AGENT_KEY_DIR ]]; then
            stop_isolated_agent || rc=1
        fi
        if [[ -n $FORWARD_SOCK || -n $FORWARD_REMOTE_SOCK || -n $FORWARD_RELEASE ]]; then
            forward_artifact_cleanup || rc=1
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
        if [[ -z $AGENT_PID ]]; then remove_temp_root "$TMP_ROOT" || rc=1; else rc=1; fi
    fi

    if (( original_status != 0 )); then
        exit "$original_status"
    fi
    if (( rc != 0 )); then
        exit 1
    fi
    if [[ $MODE == parent ]]; then
        printf 'EverSSH Slice 5A production OpenSSH path: PASS\n'
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
    printf 'target/debug/everssh is stale or invalid\n' >&2
    exit 1
}

TMP_ROOT=$("$MKtemp_TOOL" -d -- /tmp/everssh-slice5a.XXXXXX)
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
run_production_session 1 0 'EverSSH isolated production connection' || {
    printf 'first production ProxyCommand session failed\n' >&2
    exit 1
}
run_direct_ssh 2 || {
    printf 'second direct ssh health check failed\n' >&2
    exit 1
}
run_production_session 2 42 'EverSSH isolated production connection 2' || {
    printf 'second production ProxyCommand session failed\n' >&2
    exit 1
}
run_direct_ssh 3 || {
    printf 'third direct ssh health check failed\n' >&2
    exit 1
}
run_binary_production_session 3 || {
    printf 'third production binary ProxyCommand session failed\n' >&2
    exit 1
}
run_direct_ssh 4 || {
    printf 'fourth direct ssh health check failed\n' >&2
    exit 1
}
run_pty_production_session 4 || {
    printf 'fourth production forced-PTY ProxyCommand session failed\n' >&2
    exit 1
}
run_direct_ssh 5 || {
    printf 'fifth direct ssh health check failed\n' >&2
    exit 1
}
run_sftp_production_session 5 || {
    printf 'fifth production SFTP batch ProxyCommand session failed\n' >&2
    exit 1
}
run_direct_ssh 6 || {
    printf 'sixth direct ssh health check failed\n' >&2
    exit 1
}
run_scp_production_session 6 || {
    printf 'sixth production scp ProxyCommand session failed\n' >&2
    exit 1
}
run_direct_ssh 7 || {
    printf 'seventh direct ssh health check failed\n' >&2
    exit 1
}
run_forward_production_session 7 || {
    printf 'seventh production local/remote-forward ProxyCommand session failed\n' >&2
    exit 1
}
run_direct_ssh 8 || {
    printf 'eighth direct ssh health check failed\n' >&2
    exit 1
}
run_agent_certificate_production_session 8 || {
    printf 'eighth production agent-certificate ProxyCommand session failed\n' >&2
    exit 1
}
run_direct_ssh 9 || {
    printf 'ninth direct ssh health check failed\n' >&2
    exit 1
}
clear_server_tuple
exit 0
