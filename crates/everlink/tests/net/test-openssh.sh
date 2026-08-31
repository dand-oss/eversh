#!/usr/bin/bash
set -Eeuo pipefail

# Slice 5A is deliberately only the ownership foundation.  Later sshd and
# production EverLink cases will be added below this self-test boundary.

readonly BASH_TOOL=/usr/bin/bash
readonly CHMOD_TOOL=/usr/bin/chmod
readonly MKtemp_TOOL=/usr/bin/mktemp
readonly READLINK_TOOL=/usr/bin/readlink
readonly RM_TOOL=/usr/bin/rm
readonly SLEEP_TOOL=/usr/bin/sleep
readonly STAT_TOOL=/usr/bin/stat
readonly SETSID_TOOL=/usr/bin/setsid
readonly TIMEOUT_TOOL=/usr/bin/timeout
readonly SSHD_EXE=/usr/sbin/sshd
readonly WATCHDOG_SECONDS=45
readonly POLL_SECONDS=5
readonly READINESS_POLL_ATTEMPTS=120

for tool in "$BASH_TOOL" "$CHMOD_TOOL" "$MKtemp_TOOL" \
    "$READLINK_TOOL" "$RM_TOOL" "$SLEEP_TOOL" "$STAT_TOOL" \
    "$SETSID_TOOL" "$TIMEOUT_TOOL"; do
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
    group_empty "$pgrp" || rc=1
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
    group_empty "$CHILD_SLEEP_PGRP" || return 1
    [[ ! -e $CHILD_ROOT ]] || return 1
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
    local original_status=$? rc=0 result
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
        if [[ -n $OWN_PID ]]; then
            cleanup_owned "$OWN_PID" "$OWN_START" "$OWN_EXE" "$OWN_PGRP" "$OWN_ROLE" || rc=1
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
        printf 'EverLink Slice 5A ownership foundation: PASS\n'
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
exit 0
