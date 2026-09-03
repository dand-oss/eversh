#!/usr/bin/bash
set -Eeuo pipefail

# Milestone 5 / S3: the real-OpenSSH end-to-end release gate (design 11.4).
#
# This drives the COMPLETE real chain, unprivileged, with no fakes:
#   local `eversh connect` (real TTY via /usr/bin/script)
#     -> real /usr/bin/ssh with eversh's injected ProxyCommand
#     -> `eversh __everssh ssh-proxy` (real QUIC/UDP on an isolated address;
#        its inner bootstrap ssh reuses the SAME -F config and launches
#        `eversh __everssh __bootstrap-parent-v1` on the isolated sshd)
#     -> the outer ssh session (through the QUIC proxy, back to the SAME
#        isolated sshd via its 127.0.0.1 listener), `-t` allocated, running
#        `eversh __everpty v1 attach-or-create ...` against a REAL everpty
#        broker + child.
#
# Six scenarios exercise: child-exit passthrough, no-replay reattach after a
# killed transport, a session torn down mid-reconnect ("no longer live"),
# Busy visibility with no retry, list/detach persistence, and a final
# process/health sweep. A seventh (r3 repair): pre-establishment auth failure
# through the real chain (unauthorized key -> ordinary ssh 255, no probe, no
# reconnect, pinned diagnostics, exactly one supervisor ssh). Stdout carries
# ONLY the final PASS line; everything else goes to stderr or to per-scenario
# logs under the temp root (removed on success, preserved with its path
# printed to stderr on failure).

readonly AWK_TOOL=/usr/bin/awk
readonly BASH_TOOL=/usr/bin/bash
readonly CAT_TOOL=/usr/bin/cat
readonly PYTHON3=/usr/bin/python3
readonly CHMOD_TOOL=/usr/bin/chmod
readonly CUT_TOOL=/usr/bin/cut
readonly GREP_TOOL=/usr/bin/grep
readonly ID_TOOL=/usr/bin/id
readonly IP_TOOL=/usr/sbin/ip
readonly MKDIR_TOOL=/usr/bin/mkdir
readonly MKTEMP_TOOL=/usr/bin/mktemp
readonly PRINTF_TOOL=/usr/bin/printf
readonly READLINK_TOOL=/usr/bin/readlink
readonly RM_TOOL=/usr/bin/rm
readonly SCRIPT_TOOL=/usr/bin/script
readonly SED_TOOL=/usr/bin/sed
readonly SLEEP_TOOL=/usr/bin/sleep
readonly SORT_TOOL=/usr/bin/sort
readonly SS_TOOL=/usr/bin/ss
readonly SSH_TOOL=/usr/bin/ssh
readonly SSHD_EXE=/usr/sbin/sshd
readonly SSHKEYGEN_TOOL=/usr/bin/ssh-keygen
readonly SSHKEYSCAN_TOOL=/usr/bin/ssh-keyscan
readonly STAT_TOOL=/usr/bin/stat
readonly STTY_TOOL=/usr/bin/stty
readonly SETSID_TOOL=/usr/bin/setsid
readonly TIMEOUT_TOOL=/usr/bin/timeout

for tool in "$AWK_TOOL" "$BASH_TOOL" "$CAT_TOOL" "$CHMOD_TOOL" "$CUT_TOOL" \
    "$GREP_TOOL" "$ID_TOOL" "$IP_TOOL" "$MKDIR_TOOL" "$MKTEMP_TOOL" \
    "$PRINTF_TOOL" "$READLINK_TOOL" "$RM_TOOL" "$SCRIPT_TOOL" "$SED_TOOL" \
    "$SLEEP_TOOL" "$SORT_TOOL" "$SS_TOOL" "$SSH_TOOL" "$SSHD_EXE" \
    "$SSHKEYGEN_TOOL" "$SSHKEYSCAN_TOOL" "$STAT_TOOL" "$STTY_TOOL" \
    "$SETSID_TOOL" "$TIMEOUT_TOOL"; do
    [[ -x "$tool" ]] || {
        printf 'missing required executable: %s\n' "$tool" >&2
        exit 1
    }
done

# The whole run (sshd startup, seven scenarios, health checks, cleanup) must
# fit well under the watchdog; the watchdog is a hard outer safety net, not
# the expected duration. Scenario 2 spans the released v2 association's
# bounded drain: ~20s remote stall + 360s renewed lease + finalize slack.
readonly WATCHDOG_SECONDS=900
readonly READINESS_POLL_ATTEMPTS=100
readonly POLL_SECONDS=5
readonly BATCH_TIMEOUT_SECONDS=10
readonly KILL_TIMEOUT_SECONDS=20
readonly SCENARIO1_TIMEOUT_SECONDS=20
readonly AUTH_FAIL_TIMEOUT_SECONDS=20
readonly TICK_WAIT_SECONDS=15
readonly KILL_POLL_SECONDS=6
readonly REATTACH_WAIT_SECONDS=420
readonly SETTLE_SECONDS_MS=350
readonly ATTACH_BUSY_TIMEOUT_SECONDS=15
readonly BG_READY_ATTEMPTS=60

SCRIPT_PATH=$("$READLINK_TOOL" -e -- "${BASH_SOURCE[0]}") || {
    printf 'cannot resolve test script\n' >&2
    exit 1
}
[[ -x "$SCRIPT_PATH" ]] || {
    printf 'test script is not executable\n' >&2
    exit 1
}
WORKSPACE_ROOT=${SCRIPT_PATH%/crates/eversh/tests/net/test-eversh-openssh.sh}
[[ "$SCRIPT_PATH" == "$WORKSPACE_ROOT/crates/eversh/tests/net/test-eversh-openssh.sh" ]] || {
    printf 'unexpected script location\n' >&2
    exit 1
}
EVERSH_BIN="$WORKSPACE_ROOT/target/debug/eversh"

WATCHDOG_CHILD=0
if [[ ${1-} == --watchdog-child ]]; then
    WATCHDOG_CHILD=1
    shift
fi
[[ $# -eq 0 ]] || {
    printf 'unexpected arguments\n' >&2
    exit 1
}

# ---------------------------------------------------------------------------
# State (initialized before traps so a signal during startup is safe)
# ---------------------------------------------------------------------------
CLEANUP_DONE=0
TMP_ROOT=
OWN_PID= OWN_START= OWN_EXE= OWN_PGRP=
ISOLATED_ADDR=
ISOLATED_PORT=
SSHD_CONFIG= SSHD_LOG= SSHD_PID_FILE= SSHD_HOST_KEY= SSHD_CLIENT_KEY=
SSHD_AUTHORIZED_KEYS= SSHD_KNOWN_HOSTS= SSHD_HOST_BLOB=
CURRENT_USER=
CLIENT_CONFIG=
STATE_DIR=
ALIAS=eversh-m5s3-alias
EXPECTED_ORIGIN=

# ---------------------------------------------------------------------------
# Identity-tuple process capture / validated reaping (capture_identity
# pattern), generalized from crates/everssh/tests/net/test-openssh.sh.
# ---------------------------------------------------------------------------

capture_identity() {
    local pid=$1 line suffix state ppid pgrp session tty_nr tpgid flags minflt
    local cminflt majflt cmajflt utime stime cutime cstime priority nice
    local num_threads itrealvalue starttime remainder
    CAP_STATE= CAP_START= CAP_EXE= CAP_PGRP= CAP_PPID=
    [[ $pid =~ ^[0-9]+$ ]] || return 1
    [[ -r "/proc/$pid/stat" ]] || return 1
    IFS= read -r line 2>/dev/null < "/proc/$pid/stat" || return 1
    suffix=${line##*) }
    [[ $suffix != "$line" ]] || return 1
    read -r state ppid pgrp session tty_nr tpgid flags minflt cminflt \
        majflt cmajflt utime stime cutime cstime priority nice num_threads \
        itrealvalue starttime remainder <<< "$suffix" || return 1
    [[ $state =~ ^[[:alpha:]]$ ]] || return 1
    [[ $ppid =~ ^[0-9]+$ && $pgrp =~ ^[0-9]+$ && $starttime =~ ^[0-9]+$ ]] || return 1
    CAP_STATE=$state
    CAP_START=$starttime
    CAP_PGRP=$pgrp
    CAP_PPID=$ppid
    CAP_EXE=$("$READLINK_TOOL" -e -- "/proc/$pid/exe" 2>/dev/null) || return 1
    [[ -n $CAP_EXE ]]
}

# 0 exact owned tuple, 2 disappearance, 1 mismatch.
validate_owned() {
    local pid=$1 expected_start=$2 expected_exe=$3 expected_pgrp=$4
    if ! capture_identity "$pid"; then
        if [[ ! -e "/proc/$pid/stat" || ${CAP_STATE:-} == Z ]]; then
            return 2
        fi
        return 1
    fi
    [[ $CAP_START == "$expected_start" && $CAP_EXE == "$expected_exe" \
        && $CAP_PGRP == "$expected_pgrp" ]] || return 1
    [[ $CAP_STATE != Z ]] || return 2
    return 0
}

poll_owned_gone() {
    local pid=$1 start=$2 exe=$3 pgrp=$4 timeout_s=$5
    local deadline=$((SECONDS + timeout_s)) result
    while (( SECONDS < deadline )); do
        if validate_owned "$pid" "$start" "$exe" "$pgrp"; then
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

reap_owned_child() {
    local pid=$1 start=$2 exe=$3 pgrp=$4 result
    if validate_owned "$pid" "$start" "$exe" "$pgrp"; then
        return 1
    else
        result=$?
    fi
    [[ $result -eq 2 ]] || return 1
    builtin wait "$pid" 2>/dev/null || :
    return 0
}

cleanup_owned() {
    local pid=$1 start=$2 exe=$3 pgrp=$4
    local result rc=0 term_sent=0
    [[ -n $pid ]] || return 0

    if validate_owned "$pid" "$start" "$exe" "$pgrp"; then
        if builtin kill -TERM "$pid" 2>/dev/null; then
            term_sent=1
        elif validate_owned "$pid" "$start" "$exe" "$pgrp"; then
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
        if ! poll_owned_gone "$pid" "$start" "$exe" "$pgrp" "$POLL_SECONDS"; then
            if validate_owned "$pid" "$start" "$exe" "$pgrp"; then
                if builtin kill -KILL "$pid" 2>/dev/null; then
                    poll_owned_gone "$pid" "$start" "$exe" "$pgrp" "$POLL_SECONDS" || rc=1
                elif validate_owned "$pid" "$start" "$exe" "$pgrp"; then
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

    reap_owned_child "$pid" "$start" "$exe" "$pgrp" || rc=1
    return "$rc"
}

# All processes with the given pgrp, excluding one known pid (typically the
# group leader itself, still alive).
count_group_members_excluding() {
    local wanted=$1 exclude=$2 proc pid line suffix state ppid this_pgrp rest
    local count=0
    for proc in /proc/[0-9]*; do
        pid=${proc##*/}
        [[ $pid == "$exclude" ]] && continue
        [[ -r "$proc/stat" ]] || continue
        IFS= read -r line 2>/dev/null < "$proc/stat" || continue
        suffix=${line##*) }
        [[ $suffix != "$line" ]] || continue
        read -r state ppid this_pgrp rest <<< "$suffix" || continue
        [[ $this_pgrp == "$wanted" ]] || continue
        count=$((count + 1))
    done
    printf '%s\n' "$count"
}

# Any /proc/PID/cmdline containing the temp-root path (excluding one pid)
# identifies a harness-owned process: every wrapper, ssh, and proxy invocation
# carries an argument under $TMP_ROOT (the -F config, the wrapper path, or
# the state dir).
sweep_tmproot_processes() {
    local exclude=${1-} proc pid
    for proc in /proc/[0-9]*; do
        pid=${proc##*/}
        [[ -n $exclude && $pid == "$exclude" ]] && continue
        [[ $pid == "$$" || $pid == "$BASHPID" ]] && continue
        [[ -r "$proc/cmdline" ]] || continue
        if "$GREP_TOOL" -q -a -F -- "$TMP_ROOT" "$proc/cmdline" 2>/dev/null; then
            builtin kill -KILL "$pid" 2>/dev/null || :
        fi
    done
}

assert_no_stray_harness_processes() {
    local exclude=${1-} proc pid found=0
    for proc in /proc/[0-9]*; do
        pid=${proc##*/}
        [[ -n $exclude && $pid == "$exclude" ]] && continue
        [[ $pid == "$$" || $pid == "$BASHPID" ]] && continue
        [[ -r "$proc/cmdline" ]] || continue
        if "$GREP_TOOL" -q -a -F -- "$TMP_ROOT" "$proc/cmdline" 2>/dev/null; then
            printf 'stray harness process pid=%s\n' "$pid" >&2
            found=1
        fi
    done
    [[ $found -eq 0 ]]
}

proc_ppid() {
    local pid=$1 line suffix state ppid rest
    [[ -r "/proc/$pid/stat" ]] || return 1
    IFS= read -r line 2>/dev/null < "/proc/$pid/stat" || return 1
    suffix=${line##*) }
    [[ $suffix != "$line" ]] || return 1
    read -r state ppid rest <<< "$suffix" || return 1
    [[ $ppid =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$ppid"
}

pid_is_descendant() {
    local current=$1 ancestor=$2 depth=$3 hops=0 next
    while (( hops < depth )); do
        [[ $current == "$ancestor" ]] && return 0
        next=$(proc_ppid "$current") || return 1
        [[ $next =~ ^[0-9]+$ ]] || return 1
        (( next > 1 )) || return 1
        current=$next
        hops=$((hops + 1))
    done
    [[ $current == "$ancestor" ]]
}

proc_cmdline_has() {
    local pid=$1
    shift
    local -a argv=()
    [[ -r "/proc/$pid/cmdline" ]] || return 1
    while IFS= read -r -d '' part; do
        argv+=("$part")
    done < "/proc/$pid/cmdline" 2>/dev/null
    (( ${#argv[@]} > 0 )) || return 1
    local needle a found
    for needle in "$@"; do
        found=0
        for a in "${argv[@]}"; do
            [[ $a == "$needle" ]] && { found=1; break; }
        done
        (( found )) || return 1
    done
    return 0
}

# Find the live `<eversh-bin> __everssh ssh-proxy` process descending from
# the harness's own tracked ancestor pid (never trusting argv alone).
find_ssh_proxy_pid() {
    local ancestor=$1 max_depth=$2 proc pid
    for proc in /proc/[0-9]*; do
        pid=${proc##*/}
        proc_cmdline_has "$pid" __everssh ssh-proxy || continue
        pid_is_descendant "$pid" "$ancestor" "$max_depth" || continue
        printf '%s\n' "$pid"
        return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Temp root
# ---------------------------------------------------------------------------

validate_temp_target() {
    local path=$1 canonical mode
    [[ -n $path && $path == /tmp/eversh-m5s3.* && -d $path ]] || return 1
    canonical=$("$READLINK_TOOL" -e -- "$path") || return 1
    [[ $canonical == "$path" && $canonical != /tmp && $canonical != / ]] || return 1
    mode=$("$STAT_TOOL" -c '%a' -- "$path") || return 1
    [[ $mode == 700 ]]
}

remove_temp_root() {
    local path=$1 rc=0
    [[ -n $path ]] || return 0
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
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=1s 4s "$@"
}

# ---------------------------------------------------------------------------
# Isolated non-loopback address selection (mirrors
# crates/everssh/tests/net/test-openssh.sh)
# ---------------------------------------------------------------------------

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
    records=$(run_bounded "$IP_TOOL" -o -4 addr show scope global \
        | "$AWK_TOOL" '{ broadcast=""; for (i=1; i<=NF; i++) if ($i == "brd") broadcast=$(i+1); print $4 "|" broadcast }' \
        | "$SORT_TOOL" -t '|' -k1,1) || return 1
    [[ -n $records ]] || return 1
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
    done <<< "$records"
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
    ! listener_conflict "$ISOLATED_ADDR" "$port" && ! listener_conflict 127.0.0.1 "$port"
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

# ---------------------------------------------------------------------------
# Isolated sshd
# ---------------------------------------------------------------------------

prepare_isolated_sshd() {
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
    STATE_DIR="$TMP_ROOT/estate"
    "$MKDIR_TOOL" -m 700 -- "$TMP_ROOT/sshd" || return 1
    : > "$SSHD_LOG"
    "$CHMOD_TOOL" 600 -- "$SSHD_LOG" || return 1
    run_bounded "$SSHKEYGEN_TOOL" -q -t ed25519 -N '' -f "$SSHD_HOST_KEY" >/dev/null 2>&1 || return 1
    run_bounded "$SSHKEYGEN_TOOL" -q -t ed25519 -N '' -f "$SSHD_CLIENT_KEY" >/dev/null 2>&1 || return 1
    "$CHMOD_TOOL" 600 -- "$SSHD_HOST_KEY" "$SSHD_CLIENT_KEY" \
        "$SSHD_HOST_KEY.pub" "$SSHD_CLIENT_KEY.pub" || return 1
    "$CAT_TOOL" "$SSHD_CLIENT_KEY.pub" > "$SSHD_AUTHORIZED_KEYS" || return 1
    "$CHMOD_TOOL" 600 -- "$SSHD_AUTHORIZED_KEYS" || return 1
    SSHD_HOST_BLOB=$("$AWK_TOOL" 'NF >= 2 { print $2; exit }' "$SSHD_HOST_KEY.pub") || return 1
    [[ -n $SSHD_HOST_BLOB ]] || return 1
    select_free_port || return 1

    # /tmp itself must stay sticky-mode, so StrictModes must be off; the
    # generated root and every key/config file underneath are already
    # mode-700/600.
    printf '%s\n' \
        "Port $ISOLATED_PORT" \
        "ListenAddress $ISOLATED_ADDR:$ISOLATED_PORT" \
        "ListenAddress 127.0.0.1:$ISOLATED_PORT" \
        "HostKey $SSHD_HOST_KEY" \
        "PidFile $SSHD_PID_FILE" \
        "AuthorizedKeysFile $SSHD_AUTHORIZED_KEYS" \
        "AllowUsers $CURRENT_USER" \
        "SetEnv PATH=/usr/bin:/bin EVERSH_STATE_DIR=$STATE_DIR" \
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
        'UseDNS no' \
        'PermitUserEnvironment no' \
        'PermitUserRC no' \
        'Match LocalAddress 127.0.0.1' \
        '    PermitTTY yes' \
        'Match all' \
        '    PermitTTY no' > "$SSHD_CONFIG"
    "$CHMOD_TOOL" 600 -- "$SSHD_CONFIG" || return 1
    run_bounded "$SSHD_EXE" -t -f "$SSHD_CONFIG" >/dev/null 2>"$SSHD_LOG" || return 1
}

wait_for_sshd() {
    local i pid=$1
    for ((i = 0; i < READINESS_POLL_ATTEMPTS; i++)); do
        if capture_identity "$pid" && [[ $CAP_EXE == "$SSHD_EXE" ]]; then
            OWN_PID=$pid OWN_START=$CAP_START OWN_EXE=$CAP_EXE OWN_PGRP=$CAP_PGRP
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
    wait_for_sshd "$pid"
}

make_known_hosts() {
    local output status count address expected blob
    : > "$SSHD_KNOWN_HOSTS.stderr"
    set +e
    output=$(run_bounded "$SSHKEYSCAN_TOOL" -4 -T 2 -p "$ISOLATED_PORT" \
        -t ed25519 127.0.0.1 "$ISOLATED_ADDR" 2>"$SSHD_KNOWN_HOSTS.stderr")
    status=$?
    set -e
    (( status == 0 )) || return 1
    [[ -n $output && ! -s "$SSHD_KNOWN_HOSTS.stderr" ]] || return 1
    printf '%s\n' "$output" > "$SSHD_KNOWN_HOSTS"
    "$CHMOD_TOOL" 600 -- "$SSHD_KNOWN_HOSTS" || return 1
    count=$(printf '%s\n' "$output" \
        | "$AWK_TOOL" '$2 == "ssh-ed25519" { count++ } END { print count + 0 }') || return 1
    [[ $count == 2 ]] || return 1
    for address in 127.0.0.1 "$ISOLATED_ADDR"; do
        expected="[$address]:$ISOLATED_PORT"
        blob=$(printf '%s\n' "$output" \
            | "$AWK_TOOL" -v expected="$expected" \
                '$1 == expected && $2 == "ssh-ed25519" { print $3; exit }') || return 1
        [[ -n $blob && $blob == "$SSHD_HOST_BLOB" ]] || return 1
    done
}

write_client_config() {
    CLIENT_CONFIG="$TMP_ROOT/client_config"
    printf '%s\n' \
        "Host $ALIAS" \
        "    HostName $ISOLATED_ADDR" \
        "    Port $ISOLATED_PORT" \
        "    User $CURRENT_USER" \
        "    IdentityFile $SSHD_CLIENT_KEY" \
        '    IdentitiesOnly yes' \
        "    UserKnownHostsFile $SSHD_KNOWN_HOSTS" \
        '    GlobalKnownHostsFile /dev/null' \
        '    StrictHostKeyChecking yes' \
        '    HostKeyAlgorithms ssh-ed25519' \
        '    ProxyCommand none' \
        '    ProxyJump none' \
        '    BatchMode yes' \
        '    PubkeyAuthentication yes' \
        '    PasswordAuthentication no' \
        '    KbdInteractiveAuthentication no' \
        '    ChallengeResponseAuthentication no' \
        '    PreferredAuthentications publickey' \
        '    NumberOfPasswordPrompts 0' \
        '    ConnectTimeout 5' \
        '    ConnectionAttempts 1' \
        '    UpdateHostKeys no' \
        '    ControlMaster no' \
        '    ControlPath none' \
        '    ControlPersist no' \
        '    ClearAllForwardings yes' \
        '    ForwardAgent no' \
        '    ForwardX11 no' \
        '    ForwardX11Trusted no' \
        '    Tunnel no' \
        '    ServerAliveInterval 5' \
        '    ServerAliveCountMax 4' > "$CLIENT_CONFIG"
    "$CHMOD_TOOL" 600 -- "$CLIENT_CONFIG"
}

direct_health_check() {
    local label=$1 status
    set +e
    run_bounded "$SSH_TOOL" -4 -F "$CLIENT_CONFIG" -n -T -- "$ALIAS" true
    status=$?
    set -e
    if (( status != 0 )); then
        printf 'direct ssh health check failed (%s): status=%s\n' "$label" "$status" >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Wrapper generation and eversh invocation helpers
# ---------------------------------------------------------------------------

write_exec_wrapper() {
    local path=$1
    shift
    {
        printf '#!/usr/bin/bash\nset -Eeuo pipefail\n'
        # The harness itself has no controlling terminal, so the pty that
        # `script` allocates comes up with a zero winsize; set one explicitly
        # from inside the child (this IS the slave side) before exec so the
        # remote everpty broker sees a real TTY size.
        printf '%q rows 24 cols 80 -echo -echoctl 2>/dev/null || :\n' "$STTY_TOOL"
        printf 'exec'
        local a
        for a in "$@"; do
            printf ' %q' "$a"
        done
        printf '\n'
    } > "$path"
    "$CHMOD_TOOL" 700 -- "$path"
}

# Run one non-interactive eversh batch call (list/detach/kill), capturing
# stdout/stderr, returning eversh's own exit status.
run_batch() {
    local timeout_s=$1 outfile=$2 errfile=$3
    shift 3
    local status
    set +e
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=2s "${timeout_s}s" \
        "$EVERSH_BIN" "$@" --remote-eversh "$EVERSH_BIN" \
        --ssh-option -F"$CLIENT_CONFIG" > "$outfile" 2> "$errfile"
    status=$?
    set -e
    return "$status"
}

# Launch one interactive eversh invocation under a real local PTY
# (util-linux `script`), backgrounded; captures the script process's own
# identity tuple. Sets BG_PID/BG_START/BG_EXE/BG_PGRP on success.
launch_interactive() {
    local wrapper=$1 log=$2 i
    : > "$log"
    "$CHMOD_TOOL" 600 -- "$log"
    "$SCRIPT_TOOL" -qefc "$wrapper" /dev/null > "$log" 2>&1 &
    local pid=$!
    BG_PID= BG_START= BG_EXE= BG_PGRP=
    for ((i = 0; i < BG_READY_ATTEMPTS; i++)); do
        if capture_identity "$pid" && [[ $CAP_EXE == "$SCRIPT_TOOL" ]]; then
            BG_PID=$pid BG_START=$CAP_START BG_EXE=$CAP_EXE BG_PGRP=$CAP_PGRP
            return 0
        fi
        "$SLEEP_TOOL" 0.05
    done
    return 1
}

# ---------------------------------------------------------------------------
# Tick-stream parsing (PTY output is CRLF; tolerate torn lines)
# ---------------------------------------------------------------------------

extract_ticks() {
    # Anchored only at the END: a torn write boundary can prepend stray
    # bytes (observed: a leading NUL) to an otherwise-intact "T:<n>" line;
    # tolerate that garbage rather than silently mis-count it as a gap.
    "$AWK_TOOL" '
        { line = $0; sub(/\r$/, "", line) }
        line ~ /T:[0-9]+$/ {
            match(line, /T:[0-9]+$/)
            print substr(line, RSTART + 2, RLENGTH - 2)
        }' "$1"
}

wait_for_tick_count() {
    local log=$1 min=$2 timeout_s=$3 deadline count
    deadline=$((SECONDS + timeout_s))
    while (( SECONDS < deadline )); do
        count=$(extract_ticks "$log" | "$AWK_TOOL" 'END { print NR + 0 }')
        (( count >= min )) && return 0
        "$SLEEP_TOOL" 0.05
    done
    return 1
}

wait_for_tick_above() {
    local log=$1 threshold=$2 timeout_s=$3 deadline hit
    deadline=$((SECONDS + timeout_s))
    while (( SECONDS < deadline )); do
        hit=$(extract_ticks "$log" | "$AWK_TOOL" -v want="$threshold" \
            '$1 + 0 > want { f = 1 } END { print f + 0 }')
        [[ $hit == 1 ]] && return 0
        "$SLEEP_TOOL" 0.1
    done
    return 1
}

last_tick() {
    extract_ticks "$1" | "$AWK_TOOL" 'END { print $0 }'
}

# Strictly increasing overall, with EXACTLY one gap >= 2 (the killed span).
validate_tick_sequence() {
    extract_ticks "$1" | "$AWK_TOOL" '
        { n[NR] = $1 }
        END {
            if (NR < 4) { print "short:" NR; exit 1 }
            gaps = 0
            for (i = 2; i <= NR; i++) {
                d = n[i] - n[i - 1]
                if (d <= 0) { print "nonmonotonic@" i; exit 1 }
                if (d >= 2) gaps++
            }
            if (gaps != 1) { print "gapcount=" gaps; exit 1 }
        }'
}

# ---------------------------------------------------------------------------
# list --json helpers
# ---------------------------------------------------------------------------

run_list_json() {
    local outfile=$1 errfile=$2
    run_batch "$BATCH_TIMEOUT_SECONDS" "$outfile" "$errfile" list "$ALIAS" --json
}

broker_pid_for() {
    local jsonfile=$1 name=$2
    "$GREP_TOOL" -oE '"name":"'"$name"'","broker":\{"pid":[0-9]+' "$jsonfile" \
        | "$GREP_TOOL" -oE '[0-9]+$'
}

json_has_name() {
    "$GREP_TOOL" -q -F -- "\"name\":\"$2\"" "$1"
}

die() {
    printf '%s\n' "$1" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Scenario 1: create-and-exit (child exit-code passthrough)
# ---------------------------------------------------------------------------

scenario_create_and_exit() {
    local name=m5s3create
    local wrapper="$TMP_ROOT/s1.wrap.sh" log="$TMP_ROOT/s1.log" status
    local -a argv=(
        "$EVERSH_BIN" connect "$ALIAS" --session "$name"
        --remote-eversh "$EVERSH_BIN" --ssh-option -F"$CLIENT_CONFIG"
        -- /bin/sh -c 'printf "M5-MARKER-%s\n" ready; exit 43'
    )
    write_exec_wrapper "$wrapper" "${argv[@]}"
    : > "$log"
    "$CHMOD_TOOL" 600 -- "$log"
    set +e
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=2s "${SCENARIO1_TIMEOUT_SECONDS}s" \
        "$SCRIPT_TOOL" -qefc "$wrapper" /dev/null > "$log" 2>&1
    status=$?
    set -e
    [[ $status -eq 43 ]] || die "scenario1: wrapped exit=$status (want 43)"
    "$GREP_TOOL" -q -F -- 'M5-MARKER-ready' "$log" || die "scenario1: marker missing from output"
}

# ---------------------------------------------------------------------------
# Scenario 2: no-replay reattach across a killed proxy transport
# ---------------------------------------------------------------------------

readonly TICK_SCRIPT='trap "exit 41" TERM; printf "READY\n"; i=0; while :; do printf "T:%d\n" "$i"; i=$((i+1)); sleep 0.05; done'

scenario_no_replay_reattach() {
    local name=m5s3tickA
    local wrapper="$TMP_ROOT/s2.wrap.sh" log="$TMP_ROOT/s2.log"
    local list1="$TMP_ROOT/s2.list1.json" list1err="$TMP_ROOT/s2.list1.err"
    local list2="$TMP_ROOT/s2.list2.json" list2err="$TMP_ROOT/s2.list2.err"
    local killout="$TMP_ROOT/s2.kill.out" killerr="$TMP_ROOT/s2.kill.err"
    # Plain reconnect (no --take-over): this asserts the production
    # CONTRACT -- after a hard transport kill, the supervisor's own
    # probe-gated reconnect episode (bounded attempts/backoff/deadline)
    # reattaches to the SAME broker once the broker naturally revokes the
    # dead writer, without ever replaying discarded output.
    local -a argv=(
        "$EVERSH_BIN" connect "$ALIAS" --session "$name"
        --remote-eversh "$EVERSH_BIN" --ssh-option -F"$CLIENT_CONFIG"
        -- /bin/sh -c "$TICK_SCRIPT"
    )
    write_exec_wrapper "$wrapper" "${argv[@]}"
    launch_interactive "$wrapper" "$log" || die "scenario2: failed to launch connect wrapper"
    local script_pid=$BG_PID script_start=$BG_START script_exe=$BG_EXE script_pgrp=$BG_PGRP

    wait_for_tick_count "$log" 4 "$TICK_WAIT_SECONDS" || die "scenario2: ticks did not flow before kill"

    local broker_before
    run_list_json "$list1" "$list1err" || die "scenario2: pre-kill list failed"
    json_has_name "$list1" "$name" || die "scenario2: pre-kill list missing session"
    broker_before=$(broker_pid_for "$list1" "$name")
    [[ $broker_before =~ ^[0-9]+$ ]] || die "scenario2: could not read pre-kill broker pid"

    local proxy_pid
    proxy_pid=$(find_ssh_proxy_pid "$script_pid" 8) || die "scenario2: could not locate ssh-proxy process"
    capture_identity "$proxy_pid" || die "scenario2: proxy identity vanished before kill"
    [[ $CAP_EXE == "$EVERSH_BIN" ]] || die "scenario2: proxy exe mismatch: $CAP_EXE"
    local proxy_start=$CAP_START proxy_exe=$CAP_EXE proxy_pgrp=$CAP_PGRP
    builtin kill -KILL "$proxy_pid" 2>/dev/null || die "scenario2: SIGKILL on proxy failed"
    poll_owned_gone "$proxy_pid" "$proxy_start" "$proxy_exe" "$proxy_pgrp" "$KILL_POLL_SECONDS" \
        || die "scenario2: proxy process did not disappear after SIGKILL"

    local max_pre
    max_pre=$(last_tick "$log")
    [[ $max_pre =~ ^[0-9]+$ ]] || die "scenario2: no pre-kill tick recorded"

    wait_for_tick_above "$log" "$max_pre" "$REATTACH_WAIT_SECONDS" \
        || die "scenario2: no post-reattach ticks arrived"
    "$TIMEOUT_TOOL" 1s "$SLEEP_TOOL" 0.35 || :

    local broker_after
    run_list_json "$list2" "$list2err" || die "scenario2: post-reattach list failed"
    json_has_name "$list2" "$name" || die "scenario2: post-reattach list missing session"
    broker_after=$(broker_pid_for "$list2" "$name")
    [[ $broker_after =~ ^[0-9]+$ ]] || die "scenario2: could not read post-reattach broker pid"
    [[ $broker_before == "$broker_after" ]] \
        || die "scenario2: broker pid changed ($broker_before -> $broker_after); session was NOT reattached"

    local tick_report
    tick_report=$(validate_tick_sequence "$log") \
        || die "scenario2: tick sequence invalid ($tick_report)"

    if ! run_batch "$KILL_TIMEOUT_SECONDS" "$killout" "$killerr" kill "$ALIAS" "$name"; then
        die "scenario2: kill of session failed"
    fi

    local status=0
    builtin wait "$script_pid" 2>/dev/null || status=$?
    [[ $status -eq 41 ]] || die "scenario2: wrapped exit=$status (want 41 from TERM trap)"
}

# ---------------------------------------------------------------------------
# Scenario 3: session torn down mid-reconnect ("no longer live")
# ---------------------------------------------------------------------------

scenario_session_gone() {
    local name=m5s3tickB
    local wrapper="$TMP_ROOT/s3.wrap.sh" log="$TMP_ROOT/s3.log"
    local killout="$TMP_ROOT/s3.kill.out" killerr="$TMP_ROOT/s3.kill.err"
    local listout="$TMP_ROOT/s3.list.json" listerr="$TMP_ROOT/s3.list.err"
    local -a argv=(
        "$EVERSH_BIN" connect "$ALIAS" --session "$name"
        --remote-eversh "$EVERSH_BIN" --ssh-option -F"$CLIENT_CONFIG"
        -- /bin/sh -c "$TICK_SCRIPT"
    )
    write_exec_wrapper "$wrapper" "${argv[@]}"
    launch_interactive "$wrapper" "$log" || die "scenario3: failed to launch connect wrapper"
    local script_pid=$BG_PID

    wait_for_tick_count "$log" 2 "$TICK_WAIT_SECONDS" || die "scenario3: ticks did not flow before kill"

    local proxy_pid
    proxy_pid=$(find_ssh_proxy_pid "$script_pid" 8) || die "scenario3: could not locate ssh-proxy process"
    capture_identity "$proxy_pid" || die "scenario3: proxy identity vanished before kill"
    [[ $CAP_EXE == "$EVERSH_BIN" ]] || die "scenario3: proxy exe mismatch: $CAP_EXE"

    # SIGKILL the transport, then immediately race an independent `eversh
    # kill` (its own fresh connection, unrelated to the tick session's
    # transport) against that session's own probe-gated reconnect episode.
    #
    # NOTE (real-chain quirk, see final report): this needs the SAME
    # in-flight supervisor repair as scenario 2. `eversh kill`'s own floor
    # is ~kill_grace_ms (~5s) before the broker reaps and replies -- even
    # when the child (which traps TERM and exits at once) is long gone,
    # crates/everpty/src/broker.rs's advance_lifecycle only reaps once
    # kill_phase reaches KillSent, which requires the TermSent deadline to
    # elapse. No local synchronization can make that finish inside the
    # ~250ms window before the FIRST reconnect attach attempt, which
    # currently treats remote Busy as terminal. Once Busy-during-reconnect
    # is retried across the bounded backoff episode, that episode's several
    # extra seconds comfortably cover this kill's ~5s floor and probe
    # correctly observes NotLive.
    set +e
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=2s "${KILL_TIMEOUT_SECONDS}s" \
        "$EVERSH_BIN" kill "$ALIAS" "$name" --remote-eversh "$EVERSH_BIN" \
        --ssh-option -F"$CLIENT_CONFIG" > "$killout" 2> "$killerr" &
    local kill_pid=$!
    set -e
    builtin kill -KILL "$proxy_pid" 2>/dev/null || die "scenario3: SIGKILL on proxy failed"
    local kill_status=0
    builtin wait "$kill_pid" 2>/dev/null || kill_status=$?
    (( kill_status == 0 )) || die "scenario3: independent kill failed with status $kill_status"

    # Whichever observer first reaches the torn-down session terminates the
    # invocation, and BOTH terminal outcomes are correct product behavior
    # (the harness originally pinned only the first): the PROBE observing
    # NotLive ends the episode locally (wrapped exit 255 with 'no longer
    # live'), while an in-flight REATTACH whose remote attach-or-create
    # finds the session already gone exits 1 remotely and is passed through
    # as the child exit it is -- never retried, 'session is not live' (the
    # same deterministic NotLive passthrough scenario 5 asserts after
    # detach). Which one wins is a race inside the kill's ~5s teardown
    # window; assert the diagnostic matches the exit code, and the session
    # is really gone either way.
    local status=0
    builtin wait "$script_pid" 2>/dev/null || status=$?
    case $status in
        255)
            "$GREP_TOOL" -q -F -- 'no longer live' "$log" \
                || die "scenario3: wrapped 255 but log missing 'no longer live'"
            ;;
        1)
            "$GREP_TOOL" -q -F -- 'session is not live' "$log" \
                || die "scenario3: wrapped exit 1 but log missing 'session is not live'"
            ;;
        *)
            die "scenario3: wrapped exit=$status (want 255 probe-observed or 1 attach-passthrough)"
            ;;
    esac

    run_list_json "$listout" "$listerr" || die "scenario3: post-gone list failed"
    if json_has_name "$listout" "$name"; then
        die "scenario3: session '$name' is still listed after being killed"
    fi
}

# ---------------------------------------------------------------------------
# Scenario 4: busy-visible (second writer without take-over)
# ---------------------------------------------------------------------------

scenario_busy_visible() {
    local name=m5s3busy
    local holder_wrapper="$TMP_ROOT/s4.holder.wrap.sh" holder_log="$TMP_ROOT/s4.holder.log"
    local attach_wrapper="$TMP_ROOT/s4.attach.wrap.sh" attach_log="$TMP_ROOT/s4.attach.log"
    local killout="$TMP_ROOT/s4.kill.out" killerr="$TMP_ROOT/s4.kill.err"
    local -a holder_argv=(
        "$EVERSH_BIN" connect "$ALIAS" --session "$name"
        --remote-eversh "$EVERSH_BIN" --ssh-option -F"$CLIENT_CONFIG"
        -- /bin/sh -c "$TICK_SCRIPT"
    )
    write_exec_wrapper "$holder_wrapper" "${holder_argv[@]}"
    launch_interactive "$holder_wrapper" "$holder_log" || die "scenario4: failed to launch holder"
    local holder_pid=$BG_PID
    wait_for_tick_count "$holder_log" 1 "$TICK_WAIT_SECONDS" || die "scenario4: holder never became ready"

    local -a attach_argv=(
        "$EVERSH_BIN" attach "$ALIAS" "$name"
        --remote-eversh "$EVERSH_BIN" --ssh-option -F"$CLIENT_CONFIG"
    )
    write_exec_wrapper "$attach_wrapper" "${attach_argv[@]}"
    local status=0
    : > "$attach_log"
    "$CHMOD_TOOL" 600 -- "$attach_log"
    set +e
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=2s "${ATTACH_BUSY_TIMEOUT_SECONDS}s" \
        "$SCRIPT_TOOL" -qefc "$attach_wrapper" /dev/null > "$attach_log" 2>&1
    status=$?
    set -e
    [[ $status -eq 3 ]] || die "scenario4: second attach exit=$status (want 3, Busy)"
    [[ -s $attach_log ]] || die "scenario4: second attach produced no stderr/output"

    if ! run_batch "$KILL_TIMEOUT_SECONDS" "$killout" "$killerr" kill "$ALIAS" "$name"; then
        die "scenario4: kill of holder session failed"
    fi
    status=0
    builtin wait "$holder_pid" 2>/dev/null || status=$?
    [[ $status -eq 41 ]] || die "scenario4: holder wrapped exit=$status (want 41)"
}

# ---------------------------------------------------------------------------
# Scenario 5: list / detach persistence
# ---------------------------------------------------------------------------

scenario_list_detach() {
    local name=m5s3list
    local wrapper="$TMP_ROOT/s5.wrap.sh" log="$TMP_ROOT/s5.log"
    local list1="$TMP_ROOT/s5.list1.json" list1err="$TMP_ROOT/s5.list1.err"
    local list2="$TMP_ROOT/s5.list2.json" list2err="$TMP_ROOT/s5.list2.err"
    local detachout="$TMP_ROOT/s5.detach.out" detacherr="$TMP_ROOT/s5.detach.err"
    local killout="$TMP_ROOT/s5.kill.out" killerr="$TMP_ROOT/s5.kill.err"
    local -a argv=(
        "$EVERSH_BIN" connect "$ALIAS" --session "$name"
        --remote-eversh "$EVERSH_BIN" --ssh-option -F"$CLIENT_CONFIG"
        -- /bin/sh -c "$TICK_SCRIPT"
    )
    write_exec_wrapper "$wrapper" "${argv[@]}"
    launch_interactive "$wrapper" "$log" || die "scenario5: failed to launch connect wrapper"
    local script_pid=$BG_PID
    wait_for_tick_count "$log" 1 "$TICK_WAIT_SECONDS" || die "scenario5: session never became ready"

    local broker1
    run_list_json "$list1" "$list1err" || die "scenario5: first list failed"
    json_has_name "$list1" "$name" || die "scenario5: first list missing session"
    "$GREP_TOOL" -q -F -- "$EXPECTED_ORIGIN" "$list1" \
        || die "scenario5: first list missing origin label $EXPECTED_ORIGIN"
    broker1=$(broker_pid_for "$list1" "$name")
    [[ $broker1 =~ ^[0-9]+$ ]] || die "scenario5: could not read first broker pid"

    if ! run_batch "$BATCH_TIMEOUT_SECONDS" "$detachout" "$detacherr" detach "$ALIAS" "$name"; then
        die "scenario5: detach failed"
    fi

    # Detach (from this independent control connection) revokes the writer
    # and closes its socket right after the Revoked frame; the writer's own
    # next socket read sees that close as a plain EOF (Error::NotLive,
    # local exit 1), not a clean 0 -- confirmed against
    # crates/everpty/src/attach.rs's socket-EOF handling, which does not
    # special-case an immediately-preceding Revoked. This is deterministic
    # production behavior, not a race: the remote command exits with a
    # REMOTE (non-255) status, so the local outer ssh does too, and the
    # supervisor never enters its reconnect path.
    local status=0
    builtin wait "$script_pid" 2>/dev/null || status=$?
    [[ $status -eq 1 ]] || die "scenario5: detached wrapper exit=$status (want 1, NotLive)"
    "$GREP_TOOL" -q -F -- 'session is not live' "$log" \
        || die "scenario5: detached wrapper log missing 'session is not live'"

    local broker2
    run_list_json "$list2" "$list2err" || die "scenario5: second list failed"
    json_has_name "$list2" "$name" || die "scenario5: session vanished after detach"
    broker2=$(broker_pid_for "$list2" "$name")
    [[ $broker2 =~ ^[0-9]+$ ]] || die "scenario5: could not read second broker pid"
    [[ $broker1 == "$broker2" ]] \
        || die "scenario5: broker pid changed across detach ($broker1 -> $broker2)"

    if ! run_batch "$KILL_TIMEOUT_SECONDS" "$killout" "$killerr" kill "$ALIAS" "$name"; then
        die "scenario5: kill after detach failed"
    fi
}

# ---------------------------------------------------------------------------
# Scenario 7: pre-establishment auth failure (ordinary 255, no probe, no
# reconnect) -- the r3 repair's F2/F4 contract on the real chain.
#
# A fresh, never-authorized identity is swapped into an otherwise identical
# client config, so the outer ssh (and the proxy's inner bootstrap ssh) fail
# publickey before anything is established. The supervisor must classify the
# resulting 255 as an ordinary failure: pinned diagnostics, zero probe /
# reconnect spawns, exactly ONE supervisor ssh invocation, and (if the
# status file is captured before the supervisor removes it) exactly one
# clean-close carried=0 record with no carrying line.
# ---------------------------------------------------------------------------

scenario_auth_failure() {
    local name=m5s3authfail
    local bad_key="$TMP_ROOT/sshd/auth_fail_ed25519"
    local bad_config="$TMP_ROOT/auth_fail_config"
    local s7_bin="$TMP_ROOT/s7.bin"
    local s7_ssh="$s7_bin/ssh"
    local s7_state="$TMP_ROOT/s7.state"
    local count_file="$TMP_ROOT/s7.ssh-count"
    local pid_file="$TMP_ROOT/s7.eversh-pid"
    local snap_dir="$TMP_ROOT/s7.status-snap"
    local wrapper="$TMP_ROOT/s7.wrap.sh" log="$TMP_ROOT/s7.log"
    local status poller_pid

    run_bounded "$SSHKEYGEN_TOOL" -q -t ed25519 -N '' -f "$bad_key" >/dev/null 2>&1 \
        || die "scenario7: unauthorized key generation failed"
    "$CHMOD_TOOL" 600 -- "$bad_key" "$bad_key.pub" \
        || die "scenario7: chmod on unauthorized key failed"

    # Same client config, unauthorized identity: with BatchMode and
    # publickey-only this deterministically fails before establishment.
    "$SED_TOOL" "s|^    IdentityFile .*|    IdentityFile $bad_key|" \
        "$CLIENT_CONFIG" > "$bad_config" \
        || die "scenario7: auth-fail config generation failed"
    "$GREP_TOOL" -q -F -- "IdentityFile $bad_key" "$bad_config" \
        || die "scenario7: auth-fail config identity was not replaced"
    "$GREP_TOOL" -q -F -- "IdentityFile $SSHD_CLIENT_KEY" "$bad_config" \
        && die "scenario7: auth-fail config still names the authorized key"
    "$CHMOD_TOOL" 600 -- "$bad_config" || die "scenario7: chmod on auth-fail config failed"

    # ssh-invocation counting shim, PATH-injected only into this scenario's
    # process tree (eversh resolves "ssh" through PATH). Each ssh spawn
    # appends its parent pid: the supervisor's ssh has ppid == the eversh
    # process (the wrapper execs into it, so its pid is stable), while the
    # ssh-proxy's inner bootstrap ssh has ppid == the proxy process.
    "$MKDIR_TOOL" -m 700 -- "$s7_bin" || die "scenario7: shim dir creation failed"
    {
        printf '#!/usr/bin/bash\n'
        printf 'echo "$PPID" >> %q\n' "$count_file"
        printf 'exec %q "$@"\n' "$SSH_TOOL"
    } > "$s7_ssh"
    "$CHMOD_TOOL" 700 -- "$s7_ssh" || die "scenario7: chmod on ssh shim failed"

    "$MKDIR_TOOL" -m 700 -- "$s7_state" "$snap_dir" \
        || die "scenario7: status-root/snapshot dir creation failed"
    : > "$count_file"
    "$CHMOD_TOOL" 600 -- "$count_file"

    {
        printf '#!/usr/bin/bash\nset -Eeuo pipefail\n'
        printf 'export PATH=%q:"$PATH"\n' "$s7_bin"
        printf 'export EVERSH_STATE_DIR=%q\n' "$s7_state"
        printf 'echo "$$" > %q\n' "$pid_file"
        printf '%q rows 24 cols 80 -echo -echoctl 2>/dev/null || :\n' "$STTY_TOOL"
        printf 'exec'
        local a
        for a in "$EVERSH_BIN" connect "$ALIAS" --session "$name" \
            --remote-eversh "$EVERSH_BIN" --ssh-option -F"$bad_config" \
            -- /bin/sh -c 'printf "S7-MARKER-AUTHFAIL\n"; exit 0'; do
            printf ' %q' "$a"
        done
        printf '\n'
    } > "$wrapper"
    "$CHMOD_TOOL" 700 -- "$wrapper" || die "scenario7: chmod on wrapper failed"

    # Snapshot link-status file contents while they exist: the supervisor
    # removes the file after reading it, so keep the newest read per file
    # (the proxy only ever appends records, never truncates).
    (
        while :; do
            local f
            for f in "$s7_state"/link-status/*.status; do
                [[ -f $f ]] || continue
                "$CAT_TOOL" "$f" > "$snap_dir/${f##*/}" 2>/dev/null || :
            done
            "$SLEEP_TOOL" 0.01
        done
    ) &
    poller_pid=$!

    : > "$log"
    "$CHMOD_TOOL" 600 -- "$log"
    set +e
    "$TIMEOUT_TOOL" --signal=TERM --kill-after=2s "${AUTH_FAIL_TIMEOUT_SECONDS}s" \
        "$SCRIPT_TOOL" -qefc "$wrapper" /dev/null > "$log" 2>&1
    status=$?
    set -e
    builtin kill "$poller_pid" 2>/dev/null || :
    builtin wait "$poller_pid" 2>/dev/null || :

    [[ $status -eq 255 ]] || die "scenario7: wrapped exit=$status (want 255)"
    "$GREP_TOOL" -q -F -- 'eversh: ssh reported failure with the transport intact' "$log" \
        || die "scenario7: log missing the pinned event diagnostic"
    "$GREP_TOOL" -q -F -- 'eversh: ssh reported failure with the transport intact; not retried' "$log" \
        || die "scenario7: log missing the pinned not-retried diagnostic"
    "$GREP_TOOL" -q -F -- 'probing' "$log" \
        && die "scenario7: unexpected probe on pre-establishment failure"
    "$GREP_TOOL" -q -F -- 'reattaching' "$log" \
        && die "scenario7: unexpected reattach on pre-establishment failure"
    "$GREP_TOOL" -q -F -- 'S7-MARKER-AUTHFAIL' "$log" \
        && die "scenario7: remote command ran despite the auth failure"

    [[ -s $pid_file ]] || die "scenario7: wrapper pid file missing"
    local eversh_pid supervisor_ssh=0 total_ssh=0 line
    eversh_pid=$("$CAT_TOOL" "$pid_file")
    [[ $eversh_pid =~ ^[0-9]+$ ]] || die "scenario7: bad eversh pid '$eversh_pid'"
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        total_ssh=$((total_ssh + 1))
        [[ $line == "$eversh_pid" ]] && supervisor_ssh=$((supervisor_ssh + 1))
    done < "$count_file"
    (( supervisor_ssh == 1 )) || die \
"scenario7: supervisor spawned ssh $supervisor_ssh times (want exactly 1; total ssh invocations $total_ssh)"

    # The status file is best-effort to preserve (the supervisor removes it
    # right after the 255). Any non-empty capture must be exactly one
    # clean-close carried=0 record with no carrying line; an empty or missed
    # capture is reported, not fatal.
    local snap_f snap_content captured_final=0
    for snap_f in "$snap_dir"/*.status; do
        [[ -f $snap_f ]] || continue
        snap_content=$("$CAT_TOOL" "$snap_f")
        [[ -n $snap_content ]] || continue
        captured_final=1
        [[ $snap_content == 'everssh-status-v1 cause clean-close carried=0' ]] \
            || die "scenario7: captured status record mismatch: '$snap_content'"
    done
    (( captured_final == 1 )) \
        || printf 'scenario7: status file not captured in final state; content assert skipped\n' >&2
}

# ---------------------------------------------------------------------------
# Scenario 8: concurrent connect atomicity — exactly one broker/child
# ---------------------------------------------------------------------------

scenario_concurrent_connect() {
    local name=m5s3atomic
    local first_wrapper="$TMP_ROOT/s8.first.wrap.sh" first_log="$TMP_ROOT/s8.first.log"
    local second_wrapper="$TMP_ROOT/s8.second.wrap.sh" second_log="$TMP_ROOT/s8.second.log"
    local listout="$TMP_ROOT/s8.list.json" listerr="$TMP_ROOT/s8.list.err"
    local killout="$TMP_ROOT/s8.kill.out" killerr="$TMP_ROOT/s8.kill.err"
    local -a argv=(
        "$EVERSH_BIN" connect "$ALIAS" --session "$name"
        --remote-eversh "$EVERSH_BIN" --ssh-option -F"$CLIENT_CONFIG"
        -- /bin/sh -c "$TICK_SCRIPT"
    )
    write_exec_wrapper "$first_wrapper" "${argv[@]}"
    write_exec_wrapper "$second_wrapper" "${argv[@]}"
    launch_interactive "$first_wrapper" "$first_log" \
        || die "scenario8: failed to launch first connect"
    local first_pid=$BG_PID
    launch_interactive "$second_wrapper" "$second_log" \
        || die "scenario8: failed to launch second connect"
    local second_pid=$BG_PID

    # Exactly one competitor may own the writer; the other must terminate
    # visibly with Busy rather than silently attaching or creating a child.
    local deadline=$((SECONDS + TICK_WAIT_SECONDS)) winner= loser_pid=
    while (( SECONDS < deadline )); do
        if ! kill -0 "$first_pid" 2>/dev/null; then
            winner=second loser_pid=$first_pid
            break
        fi
        if ! kill -0 "$second_pid" 2>/dev/null; then
            winner=first loser_pid=$second_pid
            break
        fi
        "$SLEEP_TOOL" 0.1
    done
    [[ -n $winner ]] || die "scenario8: neither concurrent connect resolved as Busy"
    local winner_log winner_pid loser_log
    if [[ $winner == first ]]; then
        winner_log=$first_log winner_pid=$first_pid loser_log=$second_log
    else
        winner_log=$second_log winner_pid=$second_pid loser_log=$first_log
    fi
    wait_for_tick_count "$winner_log" 4 "$TICK_WAIT_SECONDS" \
        || die "scenario8: winning connect never carried ticks"
    local loser_status=0
    builtin wait "$loser_pid" 2>/dev/null || loser_status=$?
    [[ $loser_status -eq 3 ]] \
        || die "scenario8: loser exit=$loser_status (want 3, Busy)"
    local loser_ticks
    loser_ticks=$(extract_ticks "$loser_log" | "$AWK_TOOL" 'END { print NR + 0 }')
    [[ $loser_ticks -eq 0 ]] || die "scenario8: Busy loser emitted $loser_ticks ticks"

    run_list_json "$listout" "$listerr" || die "scenario8: list failed"
    json_has_name "$listout" "$name" || die "scenario8: session missing after race"
    local broker count
    broker=$(broker_pid_for "$listout" "$name")
    [[ $broker =~ ^[0-9]+$ ]] || die "scenario8: missing broker pid"
    count=$("$GREP_TOOL" -oE '"name":"'"$name"'"' "$listout" | "$GREP_TOOL" -c .)
    [[ $count -eq 1 ]] || die "scenario8: duplicate session records ($count)"

    if ! run_batch "$KILL_TIMEOUT_SECONDS" "$killout" "$killerr" kill "$ALIAS" "$name"; then
        die "scenario8: kill failed"
    fi
    local status=0
    builtin wait "$winner_pid" 2>/dev/null || status=$?
    [[ $status -eq 41 ]] || die "scenario8: winner wrapped exit=$status (want 41)"
}

# ---------------------------------------------------------------------------
# Scenario 9: explicit takeover — old writer survives as observer
# ---------------------------------------------------------------------------

scenario_explicit_takeover() {
    local name=m5s3takeover
    local holder_wrapper="$TMP_ROOT/s9.holder.wrap.sh" holder_log="$TMP_ROOT/s9.holder.log"
    local takeover_wrapper="$TMP_ROOT/s9.takeover.wrap.sh" takeover_log="$TMP_ROOT/s9.takeover.log"
    local listout="$TMP_ROOT/s9.list.json" listerr="$TMP_ROOT/s9.list.err"
    local killout="$TMP_ROOT/s9.kill.out" killerr="$TMP_ROOT/s9.kill.err"
    local -a holder_argv=(
        "$EVERSH_BIN" connect "$ALIAS" --session "$name"
        --remote-eversh "$EVERSH_BIN" --ssh-option -F"$CLIENT_CONFIG"
        -- /bin/sh -c "$TICK_SCRIPT"
    )
    write_exec_wrapper "$holder_wrapper" "${holder_argv[@]}"
    launch_interactive "$holder_wrapper" "$holder_log" \
        || die "scenario9: failed to launch holder"
    local holder_pid=$BG_PID
    wait_for_tick_count "$holder_log" 4 "$TICK_WAIT_SECONDS" \
        || die "scenario9: holder never carried ticks"

    local -a takeover_argv=(
        "$EVERSH_BIN" attach "$ALIAS" "$name" --take-over
        --remote-eversh "$EVERSH_BIN" --ssh-option -F"$CLIENT_CONFIG"
    )
    write_exec_wrapper "$takeover_wrapper" "${takeover_argv[@]}"
    launch_interactive "$takeover_wrapper" "$takeover_log" \
        || die "scenario9: failed to launch takeover attach"
    local takeover_pid=$BG_PID
    wait_for_tick_count "$takeover_log" 4 "$TICK_WAIT_SECONDS" \
        || die "scenario9: takeover attach never acquired the writer"
    kill -0 "$holder_pid" 2>/dev/null \
        || die "scenario9: prior writer exited instead of becoming observer"

    run_list_json "$listout" "$listerr" || die "scenario9: list failed"
    json_has_name "$listout" "$name" || die "scenario9: session missing"
    local count
    count=$("$GREP_TOOL" -oE '"name":"'"$name"'"' "$listout" | "$GREP_TOOL" -c .)
    [[ $count -eq 1 ]] || die "scenario9: duplicate session records ($count)"

    if ! run_batch "$KILL_TIMEOUT_SECONDS" "$killout" "$killerr" kill "$ALIAS" "$name"; then
        die "scenario9: kill failed"
    fi
    local holder_status=0 takeover_status=0
    builtin wait "$holder_pid" 2>/dev/null || holder_status=$?
    builtin wait "$takeover_pid" 2>/dev/null || takeover_status=$?
    [[ $holder_status -eq 41 ]] \
        || die "scenario9: holder wrapped exit=$holder_status (want 41)"
    [[ $takeover_status -eq 41 ]] \
        || die "scenario9: takeover wrapped exit=$takeover_status (want 41)"
}

# ---------------------------------------------------------------------------
# Scenario 10: raw ssh transport kill — one outer OpenSSH, never replaced
# ---------------------------------------------------------------------------

scenario_raw_ssh_never_replaced() {
    local s10_bin="$TMP_ROOT/s10.bin"
    local s10_ssh="$s10_bin/ssh"
    local count_file="$TMP_ROOT/s10.ssh-count"
    local pid_file="$TMP_ROOT/s10.eversh-pid"
    local wrapper="$TMP_ROOT/s10.wrap.sh" log="$TMP_ROOT/s10.log"
    local status proxy_pid proxy_start proxy_exe proxy_pgrp max_pre

    "$MKDIR_TOOL" -m 700 -- "$s10_bin" || die "scenario10: shim dir creation failed"
    {
        printf '#!/usr/bin/bash\n'
        printf 'echo "$PPID" >> %q\n' "$count_file"
        printf 'exec %q "$@"\n' "$SSH_TOOL"
    } > "$s10_ssh"
    "$CHMOD_TOOL" 700 -- "$s10_ssh" || die "scenario10: ssh shim creation failed"
    : > "$count_file"
    "$CHMOD_TOOL" 600 -- "$count_file"

    {
        printf '#!/usr/bin/bash\nset -Eeuo pipefail\n'
        printf 'export PATH=%q:"$PATH"\n' "$s10_bin"
        printf 'echo "$$" > %q\n' "$pid_file"
        printf '%q rows 24 cols 80 -echo -echoctl 2>/dev/null || :\n' "$STTY_TOOL"
        printf 'exec'
        local a
        for a in "$EVERSH_BIN" ssh "$ALIAS" \
            --remote-eversh "$EVERSH_BIN" \
            -- "-F$CLIENT_CONFIG" -- /bin/sh -c "$TICK_SCRIPT"; do
            printf ' %q' "$a"
        done
        printf '\n'
    } > "$wrapper"
    "$CHMOD_TOOL" 700 -- "$wrapper" || die "scenario10: wrapper creation failed"

    launch_interactive "$wrapper" "$log" \
        || die "scenario10: failed to launch raw ssh wrapper"
    local raw_pid=$BG_PID
    wait_for_tick_count "$log" 4 "$TICK_WAIT_SECONDS" \
        || die "scenario10: raw ssh never carried ticks"
    local eversh_pid
    eversh_pid=$("$CAT_TOOL" "$pid_file")
    [[ $eversh_pid =~ ^[0-9]+$ ]] || die "scenario10: bad eversh pid '$eversh_pid'"

    proxy_pid=$(find_ssh_proxy_pid "$raw_pid" 10) \
        || die "scenario10: could not locate raw ssh-proxy"
    capture_identity "$proxy_pid" || die "scenario10: proxy identity vanished"
    proxy_start=$CAP_START proxy_exe=$CAP_EXE proxy_pgrp=$CAP_PGRP
    builtin kill -KILL "$proxy_pid" 2>/dev/null || die "scenario10: proxy kill failed"
    poll_owned_gone "$proxy_pid" "$proxy_start" "$proxy_exe" "$proxy_pgrp" "$KILL_POLL_SECONDS" \
        || die "scenario10: proxy did not disappear"
    max_pre=$(last_tick "$log")
    [[ $max_pre =~ ^[0-9]+$ ]] || die "scenario10: no pre-kill tick"

    status=0
    builtin wait "$raw_pid" 2>/dev/null || status=$?
    (( status != 0 )) || die "scenario10: raw ssh unexpectedly succeeded after transport kill"

    local supervisor_ssh=0 total_ssh=0 line
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        total_ssh=$((total_ssh + 1))
        [[ $line == "$eversh_pid" ]] && supervisor_ssh=$((supervisor_ssh + 1))
    done < "$count_file"
    (( supervisor_ssh == 1 )) || die \
"scenario10: supervisor spawned ssh $supervisor_ssh times (want exactly 1)"
    # Exactly three invocations are the correct raw-mode process shape: the
    # supervisor's one outer ssh, plus the proxy's effective-config `ssh -G`
    # query and one bootstrap ssh. Any fourth spawn would be a replacement
    # operation after the terminal transport kill.
    (( total_ssh == 3 )) || die \
"scenario10: unexpected ssh invocations: $total_ssh (want outer + query + bootstrap = 3)"
    "$GREP_TOOL" -q -F -- 'probing' "$log" \
        && die "scenario10: raw ssh unexpectedly probed"
    "$GREP_TOOL" -q -F -- 'reattaching' "$log" \
        && die "scenario10: raw ssh unexpectedly reattached"
    local after_ticks
    after_ticks=$(extract_ticks "$log" | "$AWK_TOOL" -v max="$max_pre" \
        '$1 + 0 > max { n++ } END { print n + 0 }')
    [[ $after_ticks -eq 0 ]] \
        || die "scenario10: output arrived after terminal transport kill ($after_ticks)"
}

# ---------------------------------------------------------------------------
# Scenario 11: raw local forwarding is never replaced after transport kill
# ---------------------------------------------------------------------------

scenario_forward_never_replaced() {
    local s11_bin="$TMP_ROOT/s11.bin"
    local s11_ssh="$s11_bin/ssh"
    local count_file="$TMP_ROOT/s11.ssh-count"
    local pid_file="$TMP_ROOT/s11.eversh-pid"
    local wrapper="$TMP_ROOT/s11.wrap.sh" log="$TMP_ROOT/s11.log"
    local status proxy_pid proxy_start proxy_exe proxy_pgrp

    "$MKDIR_TOOL" -m 700 -- "$s11_bin" || die "scenario11: shim dir creation failed"
    {
        printf '#!/usr/bin/bash\n'
        printf 'echo "$PPID" >> %q\n' "$count_file"
        printf 'exec %q "$@"\n' "$SSH_TOOL"
    } > "$s11_ssh"
    "$CHMOD_TOOL" 700 -- "$s11_ssh" || die "scenario11: ssh shim creation failed"
    : > "$count_file"
    "$CHMOD_TOOL" 600 -- "$count_file"

    # Forward the isolated sshd back to a random local port, then keep the
    # raw forwarding session alive without a remote command.
    local forward_port
    forward_port=$("$PYTHON3" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null || true)
    [[ $forward_port =~ ^[0-9]+$ ]] || die "scenario11: no free local port"
    {
        printf '#!/usr/bin/bash\nset -Eeuo pipefail\n'
        printf 'export PATH=%q:"$PATH"\n' "$s11_bin"
        printf 'echo "$$" > %q\n' "$pid_file"
        printf 'exec'
        local a
        for a in "$EVERSH_BIN" ssh "$ALIAS" \
            --remote-eversh "$EVERSH_BIN" \
            -- "-F$CLIENT_CONFIG" -o ClearAllForwardings=no \
            "-L127.0.0.1:$forward_port:127.0.0.1:$ISOLATED_PORT" -N; do
            printf ' %q' "$a"
        done
        printf '\n'
    } > "$wrapper"
    "$CHMOD_TOOL" 700 -- "$wrapper" || die "scenario11: wrapper creation failed"

    launch_interactive "$wrapper" "$log" \
        || die "scenario11: failed to launch forwarding wrapper"
    local forward_pid=$BG_PID
    local deadline=$((SECONDS + 10)) probe_ok=0
    while (( SECONDS < deadline )); do
        if run_bounded "$BASH_TOOL" -c \
            'exec 3<>/dev/tcp/127.0.0.1/$1; IFS= read -r -n 4 banner <&3; [[ $banner == SSH- ]]' \
            probe "$forward_port" >/dev/null 2>&1; then
            probe_ok=1
            break
        fi
        "$SLEEP_TOOL" 0.2
    done
    if (( probe_ok != 1 )); then
        "$SS_TOOL" -ltnp "sport = :$forward_port" >&2 || :
        ps -p "$forward_pid" -o pid,stat,args >&2 || :
        cat "$log" >&2 || :
        die "scenario11: forwarded sshd never answered"
    fi

    local eversh_pid
    eversh_pid=$("$CAT_TOOL" "$pid_file")
    [[ $eversh_pid =~ ^[0-9]+$ ]] || die "scenario11: bad eversh pid"
    proxy_pid=$(find_ssh_proxy_pid "$forward_pid" 10) \
        || die "scenario11: could not locate forwarding proxy"
    capture_identity "$proxy_pid" || die "scenario11: proxy identity vanished"
    proxy_start=$CAP_START proxy_exe=$CAP_EXE proxy_pgrp=$CAP_PGRP
    builtin kill -KILL "$proxy_pid" 2>/dev/null || die "scenario11: proxy kill failed"
    poll_owned_gone "$proxy_pid" "$proxy_start" "$proxy_exe" "$proxy_pgrp" "$KILL_POLL_SECONDS" \
        || die "scenario11: proxy did not disappear"

    status=0
    builtin wait "$forward_pid" 2>/dev/null || status=$?
    (( status != 0 )) || die "scenario11: forwarding session unexpectedly succeeded"
    if run_bounded "$BASH_TOOL" -c \
        'exec 3<>/dev/tcp/127.0.0.1/$1; IFS= read -r -n 4 banner <&3; [[ $banner == SSH- ]]' \
        probe "$forward_port" >/dev/null 2>&1; then
        die "scenario11: forwarded listener survived terminal transport kill"
    fi

    local supervisor_ssh=0 total_ssh=0 line
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        total_ssh=$((total_ssh + 1))
        [[ $line == "$eversh_pid" ]] && supervisor_ssh=$((supervisor_ssh + 1))
    done < "$count_file"
    (( supervisor_ssh == 1 )) || die \
"scenario11: supervisor spawned ssh $supervisor_ssh times (want exactly 1)"
    (( total_ssh == 3 )) || die \
"scenario11: unexpected ssh invocations: $total_ssh (want outer + query + bootstrap = 3)"
    "$GREP_TOOL" -q -F -- 'probing' "$log" \
        && die "scenario11: forwarding unexpectedly probed"
    "$GREP_TOOL" -q -F -- 'reattaching' "$log" \
        && die "scenario11: forwarding unexpectedly reattached"
    return 0
}

# ---------------------------------------------------------------------------
# Scenario 6: cleanup + health
# ---------------------------------------------------------------------------

scenario_cleanup_health() {
    assert_no_stray_harness_processes "$OWN_PID" \
        || die "scenario6: harness-owned processes survived the five scenarios"
    local leftover
    leftover=$(count_group_members_excluding "$OWN_PGRP" "$OWN_PID")
    [[ $leftover -eq 0 ]] || die "scenario6: $leftover leftover sshd session process(es) in its group"
    direct_health_check final || die "scenario6: sshd is no longer healthy"
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

cleanup() {
    local original_status=$? rc=0
    if (( CLEANUP_DONE )); then
        exit "$original_status"
    fi
    CLEANUP_DONE=1
    trap - EXIT INT TERM HUP
    set +e

    if [[ -n $TMP_ROOT ]]; then
        sweep_tmproot_processes "$OWN_PID"
    fi
    if [[ -n $OWN_PID ]]; then
        cleanup_owned "$OWN_PID" "$OWN_START" "$OWN_EXE" "$OWN_PGRP" || rc=1
    fi
    if [[ -n $TMP_ROOT ]]; then
        sweep_tmproot_processes ""
    fi

    if (( original_status != 0 || rc != 0 )); then
        if [[ -n $TMP_ROOT ]]; then
            printf 'FAILED: diagnostics preserved at %s\n' "$TMP_ROOT" >&2
        fi
        exit "$(( original_status != 0 ? original_status : 1 ))"
    fi

    if [[ -n $TMP_ROOT ]]; then
        remove_temp_root "$TMP_ROOT" || {
            printf 'FAILED: could not remove temp root %s\n' "$TMP_ROOT" >&2
            exit 1
        }
    fi
    printf 'eversh M5 production OpenSSH path: PASS\n'
    exit 0
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if (( WATCHDOG_CHILD == 0 )); then
    exec "$TIMEOUT_TOOL" --signal=TERM --kill-after=3s "${WATCHDOG_SECONDS}s" \
        "$BASH_TOOL" "$SCRIPT_PATH" --watchdog-child
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

[[ -x "$EVERSH_BIN" ]] || {
    printf 'target/debug/eversh is missing or not executable; build first\n' >&2
    exit 1
}
EVERSH_BIN=$("$READLINK_TOOL" -e -- "$EVERSH_BIN") || {
    printf 'cannot resolve target/debug/eversh\n' >&2
    exit 1
}

TMP_ROOT=$("$MKTEMP_TOOL" -d -- /tmp/eversh-m5s3.XXXXXX)
"$CHMOD_TOOL" 700 -- "$TMP_ROOT"
validate_temp_target "$TMP_ROOT" || {
    printf 'invalid temporary root\n' >&2
    exit 1
}

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
write_client_config

RAW_HOSTNAME=$("$CAT_TOOL" /proc/sys/kernel/hostname 2>/dev/null || printf 'unknown')
LOCAL_LABEL=$(printf '%s' "$RAW_HOSTNAME" | "$CUT_TOOL" -c1-32 | "$SED_TOOL" 's/[^A-Za-z0-9._-]/-/g')
[[ -n $LOCAL_LABEL ]] || LOCAL_LABEL=unknown
EXPECTED_ORIGIN="eversh:$LOCAL_LABEL"

# Fail closed if the remote environment does not actually receive
# EVERSH_STATE_DIR from sshd's own SetEnv before running any scenario.
STATE_CHECK_OUT="$TMP_ROOT/state-check.out"
STATE_CHECK_ERR="$TMP_ROOT/state-check.err"
set +e
run_bounded "$SSH_TOOL" -4 -F "$CLIENT_CONFIG" -n -T -- "$ALIAS" \
    '[ -n "${EVERSH_STATE_DIR-}" ] && printf "%s\n" "$EVERSH_STATE_DIR"' \
    > "$STATE_CHECK_OUT" 2> "$STATE_CHECK_ERR"
STATE_CHECK_STATUS=$?
set -e
(( STATE_CHECK_STATUS == 0 )) || {
    printf 'EVERSH_STATE_DIR was not received by the remote session\n' >&2
    exit 1
}
[[ "$("$CAT_TOOL" "$STATE_CHECK_OUT")" == "$STATE_DIR" ]] || {
    printf 'EVERSH_STATE_DIR mismatch: got %s want %s\n' "$("$CAT_TOOL" "$STATE_CHECK_OUT")" "$STATE_DIR" >&2
    exit 1
}

direct_health_check initial || {
    printf 'initial direct ssh health check failed\n' >&2
    exit 1
}

scenario_create_and_exit
scenario_no_replay_reattach
scenario_session_gone
scenario_busy_visible
scenario_list_detach
scenario_auth_failure
scenario_concurrent_connect
scenario_explicit_takeover
scenario_raw_ssh_never_replaced
scenario_forward_never_replaced
scenario_cleanup_health

exit 0
