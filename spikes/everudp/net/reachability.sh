#!/usr/bin/env bash
# Exact-SHA reachability, NAT-semantics, overlay, and blocked-UDP gate.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/../../.." && pwd -P)
OUTDIR=${1:-$ROOT/target/qualification/everudp/reachability}
ATTEMPTS=${2:-20}
SPIKE=${EVERUDP_BIN:-$ROOT/spikes/everudp/target/release/everudp-spike}
EVERSH=${EVERSH_BIN:-$ROOT/target/release/eversh}
KEY=62bc8275e2d0fa1d11abb04d07d7e47731c70879c2d343bc47deb577df13ee7d
IP=/usr/bin/ip
IPTABLES=/usr/sbin/iptables
IPTABLES_SAVE=/usr/sbin/iptables-save
PYTHON=/usr/bin/python3
TIMEOUT=/usr/bin/timeout
NAT_PROBE=$ROOT/spikes/everudp/net/nat-probe.py
TAG=r$((RANDOM % 9000 + 1000))
RUN_USER=${SUDO_USER:-$(stat -c %U "$ROOT")}
CALLER_SSH_AUTH_SOCK=${SSH_AUTH_SOCK:-}
TMP=$(mktemp -d)
ROWS=$TMP/rows.tsv
NAMESPACE_WORDS=
SERVER_PID=
REMOTE_PID=
REMOTE_HOST=
REMOTE_LOG=
cleaned=0

if (( EUID != 0 )); then
    echo "reachability gate requires root network-namespace privileges" >&2
    exit 2
fi
if ! [[ $ATTEMPTS =~ ^[0-9]+$ ]] || (( ATTEMPTS < 20 )); then
    echo "reachability gate requires at least 20 attempts per row" >&2
    exit 2
fi
for executable in "$SPIKE" "$EVERSH" "$IP" "$IPTABLES" "$IPTABLES_SAVE" "$PYTHON" "$TIMEOUT"; do
    [[ -x $executable ]] || { echo "missing executable: $executable" >&2; exit 1; }
done
[[ -f $NAT_PROBE ]] || { echo "missing NAT probe: $NAT_PROBE" >&2; exit 1; }

run_user() {
    if [[ -n $CALLER_SSH_AUTH_SOCK ]]; then
        /usr/bin/sudo -n -H -u "$RUN_USER" /usr/bin/env \
            SSH_AUTH_SOCK="$CALLER_SSH_AUTH_SOCK" "$@"
    else
        /usr/bin/sudo -n -H -u "$RUN_USER" "$@"
    fi
}

remote() {
    local host=$1
    shift
    run_user /usr/bin/ssh -oBatchMode=yes -oConnectTimeout=5 "$host" "$@"
}

cleanup() {
    (( cleaned )) && return
    cleaned=1
    set +e
    [[ -z $SERVER_PID ]] || kill -KILL "$SERVER_PID" 2>/dev/null
    if [[ -n $REMOTE_PID && -n $REMOTE_HOST ]]; then
        remote "$REMOTE_HOST" "kill -KILL $REMOTE_PID 2>/dev/null; rm -f -- '$REMOTE_LOG'"
    fi
    for ns in $NAMESPACE_WORDS; do
        "$IP" netns pids "$ns" 2>/dev/null | xargs -r kill -KILL 2>/dev/null
        "$IP" netns del "$ns" 2>/dev/null
    done
    rm -rf -- "$TMP"
}
trap cleanup EXIT

add_ns() {
    "$IP" netns add "$1"
    NAMESPACE_WORDS="$NAMESPACE_WORDS $1"
    "$IP" -n "$1" link set lo up
}

del_ns() {
    "$IP" netns pids "$1" 2>/dev/null | xargs -r kill -KILL 2>/dev/null
    "$IP" netns del "$1" 2>/dev/null || true
}

endpoint() {
    local address=$1 port=$2
    if [[ $address == *:* ]]; then
        printf '[%s]:%s' "$address" "$port"
    else
        printf '%s:%s' "$address" "$port"
    fi
}

start_server() {
    local ns=$1 address=$2 port=$3 log=$4
    "$IP" netns exec "$ns" "$SPIKE" udp-server \
        --bind "$(endpoint "$address" "$port")" --key-hex "$KEY" \
        >"$log" 2>&1 &
    SERVER_PID=$!
}

stop_server() {
    [[ -z $SERVER_PID ]] && return
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=
}

try_udp_ns() {
    local ns=$1 address=$2 port=$3 stdout=$4 stderr=$5
    "$IP" netns exec "$ns" "$TIMEOUT" 3 "$SPIKE" reach --transport udp \
        --host "$(endpoint "$address" "$port")" --key-hex "$KEY" \
        >"$stdout" 2>"$stderr"
}

record_row() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >>"$ROWS"
}

run_attempts() {
    local name=$1 client_ns=$2 server_ns=$3 address=$4 port=$5 minimum=$6
    local successes=0 attempt_exit result
    printf 'attempt\texit\tresult\n' >"$OUTDIR/$name-attempts.tsv"
    for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
        start_server "$server_ns" "$address" "$port" "$OUTDIR/$name-server-last.log"
        sleep 0.03
        if try_udp_ns "$client_ns" "$address" "$port" \
            "$OUTDIR/$name-client-last.stdout" "$OUTDIR/$name-client-last.stderr"; then
            attempt_exit=0
            result=PASS
            successes=$((successes + 1))
        else
            attempt_exit=$?
            result=FAIL
        fi
        printf '%s\t%s\t%s\n' "$attempt" "$attempt_exit" "$result" \
            >>"$OUTDIR/$name-attempts.tsv"
        stop_server
    done
    local verdict=FAIL
    (( successes >= minimum )) && verdict=PASS
    record_row "$name" "$successes" "$ATTEMPTS" "$minimum" "$verdict" \
        "independent one-association processes"
}

HEAD_SHA=$(run_user git -C "$ROOT" rev-parse HEAD)
TREE_SHA=$(run_user git -C "$ROOT" rev-parse HEAD^{tree})
[[ -z $(run_user git -C "$ROOT" status --porcelain=v1) ]] || {
    echo "refusing exact-SHA reachability gate from a dirty worktree" >&2
    exit 1
}
[[ ! -e $OUTDIR ]] || {
    echo "refusing to overwrite reachability output: $OUTDIR" >&2
    exit 1
}
mkdir -p "$OUTDIR"
printf 'environment\tsuccesses\tattempts\tminimum\tverdict\tnote\n' >"$ROWS"
STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Direct IPv4 and IPv6 share one isolated veth topology.
DIRECT_SERVER=$TAG-ds
DIRECT_CLIENT=$TAG-dc
add_ns "$DIRECT_SERVER"
add_ns "$DIRECT_CLIENT"
"$IP" link add "$TAG-ds0" type veth peer name "$TAG-dc0"
"$IP" link set "$TAG-ds0" netns "$DIRECT_SERVER"
"$IP" link set "$TAG-dc0" netns "$DIRECT_CLIENT"
"$IP" -n "$DIRECT_SERVER" link set "$TAG-ds0" name s0
"$IP" -n "$DIRECT_CLIENT" link set "$TAG-dc0" name c0
"$IP" -n "$DIRECT_SERVER" addr add 10.242.0.1/24 dev s0
"$IP" -n "$DIRECT_CLIENT" addr add 10.242.0.2/24 dev c0
"$IP" -n "$DIRECT_SERVER" addr add fd42:242::1/64 dev s0 nodad
"$IP" -n "$DIRECT_CLIENT" addr add fd42:242::2/64 dev c0 nodad
"$IP" -n "$DIRECT_SERVER" link set s0 up
"$IP" -n "$DIRECT_CLIENT" link set c0 up
"$IP" -j -n "$DIRECT_SERVER" address show >"$OUTDIR/direct-server-addresses.json"
"$IP" -j -n "$DIRECT_CLIENT" address show >"$OUTDIR/direct-client-addresses.json"
"$IP" -j -n "$DIRECT_SERVER" route show table all >"$OUTDIR/direct-server-routes.json"
"$IP" -j -n "$DIRECT_CLIENT" route show table all >"$OUTDIR/direct-client-routes.json"
run_attempts direct-ipv4 "$DIRECT_CLIENT" "$DIRECT_SERVER" 10.242.0.1 60300 19
run_attempts direct-ipv6 "$DIRECT_CLIENT" "$DIRECT_SERVER" fd42:242::1 60301 19

# A blocked path must produce the exact bounded UDP diagnostic on all attempts.
"$IP" netns exec "$DIRECT_SERVER" "$IPTABLES" -I INPUT -i s0 -p udp --dport 60302 -j DROP
start_server "$DIRECT_SERVER" 10.242.0.1 60302 "$OUTDIR/udp-blocked-server.log"
sleep 0.05
blocked_failures=0
: >"$OUTDIR/udp-blocked-elapsed-ms.txt"
for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
    before_ns=$(date +%s%N)
    if try_udp_ns "$DIRECT_CLIENT" 10.242.0.1 60302 \
        "$OUTDIR/udp-blocked-last.stdout" "$OUTDIR/udp-blocked-last.stderr"; then
        :
    else
        after_ns=$(date +%s%N)
        elapsed_ms=$(((after_ns - before_ns) / 1000000))
        printf '%s\n' "$elapsed_ms" >>"$OUTDIR/udp-blocked-elapsed-ms.txt"
        if grep -Fxq 'everudp-spike: UDP association handshake timed out' \
            "$OUTDIR/udp-blocked-last.stderr" && (( elapsed_ms < 3000 )); then
            blocked_failures=$((blocked_failures + 1))
        fi
    fi
done
stop_server
"$IP" netns exec "$DIRECT_SERVER" "$IPTABLES" -D INPUT -i s0 -p udp --dport 60302 -j DROP
blocked_verdict=FAIL
(( blocked_failures == ATTEMPTS )) && blocked_verdict=PASS
record_row udp-blocked "$blocked_failures" "$ATTEMPTS" "$ATTEMPTS" "$blocked_verdict" \
    "exact handshake-timeout diagnostic below 3000ms"

setup_nat() {
    local model=$1 suffix=$2
    NAT_CLIENT=$TAG-$suffix-c
    NAT_ROUTER=$TAG-$suffix-r
    NAT_SERVER=$TAG-$suffix-s
    local client_if=$TAG-$suffix-i0
    local router_in=$TAG-$suffix-i1
    local router_out=$TAG-$suffix-e0
    local server_if=$TAG-$suffix-e1
    add_ns "$NAT_CLIENT"
    add_ns "$NAT_ROUTER"
    add_ns "$NAT_SERVER"
    "$IP" link add "$client_if" type veth peer name "$router_in"
    "$IP" link add "$router_out" type veth peer name "$server_if"
    "$IP" link set "$client_if" netns "$NAT_CLIENT"
    "$IP" link set "$router_in" netns "$NAT_ROUTER"
    "$IP" link set "$router_out" netns "$NAT_ROUTER"
    "$IP" link set "$server_if" netns "$NAT_SERVER"
    "$IP" -n "$NAT_CLIENT" link set "$client_if" name i0
    "$IP" -n "$NAT_ROUTER" link set "$router_in" name i0
    "$IP" -n "$NAT_ROUTER" link set "$router_out" name e0
    "$IP" -n "$NAT_SERVER" link set "$server_if" name e0
    "$IP" -n "$NAT_CLIENT" addr add 192.168.50.2/24 dev i0
    "$IP" -n "$NAT_ROUTER" addr add 192.168.50.1/24 dev i0
    "$IP" -n "$NAT_ROUTER" addr add 10.242.1.1/24 dev e0
    "$IP" -n "$NAT_SERVER" addr add 10.242.1.2/24 dev e0
    "$IP" -n "$NAT_SERVER" addr add 10.242.1.3/24 dev e0
    "$IP" -n "$NAT_CLIENT" link set i0 up
    "$IP" -n "$NAT_ROUTER" link set i0 up
    "$IP" -n "$NAT_ROUTER" link set e0 up
    "$IP" -n "$NAT_SERVER" link set e0 up
    "$IP" -n "$NAT_CLIENT" route add default via 192.168.50.1
    "$IP" -n "$NAT_SERVER" route add default via 10.242.1.1
    "$IP" netns exec "$NAT_ROUTER" /usr/sbin/sysctl -qw net.ipv4.ip_forward=1
    "$IP" netns exec "$NAT_ROUTER" "$IPTABLES" -P FORWARD DROP
    "$IP" netns exec "$NAT_ROUTER" "$IPTABLES" -A FORWARD -i i0 -o e0 -j ACCEPT
    "$IP" netns exec "$NAT_ROUTER" "$IPTABLES" -A FORWARD -i e0 -o i0 \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    if [[ $model == symmetric ]]; then
        "$IP" netns exec "$NAT_ROUTER" "$IPTABLES" -t nat -A POSTROUTING \
            -s 192.168.50.2 -d 10.242.1.2 -p udp \
            -j SNAT --to-source 10.242.1.1:40001-45000
        "$IP" netns exec "$NAT_ROUTER" "$IPTABLES" -t nat -A POSTROUTING \
            -s 192.168.50.2 -d 10.242.1.3 -p udp \
            -j SNAT --to-source 10.242.1.1:50001-55000
    else
        "$IP" netns exec "$NAT_ROUTER" "$IPTABLES" -t nat -A POSTROUTING \
            -s 192.168.50.2 -o e0 -p udp -j SNAT --to-source 10.242.1.1
        "$IP" netns exec "$NAT_ROUTER" "$IPTABLES" -t nat -A PREROUTING \
            -i e0 -d 10.242.1.1 -p udp --dport 40000 \
            -j DNAT --to-destination 192.168.50.2:40000
        if [[ $model == full-cone ]]; then
            "$IP" netns exec "$NAT_ROUTER" "$IPTABLES" -A FORWARD \
                -i e0 -o i0 -p udp -d 192.168.50.2 --dport 40000 -j ACCEPT
        elif [[ $model == restricted-cone ]]; then
            "$IP" netns exec "$NAT_ROUTER" "$IPTABLES" -A FORWARD \
                -i e0 -o i0 -p udp -s 10.242.1.2 -d 192.168.50.2 --dport 40000 -j ACCEPT
        fi
    fi
}

capture_nat_topology() {
    local model=$1
    "$IP" -j -n "$NAT_CLIENT" address show >"$OUTDIR/nat-$model-client-addresses.json"
    "$IP" -j -n "$NAT_CLIENT" route show table all >"$OUTDIR/nat-$model-client-routes.json"
    "$IP" -j -n "$NAT_ROUTER" address show >"$OUTDIR/nat-$model-router-addresses.json"
    "$IP" -j -n "$NAT_ROUTER" route show table all >"$OUTDIR/nat-$model-router-routes.json"
    "$IP" netns exec "$NAT_ROUTER" "$IPTABLES_SAVE" >"$OUTDIR/nat-$model-iptables.txt"
    "$IP" -j -n "$NAT_SERVER" address show >"$OUTDIR/nat-$model-server-addresses.json"
}

probe_cone() {
    local model=$1 expected=$2
    "$IP" netns exec "$NAT_SERVER" "$PYTHON" "$NAT_PROBE" cone-server \
        >"$OUTDIR/nat-$model-probe-server.json" &
    local probe_pid=$!
    sleep 0.05
    "$IP" netns exec "$NAT_CLIENT" "$PYTHON" "$NAT_PROBE" cone-client \
        >"$OUTDIR/nat-$model-probe-client.json"
    wait "$probe_pid"
    "$PYTHON" - "$OUTDIR/nat-$model-probe-client.json" "$expected" <<'PY'
import json
import sys

actual = json.load(open(sys.argv[1], encoding="utf-8"))["received"]
expected = sys.argv[2].split(",")
if actual != expected:
    raise SystemExit(f"NAT filtering mismatch: expected {expected}, got {actual}")
PY
}

probe_symmetric() {
    "$IP" netns exec "$NAT_SERVER" "$PYTHON" "$NAT_PROBE" symmetric-server \
        >"$OUTDIR/nat-symmetric-probe-server.json" &
    local probe_pid=$!
    sleep 0.05
    "$IP" netns exec "$NAT_CLIENT" "$PYTHON" "$NAT_PROBE" symmetric-client \
        >"$OUTDIR/nat-symmetric-probe-client.json"
    wait "$probe_pid"
    "$PYTHON" - "$OUTDIR/nat-symmetric-probe-client.json" \
        "$OUTDIR/nat-symmetric-probe-server.json" <<'PY'
import json
import sys

client = json.load(open(sys.argv[1], encoding="utf-8"))
server = json.load(open(sys.argv[2], encoding="utf-8"))
if client["received"] != ["from-a", "from-b"]:
    raise SystemExit(f"symmetric NAT replies missing: {client}")
ports = [server["mapped_peers"][name][1] for name in ("a", "b")]
if not (40001 <= ports[0] <= 45000 and 50001 <= ports[1] <= 55000):
    raise SystemExit(f"symmetric NAT did not use destination-specific mappings: {ports}")
PY
}

run_nat_model() {
    local model=$1 suffix=$2 port=$3 minimum=$4 expected=${5:-}
    setup_nat "$model" "$suffix"
    capture_nat_topology "$model"
    if [[ $model == symmetric ]]; then
        probe_symmetric
    else
        probe_cone "$model" "$expected"
    fi
    run_attempts "$model" "$NAT_CLIENT" "$NAT_SERVER" 10.242.1.2 "$port" "$minimum"
    del_ns "$NAT_CLIENT"
    del_ns "$NAT_ROUTER"
    del_ns "$NAT_SERVER"
}

run_nat_model full-cone f 60310 19 a-other-port,a-same,b-other-ip,open-ack
run_nat_model restricted-cone r 60311 19 a-other-port,a-same,open-ack
run_nat_model port-restricted-cone p 60312 19 a-same,open-ack
run_nat_model symmetric y 60313 18

# Overlay rows must use a distinct machine and the exact same spike binary.
ZT_PEER_HOST=${EVERUDP_ZT_PEER_HOST:-}
ZT_PEER_ADDR=${EVERUDP_ZT_PEER_ADDR:-}
ZT_REMOTE_BIN=${EVERUDP_ZT_REMOTE_BIN:-}
ZT_LOCAL_IFACE=${EVERUDP_ZT_LOCAL_IFACE:-zt3middjio}
ZT_REMOTE_IFACE=${EVERUDP_ZT_REMOTE_IFACE:-zt3middjio}

safe_host() {
    [[ $1 =~ ^[A-Za-z0-9._-]+$ ]]
}

safe_address() {
    [[ $1 =~ ^[0-9A-Fa-f:.]+$ ]]
}

safe_path() {
    [[ $1 =~ ^/[A-Za-z0-9._/+:-]+$ ]]
}

safe_interface() {
    [[ $1 =~ ^[A-Za-z0-9._:-]+$ ]]
}

SPIKE_SHA=$(sha256sum "$SPIKE" | awk '{print $1}')
EVERSH_SHA=$(sha256sum "$EVERSH" | awk '{print $1}')

run_zerotier() {
    if [[ -z $ZT_PEER_HOST || -z $ZT_PEER_ADDR || -z $ZT_REMOTE_BIN ]]; then
        printf '%s\n' \
            'UNAVAILABLE: EVERUDP_ZT_PEER_HOST, EVERUDP_ZT_PEER_ADDR, and EVERUDP_ZT_REMOTE_BIN are required' \
            >"$OUTDIR/zerotier-unavailable.txt"
        record_row zerotier 0 "$ATTEMPTS" 18 UNAVAILABLE \
            "no configured distinct peer"
        return
    fi
    safe_host "$ZT_PEER_HOST" || { echo "unsafe ZeroTier peer host" >&2; exit 1; }
    safe_address "$ZT_PEER_ADDR" || { echo "unsafe ZeroTier peer address" >&2; exit 1; }
    safe_path "$ZT_REMOTE_BIN" || { echo "unsafe ZeroTier remote binary path" >&2; exit 1; }
    safe_interface "$ZT_LOCAL_IFACE" || { echo "unsafe local ZeroTier interface" >&2; exit 1; }
    safe_interface "$ZT_REMOTE_IFACE" || { echo "unsafe remote ZeroTier interface" >&2; exit 1; }

    local local_host remote_host remote_sha successes=0 port=60320
    local attempt_exit result
    local_host=$(hostname)
    remote_host=$(remote "$ZT_PEER_HOST" hostname)
    [[ $remote_host != "$local_host" ]] || {
        echo "ZeroTier peer resolves to the local host" >&2
        exit 1
    }
    printf '%s\n' "$local_host" >"$OUTDIR/zerotier-local-hostname.txt"
    printf '%s\n' "$remote_host" >"$OUTDIR/zerotier-remote-hostname.txt"
    "$IP" -j address show dev "$ZT_LOCAL_IFACE" >"$OUTDIR/zerotier-local-addresses.json"
    "$IP" -j route get "$ZT_PEER_ADDR" >"$OUTDIR/zerotier-local-route.json"
    remote "$ZT_PEER_HOST" "/usr/bin/ip -j address show dev '$ZT_REMOTE_IFACE'" \
        >"$OUTDIR/zerotier-remote-addresses.json"
    remote "$ZT_PEER_HOST" "/usr/bin/sha256sum '$ZT_REMOTE_BIN'" \
        >"$OUTDIR/zerotier-remote-binary.sha256"
    remote_sha=$(awk '{print $1}' "$OUTDIR/zerotier-remote-binary.sha256")
    [[ $remote_sha == "$SPIKE_SHA" ]] || {
        echo "ZeroTier peer binary does not match the local spike binary" >&2
        exit 1
    }

    REMOTE_HOST=$ZT_PEER_HOST
    REMOTE_LOG=/tmp/everudp-zt-$HEAD_SHA-$TAG.log
    printf 'attempt\texit\tresult\n' >"$OUTDIR/zerotier-attempts.tsv"
    for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
        REMOTE_PID=$(remote "$ZT_PEER_HOST" \
            "nohup '$ZT_REMOTE_BIN' udp-server --bind '$ZT_PEER_ADDR:$port' --key-hex '$KEY' >'$REMOTE_LOG' 2>&1 & echo \$!")
        [[ $REMOTE_PID =~ ^[0-9]+$ ]] || {
            echo "ZeroTier peer returned an invalid server PID" >&2
            exit 1
        }
        sleep 0.05
        if run_user "$TIMEOUT" 3 "$SPIKE" reach --transport udp \
            --host "$ZT_PEER_ADDR:$port" --key-hex "$KEY" \
            >"$OUTDIR/zerotier-client-last.stdout" \
            2>"$OUTDIR/zerotier-client-last.stderr"; then
            attempt_exit=0
            result=PASS
            successes=$((successes + 1))
        else
            attempt_exit=$?
            result=FAIL
        fi
        printf '%s\t%s\t%s\n' "$attempt" "$attempt_exit" "$result" \
            >>"$OUTDIR/zerotier-attempts.tsv"
        remote "$ZT_PEER_HOST" "kill '$REMOTE_PID' 2>/dev/null || true"
        REMOTE_PID=
    done
    remote "$ZT_PEER_HOST" "cat '$REMOTE_LOG'" >"$OUTDIR/zerotier-server-last.log" || true
    remote "$ZT_PEER_HOST" "rm -f -- '$REMOTE_LOG'"
    REMOTE_LOG=
    REMOTE_HOST=
    local verdict=FAIL
    (( successes >= 18 )) && verdict=PASS
    record_row zerotier "$successes" "$ATTEMPTS" 18 "$verdict" \
        "distinct hosts $local_host to $remote_host over $ZT_LOCAL_IFACE/$ZT_REMOTE_IFACE"
}

run_zerotier

# Inventory every known fleet peer. A missing/stopped daemon is an exact
# UNAVAILABLE result, never evidence of overlay reachability.
TAILSCALE_HOSTS=${EVERUDP_TAILSCALE_HOSTS:-"local bugger.a bagger.a"}
TAILSCALE_ROWS=$OUTDIR/tailscale-status.tsv
printf 'host\tstate\tdetail\n' >"$TAILSCALE_ROWS"
tailscale_running=0
tailscale_inventory=

probe_tailscale_local() {
    local artifact=$OUTDIR/tailscale-local.txt state detail
    if ! run_user /bin/sh -c 'command -v tailscale >/dev/null 2>&1'; then
        state=MISSING
        detail="tailscale executable not installed"
        printf '%s\n' "$detail" >"$artifact"
    elif run_user tailscale status --json >"$artifact" 2>&1 && \
        "$PYTHON" - "$artifact" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if value.get("BackendState") == "Running" else 1)
PY
    then
        state=RUNNING
        detail="BackendState=Running"
        tailscale_running=$((tailscale_running + 1))
    else
        state=STOPPED
        detail="installed but BackendState is not Running"
    fi
    printf 'local\t%s\t%s\n' "$state" "$detail" >>"$TAILSCALE_ROWS"
    tailscale_inventory="local=$state"
}

probe_tailscale_remote() {
    local host=$1 safe_name artifact state detail
    safe_host "$host" || { echo "unsafe Tailscale inventory host" >&2; exit 1; }
    safe_name=${host//./-}
    artifact=$OUTDIR/tailscale-$safe_name.txt
    if ! remote "$host" "command -v tailscale >/dev/null 2>&1"; then
        state=MISSING
        detail="tailscale executable not installed"
        printf '%s\n' "$detail" >"$artifact"
    elif remote "$host" "tailscale status --json" >"$artifact" 2>&1 && \
        "$PYTHON" - "$artifact" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if value.get("BackendState") == "Running" else 1)
PY
    then
        state=RUNNING
        detail="BackendState=Running"
        tailscale_running=$((tailscale_running + 1))
    else
        state=STOPPED
        detail="installed but BackendState is not Running"
    fi
    printf '%s\t%s\t%s\n' "$host" "$state" "$detail" >>"$TAILSCALE_ROWS"
    tailscale_inventory="$tailscale_inventory,$host=$state"
}

for tailscale_host in $TAILSCALE_HOSTS; do
    if [[ $tailscale_host == local ]]; then
        probe_tailscale_local
    else
        probe_tailscale_remote "$tailscale_host"
    fi
done

if (( tailscale_running >= 2 )); then
    record_row tailscale 0 "$ATTEMPTS" 18 FAIL \
        "two running peers found but no peer pair configured: $tailscale_inventory"
else
    record_row tailscale 0 "$ATTEMPTS" 18 UNAVAILABLE \
        "fewer than two running peers: $tailscale_inventory"
fi

# The blocked-UDP diagnosis above is followed by exactly one transition to
# the existing stable everssh transport on a distinct host.
FALLBACK_HOST=${EVERUDP_FALLBACK_HOST:-}
FALLBACK_REMOTE_EVERSH=${EVERUDP_FALLBACK_REMOTE_EVERSH:-}
fallback_invocations=0
fallback_successes=0
fallback_exit=125
if [[ -n $FALLBACK_HOST && -n $FALLBACK_REMOTE_EVERSH ]]; then
    safe_host "$FALLBACK_HOST" || { echo "unsafe fallback host" >&2; exit 1; }
    safe_path "$FALLBACK_REMOTE_EVERSH" || { echo "unsafe fallback remote binary path" >&2; exit 1; }
    remote "$FALLBACK_HOST" "/usr/bin/sha256sum '$FALLBACK_REMOTE_EVERSH'" \
        >"$OUTDIR/everssh-fallback-remote-binary.sha256"
    fallback_remote_sha=$(awk '{print $1}' "$OUTDIR/everssh-fallback-remote-binary.sha256")
    [[ $fallback_remote_sha == "$EVERSH_SHA" ]] || {
        echo "fallback peer binary does not match the local eversh binary" >&2
        exit 1
    }
    fallback_invocations=1
    printf '%s\n' 'UDP_UNAVAILABLE -> EVERSSH_FALLBACK' \
        >"$OUTDIR/fallback-transition.txt"
    set +e
    run_user "$TIMEOUT" 20 "$EVERSH" ssh \
        --remote-eversh "$FALLBACK_REMOTE_EVERSH" "$FALLBACK_HOST" -- \
        -oBatchMode=yes -oConnectTimeout=5 -- /bin/true \
        >"$OUTDIR/everssh-fallback.stdout" \
        2>"$OUTDIR/everssh-fallback.stderr"
    fallback_exit=$?
    set -e
    (( fallback_exit == 0 )) && fallback_successes=1
else
    printf '%s\n' \
        'EVERUDP_FALLBACK_HOST and EVERUDP_FALLBACK_REMOTE_EVERSH are required' \
        >"$OUTDIR/everssh-fallback.stderr"
fi
printf '%s\n' "$fallback_exit" >"$OUTDIR/everssh-fallback.exit"
fallback_verdict=FAIL
if (( blocked_failures == ATTEMPTS && fallback_invocations == 1 && fallback_successes == 1 )); then
    fallback_verdict=PASS
fi
record_row everssh-fallback "$fallback_successes" 1 1 "$fallback_verdict" \
    "exactly $fallback_invocations transition after $blocked_failures/$ATTEMPTS diagnosed UDP failures"

cp "$ROWS" "$OUTDIR/rows.tsv"
FINISHED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
{
    printf 'source_sha=%s\n' "$HEAD_SHA"
    printf 'source_tree=%s\n' "$TREE_SHA"
    printf 'spike_sha256=%s\n' "$SPIKE_SHA"
    printf 'eversh_sha256=%s\n' "$EVERSH_SHA"
    printf 'started_utc=%s\n' "$STARTED_UTC"
    printf 'finished_utc=%s\n' "$FINISHED_UTC"
    printf 'host=%s\n' "$(hostname)"
    uname -a
} >"$OUTDIR/source.txt"

(
    cd "$OUTDIR"
    find . -type f ! -name artifact-sha256.txt ! -name receipt.json \
        ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum
) >"$TMP/artifact-sha256.txt"
mv "$TMP/artifact-sha256.txt" "$OUTDIR/artifact-sha256.txt"

"$PYTHON" - "$OUTDIR/rows.tsv" "$OUTDIR/artifact-sha256.txt" \
    "$OUTDIR/receipt.json" "$HEAD_SHA" "$TREE_SHA" "$SPIKE_SHA" \
    "$EVERSH_SHA" "$STARTED_UTC" "$FINISHED_UTC" "$blocked_failures" \
    "$fallback_invocations" <<'PY'
import csv
import json
import pathlib
import sys

(
    rows_path,
    hashes_path,
    receipt_path,
    source_sha,
    source_tree,
    spike_sha,
    eversh_sha,
    started,
    finished,
    blocked_failures,
    fallback_invocations,
) = sys.argv[1:]

with open(rows_path, encoding="utf-8", newline="") as stream:
    rows = list(csv.DictReader(stream, delimiter="\t"))
for row in rows:
    for field in ("successes", "attempts", "minimum"):
        row[field] = int(row[field])

expected = {
    "direct-ipv4",
    "direct-ipv6",
    "full-cone",
    "restricted-cone",
    "port-restricted-cone",
    "symmetric",
    "udp-blocked",
    "zerotier",
    "tailscale",
    "everssh-fallback",
}
names = {row["environment"] for row in rows}
if names != expected or len(rows) != len(expected):
    raise SystemExit(f"row mismatch: expected {sorted(expected)}, got {sorted(names)}")

allowed_unavailable = {"zerotier", "tailscale"}
overall_pass = all(
    row["verdict"] == "PASS"
    or (row["environment"] in allowed_unavailable and row["verdict"] == "UNAVAILABLE")
    for row in rows
)
artifacts = {}
for line in pathlib.Path(hashes_path).read_text(encoding="utf-8").splitlines():
    digest, name = line.split(maxsplit=1)
    artifacts[name.removeprefix("./")] = digest

receipt = {
    "schema": 2,
    "gate": "everudp-reachability",
    "source": {
        "commit": source_sha,
        "tree": source_tree,
        "clean": True,
        "spike_sha256": spike_sha,
        "eversh_sha256": eversh_sha,
    },
    "started_utc": started,
    "finished_utc": finished,
    "rows": rows,
    "blocked_udp": {
        "diagnostic": "everudp-spike: UDP association handshake timed out",
        "diagnosed_failures": int(blocked_failures),
    },
    "fallback": {
        "transport": "everssh",
        "invocations": int(fallback_invocations),
    },
    "artifacts": artifacts,
    "overall_verdict": "PASS" if overall_pass else "FAIL",
}
pathlib.Path(receipt_path).write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
raise SystemExit(0 if overall_pass else 1)
PY

(
    cd "$OUTDIR"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum
) >"$TMP/SHA256SUMS"
mv "$TMP/SHA256SUMS" "$OUTDIR/SHA256SUMS"
(cd "$OUTDIR" && sha256sum -c SHA256SUMS)
chmod -R a+rX "$OUTDIR"
echo "everudp reachability gate: PASS ($OUTDIR)"
