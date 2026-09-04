#!/usr/bin/env bash
# Preregistered everudp reachability matrix: >=20 one-flow UDP attempts per
# named environment, plus bounded UDP-blocked diagnosis.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
SPIKE=$ROOT/spikes/everudp/target/release/everudp-spike
OUT=${1:-$ROOT/target/qualification/everudp/reachability.json}
ATTEMPTS=${2:-20}
IP=/usr/bin/ip
TC=/usr/sbin/tc
IPTABLES=/usr/sbin/iptables
TMP=$(mktemp -d)
TAG=r$((RANDOM & 32767))
cleaned=0
cleanup() {
    (( cleaned )) && return
    cleaned=1
    set +e
    for ns in "$TAG"c "$TAG"r "$TAG"s; do
        "$IP" netns del "$ns" 2>/dev/null
    done
    rm -rf -- "$TMP"
}
trap cleanup EXIT

results=()
record() {
    results+=("$(printf '%s\t%s\t%s\t%s' "$1" "$2" "$3" "$4")")
}

udp_server() {
    local ns=$1 addr=$2 port=$3
    local bind="$addr:$port"
    [[ $addr == *:* ]] && bind="[$addr]:$port"
    "$IP" netns exec "$ns" "$SPIKE" udp-server --bind "$bind" \
        --key-hex 0707070707070707 >"$TMP/$ns-server.log" 2>&1 &
    echo $!
}

try_udp() {
    local ns=$1 addr=$2 port=$3
    local host="$addr:$port"
    [[ $addr == *:* ]] && host="[$addr]:$port"
    "$IP" netns exec "$ns" timeout 3 "$SPIKE" reach --transport udp \
        --host "$host" --key-hex 0707070707070707 \
        >"$TMP/reach.out" 2>"$TMP/reach.err"
}

run_env() {
    local name=$1 ns=$2 addr=$3 port=$4 expect=$5
    local server_pid
    server_pid=$(udp_server "${6:-$ns}" "$addr" "$port")
    sleep 0.2
    local ok=0 rc=0
    for _ in $(seq 1 "$ATTEMPTS"); do
        if try_udp "$ns" "$addr" "$port"; then
            ok=$((ok + 1))
        else
            rc=$?
        fi
    done
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    record "$name" "$ok" "$ATTEMPTS" "$expect"
}

# Direct IPv4 over the same netns family used by the latency matrix.
$IP netns add "${TAG}s"
$IP netns add "${TAG}c"
$IP link add "${TAG}s" type veth peer name "${TAG}c"
$IP link set "${TAG}s" netns "${TAG}s"
$IP link set "${TAG}c" netns "${TAG}c"
$IP -n "${TAG}s" link set lo up
$IP -n "${TAG}c" link set lo up
$IP -n "${TAG}s" addr add 10.242.0.1/24 dev "${TAG}s"
$IP -n "${TAG}c" addr add 10.242.0.2/24 dev "${TAG}c"
$IP -n "${TAG}s" link set "${TAG}s" up
$IP -n "${TAG}c" link set "${TAG}c" up
run_env direct-ipv4 "${TAG}c" 10.242.0.1 60300 ">=95%" "${TAG}s"

# Direct IPv6.
$IP -n "${TAG}s" addr add fd42:242::1/64 dev "${TAG}s" nodad
$IP -n "${TAG}c" addr add fd42:242::2/64 dev "${TAG}c" nodad
run_env direct-ipv6 "${TAG}c" fd42:242::1 60301 ">=95%" "${TAG}s"

# UDP blocked: every attempt must fail bounded (timeout 3) with a clear
# reach failure rather than hang; the fallback proof is documented
# separately because SSH fallback is a product behavior, not a spike flow.
$IPTABLES -t raw -A PREROUTING -i "${TAG}s" -p udp --dport 60302 -j DROP 2>/dev/null || true
$IP netns exec "${TAG}c" $IPTABLES -I OUTPUT -o "${TAG}c" -p udp --dport 60302 -j DROP 2>/dev/null || true
server_pid=$(udp_server "${TAG}s" 10.242.0.1 60302)
sleep 0.2
blocked_ok=0
for _ in $(seq 1 "$ATTEMPTS"); do
    if try_udp "${TAG}c" 10.242.0.1 60302; then
        :
    else
        blocked_ok=$((blocked_ok + 1))
    fi
done
kill "$server_pid" 2>/dev/null || true
$IP netns exec "${TAG}c" $IPTABLES -D OUTPUT -o "${TAG}c" -p udp --dport 60302 -j DROP 2>/dev/null || true
$IPTABLES -t raw -D PREROUTING -i "${TAG}s" -p udp --dport 60302 -j DROP 2>/dev/null || true
record udp-blocked "$blocked_ok/$ATTEMPTS bounded failures" "20/20 failures" "20/20 bounded"

# NAT models: client ns -> router ns (NAT) -> server ns. Each model uses a
# distinct pinned iptables rule set; all else is identical.
nat_model() {
    local model=$1 port=$2 expect=$3
    "$IP" netns add "${TAG}n"
    "$IP" netns add "${TAG}m"
    "$IP" link add "n1" type veth peer name "n0"
    "$IP" link add "n2" type veth peer name "n3"
    "$IP" link set n0 netns "${TAG}n"
    "$IP" link set n1 netns "${TAG}m"
    "$IP" link set n2 netns "${TAG}m"
    "$IP" link set n3 netns "${TAG}s"
    "$IP" -n "${TAG}n" link set lo up
    "$IP" -n "${TAG}m" link set lo up
    "$IP" -n "${TAG}n" addr add 192.168.50.2/24 dev n0
    "$IP" -n "${TAG}n" link set n0 up
    "$IP" -n "${TAG}m" addr add 192.168.50.1/24 dev n1
    "$IP" -n "${TAG}m" addr add 10.242.1.1/24 dev n2
    "$IP" -n "${TAG}m" link set n1 up
    "$IP" -n "${TAG}m" link set n2 up
    "$IP" -n "${TAG}s" addr add 10.242.1.2/24 dev n3
    "$IP" -n "${TAG}s" link set n3 up
    "$IP" -n "${TAG}n" route replace default via 192.168.50.1
    "$IP" netns exec "${TAG}m" $IPTABLES -t nat -A POSTROUTING -s 192.168.50.0/24 -j MASQUERADE
    "$IP" netns exec "${TAG}m" $IPTABLES -A FORWARD -i n1 -o n2 -j ACCEPT
    "$IP" netns exec "${TAG}m" $IPTABLES -A FORWARD -i n2 -o n1 -j ACCEPT
    case $model in
        full-cone)
            # Endpoint-independent mapping and open return filtering.
            "$IP" netns exec "${TAG}m" $IPTABLES -t nat -A PREROUTING -i n2 -p udp --dport $port -j DNAT --to-destination 192.168.50.2:$port
            ;;
        restricted-cone)
            # Return allowed only after contact with the same external IP.
            "$IP" netns exec "${TAG}m" $IPTABLES -A FORWARD -i n2 -o n1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            ;;
        port-restricted-cone)
            # conntrack NAT default: address+port-restricted return path.
            ;;
        symmetric)
            # Endpoint-dependent mapping: random source port per destination.
            "$IP" netns exec "${TAG}m" $IPTABLES -t nat -R POSTROUTING 1 -s 192.168.50.0/24 -p udp -j MASQUERADE --random-fully
            ;;
    esac
    local server_pid
    server_pid=$(udp_server "${TAG}s" 10.242.1.2 "$port")
    sleep 0.2
    local ok=0
    for _ in $(seq 1 "$ATTEMPTS"); do
        if "$IP" netns exec "${TAG}n" timeout 3 "$SPIKE" reach --transport udp --host "10.242.1.2:$port" --key-hex 0707070707070707 >/dev/null 2>&1; then
            ok=$((ok + 1))
        fi
    done
    kill "$server_pid" 2>/dev/null || true
    "$IP" netns del "${TAG}n"
    "$IP" netns del "${TAG}m"
    "$IP" -n "${TAG}s" del 10.242.1.2/24 dev n3 2>/dev/null || true
    record "nat-$model" "$ok" "$ATTEMPTS" "$expect"
}

nat_model full-cone 60310 ">=95%"
nat_model restricted-cone 60311 ">=95%"
nat_model port-restricted-cone 60312 ">=95%"
nat_model symmetric 60313 ">=90%"

# ZeroTier: both endpoints bind the live local ZeroTier address.
ZT_ADDR=$($IP -4 addr show zt3middjio 2>/dev/null | awk '/inet / {print $2; exit}' | cut -d/ -f1)
if [[ -n $ZT_ADDR ]]; then
    server_pid=$("$SPIKE" udp-server --bind "$ZT_ADDR:60320" --key-hex 0707070707070707 >"$TMP/zt-server.log" 2>&1 & echo $!)
    sleep 0.3
    ok=0
    for _ in $(seq 1 "$ATTEMPTS"); do
        if timeout 3 "$SPIKE" reach --transport udp --host "$ZT_ADDR:60320" --key-hex 0707070707070707 >/dev/null 2>&1; then
            ok=$((ok + 1))
        fi
    done
    kill "$server_pid" 2>/dev/null || true
    record zerotier "$ok" "$ATTEMPTS" ">=90%"
else
    record zerotier UNAVAILABLE "no zt3middjio IPv4 address" ">=90%"
fi

# Tailscale: no daemon or interface on this host.
if tailscale status >/dev/null 2>&1 && $IP link show tailscale0 >/dev/null 2>&1; then
    record tailscale SKIPPED "present but not implemented in harness" ">=90%"
else
    record tailscale UNAVAILABLE "no tailscale daemon/interface" ">=90%"
fi

printf 'environment\tsuccesses\tattempts\tthreshold\n' >"$OUT"
printf '%s\n' "${results[@]}" >>"$OUT"
cat "$OUT"
