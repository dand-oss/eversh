#!/usr/bin/env bash
# Stage D latency matrix over one isolated netns/veth path.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SPIKE=$ROOT/spikes/everudp/target/release
TRIALS=${1:?trials}
LOSS=${2:-0}
OUTDIR=${3:-$ROOT/target/qualification/everudp}
DELAY_MS=${4:-0}
REORDER_PCT=${5:-0}
SUFFIX="-loss${LOSS}"
if (( DELAY_MS > 0 )); then
    SUFFIX="$SUFFIX-jitter${DELAY_MS}"
fi
if (( REORDER_PCT > 0 )); then
    SUFFIX="$SUFFIX-reorder${REORDER_PCT}"
fi
mkdir -p "$OUTDIR"
TAG=u$((RANDOM & 32767))
SERVER_NS=${TAG}s
CLIENT_NS=${TAG}c
IP=/usr/bin/ip
TC=/usr/sbin/tc
TMP=$(mktemp -d)
SERVER_PID=
cleaned=0
cleanup() {
    (( cleaned )) && return
    cleaned=1
    set +e
    [[ -z $SERVER_PID ]] || kill -KILL "$SERVER_PID" 2>/dev/null
    for ns in "$CLIENT_NS" "$SERVER_NS"; do
        "$IP" netns exec "$ns" "$TC" qdisc del dev c0 root 2>/dev/null
        "$IP" netns exec "$ns" "$TC" qdisc del dev s0 root 2>/dev/null
        "$IP" netns pids "$ns" 2>/dev/null | xargs -r kill -KILL 2>/dev/null
        "$IP" netns del "$ns" 2>/dev/null
    done
    "$IP" link del "${TAG}c" 2>/dev/null
    rm -rf -- "$TMP"
}
trap cleanup EXIT

$IP netns add "$SERVER_NS"
$IP netns add "$CLIENT_NS"
$IP link add "${TAG}s" type veth peer name "${TAG}c"
$IP link set "${TAG}s" netns "$SERVER_NS"
$IP link set "${TAG}c" netns "$CLIENT_NS"
$IP -n "$SERVER_NS" link set "${TAG}s" name s0
$IP -n "$CLIENT_NS" link set "${TAG}c" name c0
$IP -n "$SERVER_NS" link set lo up
$IP -n "$CLIENT_NS" link set lo up
$IP -n "$SERVER_NS" addr add 10.241.0.1/24 dev s0
$IP -n "$CLIENT_NS" addr add 10.241.0.2/24 dev c0
$IP -n "$SERVER_NS" link set s0 up
$IP -n "$CLIENT_NS" link set c0 up

if (( LOSS > 0 )); then
    delay_arg=()
    if (( DELAY_MS > 0 )); then
        delay_arg=(delay "${DELAY_MS}ms" 5ms)
    elif (( REORDER_PCT > 0 )); then
        delay_arg=(delay 1ms)
    fi
    reorder_arg=()
    if (( REORDER_PCT > 0 )); then
        reorder_arg=(reorder "${REORDER_PCT}%")
    fi
    if (( DELAY_MS > 0 )); then
        $IP netns exec "$CLIENT_NS" $TC qdisc replace dev c0 root netem loss "${LOSS}%" "${delay_arg[@]}" "${reorder_arg[@]}"
        $IP netns exec "$SERVER_NS" $TC qdisc replace dev s0 root netem loss "${LOSS}%" "${delay_arg[@]}" "${reorder_arg[@]}"
    else
        $IP netns exec "$CLIENT_NS" $TC qdisc replace dev c0 root netem loss "${LOSS}%" "${delay_arg[@]}" "${reorder_arg[@]}"
        $IP netns exec "$SERVER_NS" $TC qdisc replace dev s0 root netem loss "${LOSS}%" "${delay_arg[@]}" "${reorder_arg[@]}"
    fi
fi

ssh-keygen -q -t ed25519 -N '' -f "$TMP/host" >/dev/null
ssh-keygen -q -t ed25519 -N '' -f "$TMP/client" >/dev/null
cp "$TMP/client.pub" "$TMP/authorized_keys"
PORT=2201
cat >"$TMP/sshd_config" <<EOF
Port $PORT
ListenAddress 10.241.0.1
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
AcceptEnv EVERSSH_DEBUG_SERVER
LogLevel ERROR
EOF
$IP netns exec "$SERVER_NS" /usr/sbin/sshd -D -e -f "$TMP/sshd_config" 2>"$TMP/sshd.err" &
SERVER_PID=$!
for _ in $(seq 1 50); do
    $IP netns exec "$CLIENT_NS" /usr/bin/ssh-keyscan -T 1 -p "$PORT" 10.241.0.1 >"$TMP/known" 2>/dev/null || true
    grep -q ssh-ed25519 "$TMP/known" && break
    sleep 0.1
done
grep -q ssh-ed25519 "$TMP/known" || { cat "$TMP/sshd.err" >&2; exit 1; }
cat >"$TMP/client_config" <<EOF
Host bench 10.241.0.1
    HostName 10.241.0.1
    Port $PORT
    User $USER
    IdentityFile $TMP/client
    IdentitiesOnly yes
    UserKnownHostsFile $TMP/known
    GlobalKnownHostsFile /dev/null
    StrictHostKeyChecking yes
    BatchMode yes
    ClearAllForwardings yes
    ServerAliveInterval 60
    ServerAliveCountMax 12
    ProxyCommand none
    ProxyJump none
    RequestTTY auto
    SendEnv EVERSSH_DEBUG_SERVER
EOF

run_ssh_control() {
    local mode=$1
    local proxy=()
    local debug_env=(EVERSSH_DEBUG_SERVER=1)
    if [[ $mode == everssh ]]; then
        proxy=(-o "ProxyCommand=$ROOT/target/release/everssh ssh-proxy 10.241.0.1 $PORT --remote-eversh $ROOT/target/release/eversh --ssh-option -F$TMP/client_config --status-file $TMP/status-$mode")
    fi
    $IP netns exec "$CLIENT_NS" /usr/bin/env "${debug_env[@]}" /usr/bin/python3 "$NET/drive-ssh.py" \
        "$OUTDIR/${mode}-${SUFFIX}.json" "$TRIALS" 0.15 \
        ssh -F "$TMP/client_config" "${proxy[@]}" -tt bench \
        "/bin/sh -c 'printf EVERUDP_READY; stty raw -echo; exec /usr/bin/python3 -u $NET/echo1.py'"
    python3 - "$OUTDIR/${mode}-${SUFFIX}.json" <<'PY'
import json, sys
path = sys.argv[1]
try:
    events = json.load(open(path))
except Exception:
    sys.exit(0)
if not isinstance(events, list):
    sys.exit(0)
samples = sorted((e["echo_t"] - e["t"]) // 1000 for e in events if e.get("echo_t"))
def pick(q):
    return samples[round((len(samples) - 1) * q)] if samples else 0
json.dump({
    "summary": {
        "trials": len(events),
        "nonzero": len(samples),
        "median_us": pick(0.5),
        "p95_us": pick(0.95),
        "max_us": samples[-1] if samples else 0,
    },
    "samples": samples,
}, open(path, "w"))
PY
}

run_ssh_strace() {
    $IP netns exec "$CLIENT_NS" /usr/bin/strace -f -tt -e trace=sendto,recvfrom,connect,socket \
        -o "$TMP/everssh.strace" ssh -F "$TMP/client_config" \
        -o "ProxyCommand=$ROOT/target/release/everssh ssh-proxy 10.241.0.1 $PORT --remote-eversh $ROOT/target/release/eversh --ssh-option -F$TMP/client_config --status-file $TMP/status-strace" \
        -tt bench "echo ready" </dev/null >/dev/null 2>&1 || true
}

run_everudp_udp() {
    local prediction=$1
    local name="everudp-udp-$([[ $prediction == on ]] && echo pred || echo nopred)${SUFFIX}"
    $IP netns exec "$SERVER_NS" "$SPIKE/everudp-spike" udp-pty-server \
        --bind 10.241.0.1:60200 --key-hex 0707070707070707 \
        --echo-command "/usr/bin/python3 -u $NET/echo1.py" \
        >"$TMP/udp-server.log" 2>&1 &
    local udp_server=$!
    sleep 0.3
    $IP netns exec "$CLIENT_NS" "$SPIKE/everudp-spike" bench \
        --transport udp --prediction "$prediction" --trials "$TRIALS" \
        --server 10.241.0.1:60200 >"$OUTDIR/$name.json" 2>"$OUTDIR/$name.err"
    kill "$udp_server" 2>/dev/null || true
}

run_everudp_quic() {
    local prediction=$1
    local name="everudp-quic-$([[ $prediction == on ]] && echo pred || echo nopred)${SUFFIX}"
    $IP netns exec "$SERVER_NS" "$SPIKE/everudp-spike" quic-server \
        --bind 10.241.0.1:60201 >"$TMP/quic-server.log" 2>&1 &
    local quic_server=$!
    for _ in $(seq 1 30); do
        grep -q '^spki=' "$TMP/quic-server.log" && break
        sleep 0.1
    done
    local spki
    spki=$(sed -n 's/^spki=//p' "$TMP/quic-server.log")
    [[ ${#spki} == 64 ]] || { cat "$TMP/quic-server.log" >&2; exit 1; }
    $IP netns exec "$CLIENT_NS" "$SPIKE/everudp-spike" bench \
        --transport quic --prediction "$prediction" --trials "$TRIALS" \
        --server 10.241.0.1:60201 --spki-hex "$spki" \
        >"$OUTDIR/$name.json" 2>"$OUTDIR/$name.err"
    kill "$quic_server" 2>/dev/null || true
}

run_mosh() {
    local out="$OUTDIR/mosh-${SUFFIX}.json"
    local port=60100
    local mosh_output
    mosh_output=$($IP netns exec "$SERVER_NS" mosh-server new -p $port \
        -- /usr/bin/python3 -u "$NET/echo1.py" 2>"$TMP/mosh-server.err")
    read -r _ _ actual_port key <<<"$mosh_output"
    $IP netns exec "$CLIENT_NS" /usr/bin/tcpdump -i c0 -nn -U -w "$TMP/mosh.pcap" \
        "udp port $actual_port" 2>"$TMP/tcpdump.err" &
    local tdump=$!
    sleep 1
    $IP netns exec "$CLIENT_NS" /usr/bin/python3 "$NET/drive-mosh.py" \
        "$actual_port" "$key" "$TRIALS" "$TMP/mosh-events.json" 0.15 10.241.0.1
    sleep 1
    kill "$tdump" 2>/dev/null || true
    sleep 0.3
    python3 "$NET/parse-pcap.py" "$TMP/mosh.pcap" "$TMP/mosh-events.json" "$out" "$actual_port"
    pkill -f "mosh-server new -p $actual_port" 2>/dev/null || true
}

run_zmosh() {
    local out="$OUTDIR/zmosh-${SUFFIX}.json"
    local zdir="$TMP/zmx"
    mkdir -p "$zdir"
    $IP netns exec "$SERVER_NS" /usr/bin/env \
        -u ZMX_SESSION TERM=xterm-256color ZMX_DIR="$zdir" \
        /tmp/zmosh-059-out/bin/zmosh run everudp-zmosh \
        /usr/bin/python3 -u "$NET/echo1.py" >/dev/null
    sleep 0.3
    $IP netns exec "$SERVER_NS" /usr/bin/env \
        -u ZMX_SESSION TERM=xterm-256color ZMX_DIR="$zdir" \
        /tmp/zmosh-059-out/bin/zmosh serve everudp-zmosh \
        >"$TMP/zmosh-connect.txt" 2>"$TMP/zmosh-serve.err" &
    local zserve=$!
    for _ in $(seq 1 50); do
        grep -q '^ZMX_CONNECT' "$TMP/zmosh-connect.txt" && break
        sleep 0.1
    done
    read -r _ _ zport zkey <"$TMP/zmosh-connect.txt"
    [[ -n $zkey ]] || { cat "$TMP/zmosh-serve.err" >&2; exit 1; }
    local samples
    samples=$($IP netns exec "$CLIENT_NS" /tmp/zmosh-bench 10.241.0.1 "$zport" "$zkey" "$TRIALS" 100)
    kill "$zserve" 2>/dev/null || true
    python3 - "$out" "$samples" "$TRIALS" <<'PY'
import json, sys
out, raw, trials = sys.argv[1], sys.argv[2], int(sys.argv[3])
samples = json.loads(raw)
ordered = sorted(value for value in samples if value > 0)
def pick(q):
    return ordered[round((len(ordered) - 1) * q)] if ordered else 0
json.dump({
    "summary": {
        "trials": trials,
        "nonzero": len(ordered),
        "median_us": pick(0.5),
        "p95_us": pick(0.95),
        "max_us": ordered[-1] if ordered else 0,
    },
    "samples": samples,
}, open(out, "w"))
print(open(out).read())
PY
    $IP netns exec "$SERVER_NS" /usr/bin/env -u ZMX_SESSION ZMX_DIR="$zdir" \
        /tmp/zmosh-059-out/bin/zmosh kill everudp-zmosh >/dev/null 2>&1 || true
}

run_ssh_control ssh
run_ssh_control everssh || true
run_ssh_strace
cp "$TMP/everssh.strace" "$OUTDIR/everssh.strace" 2>/dev/null || true
run_mosh
run_zmosh
run_everudp_udp on
run_everudp_udp off
run_everudp_quic on
run_everudp_quic off

python3 - "$OUTDIR" "$LOSS" <<'PY'
import glob, json, sys
outdir, loss = sys.argv[1], sys.argv[2]
for path in sorted(glob.glob(f"{outdir}/*loss{loss}.json")):
    try:
        data = json.load(open(path))
    except Exception:
        continue
    summary = data.get("summary") or {
        "median_us": data.get("median_us"),
        "p95_us": data.get("p95_us"),
    }
    print(path, json.dumps(summary))
PY
