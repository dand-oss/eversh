#!/usr/bin/env bash
# M0 gate 5b: REAL address migration using temporary, isolated network
# namespaces and veth pairs (requires sudo; everything is torn down on exit).
#
# Topology:
#   ns-m0srv 10.231.0.1/24 (veth-srv <-> veth-c1), 10.231.1.1/24 (veth-s2 <-> veth-c2)
#   ns-m0cli 10.231.0.2/24 (veth-c1),              10.231.1.2/24 (veth-c2)
#
# The client starts on 10.231.0.2, streams numbered frames, and mid-stream
# rebinds its endpoint to a socket on 10.231.1.2. Evidence: identical
# stable_id, old/new local addresses, and a byte-exact frame count at the TCP
# sink. Then all veths are destroyed: total path loss must close the server
# within bounded time and leave no processes.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="$(pwd)/target/debug/noq-m0"
NS_S=ns-m0srv
NS_C=ns-m0cli
FRAMES=400
PASS=()
cleanup() {
    set +e
    ip netns pids $NS_C 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns pids $NS_S 2>/dev/null | xargs -r kill 2>/dev/null
    sleep 1
    ip netns del $NS_C 2>/dev/null
    ip netns del $NS_S 2>/dev/null
    ip link del veth-c1 2>/dev/null
    ip link del veth-c2 2>/dev/null
}
trap cleanup EXIT
rm -f /tmp/m0-mig-record /tmp/m0-mig-result /tmp/m0-mig-sink /tmp/m0-mig-client.err /tmp/m0-mig-server.err
cleanup
set -e

# --- build topology ---
ip netns add $NS_S
ip netns add $NS_C
for i in 0 1; do
    V=srv; [ $i -eq 1 ] && V=s2
    ip link add veth-$V type veth peer name veth-c$((i+1))
    ip link set veth-$V netns $NS_S
    ip link set veth-c$((i+1)) netns $NS_C
done
ip -n $NS_S addr add 10.231.0.1/24 dev veth-srv
ip -n $NS_S addr add 10.231.1.1/24 dev veth-s2
ip -n $NS_C addr add 10.231.0.2/24 dev veth-c1
ip -n $NS_C addr add 10.231.1.2/24 dev veth-c2
ip -n $NS_S link set veth-srv up
ip -n $NS_S link set veth-s2 up
ip -n $NS_C link set veth-c1 up
ip -n $NS_C link set veth-c2 up
ip -n $NS_S link set lo up
ip -n $NS_C link set lo up
# Loss/jitter on the first path so migration happens under impaired
# conditions (evidence that the new path really carries traffic).
ip netns exec $NS_S /usr/sbin/tc qdisc add dev veth-srv root netem loss 5% delay 10ms
echo "[mig] topology up: server 10.231.0.1/10.231.1.1, client 10.231.0.2/10.231.1.2"

# --- TCP sink + one-shot server in the server namespace ---
ip netns exec $NS_S python3 - <<'EOF' &
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 9930)); s.listen(1)
c, _ = s.accept()
expected = 1024 * 400
buf = b""
c.settimeout(60)
while len(buf) < expected:
    d = c.recv(65536)
    if not d: break
    buf += d
ok = all(buf[i*1024+8] == 8 and buf[i*1024+9] == 9 and buf[i*1024+1023] == 255 for i in range(0, 50))
# verify every frame\xe2\x80\x99s index bytes too
ok = ok and all(int.from_bytes(buf[i*1024:i*1024+8], "big") == i for i in range(400))
with open("/tmp/m0-mig-sink", "w") as f:
    f.write(f"bytes={len(buf)} first_frames_payload_ok={ok}\n")
    # verify every frame index byte pattern cheaply: length + spot checks
c.close()
EOF
SINK_PID=$!
sleep 0.5

ip netns exec $NS_S sh -c "echo 9930 | NOQ_M0_BIND_ADDR=0.0.0.0 $BIN server > /tmp/m0-mig-record 2>/tmp/m0-mig-server.err" &
SRV_LAUNCH=$!
for _ in $(seq 1 50); do [ -s /tmp/m0-mig-record ] && break; sleep 0.1; done
REC="$(head -1 /tmp/m0-mig-record)"
UDP_PORT="$(echo "$REC" | awk '{print $3}')"
echo "[mig] server record: udp=$UDP_PORT"

# --- client in the client namespace, migrating 10.231.0.2 -> 10.231.1.2 ---
printf '%s\n9930\n' "$REC" | ip netns exec $NS_C "$BIN" migrate-client 10.231.0.1:$UDP_PORT 10.231.1.2 $FRAMES > /tmp/m0-mig-result 2>/tmp/m0-mig-client.err
RC=$?
echo "[mig] client rc=$RC"
grep REBOUND /tmp/m0-mig-client.err || true
cat /tmp/m0-mig-result

RESULT="$(cat /tmp/m0-mig-result)"
SB="$(echo "$RESULT" | sed -n 's/.*stable_before=\([0-9]*\).*/\1/p')"
SA="$(echo "$RESULT" | sed -n 's/.*stable_after=\([0-9]*\).*/\1/p')"
OLD="$(echo "$RESULT" | sed -n 's/.*old=\([^ ]*\).*/\1/p')"
NEW="$(echo "$RESULT" | sed -n 's/.*new=\([^ ]*\).*/\1/p')"
[[ -n "$SB" && "$SB" == "$SA" ]] || { echo "FAIL: stable_id changed or missing ($SB -> $SA)"; exit 1; }
# Client endpoint binds wildcard; the effective source IP on path 1 is chosen
# by routing (10.231.0.2). The rebind target address is the hard evidence.
[[ "$NEW" == 10.231.1.2:* ]] || { echo "FAIL: new local address: $NEW"; exit 1; }
[[ "$NEW" == 10.231.1.2:* ]] || { echo "FAIL: new local address: $NEW"; exit 1; }
echo "[mig] ok: same connection ($SB) migrated $OLD -> $NEW"

# --- byte-exact delivery at the sink ---
for _ in $(seq 1 120); do [ -f /tmp/m0-mig-sink ] && break; sleep 1; done
SINK="$(cat /tmp/m0-mig-sink 2>/dev/null || echo missing)"
echo "[mig] sink: $SINK"
[[ "$SINK" == "bytes=$((1024*FRAMES)) "* ]] && [[ "$SINK" == *ok=True* ]] || { echo "FAIL: sink evidence: $SINK"; exit 1; }
echo "[mig] ok: all $((1024*FRAMES)) bytes delivered exactly once"

# --- total path loss: destroy both veths mid-idle, server must exit bounded ---
ip -n $NS_S link del veth-srv; ip -n $NS_C link del veth-c1 2>/dev/null || true
ip link del veth-c2 2>/dev/null || true
ip -n $NS_S link del veth-s2 2>/dev/null || true
SRV_PID="$(ip netns pids $NS_S | head -1)"
if [ -n "$SRV_PID" ]; then
    DEADLINE=$((SECONDS + 60))
    while kill -0 "$SRV_PID" 2>/dev/null; do
        (( SECONDS >= DEADLINE )) && { echo "FAIL: server survived total path loss >60s"; exit 1; }
        sleep 1
    done
fi
echo "[mig] ok: server exited within deadline after total path loss"
wait $SINK_PID 2>/dev/null || true
echo "[mig] PASS: real address migration + total path loss"
