#!/usr/bin/env bash
# M0 gate 6: real OpenSSH end-to-end through the spike ProxyCommand into the
# isolated sshd. Covers: remote command, exit code propagation, binary-safe
# transfer, SFTP, SCP, local forwarding, remote forwarding, and stdout purity.
set -euo pipefail
cd "$(dirname "$0")/.."
source net/harness.sh

harness_start
trap 'cp -r $HDIR /tmp/m0-e2e-keep 2>/dev/null; harness_stop' EXIT

SSH_OPTS=(
    -F none
    -i "$HDIR/client_key"
    -o UserKnownHostsFile="$HDIR/known_hosts"
    -o StrictHostKeyChecking=yes
    -o ClearAllForwardings=yes
    -o ForwardX11=no
    -o BatchMode=yes
    -o ProxyCommand="$BIN proxy %n %p -i $HDIR/client_key -o UserKnownHostsFile=$HDIR/known_hosts -o StrictHostKeyChecking=yes -o ClearAllForwardings=yes -o ForwardX11=no -F none"
    -p "$SSHD_PORT"
    127.0.0.1
)

echo "[e2e] remote command"
OUT=$(ssh "${SSH_OPTS[@]}" 'echo hello-from-quic' 2>"$HDIR/e2e.stderr")
[[ "$OUT" == "hello-from-quic" ]] || { echo "FAIL: got '$OUT'"; cp -r "$HDIR" /tmp/m0-e2e-keep; cat "$HDIR/e2e.stderr"; exit 1; }

echo "[e2e] exit code propagation"
ssh "${SSH_OPTS[@]}" 'exit 42' 2>/dev/null && { echo "FAIL: expected exit 42"; exit 1; }
RC=0; ssh "${SSH_OPTS[@]}" 'exit 42' 2>/dev/null || RC=$?
[[ "$RC" == 42 ]] || { echo "FAIL: exit propagation got $RC"; exit 1; }

echo "[e2e] arbitrary binary stream (od round-trip)"
head -c 65536 /dev/urandom > "$HDIR/random.bin"
ssh "${SSH_OPTS[@]}" 'cat' < "$HDIR/random.bin" > "$HDIR/random.out" 2>>"$HDIR/e2e.stderr"
cmp "$HDIR/random.bin" "$HDIR/random.out" || { echo "FAIL: binary corruption"; exit 1; }

echo "[e2e] SFTP batch"
printf 'put %s/random.bin remote.bin\nls -l remote.bin\nrm remote.bin\n' "$HDIR" > "$HDIR/sftp.cmds"
sftp -b "$HDIR/sftp.cmds" -P "$SSHD_PORT" -i "$HDIR/client_key" \
    -o UserKnownHostsFile="$HDIR/known_hosts" -o StrictHostKeyChecking=yes -o BatchMode=yes \
    -o ProxyCommand="$BIN proxy %n %p -i $HDIR/client_key -o UserKnownHostsFile=$HDIR/known_hosts -o StrictHostKeyChecking=yes -o ClearAllForwardings=yes -o ForwardX11=no -F none" 127.0.0.1 >/dev/null 2>>"$HDIR/e2e.stderr" \
    || { echo "FAIL: sftp"; cat "$HDIR/e2e.stderr"; exit 1; }

echo "[e2e] SCP"
echo "scp-over-quic" > "$HDIR/scp.txt"
scp -P "$SSHD_PORT" -i "$HDIR/client_key" -O \
    -o UserKnownHostsFile="$HDIR/known_hosts" -o StrictHostKeyChecking=yes -o BatchMode=yes \
    -o ProxyCommand="$BIN proxy %n %p -i $HDIR/client_key -o UserKnownHostsFile=$HDIR/known_hosts -o StrictHostKeyChecking=yes -o ClearAllForwardings=yes -o ForwardX11=no -F none" "$HDIR/scp.txt" 127.0.0.1:"$HDIR/scp.remote" \
    2>>"$HDIR/e2e.stderr" || { echo "FAIL: scp"; cat "$HDIR/e2e.stderr"; exit 1; }
[[ "$(cat "$HDIR/scp.remote")" == "scp-over-quic" ]] || { echo "FAIL: scp content"; exit 1; }

echo "[e2e] local forwarding"
# Forwarding cases must NOT pass ClearAllForwardings (it disables -L/-R).
FWD_OPTS=(
    -F none
    -i "$HDIR/client_key"
    -o UserKnownHostsFile="$HDIR/known_hosts"
    -o StrictHostKeyChecking=yes
    -o BatchMode=yes
    -o ForwardX11=no
    -o ProxyCommand="$BIN proxy %n %p -i $HDIR/client_key -o UserKnownHostsFile=$HDIR/known_hosts -o StrictHostKeyChecking=yes -o ClearAllForwardings=yes -o ForwardX11=no -F none"
    -p "$SSHD_PORT"
    127.0.0.1
)
LF_PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
ssh "${FWD_OPTS[@]}" -N -L "$LF_PORT:127.0.0.1:$SSHD_PORT" &
LF_PID=$!
sleep 1.5
LF_OUT=$(timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$LF_PORT && head -c 30 <&3" 2>/dev/null || true)
kill $LF_PID 2>/dev/null || true; wait $LF_PID 2>/dev/null || true
[[ -n "$LF_OUT" ]] || { echo "FAIL: local forwarding (banner: '$LF_OUT')"; exit 1; }
echo "[e2e]   (tunnel reached sshd banner: $(printf '%s' "$LF_OUT" | head -c 20)...)"

echo "[e2e] remote forwarding"
RF_PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
( sleep 2; timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$RF_PORT && head -c 30 <&3" > "$HDIR/rf.out" 2>/dev/null ) &
RF_CLI=$!
ssh "${FWD_OPTS[@]}" -N -R "$RF_PORT:127.0.0.1:$SSHD_PORT" &
RF_PID=$!
sleep 2
sleep 4
kill $RF_PID 2>/dev/null || true; wait $RF_PID 2>/dev/null || true
wait $RF_CLI 2>/dev/null || true
grep -q SSH "$HDIR/rf.out" 2>/dev/null || { echo "FAIL: remote forwarding"; cat "$HDIR/rf.out" 2>/dev/null; exit 1; }

echo "[e2e] clean exit on connection close (no hanging processes)"
# One-shot servers must exit within lease + idle/drain deadlines (bounded).
DEADLINE=$((SECONDS + 75))
while pgrep -f "debug/noq-m0 server" >/dev/null 2>&1; do
    if (( SECONDS >= DEADLINE )); then
        pgrep -af "debug/noq-m0 server"
        echo "FAIL: surviving server processes after 75s"
        exit 1
    fi
    sleep 1
done
pgrep -f "debug/noq-m0 proxy" >/dev/null 2>&1 && { echo "FAIL: surviving proxy"; exit 1; } || true

echo "[e2e] PASS: OpenSSH/SCP/SFTP/forwarding compatibility"
