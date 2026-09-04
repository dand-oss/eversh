#!/usr/bin/env bash
# everssh-v2 and plain-OpenSSH controls through an isolated sshd.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
NET=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
OUT=${1:?output prefix}
TRIALS=${2:?trials}
MODE=${3:?ssh|everssh}
TMP=$(mktemp -d)
HOST_ADDR=${EVERUDP_SSH_ADDR:-192.168.1.158}
PORT=$(python3 -c "import socket; s=socket.socket(); s.bind((\"$HOST_ADDR\",0)); print(s.getsockname()[1]); s.close()")
ssh-keygen -q -t ed25519 -N '' -f "$TMP/host" >/dev/null 2>&1
ssh-keygen -q -t ed25519 -N '' -f "$TMP/client" >/dev/null 2>&1
cp "$TMP/client.pub" "$TMP/authorized_keys"
cat >"$TMP/sshd_config" <<EOF
Port $PORT
ListenAddress $HOST_ADDR
HostKey $TMP/host
AuthorizedKeysFile $TMP/authorized_keys
PermitRootLogin no
AuthenticationMethods publickey
PasswordAuthentication no
UsePAM no
StrictModes no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
UseDNS no
PermitUserEnvironment no
AcceptEnv EVERSSH_DEBUG_SERVER
Subsystem sftp internal-sftp
LogLevel ERROR
EOF
/usr/sbin/sshd -D -e -f "$TMP/sshd_config" 2>"$TMP/sshd.err" &
SSHD_PID=$!
cleanup() {
    kill -KILL "$SSHD_PID" 2>/dev/null || :
    rm -rf -- "$TMP"
}
trap cleanup EXIT
for _ in $(seq 1 50); do
    (exec 3<>/dev/tcp/$HOST_ADDR/$PORT) 2>/dev/null && break
    sleep 0.1
done
ssh-keyscan -T 2 -p "$PORT" "$HOST_ADDR" >"$TMP/known" 2>/dev/null
cat >"$TMP/client_config" <<EOF
Host $HOST_ADDR
    HostName $HOST_ADDR
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
SSH_OPTS=(
    -F "$TMP/client_config"
    -o BatchMode=yes
    -o UserKnownHostsFile="$TMP/known"
    -o GlobalKnownHostsFile=/dev/null
    -o StrictHostKeyChecking=yes
    -o IdentitiesOnly=yes
    -o IdentityFile="$TMP/client"
    -o ClearAllForwardings=yes
    -o ServerAliveInterval=60
    -o ServerAliveCountMax=12
    -tt
)
if [[ $MODE == everssh ]]; then
    EVERSCH="$ROOT/target/release/everssh"
    [[ -x $EVERSCH ]] || EVERSCH="$ROOT/target/debug/everssh"
    EVERSUPERVISOR="$ROOT/target/release/eversh"
    [[ -x $EVERSUPERVISOR ]] || EVERSUPERVISOR="$ROOT/target/debug/eversh"
    [[ -x $EVERSCH ]] || { echo "no everssh binary" >&2; exit 1; }
    [[ -x $EVERSUPERVISOR ]] || { echo "no combined eversh binary" >&2; exit 1; }
    STATUS="$TMP/status"
    SSH_OPTS=(-o "ProxyCommand=$EVERSCH ssh-proxy $HOST_ADDR $PORT --remote-eversh $EVERSUPERVISOR --ssh-option -F$TMP/client_config --status-file $STATUS" "${SSH_OPTS[@]}")
fi
python3 "$NET/drive-ssh.py" "$OUT" "$TRIALS" 0.15 \
    ssh "${SSH_OPTS[@]}" -p "$PORT" "$HOST_ADDR" \
    /bin/sh -c "stty raw -echo; exec /usr/bin/python3 -u '$NET/echo1.py'"
python3 - "$OUT" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    events = json.load(f)
samples = [(e["echo_t"] - e["t"]) // 1000 for e in events if e.get("echo_t")]
samples.sort()
def pick(q):
    return samples[round((len(samples)-1)*q)] if samples else 0
json.dump({
    "summary": {
        "trials": len(events),
        "nonzero": len(samples),
        "median_us": pick(0.5),
        "p95_us": pick(0.95),
        "max_us": samples[-1] if samples else 0,
    },
    "samples": samples,
}, open(sys.argv[1], "w"))
print(open(sys.argv[1]).read())
PY
