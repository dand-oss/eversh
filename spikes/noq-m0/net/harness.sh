#!/usr/bin/env bash
# M0 harness: isolated unprivileged sshd on a high loopback port, temporary
# host/client keys under a temp dir, never in the repository.
# Usage: source net/harness.sh   (exposes $SSHD_PORT, $HDIR, spike_start/sshd_stop)
set -euo pipefail

SSHD=/usr/sbin/sshd
BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/debug/noq-m0"

harness_start() {
    HDIR="$(mktemp -d /tmp/noq-m0-harness.XXXXXX)"
    chmod 700 "$HDIR"
    SSHD_PORT=$(python3 - <<'EOF'
import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()
EOF
)
    # Temporary host + client keys.
    ssh-keygen -q -t ed25519 -N '' -f "$HDIR/host_key"
    ssh-keygen -q -t ed25519 -N '' -f "$HDIR/client_key"
    cat > "$HDIR/sshd_config" <<EOF
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $HDIR/host_key
PidFile $HDIR/sshd.pid
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
PermitOpen none
PermitListen none
StrictModes no
AuthorizedKeysFile $HDIR/authorized_keys
LogLevel VERBOSE
EOF
    cat "$HDIR/client_key.pub" > "$HDIR/authorized_keys"
    "$SSHD" -f "$HDIR/sshd_config" -E "$HDIR/sshd.log"
    # Pin the ephemeral host key so StrictHostKeyChecking=yes works.
    ssh-keyscan -p "$SSHD_PORT" -t ed25519 127.0.0.1 > "$HDIR/known_hosts" 2>/dev/null
    for _ in $(seq 1 50); do
        if (exec 3<>/dev/tcp/127.0.0.1/$SSHD_PORT) 2>/dev/null; then exec 3>&-; break; fi
        sleep 0.1
    done
}

harness_stop() {
    if [[ -f "${HDIR:-}/sshd.pid" ]]; then kill "$(<"$HDIR/sshd.pid")" 2>/dev/null || true; fi
    # The detached one-shot server children exit by lease; force-clean any
    # stragglers named after our binary.
    pkill -f "noq-m0 server" 2>/dev/null || true
    rm -rf "${HDIR:-/tmp/noq-m0-harness.nonexistent}"
}

# SSH bootstrap: run the bootstrap-parent over real system ssh into the
# isolated sshd, capturing the single record line on stdout.
# $1 = authorized loopback target port (goes over the SSH channel to the
# bootstrap parent's stdin; never argv/env).
ssh_bootstrap() {
    local target_port="$1"
    printf '%s\n' "$target_port" | ssh \
        -i "$HDIR/client_key" \
        -o UserKnownHostsFile="$HDIR/known_hosts" \
        -o StrictHostKeyChecking=yes \
        -o User="$(id -un)" \
        -o ProxyCommand=none \
        -o ClearAllForwardings=yes \
        -o ForwardX11=no \
        -o RequestTTY=no \
        -p "$SSHD_PORT" \
        127.0.0.1 "$BIN bootstrap-parent"
}
