#!/usr/bin/env python3
"""Drive mosh-client under a PTY and record precise key-injection times."""
import json
import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import time


def main() -> int:
    port, key, trials, output = sys.argv[1:5]
    if key == "-":
        key = os.environ.get("MOSH_BENCH_KEY", "")
    if not key:
        raise SystemExit("missing Mosh benchmark key")
    gap = float(sys.argv[5]) if len(sys.argv) > 5 else 0.1
    host = sys.argv[6] if len(sys.argv) > 6 else "127.0.0.1"
    pid, master = pty.fork()
    if pid == 0:
        os.environ["MOSH_KEY"] = key
        os.environ["TERM"] = "xterm-256color"
        os.execvp("mosh-client", ["mosh-client", host, port])
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    deadline = time.time() + 5
    ready = False
    while time.time() < deadline:
        readable, _, _ = select.select([master], [], [], 0.1)
        if readable:
            try:
                data = os.read(master, 4096)
            except OSError:
                break
            if data:
                ready = True
                break
    if not ready:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        print("mosh-client never became ready", file=sys.stderr)
        return 1
    time.sleep(0.5)
    ready_file = os.environ.get("EVERUDP_BENCH_READY_FILE")
    go_file = os.environ.get("EVERUDP_BENCH_GO_FILE")
    if (ready_file is None) != (go_file is None):
        raise RuntimeError("benchmark barrier requires both ready and go files")
    if ready_file is not None:
        with open(ready_file, "w", encoding="utf-8") as stream:
            stream.write("ready\n")
        deadline = time.time() + 60
        while not os.path.exists(go_file):
            if time.time() >= deadline:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                print("mosh benchmark barrier timed out", file=sys.stderr)
                return 1
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                print("mosh client exited at benchmark barrier", file=sys.stderr)
                return 1
            time.sleep(0.01)
    events = []
    for _ in range(int(trials)):
        events.append({"t": time.time_ns(), "kind": "key"})
        os.write(master, b"k")
        deadline = time.time() + gap
        while time.time() < deadline:
            readable, _, _ = select.select(
                [master], [], [], min(0.01, max(0, deadline - time.time()))
            )
            if not readable:
                continue
            try:
                os.read(master, 4096)
            except OSError:
                break
    # Keep the client alive long enough to transmit the final terminal-state
    # update and receive its authoritative reply. The packet capture, not this
    # drain, supplies the latency timestamps.
    deadline = time.time() + max(1.0, gap * 2)
    while time.time() < deadline:
        readable, _, _ = select.select([master], [], [], 0.05)
        if not readable:
            continue
        try:
            os.read(master, 4096)
        except OSError:
            break
    os.kill(pid, signal.SIGTERM)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(events, handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
