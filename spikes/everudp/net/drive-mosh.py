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
    events = []
    for _ in range(int(trials)):
        events.append({"t": time.time_ns(), "kind": "key"})
        os.write(master, b"k")
        deadline = time.time() + gap
        while time.time() < deadline:
            readable, _, _ = select.select([master], [], [], 0)
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
