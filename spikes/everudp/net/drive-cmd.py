#!/usr/bin/env python3
"""Run a command under a PTY, inject timed keystrokes, and record PTY echoes."""
import json
import fcntl
import os
import pty
import select
import signal
import termios
import struct
import sys
import termios
import time


def main() -> int:
    output = sys.argv[1]
    trials = int(sys.argv[2])
    gap = float(sys.argv[3]) if len(sys.argv) > 3 else 0.1
    command = sys.argv[4:]
    pid, master = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.execvp(command[0], command)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    attrs = termios.tcgetattr(master)
    attrs[3] &= ~termios.ECHO
    termios.tcsetattr(master, termios.TCSANOW, attrs)
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
        print("command never became ready", file=sys.stderr)
        return 1
    time.sleep(0.5)
    events = []
    for _ in range(trials):
        t0 = time.time_ns()
        os.write(master, b"k")
        echo_t = None
        deadline = time.time() + 2
        while time.time() < deadline:
            readable, _, _ = select.select([master], [], [], 0)
            if not readable:
                continue
            try:
                data = os.read(master, 4096)
            except OSError:
                break
            if echo_t is None and b"k" in data:
                echo_t = time.time_ns()
            if echo_t is not None:
                break
        events.append({"t": t0, "kind": "key", "echo_t": echo_t or 0})
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
