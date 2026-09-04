#!/usr/bin/env python3
"""Drive an ssh session under `script` and timestamp authoritative echoes."""
import json
import os
import select
import subprocess
import sys
import time


def drain(stdout, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        readable, _, _ = select.select([stdout], [], [], 0)
        if not readable:
            continue
        data = os.read(stdout, 4096)
        if data:
            return True
    return False


def main() -> int:
    output, trials = sys.argv[1], int(sys.argv[2])
    gap = float(sys.argv[3]) if len(sys.argv) > 3 else 0.15
    command = sys.argv[4:]
    typescript = output + ".typescript"
    quoted = " ".join("'" + part.replace("'", "'\"'\"'") + "'" for part in command)
    proc = subprocess.Popen(
        ["/usr/bin/script", "-qefc", quoted, typescript],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    # Remote `stty raw -echo` may print settings before the reader starts;
    # a newline proves the remote echo path is live.
    time.sleep(2.0)
    try:
        os.write(proc.stdin.fileno(), b"\n")
    except BrokenPipeError:
        pass
    if not drain(proc.stdout.fileno(), 5):
        proc.kill()
        proc.wait()
        print("ssh remote echo never became ready", file=sys.stderr)
        return 1
    time.sleep(0.2)
    events = []
    try:
        for _ in range(trials):
            t0 = time.time_ns()
            os.write(proc.stdin.fileno(), b"k")
            echo_t = None
            deadline = time.time() + 2
            while time.time() < deadline:
                readable, _, _ = select.select([proc.stdout.fileno()], [], [], 0)
                if not readable:
                    continue
                data = os.read(proc.stdout.fileno(), 4096)
                if echo_t is None and b"k" in data:
                    echo_t = time.time_ns()
                if echo_t is not None:
                    break
            events.append({"t": t0, "kind": "key", "echo_t": echo_t or 0})
            deadline = time.time() + gap
            while time.time() < deadline:
                readable, _, _ = select.select([proc.stdout.fileno()], [], [], 0)
                if not readable:
                    continue
                os.read(proc.stdout.fileno(), 4096)
    except BrokenPipeError:
        pass
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(events, handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
