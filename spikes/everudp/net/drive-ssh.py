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


def wait_for(stdout, needle, seconds):
    buffer = b""
    deadline = time.time() + seconds
    while time.time() < deadline:
        readable, _, _ = select.select([stdout], [], [], 0)
        if not readable:
            continue
        data = os.read(stdout, 4096)
        if not data:
            return False
        buffer += data
        if needle in buffer:
            return True
    return False


def benchmark_barrier(proc):
    ready = os.environ.get("EVERUDP_BENCH_READY_FILE")
    go = os.environ.get("EVERUDP_BENCH_GO_FILE")
    if ready is None and go is None:
        return True
    if ready is None or go is None:
        raise RuntimeError("benchmark barrier requires both ready and go files")
    with open(ready, "w", encoding="utf-8") as stream:
        stream.write("ready\n")
    deadline = time.time() + 60
    while time.time() < deadline:
        if os.path.exists(go):
            return True
        if proc.poll() is not None:
            return False
        time.sleep(0.01)
    return False


def main() -> int:
    output, trials = sys.argv[1], int(sys.argv[2])
    gap = float(sys.argv[3]) if len(sys.argv) > 3 else 0.15
    trial_timeout = float(os.environ.get("EVERUDP_TRIAL_TIMEOUT_SECONDS", "10"))
    ready_timeout = float(os.environ.get("EVERUDP_READY_TIMEOUT_SECONDS", "60"))
    if trial_timeout <= 0 or ready_timeout <= 0:
        raise SystemExit("driver timeout values must be positive")
    command = sys.argv[4:]
    typescript = output + ".typescript"
    quoted = " ".join("'" + part.replace("'", "'\"'\"'") + "'" for part in command)
    proc = subprocess.Popen(
        ["/usr/bin/script", "-qefc", quoted, typescript],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    # The remote banner proves the session is established AND remote output
    # flows; only then do single-keystroke trials measure the network path
    # rather than the local canonical-mode echo.
    if not wait_for(proc.stdout.fileno(), b"EVERUDP_READY", ready_timeout):
        proc.kill()
        proc.wait()
        print("ssh remote echo never became ready", file=sys.stderr)
        return 1
    if not benchmark_barrier(proc):
        proc.kill()
        proc.wait()
        print("ssh benchmark barrier failed", file=sys.stderr)
        return 1
    time.sleep(0.2)
    events = []
    try:
        for _ in range(trials):
            t0 = time.time_ns()
            os.write(proc.stdin.fileno(), b"k")
            echo_t = None
            deadline = time.time() + trial_timeout
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
