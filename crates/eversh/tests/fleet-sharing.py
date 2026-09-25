#!/usr/bin/env python3
"""Disposable real-SSH shared-writer deployment canary; never attaches user sessions."""
import argparse
import errno
import fcntl
import json
import os
import pty
import re
import select
import signal
import socket
import struct
import subprocess
import tempfile
import termios
import time
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--binary", default="/home/appsmith/.local/bin/eversh")
    parser.add_argument("--remote-binary", default="/home/appsmith/.local/bin/eversh")
    args = parser.parse_args()
    version = subprocess.check_output([args.binary, "--version"], text=True).strip()
    if version != "eversh 0.2.5":
        raise RuntimeError(f"unexpected canary client version: {version}")
    name = "shared-canary-" + uuid.uuid4().hex[:16]
    clients = []
    common = [args.binary, "--remote-eversh", args.remote_binary]
    program = (
        "n=0; while IFS= read -r line; do "
        "[ \"$line\" != quit ] || exit 0; n=$((n+1)); "
        "printf 'CANARY:%s:%s:%s\\n' \"$$\" \"$n\" \"$line\"; done"
    )

    def spawn(first=False):
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        error = tempfile.TemporaryFile()
        command = common + (
            ["connect", args.host, "--session", name] if first
            else ["attach", args.host, name]
        )
        command += ["--transport", "everudp"]
        if first:
            command += ["--", "/bin/sh", "-c", program]

        def setup():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=error,
                                   preexec_fn=setup, close_fds=True)
        os.close(slave)
        os.set_blocking(master, False)
        client = {"process": process, "master": master, "output": bytearray(), "error": error}
        clients.append(client)
        return client

    def pump():
        ready, _, _ = select.select([c["master"] for c in clients], [], [], 0.02)
        for c in clients:
            if c["master"] not in ready:
                continue
            try:
                data = os.read(c["master"], 65536)
            except OSError as error:
                if error.errno in (errno.EIO, errno.EAGAIN):
                    continue
                raise
            c["output"].extend(data)
            if len(c["output"]) > 262144:
                raise RuntimeError("unexpected canary output volume")

    def wait_marker(client, count, word, pid=None):
        pattern = re.compile(
            rb"CANARY:([0-9]+):" + str(count).encode() + b":" + word.encode() + rb"\r?\n"
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            pump()
            matches = pattern.findall(client["output"])
            if matches:
                if len(matches) != 1 or (pid is not None and matches[0] != pid):
                    raise RuntimeError("duplicate response or changed shell PID")
                return matches[0]
            if client["process"].poll() is not None:
                client["error"].seek(0)
                diagnostic = client["error"].read(2048).decode(errors="replace")
                raise RuntimeError(f"canary client exited before response: {diagnostic}")
        raise TimeoutError(f"missing canary response {count}:{word}")

    def send(client, value):
        os.write(client["master"], value.encode() + b"\n")

    try:
        first = spawn(True)
        send(first, "first")
        pid = wait_marker(first, 1, "first")
        second = spawn()
        send(second, "second")
        wait_marker(second, 2, "second", pid)
        wait_marker(first, 2, "second", pid)
        send(first, "both")
        wait_marker(first, 3, "both", pid)
        wait_marker(second, 3, "both", pid)
        first["process"].send_signal(signal.SIGTERM)
        first["process"].wait(timeout=10)
        send(second, "survivor")
        wait_marker(second, 4, "survivor", pid)
        third = spawn()
        send(third, "reattach")
        wait_marker(third, 5, "reattach", pid)
        wait_marker(second, 5, "reattach", pid)
        send(second, "quit")
        for client in (second, third):
            if client["process"].wait(timeout=15) != 0:
                raise RuntimeError("common child exit was not clean")
        print(json.dumps({"verdict": "PASS", "client_host": socket.gethostname(),
                          "server": args.host, "version": version,
                          "session": name, "unchanged_shell_pid": int(pid),
                          "writers": 2, "local_detach_and_new_attach": True}))
    finally:
        for client in clients:
            process = client["process"]
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            os.close(client["master"])
            client["error"].close()
        # This exact UUID-named session belongs only to this canary.
        subprocess.run(common + ["kill", args.host, name],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15, check=False)


if __name__ == "__main__":
    main()
