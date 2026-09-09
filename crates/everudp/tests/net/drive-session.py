#!/usr/bin/env python3
"""Drive one real everudp client through a pseudoterminal.

The surrounding root netns gate owns network changes. This process owns only
the terminal edge and a small filesystem rendezvous with that gate.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time


GAP_NOTICE = b"everudp: output skipped during network outage"
MAX_TRANSCRIPT = 16 * 1024 * 1024
REMOTE_SCRIPT = r'''
set -eu
control=$1
mode=$2
label=$3
(
    while [ ! -f "$control/go" ]; do sleep 0.02; done
    case "$mode" in
        outage|pause|cancel)
            printf 'ASYNC:%s\n' "$label"
            ;;
        overrun)
            /usr/bin/head -c 6291456 /dev/zero
            : >"$control/burst-done"
            ;;
        stream)
            ;;
        *)
            exit 97
            ;;
    esac
) &
producer=$!
while IFS= read -r line; do
    printf 'RX:%s\n' "$line"
    if [ "$line" = quit ]; then
        wait "$producer"
        exit 0
    fi
done
wait "$producer"
'''


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--remote-program", required=True)
    parser.add_argument("--ssh-config", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument(
        "--mode",
        choices=("stream", "outage", "overrun", "pause", "cancel"),
        required=True,
    )
    parser.add_argument("--control-dir", type=Path, required=True)
    parser.add_argument("--status", type=Path, required=True)
    parser.add_argument("--transcript", type=Path, required=True)
    parser.add_argument("--stderr", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--messages", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=2400.0)
    parser.add_argument("--hold-at-driver-done", action="store_true")
    return parser.parse_args()


class Driver:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.transcript = bytearray()
        self.started = time.monotonic()
        self.master = -1
        self.process: subprocess.Popen[bytes] | None = None
        self.original_termios: list[object] | None = None

    def spawn(self) -> None:
        master, slave = pty.openpty()
        self.original_termios = termios.tcgetattr(slave)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        flags = fcntl.fcntl(master, fcntl.F_GETFL)
        fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        command = [
            self.args.binary,
            "--remote-program",
            self.args.remote_program,
            "connect",
            self.args.destination,
            "--session",
            self.args.session,
            "--ssh-option",
            f"-F{self.args.ssh_config}",
            "--status-file",
            str(self.args.status),
            "--",
            "/bin/sh",
            "-c",
            REMOTE_SCRIPT,
            "everudp-net-child",
            str(self.args.control_dir),
            self.args.mode,
            self.args.session,
        ]

        def child_setup() -> None:
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        stderr = self.args.stderr.open("wb")
        self.process = subprocess.Popen(
            command,
            stdin=slave,
            stdout=slave,
            stderr=stderr,
            close_fds=True,
            preexec_fn=child_setup,
        )
        stderr.close()
        os.close(slave)
        self.master = master
        (self.args.control_dir / "client-pid").write_text(
            f"{self.process.pid}\n", encoding="ascii"
        )

    def pump(self, wait: float = 0.02) -> None:
        if self.master < 0:
            return
        readable, _, _ = select.select([self.master], [], [], wait)
        if not readable:
            return
        while True:
            try:
                chunk = os.read(self.master, 65536)
            except BlockingIOError:
                return
            except OSError as error:
                if error.errno == 5:  # Linux PTY EOF.
                    return
                raise
            if not chunk:
                return
            self.transcript.extend(chunk)
            if len(self.transcript) > MAX_TRANSCRIPT:
                raise RuntimeError("terminal transcript exceeded the fail-closed cap")

    def status_text(self) -> str:
        try:
            return self.args.status.read_text(encoding="utf-8")
        except FileNotFoundError:
            return ""

    def stderr_bytes(self) -> bytes:
        try:
            return self.args.stderr.read_bytes()
        except FileNotFoundError:
            return b""

    def check_running(self) -> None:
        assert self.process is not None
        code = self.process.poll()
        if code is not None:
            raise RuntimeError(
                f"everudp exited early as {code}; status={self.status_text()!r}; "
                f"stderr={self.stderr_bytes()[-2048:]!r}"
            )

    def wait_for(self, predicate, description: str, timeout: float | None = None) -> None:
        deadline = time.monotonic() + (self.args.timeout if timeout is None else timeout)
        while time.monotonic() < deadline:
            self.pump()
            if predicate():
                return
            self.check_running()
        raise TimeoutError(
            f"timed out waiting for {description}; status={self.status_text()!r}; "
            f"tail={bytes(self.transcript[-2048:])!r}; stderr={self.stderr_bytes()[-2048:]!r}"
        )

    def wait_path(self, name: str) -> None:
        self.wait_for(lambda: (self.args.control_dir / name).exists(), name)

    def wait_status(
        self, word: str, minimum: int = 1, timeout: float | None = None
    ) -> None:
        needle = f"everudp-status-v1 state {word}"
        self.wait_for(
            lambda: self.status_text().count(needle) >= minimum,
            f"status {word}",
            timeout,
        )

    def send(self, payload: bytes) -> None:
        offset = 0
        deadline = time.monotonic() + self.args.timeout
        while offset < len(payload):
            if time.monotonic() >= deadline:
                raise TimeoutError("PTY input remained backpressured")
            self.pump(0)
            self.check_running()
            _, writable, _ = select.select([], [self.master], [], 0.05)
            if not writable:
                continue
            try:
                offset += os.write(self.master, payload[offset:])
            except BlockingIOError:
                continue

    def wait_marker_once(self, marker: bytes, description: str) -> None:
        self.wait_for(lambda: self.transcript.count(marker) >= 1, description)
        self.pump(0.03)
        count = self.transcript.count(marker)
        if count != 1:
            raise RuntimeError(f"{description} appeared {count} times")

    def run(self) -> dict[str, object]:
        self.spawn()
        assert self.process is not None
        self.wait_status("connected", timeout=30.0)

        pre = f"pre-{self.args.session}"
        self.send(f"{pre}\n".encode())
        self.wait_marker_once(f"RX:{pre}".encode(), "preflight response")
        (self.args.control_dir / "ready").touch()
        self.wait_path("go")

        expected: list[bytes] = []
        if self.args.mode == "stream":
            for index in range(self.args.messages):
                value = f"{self.args.session}-{index:06d}"
                marker = f"RX:{value}".encode()
                expected.append(marker)
                self.send(f"{value}\n".encode())
            self.wait_for(
                lambda: all(self.transcript.count(marker) >= 1 for marker in expected),
                "all exact stream responses",
            )
            (self.args.control_dir / "driver-done").touch()
            if self.args.hold_at_driver_done:
                self.wait_path("trace-window-verified")
        elif self.args.mode == "outage":
            value = f"during-{self.args.session}"
            expected.extend(
                (f"RX:{value}".encode(), f"ASYNC:{self.args.session}".encode())
            )
            self.send(f"{value}\n".encode())
            self.wait_path("restore")
            self.wait_for(
                lambda: all(self.transcript.count(marker) >= 1 for marker in expected),
                "outage replay",
            )
        elif self.args.mode == "overrun":
            self.wait_path("restore")
            self.wait_status("gapped", timeout=30.0)
            value = f"future-after-gap-{self.args.session}"
            expected.append(f"RX:{value}".encode())
            self.send(f"{value}\n".encode())
            self.wait_for(
                lambda: all(self.transcript.count(marker) >= 1 for marker in expected),
                "future output after the completed gap handshake",
            )
        elif self.args.mode == "pause":
            expected.append(f"ASYNC:{self.args.session}".encode())
            self.wait_path("restore")
            self.wait_for(
                lambda: self.transcript.count(expected[0]) >= 1,
                "output after process wake",
            )
        elif self.args.mode == "cancel":
            self.wait_status("reconnecting", timeout=45.0)
            cancelled_at = time.monotonic()
            os.kill(self.process.pid, signal.SIGTERM)
            deadline = cancelled_at + 3.0
            while self.process.poll() is None and time.monotonic() < deadline:
                self.pump()
            if self.process.poll() is None:
                raise TimeoutError("local cancellation remained blocked in reconnect")
            self.pump(0)
            cancellation_ms = round((time.monotonic() - cancelled_at) * 1000)
            if self.process.returncode != 143:
                raise RuntimeError(
                    f"cancelled everudp exited as {self.process.returncode}, expected 143"
                )
            assert self.original_termios is not None
            terminal_restored = termios.tcgetattr(self.master) == self.original_termios
            if not terminal_restored:
                raise RuntimeError("local cancellation did not restore terminal attributes")
            status = self.status_text()
            if "everudp-status-v1 cause local-cancel" not in status:
                raise RuntimeError("local cancellation was not journalled as terminal")
            return {
                "schema_version": 1,
                "verdict": "PASS",
                "mode": self.args.mode,
                "session": self.args.session,
                "exit_code": self.process.returncode,
                "cancellation_ms": cancellation_ms,
                "terminal_restored": terminal_restored,
                "saw_reconnecting": True,
                "elapsed_ms": round((time.monotonic() - self.started) * 1000),
            }

        post = f"post-{self.args.session}"
        expected.append(f"RX:{post}".encode())
        self.send(f"{post}\n".encode())
        self.wait_for(
            lambda: self.transcript.count(expected[-1]) >= 1,
            "post-scenario response",
        )
        self.send(b"quit\n")
        expected.append(b"RX:quit")
        self.wait_for(lambda: self.transcript.count(b"RX:quit") >= 1, "quit response")

        deadline = time.monotonic() + 30.0
        while self.process.poll() is None and time.monotonic() < deadline:
            self.pump()
        if self.process.poll() is None:
            raise TimeoutError("everudp did not exit after remote PTY exit")
        self.pump(0)
        if self.process.returncode != 0:
            raise RuntimeError(f"everudp exited as {self.process.returncode}")

        duplicates = {marker.decode(): self.transcript.count(marker) for marker in expected}
        bad = {marker: count for marker, count in duplicates.items() if count != 1}
        if bad:
            raise RuntimeError(f"missing or duplicate terminal responses: {bad}")
        if self.args.mode == "overrun" and b"\x00" in self.transcript:
            raise RuntimeError("stale output from the abandoned epoch reached stdout")

        stderr = self.stderr_bytes()
        gaps = stderr.count(GAP_NOTICE)
        expected_gaps = 1 if self.args.mode == "overrun" else 0
        if gaps != expected_gaps:
            raise RuntimeError(f"expected {expected_gaps} GAP notices, observed {gaps}")
        status = self.status_text()
        if self.args.mode == "outage" and "everudp-status-v1 state reconnecting" not in status:
            raise RuntimeError("total loss never reached the reconnecting state")

        return {
            "schema_version": 1,
            "verdict": "PASS",
            "mode": self.args.mode,
            "session": self.args.session,
            "messages": self.args.messages if self.args.mode == "stream" else len(expected),
            "transcript_bytes": len(self.transcript),
            "stderr_bytes": len(stderr),
            "gap_notices": gaps,
            "saw_reconnecting": "everudp-status-v1 state reconnecting" in status,
            "elapsed_ms": round((time.monotonic() - self.started) * 1000),
            "responses": duplicates,
        }

    def close(self) -> None:
        if self.process is not None and self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait()
        if self.master >= 0:
            os.close(self.master)
            self.master = -1


def main() -> int:
    args = parse_args()
    args.control_dir.mkdir(parents=True, exist_ok=True)
    driver = Driver(args)
    try:
        result = driver.run()
        args.transcript.write_bytes(driver.transcript)
        args.result.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except Exception as error:  # Preserve a precise local qualification reason.
        args.transcript.write_bytes(driver.transcript)
        failure = {
            "schema_version": 1,
            "verdict": "FAIL",
            "mode": args.mode,
            "session": args.session,
            "error": str(error),
            "elapsed_ms": round((time.monotonic() - driver.started) * 1000),
        }
        args.result.write_text(json.dumps(failure, sort_keys=True) + "\n", encoding="utf-8")
        print(str(error), file=sys.stderr)
        return 1
    finally:
        driver.close()


if __name__ == "__main__":
    raise SystemExit(main())
