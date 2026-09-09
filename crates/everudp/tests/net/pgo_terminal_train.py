#!/usr/bin/env python3
"""Run one bounded, graceful terminal workload against an instrumented everudp."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import pty
import select
import signal
import shlex
import struct
import subprocess
import termios
import time

ONE_BYTE_ROUNDTRIPS = 256
LARGE_ROUNDTRIPS = 32
LARGE_SIZE = 4096
SPACING_SECONDS = 0.020
READY = b"EVERUDP-PGO-ECHO-READY\n"
SSH_SHIM = """#!/bin/sh
set -eu
for argument in "$@"; do
  if [ "$argument" = "-G" ]; then
    printf 'hostname localhost\\nproxycommand none\\nproxyjump none\\n'
    exit 0
  fi
done
remote=
for argument in "$@"; do remote=$argument; done
[ -n "$remote" ] || exit 255
export SSH_CONNECTION='127.0.0.1 40000 SERVER_IP 22'
exec /bin/sh -c "$remote"
"""


def route_selected_ip() -> str:
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))
        address = sock.getsockname()[0]
    finally:
        sock.close()
    if address == "127.0.0.1":
        raise RuntimeError("no routed local address for gateway")
    return address


def payload(size: int, index: int) -> bytes:
    return bytes(((index * 131 + offset * 17 + 29) & 0xFF) for offset in range(size))


BYTE_BUDGET = ONE_BYTE_ROUNDTRIPS + LARGE_ROUNDTRIPS * LARGE_SIZE


def command(binary: Path, remote_binary: Path, ssh: Path, state: Path, status: Path, fixture: Path) -> list[str]:
    return [str(binary), "--remote-program", str(remote_binary), "connect", "localhost",
            "--session", "pgo-terminal", "--status-file",
            str(status), "--", "/bin/sh", "-c", shlex.join(["exec", str(fixture), str(BYTE_BUDGET)])]


def _write_all(fd: int, data: bytes, deadline: float) -> None:
    sent = 0
    while sent < len(data):
        if time.monotonic() >= deadline:
            raise TimeoutError("PTY write timeout")
        _, writable, _ = select.select([], [fd], [], min(0.1, max(0, deadline - time.monotonic())))
        if writable:
            try:
                sent += os.write(fd, data[sent:])
            except BlockingIOError:
                pass


def _read_exact(fd: int, count: int, deadline: float, transcript: bytearray) -> bytes:
    result = bytearray()
    while len(result) < count:
        if time.monotonic() >= deadline:
            raise TimeoutError("PTY read timeout")
        readable, _, _ = select.select([fd], [], [], min(0.1, max(0, deadline - time.monotonic())))
        if not readable:
            continue
        try:
            chunk = os.read(fd, min(65536, count - len(result)))
        except OSError as error:
            if error.errno == 5:
                raise EOFError("PTY closed before exact echo") from error
            raise
        if not chunk:
            raise EOFError("PTY EOF before exact echo")
        transcript.extend(chunk)
        result.extend(chunk)
    return bytes(result)


def _require_eof(fd: int, deadline: float) -> None:
    while time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], 0.05)
        if not readable:
            continue
        try:
            data = os.read(fd, 65536)
        except OSError as error:
            if error.errno == 5:
                return
            raise
        if data:
            raise RuntimeError("unexpected trailing PTY output")
        return
    raise TimeoutError("PTY did not reach EOF")


def _kill_owned(process: subprocess.Popen[bytes] | None, gateway_pids: set[int], state: Path) -> None:
    if process is not None and process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
    for pid in gateway_pids:
        try:
            pidfd = os.pidfd_open(pid)
        except ProcessLookupError:
            continue
        try:
            if Path(f"/proc/{pid}").stat().st_uid != os.getuid():
                os.close(pidfd)
                continue
            words = [word for word in (Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")) if word]
            if b"__gateway-v1" not in words or os.fsencode(str(state)) not in words:
                os.close(pidfd)
                continue
        except (FileNotFoundError, PermissionError):
            os.close(pidfd)
            continue
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        finally:
            os.close(pidfd)


def _owned_gateways(state: Path) -> set[int]:
    """Find only this run's detached gateways (same uid, exact role/state args)."""
    found: set[int] = set()
    state_bytes = os.fsencode(str(state))
    uid = os.getuid()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            if entry.stat().st_uid != uid:
                continue
            words = [word for word in (entry / "cmdline").read_bytes().split(b"\0") if word]
            if b"__gateway-v1" in words and state_bytes in words:
                found.add(pid)
        except (FileNotFoundError, PermissionError):
            continue
    return found


def run(args: argparse.Namespace) -> dict[str, object]:
    binary, fixture, output = map(Path, (args.binary, args.fixture, args.output_dir))
    if not math.isfinite(args.timeout) or args.timeout <= 0 or not binary.is_absolute() or not fixture.is_absolute():
        raise ValueError("absolute binary/fixture paths and positive timeout are required")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("--binary must be an executable file")
    if not fixture.is_file() or not os.access(fixture, os.X_OK):
        raise ValueError("--fixture must be an executable file")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = output / "state"
    root.mkdir(mode=0o700, exist_ok=False)
    bindir = root / "bin"
    bindir.mkdir(mode=0o700)
    ssh = bindir / "ssh"
    bootstrap_shim = getattr(args, "bootstrap_shim", None)
    ssh.write_text(Path(bootstrap_shim).read_text() if bootstrap_shim else
                   SSH_SHIM.replace("SERVER_IP", route_selected_ip()))
    ssh.chmod(0o700)
    status = root / "client.status"
    stderr_path = root / "client.stderr"
    stderr_path.touch(mode=0o600)
    transcript = bytearray()
    process = None
    gateway_pids: set[int] = set()
    master = slave = -1
    original = None
    started = time.monotonic()
    receipt: dict[str, object] = {"schema_version": 1, "status": "FAILED", "qualification": False,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(), "workload": {
        "one_byte_roundtrips": ONE_BYTE_ROUNDTRIPS, "large_roundtrips": LARGE_ROUNDTRIPS,
        "large_size": LARGE_SIZE, "spacing_seconds": SPACING_SECONDS}}
    try:
        master, slave = pty.openpty()
        original = termios.tcgetattr(slave)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        os.set_blocking(master, False)
        # Keep a parent copy so the original slave attributes can be restored.
        command_line = command(binary, binary, ssh, root, status, fixture)
        env = {"PATH": f"{bindir}:/usr/bin:/bin", "SHELL": "/bin/sh", "TERM": "xterm-256color",
               "EVERSH_STATE_DIR": str(root)}
        def child_setup() -> None:
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        with stderr_path.open("ab") as stderr:
            process = subprocess.Popen(command_line, stdin=slave, stdout=slave, stderr=stderr,
                                       env=env, close_fds=True, preexec_fn=child_setup)
        deadline = time.monotonic() + args.timeout
        _read_exact(master, len(READY), deadline, transcript)
        if transcript[-len(READY):] != READY:
            raise RuntimeError("unexpected readiness marker")
        for index in range(ONE_BYTE_ROUNDTRIPS):
            byte = payload(1, index)
            _write_all(master, byte, deadline)
            if _read_exact(master, 1, deadline, transcript) != byte:
                raise RuntimeError("one-byte echo mismatch")
            time.sleep(SPACING_SECONDS)
        for index in range(LARGE_ROUNDTRIPS):
            block = payload(LARGE_SIZE, index + ONE_BYTE_ROUNDTRIPS)
            _write_all(master, block, deadline)
            if _read_exact(master, len(block), deadline, transcript) != block:
                raise RuntimeError("large echo mismatch")
        code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        if code != 0:
            raise RuntimeError(f"everudp exited {code}")
        if slave >= 0:
            termios.tcsetattr(slave, termios.TCSANOW, original)
            os.close(slave)
            slave = -1
        _require_eof(master, min(deadline, time.monotonic() + 1.0))
        os.close(master); master = -1
        gateway_pids.update(_owned_gateways(root))
        gateway_deadline = min(deadline, time.monotonic() + 2.0)
        while gateway_pids and time.monotonic() < gateway_deadline:
            gateway_pids = {pid for pid in gateway_pids if Path(f"/proc/{pid}").exists()}
            if gateway_pids:
                time.sleep(0.02)
        if gateway_pids:
            raise RuntimeError("gateway did not exit gracefully")
        receipt.update(status="TRAINED", elapsed_seconds=time.monotonic() - started,
                       transcript_sha256=hashlib.sha256(transcript).hexdigest(),
                       transcript_bytes=len(transcript))
    except Exception as error:
        receipt["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        cleanup_error = None
        try:
            if slave >= 0 and original is not None:
                termios.tcsetattr(slave, termios.TCSANOW, original)
        except Exception as error:
            cleanup_error = error
        try:
            if slave >= 0:
                os.close(slave)
            if master >= 0:
                os.close(master)
            gateway_pids.update(_owned_gateways(root))
            _kill_owned(process, gateway_pids, root)
        except Exception as error:
            cleanup_error = cleanup_error or error
        if cleanup_error is not None:
            receipt["status"] = "FAILED"
            receipt["error"] = f"cleanup {type(cleanup_error).__name__}: {cleanup_error}"
        try:
            (output / "pgo-training-receipt.json").write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n"
            )
        except Exception:
            # Preserve the original execution error if receipt storage itself fails.
            if cleanup_error is None:
                raise
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--bootstrap-shim", type=Path,
                        help="explicit training-only SSH shim for isolated namespaces")
    args = parser.parse_args()
    result = run(args)
    print(json.dumps(result, sort_keys=True))
    if result.get("status") != "TRAINED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
