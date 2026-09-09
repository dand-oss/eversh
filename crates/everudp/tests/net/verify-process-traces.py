#!/usr/bin/env python3
"""Verify that post-bootstrap process traces are metadata-only and UDP-safe."""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path
import re
import tempfile


SYSCALL = re.compile(
    rb"^\d\d:\d\d:\d\d(?:\.\d+)?\s+([A-Za-z_][A-Za-z0-9_]*)\("
)
ALLOWED = {
    b"accept",
    b"accept4",
    b"bind",
    b"clone",
    b"clone3",
    b"close",
    b"connect",
    b"epoll_pwait",
    b"epoll_pwait2",
    b"epoll_wait",
    b"exit",
    b"exit_group",
    b"fork",
    b"getpeername",
    b"getsockname",
    b"kill",
    b"listen",
    b"poll",
    b"ppoll",
    b"pselect6",
    b"select",
    b"shutdown",
    b"socket",
    b"socketpair",
    b"tgkill",
    b"vfork",
    b"wait4",
    b"waitid",
}
PAYLOAD_IO = re.compile(
    rb"\b(?:read|readv|recv|recvfrom|recvmmsg|recvmsg|send|sendmmsg|sendmsg|sendto|"
    rb"write|writev|pread64|pwrite64)\("
)
NETWORK_STREAM = re.compile(rb"socket\(AF_INET6?,\s*SOCK_STREAM\b")


class VerificationError(RuntimeError):
    pass


def trace_files(prefix: Path) -> list[Path]:
    candidates = (Path(value) for value in glob.glob(f"{prefix}.*"))
    return sorted(
        path
        for path in candidates
        if path.name.removeprefix(f"{prefix.name}.").isdigit()
    )


def verify_group(prefix: Path, expected_pid: int, markers: list[bytes]) -> dict[str, int]:
    files = trace_files(prefix)
    if not files or not any(path.name == f"{prefix.name}.{expected_pid}" for path in files):
        raise VerificationError(f"missing trace for expected pid {expected_pid}")
    events = 0
    for path in files:
        if path.stat().st_size == 0:
            continue
        data = path.read_bytes()
        if PAYLOAD_IO.search(data):
            raise VerificationError("payload-bearing syscall present")
        if b"PRIVATE KEY" in data or any(marker in data for marker in markers):
            raise VerificationError("protected payload marker present")
        if NETWORK_STREAM.search(data) or b"<TCP:" in data or b"<TCPv6:" in data:
            raise VerificationError("post-bootstrap TCP socket present")
        for line in data.splitlines():
            matched = SYSCALL.match(line)
            if matched is None:
                continue
            name = matched.group(1)
            events += 1
            if name in {b"execve", b"execveat"}:
                raise VerificationError("post-bootstrap process execution present")
            if name not in ALLOWED:
                raise VerificationError(f"unexpected traced syscall {name.decode('ascii')}")
    if events == 0:
        raise VerificationError("trace contains no parsed metadata events")
    return {"files": len(files), "events": events}


def verify_identity(path: Path, expected_pid: int) -> dict[str, int | str]:
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        name, separator, value = line.partition(":")
        if separator:
            fields[name] = value.strip()
    if fields.get("Name") != "everudp" or fields.get("Pid") != str(expected_pid):
        raise VerificationError("process identity does not name the expected everudp pid")
    try:
        parent_pid = int(fields["PPid"])
        namespace_pid = int(fields["NSpid"].split()[-1])
    except (KeyError, ValueError, IndexError) as error:
        raise VerificationError("process identity lacks canonical lineage fields") from error
    if parent_pid <= 0 or namespace_pid <= 0:
        raise VerificationError("process identity has invalid lineage")
    return {
        "name": fields["Name"],
        "host_pid": expected_pid,
        "parent_pid": parent_pid,
        "namespace_pid": namespace_pid,
    }


def verify_lifecycle(path: Path, client_pid: int, gateway_pid: int) -> dict[str, object]:
    lifecycle = json.loads(path.read_text(encoding="utf-8"))
    if lifecycle.get("schema_version") != 1:
        raise VerificationError("trace lifecycle has the wrong schema")
    window = lifecycle.get("window")
    if not isinstance(window, dict) or window.get("begin") != "before-control-go":
        raise VerificationError("trace lifecycle does not begin before control go")
    if window.get("end") != "driver-done":
        raise VerificationError("trace lifecycle does not span driver-done")
    for field in (
        "attached_before_go_utc",
        "attached_at_driver_done_utc",
        "tracers_stopped_utc",
    ):
        if not isinstance(window.get(field), str) or not window[field]:
            raise VerificationError(f"trace lifecycle lacks {field}")
    for role, expected_pid in (("client", client_pid), ("gateway", gateway_pid)):
        record = lifecycle.get(role)
        if not isinstance(record, dict):
            raise VerificationError(f"trace lifecycle lacks {role} record")
        if record.get("tracee_pid") != expected_pid:
            raise VerificationError(f"trace lifecycle has wrong {role} tracee")
        tracer_pid = record.get("tracer_pid")
        if not isinstance(tracer_pid, int) or tracer_pid <= 0:
            raise VerificationError(f"trace lifecycle has invalid {role} tracer")
        if record.get("attached_before_go") is not True:
            raise VerificationError(f"{role} tracer was not attached before control go")
        if record.get("attached_at_driver_done") is not True:
            raise VerificationError(f"{role} tracer ended before driver-done")
        if record.get("shutdown_signal") != "SIGINT" or record.get("wait_status") != 130:
            raise VerificationError(f"{role} tracer had noncanonical shutdown")
        if record.get("stderr_bytes") != 0 or record.get("stdout_bytes") != 0:
            raise VerificationError(f"{role} tracer emitted unexpected diagnostics")
    return lifecycle


def verify(
    phase_path: Path,
    lifecycle_path: Path,
    client_prefix: Path,
    gateway_prefix: Path,
    client_identity: Path,
    gateway_identity: Path,
    markers: list[bytes],
) -> dict[str, object]:
    phase = json.loads(phase_path.read_text(encoding="utf-8"))
    if phase.get("phase") != "post-bootstrap-terminal":
        raise VerificationError("trace phase is not post-bootstrap terminal traffic")
    client_pid = phase.get("client_pid")
    gateway_pid = phase.get("gateway_pid")
    if not isinstance(client_pid, int) or not isinstance(gateway_pid, int):
        raise VerificationError("trace phase lacks numeric process identities")
    return {
        "schema_version": 1,
        "verdict": "PASS",
        "phase": phase["phase"],
        "client_pid": client_pid,
        "gateway_pid": gateway_pid,
        "client": {
            **verify_group(client_prefix, client_pid, markers),
            "identity": verify_identity(client_identity, client_pid),
        },
        "gateway": {
            **verify_group(gateway_prefix, gateway_pid, markers),
            "identity": verify_identity(gateway_identity, gateway_pid),
        },
        "lifecycle": verify_lifecycle(lifecycle_path, client_pid, gateway_pid),
        "payload_syscalls": 0,
        "post_bootstrap_tcp_sockets": 0,
        "post_bootstrap_execs": 0,
    }


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="everudp-trace-verifier-") as root_value:
        root = Path(root_value)
        phase = root / "phase.json"
        lifecycle = root / "lifecycle.json"
        phase.write_text(
            json.dumps(
                {"phase": "post-bootstrap-terminal", "client_pid": 11, "gateway_pid": 22}
            ),
            encoding="utf-8",
        )
        lifecycle_value = {
            "schema_version": 1,
            "window": {
                "begin": "before-control-go",
                "end": "driver-done",
                "attached_before_go_utc": "2026-09-06T12:00:00Z",
                "attached_at_driver_done_utc": "2026-09-06T12:00:01Z",
                "tracers_stopped_utc": "2026-09-06T12:00:02Z",
            },
            "client": {
                "tracee_pid": 11,
                "tracer_pid": 111,
                "attached_before_go": True,
                "attached_at_driver_done": True,
                "shutdown_signal": "SIGINT",
                "wait_status": 130,
                "stderr_bytes": 0,
                "stdout_bytes": 0,
            },
            "gateway": {
                "tracee_pid": 22,
                "tracer_pid": 222,
                "attached_before_go": True,
                "attached_at_driver_done": True,
                "shutdown_signal": "SIGINT",
                "wait_status": 130,
                "stderr_bytes": 0,
                "stdout_bytes": 0,
            },
        }
        lifecycle.write_text(json.dumps(lifecycle_value), encoding="utf-8")
        client = root / "client"
        gateway = root / "gateway"
        client_identity = root / "client-process.txt"
        gateway_identity = root / "gateway-process.txt"
        client_identity.write_text(
            "Name:\teverudp\nPid:\t11\nPPid:\t7\nNSpid:\t11\t2\n", encoding="ascii"
        )
        gateway_identity.write_text(
            "Name:\teverudp\nPid:\t22\nPPid:\t8\nNSpid:\t22\t3\n", encoding="ascii"
        )
        (root / "client.11").write_bytes(b"12:00:00.000001 epoll_wait(4, [], 32, 0) = 0\n")
        (root / "gateway.22").write_bytes(
            b"12:00:00.000002 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 7\n"
        )
        verify(
            phase,
            lifecycle,
            client,
            gateway,
            client_identity,
            gateway_identity,
            [b"EVERUDP_TRACE_SENTINEL"],
        )

        negative_cases = [
            b"12:00:00.000003 sendto(7, \"payload\", 7, 0, NULL, 0) = 7\n",
            b"12:00:00.000003 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 8\n",
            b"12:00:00.000003 epoll_wait(4, [], 32, 0) = 0 # EVERUDP_TRACE_SENTINEL\n",
            b"12:00:00.000003 epoll_wait(4, [], 32, 0) = 0 # PRIVATE KEY\n",
        ]
        for payload in negative_cases:
            (root / "gateway.22").write_bytes(payload)
            try:
                verify(
                    phase,
                    lifecycle,
                    client,
                    gateway,
                    client_identity,
                    gateway_identity,
                    [b"EVERUDP_TRACE_SENTINEL"],
                )
            except VerificationError:
                pass
            else:
                raise AssertionError("negative process-trace fixture was accepted")

        (root / "gateway.22").unlink()
        try:
            verify(
                phase,
                lifecycle,
                client,
                gateway,
                client_identity,
                gateway_identity,
                [b"EVERUDP_TRACE_SENTINEL"],
            )
        except VerificationError:
            pass
        else:
            raise AssertionError("missing gateway process trace was accepted")

        (root / "gateway.22").write_bytes(
            b"12:00:00.000002 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 7\n"
        )
        for role, field, value in (
            ("client", "attached_at_driver_done", False),
            ("gateway", "wait_status", 1),
            ("client", "stderr_bytes", 1),
        ):
            broken_lifecycle = json.loads(json.dumps(lifecycle_value))
            broken_lifecycle[role][field] = value
            lifecycle.write_text(json.dumps(broken_lifecycle), encoding="utf-8")
            try:
                verify(
                    phase,
                    lifecycle,
                    client,
                    gateway,
                    client_identity,
                    gateway_identity,
                    [b"EVERUDP_TRACE_SENTINEL"],
                )
            except VerificationError:
                pass
            else:
                raise AssertionError("premature or noncanonical tracer was accepted")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--phase", type=Path)
    parser.add_argument("--lifecycle", type=Path)
    parser.add_argument("--client-prefix", type=Path)
    parser.add_argument("--gateway-prefix", type=Path)
    parser.add_argument("--client-identity", type=Path)
    parser.add_argument("--gateway-identity", type=Path)
    parser.add_argument("--marker", action="append", default=[])
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    if not all(
        (
            args.phase,
            args.lifecycle,
            args.client_prefix,
            args.gateway_prefix,
            args.client_identity,
            args.gateway_identity,
            args.output,
        )
    ):
        raise SystemExit(
            "phase, lifecycle, trace prefixes, process identities, and output are required"
        )
    result = verify(
        args.phase,
        args.lifecycle,
        args.client_prefix,
        args.gateway_prefix,
        args.client_identity,
        args.gateway_identity,
        [value.encode("utf-8") for value in args.marker],
    )
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
