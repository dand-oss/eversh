"""Bounded, user-space, single-thread hardware counting; never qualification."""
import os
from pathlib import Path
import select
import signal
import subprocess
import time

from perf_counter_values import parse_counter_values


def counter_command(base, tid, directory, budget_ms):
    if type(tid) is not int or tid <= 0:
        raise ValueError("expected one positive thread ID")
    if type(budget_ms) is not int or not 10 <= budget_ms <= 60000:
        raise ValueError("counter lifetime must be between 10 and 60000 ms")
    return [*base, "stat", "--no-inherit", "--json-output", "--delay=-1",
            "-e", "{cycles:u,instructions:u,cache-misses:u}", "-t", str(tid),
            "--timeout", str(budget_ms),
            "--control", f"fifo:{directory / 'control'},{directory / 'ack'}",
            "-o", str(directory / "counters.jsonl")]


def await_ack(descriptor, timeout):
    deadline = time.monotonic() + timeout
    payload = b""
    # Installed perf 7.1.13 writes the C string including its trailing NUL.
    # Read the complete observed response, including split pipe reads.
    while len(payload) < 5:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
            raise TimeoutError("perf control acknowledgement timed out")
        part = os.read(descriptor, 64)
        if not part:
            raise ValueError("perf acknowledgement channel closed")
        payload += part
    if payload != b"ack\n\x00":
        raise ValueError(f"unexpected perf control acknowledgement: {payload!r}")


class CounterSession:
    """The caller owns target identity checks and measurement-window barriers."""

    command_builder = staticmethod(counter_command)
    final_exit_codes = (0, 130, -signal.SIGINT)

    def __init__(self, base, tid, directory, budget_ms=60000):
        self.directory = Path(directory)
        command = self.command_builder(base, tid, self.directory, budget_ms)
        self.directory.mkdir(mode=0o700)
        self.descriptors = []
        self.process = None
        self.log = None
        self.enabled = False
        self.disabled = False
        self.transitions = []
        try:
            for name in ("control", "ack"):
                path = self.directory / name
                os.mkfifo(path, 0o600)
                self.descriptors.append(os.open(path, os.O_RDWR | os.O_NONBLOCK))
            self.log = (self.directory / "perf.log").open("w")
            self.process = subprocess.Popen(command, stdout=self.log, stderr=subprocess.STDOUT,
                                            start_new_session=True)
        except BaseException:
            self.close()
            raise

    def _control(self, operation):
        if self.process.poll() is not None:
            raise ValueError("perf exited before measurement control")
        sent = time.monotonic_ns()
        request = operation.encode() + b"\n"
        if os.write(self.descriptors[0], request) != len(request):
            raise ValueError("incomplete perf control request")
        await_ack(self.descriptors[1], 5)
        acknowledged = time.monotonic_ns()
        if self.process.poll() is not None:
            raise ValueError("perf exited during measurement control")
        self.transitions.append({"operation": operation, "sent_ns": sent,
                                 "acknowledged_ns": acknowledged})

    def enable(self):
        if self.enabled or self.disabled:
            raise ValueError("counter enable must occur exactly once")
        self._control("enable")
        self.enabled = True

    def disable(self):
        if not self.enabled or self.disabled:
            raise ValueError("counter disable requires an active measurement")
        self._control("disable")
        self.disabled = True

    def finalize(self):
        if not self.disabled:
            raise ValueError("measurement has no acknowledged stop")
        # SIGINT is perf stat's normal interactive finalization. When invoked
        # through sudo, sudo forwards the signal to its supervised command.
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
        code = self.process.wait(timeout=10)
        if code not in self.final_exit_codes:
            raise ValueError(f"perf failed with exit status {code}")
        return code

    def result(self):
        code = self.finalize()
        values = parse_counter_values((self.directory / "counters.jsonl").read_text(), grouped=True)
        return {"diagnostic_only": True, "scope": "selected-main-thread-user-space",
                "control": self.transitions, "exit_code": code, "values": values}

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            for escalation in ("TERM", "KILL"):
                try:
                    self.process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    # This process was launched into its own new session. Never
                    # signal an inherited or unresolved process group.
                    if os.getpgid(self.process.pid) != self.process.pid:
                        raise ValueError("counter process group identity changed")
                    subprocess.run(["sudo", "-n", "/bin/kill", f"-{escalation}",
                                    "--", f"-{self.process.pid}"], check=True, timeout=5)
            else:
                self.process.wait(timeout=5)
        for descriptor in self.descriptors:
            os.close(descriptor)
        self.descriptors = []
        if self.log is not None:
            self.log.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
