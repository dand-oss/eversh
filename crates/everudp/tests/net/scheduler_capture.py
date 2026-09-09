"""Bounded, pointer-free scheduler recording for latency diagnostics.

This module is deliberately diagnostic only.  It records scheduler tracepoints
for an explicit set of target PIDs, never terminal payloads or call stacks, and
rejects any record that cannot be proven to belong to one of those targets.
The public benchmark owns the measurement-window barriers; this session only
controls the bounded perf recording process.
"""

from __future__ import annotations

import re
import signal
import subprocess
from pathlib import Path
from typing import Iterable

from analyze_public_scheduler import _LINE, _SWITCH, _WAKE
from perf_counter_control import CounterSession


SCHEDULER_EVENTS = (
    "sched:sched_waking",
    "sched:sched_wakeup",
    "sched:sched_switch",
)
SCHEDULER_SAMPLE_TYPE = "IP|TID|TIME|CPU|PERIOD|RAW|IDENTIFIER"


def _validate_tids(tids: Iterable[int]) -> tuple[int, ...]:
    if isinstance(tids, (str, bytes)):
        raise ValueError("scheduler targets must be positive thread IDs")
    try:
        values = tuple(tids)
    except TypeError as error:
        raise ValueError("scheduler targets must be a non-empty iterable") from error
    if not values or any(type(tid) is not int or tid <= 0 for tid in values):
        raise ValueError("scheduler targets must be positive thread IDs")
    if len(set(values)) != len(values):
        raise ValueError("scheduler targets must be unique")
    return values


def _validate_budget(budget_ms: int) -> None:
    if type(budget_ms) is not int or not 10 <= budget_ms <= 60000:
        raise ValueError("scheduler lifetime must be between 10 and 60000 ms")


def _pid_filter(tids: tuple[int, ...]) -> str:
    return " || ".join(f"pid == {tid}" for tid in tids)


def _switch_filter(tids: tuple[int, ...]) -> str:
    return " || ".join(f"prev_pid == {tid} || next_pid == {tid}" for tid in tids)


def scheduler_command(base, tids, directory, budget_ms):
    """Build an all-CPU, PID-filtered, bounded scheduler perf command."""
    targets = _validate_tids(tids)
    _validate_budget(budget_ms)
    directory = Path(directory)
    wake_filter = _pid_filter(targets)
    switch_filter = _switch_filter(targets)
    command = [
        *base,
        "record",
        "-a",
        "--synth",
        "no",
        "--clockid",
        "mono",
        "--delay=-1",
    ]
    for event in SCHEDULER_EVENTS[:2]:
        command.extend(("-e", event, "--filter", wake_filter))
    command.extend(("-e", SCHEDULER_EVENTS[2], "--filter", switch_filter))
    command.extend(("--control", f"fifo:{directory / 'control'},{directory / 'ack'}"))
    command.extend(("-o", str(directory / "private-perf.data"), "--",
                    "/usr/bin/sleep", str(budget_ms / 1000)))
    return command


def _require_field(line: str, field: str) -> None:
    if not re.search(r"(?:^|, )" + re.escape(field) + r"(?:,|$)", line):
        raise ValueError("scheduler event attributes do not match capture contract")


def _validate_trace_attributes(lines: list[str]) -> None:
    for line in lines:
        if not line.startswith("sched:") or ": type: 2 (PERF_TYPE_TRACEPOINT)," not in line:
            raise ValueError("unexpected scheduler event attribute")
        _require_field(line, "{ sample_period, sample_freq }: 1")
        _require_field(line, f"sample_type: {SCHEDULER_SAMPLE_TYPE}")
        _require_field(line, "read_format: ID|LOST")
        _require_field(line, "disabled: 1")
        _require_field(line, "sample_id_all: 1")
        _require_field(line, "use_clockid: 1")
        _require_field(line, "clockid: 1")
        # No stack, register, branch, or other payload-bearing sample fields.
        if any(field in line for field in (
                "CALLCHAIN", "STACK", "REGS", "BRANCH", "WEIGHT", "DATA_SRC",
                "TRANSACTION", "PHYS_ADDR")):
            raise ValueError("scheduler attributes include sensitive sample fields")


def validate_attributes(text: str) -> None:
    """Validate the complete perf evlist contract, including its dummy event."""
    if not isinstance(text, str):
        raise ValueError("scheduler attributes must be text")
    lines = [line for line in text.splitlines() if line]
    tips = [line for line in lines if line.startswith("# Tip: ")]
    if len(tips) > 1 or (tips and tips[0] != "# Tip: use 'perf evlist --trace-fields' to show fields for tracepoint events"):
        raise ValueError("unexpected perf attribute note")
    event_lines = [line for line in lines if not line.startswith("# Tip: ")]
    if len(event_lines) != 4:
        raise ValueError("scheduler attributes must contain three events and dummy")
    names = [line.split(": type:", 1)[0] for line in event_lines]
    if names != [*SCHEDULER_EVENTS, "dummy:u"]:
        raise ValueError("unexpected scheduler event set or order")
    _validate_trace_attributes(event_lines[:3])
    dummy = event_lines[3]
    if not dummy.startswith("dummy:u: type: 1 (PERF_TYPE_SOFTWARE),"):
        raise ValueError("unexpected perf dummy event")
    for field in ("sample_type: IP|TID|TIME|CPU|IDENTIFIER", "read_format: ID|LOST",
                  "sample_id_all: 1", "use_clockid: 1", "clockid: 1"):
        _require_field(dummy, field)
    if "RAW" in dummy or "PERIOD" in dummy:
        raise ValueError("dummy event carries scheduler payload fields")


def sanitize_scheduler(text: str, tids: Iterable[int]) -> str:
    """Validate and redact perf script scheduler records.

    Every nonblank input line must be a target-scoped scheduler event.  Names
    are replaced while retaining only the fields consumed by the scheduler
    analyzers; malformed, lost, out-of-scope, and regressing records fail
    closed.
    """
    targets = set(_validate_tids(tids))
    if not isinstance(text, str):
        raise ValueError("scheduler output must be text")
    result: list[str] = []
    previous = -1
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        # perf pads event names in mixed-event output. Normalize display
        # padding only, never the scheduler record body.
        line = re.sub(r"^(\d+\.\d{9}):\s+(sched:\w+:)\s+", r"\1: \2 ", line)
        match = _LINE.fullmatch(line)
        if match is None:
            raise ValueError(f"scheduler line {line_number}: malformed record")
        timestamp = int(match["seconds"]) * 1_000_000_000 + int(match["fraction"])
        if timestamp < previous:
            raise ValueError(f"scheduler line {line_number}: timestamp regresses")
        previous = timestamp
        kind, body = match["kind"], match["body"]
        if kind in ("sched_waking", "sched_wakeup"):
            fields = _WAKE.fullmatch(body)
            if fields is None or int(fields["pid"]) not in targets:
                raise ValueError(f"scheduler line {line_number}: record outside target scope")
            body = (f"comm=<task> pid={fields['pid']} prio={fields['prio']} "
                    f"target_cpu={fields['cpu']}")
        else:
            fields = _SWITCH.fullmatch(body)
            if fields is None:
                raise ValueError(f"scheduler line {line_number}: malformed switch record")
            previous_pid, next_pid = int(fields["prev_pid"]), int(fields["next_pid"])
            if previous_pid not in targets and next_pid not in targets:
                raise ValueError(f"scheduler line {line_number}: record outside target scope")
            if previous_pid == next_pid:
                raise ValueError(f"scheduler line {line_number}: switch does not change tasks")
            body = (f"prev_comm=<task> prev_pid={fields['prev_pid']} "
                    f"prev_prio={fields['prev_prio']} prev_state={fields['prev_state']} ==> "
                    f"next_comm=<task> next_pid={fields['next_pid']} "
                    f"next_prio={fields['next_prio']}")
        result.append(f"{match['seconds']}.{match['fraction']}: sched:{kind}: {body}")
    if not result:
        raise ValueError("scheduler output has no records")
    return "\n".join(result) + "\n"


class SchedulerSession(CounterSession):
    """A bounded scheduler recorder reusing CounterSession control/cleanup."""

    command_builder = staticmethod(scheduler_command)
    final_exit_codes = (*CounterSession.final_exit_codes, -signal.SIGTERM)

    def __init__(self, base, tids, directory, budget_ms=60000):
        self.base = list(base)
        self.tids = _validate_tids(tids)
        super().__init__(self.base, self.tids, directory, budget_ms)

    def result(self):
        code = self.finalize()
        attributes = subprocess.run(
            [*self.base, "evlist", "-v", "-i", str(self.directory / "private-perf.data")],
            capture_output=True, text=True, check=True, timeout=10,
        )
        (self.directory / "events-attributes.txt").write_text(attributes.stdout)
        validate_attributes(attributes.stdout)
        decoded = subprocess.run(
            [*self.base, "script", "--show-lost-events", "--ns", "-i",
             str(self.directory / "private-perf.data"), "-F", "trace:time,event,trace"],
            capture_output=True, text=True, check=True, timeout=10,
        )
        (self.directory / "decode.log").write_text(decoded.stderr)
        if decoded.stderr.strip():
            raise ValueError("scheduler decoder reported warnings")
        scheduler_text = sanitize_scheduler(decoded.stdout, self.tids)
        return {
            "diagnostic_only": True,
            "scope": "selected-target-scheduler-events",
            "targets": list(self.tids),
            "control": self.transitions,
            "exit_code": code,
            "scheduler_text": scheduler_text,
        }
