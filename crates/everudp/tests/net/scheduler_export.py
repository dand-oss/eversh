"""Separate PID-filtered scheduler switches from pointer-free syscall events."""
from analyze_input_schedule import _parse_scheduler
from syscall_export import parse
import re


_SWITCH_LINE = re.compile(r"^\s*(\d+\.\d{9}):\s+sched:sched_switch:\s+(.*)$")


def split_capture(text, pid):
    if not isinstance(text, str):
        raise ValueError("capture text required")
    switches, syscalls = [], []
    for line in text.splitlines():
        match = _SWITCH_LINE.fullmatch(line)
        if match:
            # perf aligns mixed event names with spaces. Normalize only that
            # display padding; the existing scheduler parser validates the body.
            switches.append(f"{match[1]}: sched:sched_switch: {match[2]}")
        else:
            # Unknown, malformed and LOST records must reach the strict parser,
            # never disappear through a permissive event-name filter.
            syscalls.append(line)
    records = _parse_scheduler("\n".join(switches), pid)
    events = []
    for record in records:
        if record["kind"] not in ("switch_in", "switch_out"):
            raise ValueError("unexpected scheduler event")
        events.append({"time_ns": record["timestamp_ns"],
                       "prev_pid": record["prev_pid"], "next_pid": record["next_pid"]})
    return parse("\n".join(syscalls)), {
        "schema_version": 1, "clock": "CLOCK_MONOTONIC", "pid": pid, "events": events}
