"""Compare observed input-read scheduling boundaries, never qualification.

The caller must verify capture provenance, PID filters, monotonic clock identity
and lost events. The explicit stdin descriptor must be established independently.
No claim that these intervals are exclusively runtime cost is made.
"""
import re

from analyze_input_schedule import _parse_scheduler
from clock_alignment import _validated_boundaries

_LINE = re.compile(r"\s*(\d+)\.(\d{9}):\s+(sched:sched_\w+|syscalls:sys_enter_read|syscalls:sys_exit_read): (.*)")
_ENTER = re.compile(r"fd: 0x([0-9a-f]+), count: 0x([0-9a-f]+)")
_EXIT = re.compile(r"0x([0-9a-f]+)")


def analyze(result, text, target_pid, stdin_fd):
    """Return all trial rows, including explicit exclusions, or UNKNOWN."""
    try:
        if type(stdin_fd) is not int or stdin_fd < 0:
            raise ValueError("invalid stdin descriptor")
        trials, boundaries = _validated_boundaries(result)
        if type(result.get("transcript_failures")) is not int or result["transcript_failures"] != 0:
            raise ValueError("transcript failures or missing oracle")
        samples = result.get("samples_us")
        if not isinstance(samples, list) or len(samples) != trials:
            raise ValueError("missing public samples")
        for sample, boundary in zip(samples, boundaries):
            if type(sample) is not int or sample <= 0 or sample != (boundary["accepted_ns"] - boundary["send_ns"] + 999) // 1000:
                raise ValueError("sample disagrees with public boundary")
        stamps, scheduler_lines, reads = [], [], []
        pending = None
        for line in text.splitlines():
            match = _LINE.fullmatch(line)
            if match is None:
                raise ValueError("malformed or lost event")
            ns = int(match[1]) * 1_000_000_000 + int(match[2])
            if ns >= 1 << 64 or (stamps and ns <= stamps[-1]):
                raise ValueError("event timestamp overflow or regression")
            stamps.append(ns)
            kind, body = match[3], match[4]
            if kind.startswith("sched:"):
                scheduler_lines.append(f"{match[1]}.{match[2]}: {kind}: {body}")
            elif kind == "syscalls:sys_enter_read":
                fields = _ENTER.fullmatch(body)
                if fields is None or pending is not None:
                    raise ValueError("malformed or overlapping read entry")
                pending = (ns, int(fields[1], 16), int(fields[2], 16))
            else:
                fields = _EXIT.fullmatch(body)
                if fields is None or int(fields[1], 16) >= 1 << 64:
                    raise ValueError("malformed read exit")
                if pending is None:
                    if len(stamps) == 1:
                        continue  # Capture can begin inside a syscall.
                    raise ValueError("read exit without matching entry")
                value = int(fields[1], 16)
                returned = value - (1 << 64) if value >= 1 << 63 else value
                start, fd, requested = pending
                if returned > requested:
                    raise ValueError("read returned more than requested")
                reads.append({"enter_ns": start, "exit_ns": ns, "fd": fd, "returned": returned})
                pending = None
        scheduler = _parse_scheduler("\n".join(scheduler_lines), target_pid)
        rows = []
        for boundary in boundaries:
            start, end = boundary["send_ns"], boundary["accepted_ns"]
            row = {"trial": boundary["trial"], "status": "excluded"}
            rows.append(row)
            if start < stamps[0] or end > stamps[-1]:
                row["exclusion"] = "outside_coverage"
                continue
            operations = [r for r in reads if start <= r["enter_ns"] <= r["exit_ns"] <= end and r["fd"] == stdin_fd]
            successful = [r for r in operations if r["returned"] == 1]
            if len(successful) != 1 or any(r["returned"] > 1 for r in operations):
                row["exclusion"] = "ambiguous_read"
                continue
            read = successful[0]
            chain = [e for e in scheduler if start <= e["timestamp_ns"] <= read["enter_ns"]]
            if [e["kind"] for e in chain] != ["waking", "wakeup", "switch_in"]:
                row["exclusion"] = "ambiguous_scheduler_chain"
                continue
            waking, wakeup, scheduled = [e["timestamp_ns"] for e in chain]
            row.update(status="included", read=read, read_attempts=len(operations), intervals_ns={
                "send_to_waking": waking - start,
                "waking_to_wakeup": wakeup - waking,
                "wakeup_to_scheduled": scheduled - wakeup,
                "send_to_scheduled": scheduled - start,
                "scheduled_to_read_enter": read["enter_ns"] - scheduled,
                "read_syscall": read["exit_ns"] - read["enter_ns"],
            })
        return {"status": "DIAGNOSTIC", "qualification": "NOT_APPLICABLE",
                "independently_verified": False, "target_pid": target_pid, "stdin_fd": stdin_fd,
                "verification_required": ["PID filters", "clock identity", "lost events", "stdin descriptor"],
                "rows": rows}
    except (ValueError, TypeError, KeyError, IndexError) as error:
        return {"status": "UNKNOWN", "qualification": "NOT_APPLICABLE", "rows": [], "errors": [str(error)]}
