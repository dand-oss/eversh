"""Attribute the bounded ``poll(2)`` turn, without making a qualification claim.

The capture producer is responsible for proving PID filtering, monotonic clock
identity, and perf lost-event status.  This parser only consumes the sanitized
event text and the already validated public benchmark boundaries.  A poll is
included only when both syscall edges are inside one public send-to-accepted
boundary; calls crossing a boundary or a capture edge are reported as
exclusions.  No stage medians are added together here.
"""

from __future__ import annotations

from statistics import median
import re
from typing import Any

from clock_alignment import _validated_boundaries


_LINE = re.compile(
    r"\s*(\d+)\.(\d{9}):\s+"
    r"(syscalls:sys_enter_poll|syscalls:sys_exit_poll|"
    r"syscalls:sys_enter_read|syscalls:sys_exit_read):\s*(.*)"
)
_POLL_ENTER = re.compile(
    r"nfds:\s*0x([0-9a-fA-F]+),\s*timeout_msecs:\s*0x([0-9a-fA-F]+)"
)
_POLL_EXIT = re.compile(r"0x([0-9a-fA-F]+)")
_READ_ENTER = re.compile(r"fd:\s*0x([0-9a-fA-F]+),\s*count:\s*0x([0-9a-fA-F]+)")
_MAX_U64 = (1 << 64) - 1


def _sample_check(result: dict[str, Any], boundaries: list[dict[str, int]]) -> None:
    if type(result.get("transcript_failures")) is not int or result["transcript_failures"] != 0:
        raise ValueError("transcript failures or missing oracle")
    samples = result.get("samples_us")
    if not isinstance(samples, list) or len(samples) != len(boundaries):
        raise ValueError("missing public samples")
    for sample, boundary in zip(samples, boundaries):
        expected = (boundary["accepted_ns"] - boundary["send_ns"] + 999) // 1000
        if type(sample) is not int or sample <= 0 or sample != expected:
            raise ValueError("sample disagrees with public boundary")


def _hex(value: str, label: str) -> int:
    if not value or len(value) > 16:
        raise ValueError(f"{label}: oversized value")
    parsed = int(value, 16)
    if parsed > _MAX_U64:
        raise ValueError(f"{label}: value exceeds u64")
    return parsed


def analyze(result: dict[str, Any], text: str, target_pid: int) -> dict[str, Any]:
    """Return per-trial poll turns and medians, or ``UNKNOWN`` fail-closed."""
    try:
        if type(target_pid) is not int or target_pid <= 0:
            raise ValueError("invalid target pid")
        trials, boundaries = _validated_boundaries(result)
        _sample_check(result, boundaries)
        if not isinstance(text, str) or not text.strip():
            raise ValueError("empty event trace")

        stamps: list[int] = []
        polls: list[dict[str, Any]] = []
        pending: dict[str, Any] | None = None
        pending_read: int | None = None
        # (timestamp, zero-timeout status).  An unmatched exit has unknown
        # status and conservatively uses ``True`` so it cannot be attributed.
        partial_edges: list[tuple[int, bool]] = []
        seen_poll_events = 0
        for line in text.splitlines():
            match = _LINE.fullmatch(line)
            if match is None:
                raise ValueError("malformed or lost event")
            ns = int(match[1]) * 1_000_000_000 + int(match[2])
            if ns > _MAX_U64 or (stamps and ns <= stamps[-1]):
                raise ValueError("event timestamp overflow or regression")
            stamps.append(ns)
            kind, body = match[3], match[4]
            if kind == "syscalls:sys_enter_poll":
                seen_poll_events += 1
                fields = _POLL_ENTER.fullmatch(body)
                if fields is None or pending is not None or pending_read is not None:
                    raise ValueError("malformed or overlapping poll entry")
                pending = {
                    "enter_ns": ns,
                    "nfds": _hex(fields[1], "nfds"),
                    # perf exports this kernel signed-int field as an unsigned
                    # word; retain the observed bits and only test equality to
                    # zero.  Do not infer a signed schema here.
                    "timeout_msecs": _hex(fields[2], "timeout_msecs"),
                }
            elif kind == "syscalls:sys_exit_poll":
                seen_poll_events += 1
                fields = _POLL_EXIT.fullmatch(body)
                if fields is None or pending_read is not None:
                    raise ValueError("malformed poll exit")
                _hex(fields[1], "poll return")
                if pending is None:
                    if len(stamps) == 1:
                        # Capture can begin after the entry of a poll.  Keep
                        # an explicit edge marker so affected trials exclude.
                        partial_edges.append((ns, True))
                        continue
                    raise ValueError("poll exit without matching entry")
                pending["exit_ns"] = ns
                polls.append(pending)
                pending = None
            elif kind == "syscalls:sys_enter_read":
                fields = _READ_ENTER.fullmatch(body)
                if fields is None or pending is not None or pending_read is not None:
                    raise ValueError("malformed optional read entry")
                _hex(fields[1], "read fd")
                pending_read = _hex(fields[2], "read count")
            elif kind == "syscalls:sys_exit_read":
                fields = _POLL_EXIT.fullmatch(body)
                if fields is None or pending is not None:
                    raise ValueError("malformed optional read exit")
                returned = _hex(fields[1], "read return")
                if pending_read is None and len(stamps) != 1:
                    raise ValueError("orphan read exit")
                if pending_read is not None and returned < (1 << 63) and returned > pending_read:
                    raise ValueError("read returned more than requested")
                pending_read = None

        if pending is not None:
            # A final entry without an exit is an explicit capture-edge
            # exclusion, never a partially measured syscall.
            pending["partial_edge"] = True
            polls.append(pending)
            partial_edges.append((pending["enter_ns"], pending["timeout_msecs"] == 0))
        if not stamps:
            raise ValueError("empty event trace")

        rows: list[dict[str, Any]] = []
        included_counts: list[int] = []
        included_durations: list[int] = []
        included_total_durations: list[int] = []
        for boundary in boundaries:
            start, end = boundary["send_ns"], boundary["accepted_ns"]
            row: dict[str, Any] = {"trial": boundary["trial"], "status": "excluded"}
            rows.append(row)
            if start < stamps[0] or end > stamps[-1]:
                row["exclusion"] = "outside_coverage"
                continue
            if partial_edges:
                # An edge event cannot be assigned to a trial without knowing
                # its missing counterpart; make the uncertainty explicit.
                if any(
                    is_zero and start <= timestamp <= end
                    for timestamp, is_zero in partial_edges
                ):
                    row["exclusion"] = "capture_edge"
                    continue
            inside = [
                poll for poll in polls
                if "exit_ns" in poll
                and start <= poll["enter_ns"] <= poll["exit_ns"] <= end
            ]
            # A normal blocking poll commonly straddles the public send edge;
            # it is context, not a zero-time turn.  Only a zero-time poll that
            # straddles a boundary makes that trial ambiguous.
            zero_spans = [
                poll for poll in polls
                if "exit_ns" in poll
                and poll["timeout_msecs"] == 0
                and poll["enter_ns"] < end
                and poll["exit_ns"] > start
                and not (start <= poll["enter_ns"] <= poll["exit_ns"] <= end)
            ]
            if zero_spans:
                row["exclusion"] = "poll_spans_boundary"
                continue
            duration = sum(
                poll["exit_ns"] - poll["enter_ns"]
                for poll in inside
                if poll["timeout_msecs"] == 0
            )
            total_duration = sum(poll["exit_ns"] - poll["enter_ns"] for poll in inside)
            zero_count = sum(poll["timeout_msecs"] == 0 for poll in inside)
            zero_intervals = [
                [poll["enter_ns"], poll["exit_ns"]]
                for poll in inside
                if poll["timeout_msecs"] == 0
            ]
            row.update(
                status="included",
                poll_calls=len(inside),
                zero_timeout_polls=zero_count,
                # Attribution metrics are strictly zero-time polls.  Keep
                # total duration only as descriptive context.
                zero_poll_syscall_ns=duration,
                total_poll_syscall_ns=total_duration,
                zero_poll_intervals_ns=zero_intervals,
            )
            included_counts.append(zero_count)
            included_durations.append(duration)
            included_total_durations.append(total_duration)

        return {
            "status": "DIAGNOSTIC",
            "qualification": "NOT_APPLICABLE",
            "independently_verified": False,
            "target_pid": target_pid,
            "rows": rows,
            "aggregate": {
                "included_trials": len(included_counts),
                "median_zero_timeout_polls": median(included_counts) if included_counts else None,
                "median_zero_poll_syscall_ns": median(included_durations) if included_durations else None,
                "median_total_poll_syscall_ns": (
                    median(included_total_durations) if included_total_durations else None
                ),
            },
            "semantics": "Per-trial poll syscall durations; zero-time count is timeout_msecs == 0 only.",
        }
    except (ValueError, TypeError, KeyError, IndexError) as error:
        return {
            "status": "UNKNOWN",
            "qualification": "NOT_APPLICABLE",
            "rows": [],
            "errors": [str(error)],
        }
