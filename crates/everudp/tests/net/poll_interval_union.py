"""Union client/server zero-time poll intervals for diagnostic attribution.

This is deliberately not a qualification analyzer.  It joins only rows that
were already included independently by the two poll-turn analyzers, validates
their public trial windows, and computes the set union without double-counting
overlap between processes.
"""

from __future__ import annotations

import math
from statistics import median
from typing import Any

from clock_alignment import _validated_boundaries
from analyze_poll_turns import _sample_check


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label}: expected non-negative integer")
    return value


def _nearest_rank(values: list[int], probability: float) -> int:
    if not values:
        raise ValueError("cannot take a quantile of no samples")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def _report_rows(
    report: Any,
    label: str,
    trials: int,
    boundaries: list[dict[str, int]],
) -> tuple[int, dict[int, dict[str, Any]]]:
    if not isinstance(report, dict) or report.get("status") != "DIAGNOSTIC":
        raise ValueError(f"{label}: report is not diagnostic")
    target_pid = _integer(report.get("target_pid"), f"{label}.target_pid")
    if target_pid <= 0:
        raise ValueError(f"{label}.target_pid: must be positive")
    rows = report.get("rows")
    if not isinstance(rows, list) or len(rows) != trials:
        raise ValueError(f"{label}.rows: expected one row per trial")
    by_trial: dict[int, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{label}.rows[{index}]: expected object")
        trial = row.get("trial")
        if type(trial) is not int or trial < 0 or trial >= trials or trial in by_trial:
            raise ValueError(f"{label}.rows[{index}]: duplicate or invalid trial")
        status = row.get("status")
        if status not in ("included", "excluded"):
            raise ValueError(f"{label}.rows[{index}]: invalid status")
        if status == "excluded":
            reason = row.get("exclusion")
            if not isinstance(reason, str) or not reason:
                raise ValueError(f"{label}.rows[{index}]: missing exclusion reason")
            by_trial[trial] = {"trial": trial, "status": status, "exclusion": reason}
            continue

        intervals = row.get("zero_poll_intervals_ns")
        if not isinstance(intervals, list):
            raise ValueError(f"{label}.rows[{index}]: missing zero intervals")
        normalized: list[list[int]] = []
        previous_end: int | None = None
        for interval_index, interval in enumerate(intervals):
            if (
                not isinstance(interval, list)
                or len(interval) != 2
            ):
                raise ValueError(f"{label}.rows[{index}].zero_poll_intervals_ns[{interval_index}]: malformed")
            start = _integer(interval[0], f"{label}.rows[{index}].interval start")
            end = _integer(interval[1], f"{label}.rows[{index}].interval end")
            if end <= start:
                raise ValueError(f"{label}.rows[{index}]: interval reverses")
            if previous_end is not None and start < previous_end:
                raise ValueError(f"{label}.rows[{index}]: intervals are not ordered")
            previous_end = end
            boundary = boundaries[trial]
            if start < boundary["send_ns"] or end > boundary["accepted_ns"]:
                raise ValueError(f"{label}.rows[{index}]: interval outside public window")
            normalized.append([start, end])

        count = row.get("zero_timeout_polls")
        duration = row.get("zero_poll_syscall_ns")
        if type(count) is not int or count < 0 or count != len(normalized):
            raise ValueError(f"{label}.rows[{index}]: zero count mismatch")
        expected_duration = sum(end - start for start, end in normalized)
        if type(duration) is not int or duration < 0 or duration != expected_duration:
            raise ValueError(f"{label}.rows[{index}]: zero duration mismatch")
        by_trial[trial] = {
            "trial": trial,
            "status": status,
            "intervals": normalized,
            "count": count,
            "duration": duration,
        }
    if set(by_trial) != set(range(trials)):
        raise ValueError(f"{label}.rows: trial IDs are incomplete")
    return target_pid, by_trial


def _union(intervals: list[list[int]]) -> tuple[list[list[int]], int]:
    if not intervals:
        return [], 0
    ordered = sorted(intervals)
    merged: list[list[int]] = [ordered[0][:]]
    for start, end in ordered[1:]:
        current = merged[-1]
        if start <= current[1]:
            current[1] = max(current[1], end)
        else:
            merged.append([start, end])
    return merged, sum(end - start for start, end in merged)


def combine(result: dict[str, Any], client_report: Any, server_report: Any) -> dict[str, Any]:
    """Return a bounded client/server interval union, or ``UNKNOWN``."""
    try:
        trials, boundaries = _validated_boundaries(result)
        _sample_check(result, boundaries)
        client_pid, client = _report_rows(client_report, "client", trials, boundaries)
        server_pid, server = _report_rows(server_report, "server", trials, boundaries)
        if client_pid == server_pid:
            raise ValueError("client and server target PIDs must differ")

        rows: list[dict[str, Any]] = []
        samples: list[int] = []
        for trial in range(trials):
            left, right = client[trial], server[trial]
            if left["status"] != "included" or right["status"] != "included":
                excluded: dict[str, Any] = {"trial": trial, "status": "excluded"}
                if left["status"] != "included":
                    excluded["client_exclusion"] = left["exclusion"]
                if right["status"] != "included":
                    excluded["server_exclusion"] = right["exclusion"]
                reasons = [
                    side for side, item in (("client", left), ("server", right))
                    if item["status"] != "included"
                ]
                excluded["exclusion"] = "_and_".join(reasons) + "_excluded"
                rows.append(excluded)
                continue
            intervals, union_ns = _union(left["intervals"] + right["intervals"])
            row = {
                "trial": trial,
                "status": "included",
                "union_ns": union_ns,
                "union_intervals_ns": intervals,
                "client_zero_timeout_polls": left["count"],
                "server_zero_timeout_polls": right["count"],
            }
            rows.append(row)
            samples.append(union_ns)

        return {
            "status": "DIAGNOSTIC",
            "qualification": "NOT_APPLICABLE",
            "independently_verified": False,
            "client_target_pid": client_pid,
            "server_target_pid": server_pid,
            "rows": rows,
            "aggregate": {
                "included_trials": len(samples),
                "median_union_ns": median(samples) if samples else None,
                "p95_union_ns": _nearest_rank(samples, 0.95) if samples else None,
            },
            "semantics": "Union of independently validated zero-time poll intervals; overlap is counted once.",
        }
    except (ValueError, TypeError, KeyError, IndexError) as error:
        return {
            "status": "UNKNOWN",
            "qualification": "NOT_APPLICABLE",
            "rows": [],
            "errors": [str(error)],
        }
