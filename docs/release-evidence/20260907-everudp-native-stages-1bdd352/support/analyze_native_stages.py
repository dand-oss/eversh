"""Strict analysis of the opt-in native stage trace."""
from __future__ import annotations

from statistics import median
from typing import Any

from clock_alignment import _identity, _validated_boundaries
from analyze_poll_turns import _sample_check

STAGES = ("terminal_read", "encoded", "pre_offer_reactor_start", "pre_offer_reactor_end",
          "offer_start", "offer_end", "post_offer_reactor_start", "post_offer_reactor_end",
          "sink_accepted")
INTERVALS = (
    ("encoding", "terminal_read", "encoded"),
    ("encoded_to_pre_offer", "encoded", "pre_offer_reactor_start"),
    ("pre_offer_reactor", "pre_offer_reactor_start", "pre_offer_reactor_end"),
    ("pre_offer_to_offer", "pre_offer_reactor_end", "offer_start"),
    ("offer", "offer_start", "offer_end"),
    ("offer_to_post_offer", "offer_end", "post_offer_reactor_start"),
    ("post_offer_reactor", "post_offer_reactor_start", "post_offer_reactor_end"),
)


def _bad(message: str) -> dict[str, Any]:
    return {"status": "UNKNOWN", "qualification": "NOT_APPLICABLE", "rows": [], "reason": message}


def _int(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value < (1 << 64):
        raise ValueError(f"{label}: expected non-negative integer")
    return value


def _first_attempt(events: list[dict[str, Any]]) -> tuple[dict[str, dict[str, int]] | None, str | None]:
    for anchor in ("terminal_read", "encoded", "sink_accepted"):
        if sum(event["stage"] == anchor for event in events) != 1:
            raise ValueError("missing or duplicate terminal anchor")
    if [event["stage"] for event in events[:2]] != list(STAGES[:2]) or events[-1]["stage"] != "sink_accepted":
        raise ValueError("terminal anchor order")
    middle = events[2:-1]
    cursor, accepted = 0, 0
    first = None
    attempts = 0
    while cursor < len(middle):
        start = cursor
        if [e["stage"] for e in middle[cursor:cursor + 2]] != list(STAGES[2:4]):
            raise ValueError("pre-offer pair malformed")
        cursor += 2
        if cursor == len(middle) and accepted:
            break  # A due retry's pre-drive received the echo before offering.
        if [e["stage"] for e in middle[cursor:cursor + 2]] != list(STAGES[4:6]):
            raise ValueError("offer pair malformed")
        cursor += 2
        if cursor < len(middle) and middle[cursor]["stage"] == "post_offer_reactor_start":
            if [e["stage"] for e in middle[cursor:cursor + 2]] != list(STAGES[6:8]):
                raise ValueError("post-offer pair malformed")
            cursor += 2
            accepted += 1
            if attempts == 0:
                first = {event["stage"]: event for event in events[:2] + middle[start:cursor] + events[-1:]}
        attempts += 1
    if not accepted:
        raise ValueError("sink without a completed accepted offer")
    return (first, None) if first is not None else (None, "first_offer_blocked")


def analyze(result: dict[str, Any], trace: dict[str, Any]) -> dict[str, Any]:
    try:
        trials, boundaries = _validated_boundaries(result)
        _sample_check(result, boundaries)
        if not isinstance(trace, dict) or trace.get("diagnostic_only") is not True:
            raise ValueError("trace is not diagnostic-only")
        if set(trace) != {"schema_version", "diagnostic_only", "wall_clock", "cpu_clock", "sample_order",
                          "valid", "run_succeeded", "capacity", "overflow", "identity",
                          "cpu_clock_calibration_ns", "events"}:
            raise ValueError("unexpected trace fields")
        if type(trace.get("schema_version")) is not int or trace["schema_version"] != 1:
            raise ValueError("invalid trace schema")
        if trace.get("wall_clock") != "CLOCK_MONOTONIC" or trace.get("cpu_clock") != "CLOCK_THREAD_CPUTIME_ID":
            raise ValueError("trace clock labels are invalid")
        if trace.get("sample_order") != "wall_then_cpu_not_simultaneous":
            raise ValueError("trace sample order is invalid")
        if trace.get("run_succeeded") is not True or trace.get("valid") is not True or trace.get("overflow") is not False:
            raise ValueError("trace is invalid or incomplete")
        capacity = _int(trace.get("capacity"), "trace.capacity")
        if not 0 < capacity <= 8192:
            raise ValueError("trace capacity is outside the native recorder contract")
        calibration = trace.get("cpu_clock_calibration_ns")
        if not isinstance(calibration, list) or len(calibration) != 16:
            raise ValueError("missing clock calibration")
        for sample in calibration:
            _int(sample, "calibration")
        identity = trace.get("identity")
        if not isinstance(identity, dict) or set(identity) != {"pid", "tid", "boot_id", "time_namespace_dev", "time_namespace_ino"}:
            raise ValueError("trace identity is malformed")
        pid = _int(identity["pid"], "trace.pid"); tid = _int(identity["tid"], "trace.tid")
        if pid <= 0 or tid <= 0 or not isinstance(identity["boot_id"], str):
            raise ValueError("trace identity values are invalid")
        _int(identity["time_namespace_dev"], "namespace device")
        _int(identity["time_namespace_ino"], "namespace inode")
        public_identity = _identity(result.get("clock_identity"), "public clock")
        if identity["boot_id"] != public_identity["boot_id"] or identity["time_namespace_dev"] != public_identity["time_namespace_dev"] or identity["time_namespace_ino"] != public_identity["time_namespace_ino"]:
            raise ValueError("trace and public clock identities differ")
        events = trace.get("events")
        if not isinstance(events, list) or not events:
            raise ValueError("trace events are missing")
        if len(events) > capacity:
            raise ValueError("trace exceeds recorded capacity")
        normalized: list[dict[str, Any]] = []
        previous_wall = previous_cpu = previous_sequence = -1
        for index, event in enumerate(events):
            if not isinstance(event, dict) or set(event) != {"time_ns", "cpu_time_ns", "stage", "sequence"}:
                raise ValueError(f"event {index} fields are invalid")
            wall = _int(event["time_ns"], f"event {index}.time_ns"); cpu = _int(event["cpu_time_ns"], f"event {index}.cpu_time_ns")
            if wall < previous_wall or cpu < previous_cpu or event["stage"] not in STAGES:
                raise ValueError(f"event {index} clocks or stage are invalid")
            sequence = _int(event["sequence"], f"event {index}.sequence")
            if sequence > trials:
                raise ValueError(f"event {index} sequence is outside trial range")
            if sequence < previous_sequence:
                raise ValueError("interleaved or regressing input sequences")
            previous_sequence = sequence
            previous_wall, previous_cpu = wall, cpu
            normalized.append({"time_ns": wall, "cpu_time_ns": cpu, "stage": event["stage"], "sequence": sequence})
        grouped = {sequence: [] for sequence in range(trials + 1)}
        for event in normalized:
            grouped[event["sequence"]].append(event)
        _first_attempt(grouped[0])  # Validate warmup, but do not measure it.
        rows = []
        for trial, boundary in enumerate(boundaries):
            sequence = trial + 1
            attempt, reason = _first_attempt(grouped[sequence])
            row: dict[str, Any] = {"trial": trial, "sequence": sequence, "window_ns": [boundary["send_ns"], boundary["accepted_ns"]]}
            if attempt is None:
                row.update(status="excluded", exclusion=reason)
                rows.append(row); continue
            start, end = boundary["send_ns"], boundary["accepted_ns"]
            if attempt["terminal_read"]["time_ns"] < start or attempt["post_offer_reactor_end"]["time_ns"] > end:
                row.update(status="excluded", exclusion="attempt_outside_public_window")
            elif attempt["sink_accepted"]["time_ns"] < start or attempt["sink_accepted"]["time_ns"] > end:
                row.update(status="excluded", exclusion="sink_outside_public_window")
            else:
                wall = {name: attempt[b]["time_ns"] - attempt[a]["time_ns"] for name, a, b in INTERVALS}
                cpu = {name: attempt[b]["cpu_time_ns"] - attempt[a]["cpu_time_ns"] for name, a, b in INTERVALS}
                row.update(status="included", intervals_ns={"wall": wall, "thread_cpu": cpu})
            rows.append(row)
        included = [row for row in rows if row["status"] == "included"]
        aggregate = {clock: {name: median(row["intervals_ns"][clock][name] for row in included) for name, _, _ in INTERVALS} for clock in ("wall", "thread_cpu")} if included else {"wall": {}, "thread_cpu": {}}
        return {"status": "DIAGNOSTIC", "qualification": "NOT_APPLICABLE", "target_pid": pid, "target_tid": tid, "rows": rows, "included_trials": len(included), "aggregate_medians_ns": aggregate, "limitation": "Stage intervals are observed wall and thread-CPU samples; no causal scheduler or CPU inference."}
    except (ValueError, KeyError, TypeError) as error:
        return _bad(str(error))
