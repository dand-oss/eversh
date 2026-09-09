"""Strict validation of the bounded everudp reactor-work trace."""

from __future__ import annotations

from typing import Any

from analyze_poll_turns import _sample_check
from clock_alignment import _identity, _validated_boundaries

_MAX_U64 = (1 << 64) - 1
_PROTOCOL = "everudp-reactor-work-v1"
_PHASES = ("loop_top", "initial_post_offer", "retry_post_offer")
_ANCHORS = ("input_read", "sink_accepted")
_TOP_FIELDS = {
    "schema_version", "protocol", "diagnostic_only", "wall_clock", "cpu_clock",
    "sample_order", "valid", "run_succeeded", "capacity", "overflow", "identity",
    "cpu_clock_calibration_ns", "events",
}
_ANCHOR_FIELDS = {
    "kind", "anchor", "sequence", "begin_time_ns", "begin_cpu_time_ns",
    "end_time_ns", "end_cpu_time_ns", "clock_valid",
}
_PUMP_FIELDS = {
    "deferred_receives", "deferred_receives_queued", "timers_handled", "endpoint_events",
    "application_events_enqueued", "transmits_generated", "connections_retired", "overflow",
}
_RESULT_FIELDS = {"work", "exhausted", "write_blocked"}
_STEP_FIELDS = {
    "kind", "phase", "sequence", "timer_due", "begin_time_ns", "begin_cpu_time_ns",
    "end_time_ns", "end_cpu_time_ns", "clock_valid", "pump_drive_calls", "send_attempts",
    "send_accepted", "send_would_block", "send_interrupted", "receive_calls", "receive_batches",
    "receive_datagrams", "receive_empty", "receive_would_block", "retained_gro_segments_delivered",
    "overflow", "events_drained", "application_ready", "pump", "result",
}


def _bad(reason: str) -> dict[str, Any]:
    return {
        "status": "UNKNOWN",
        "qualification": "NOT_APPLICABLE",
        "rows": [],
        "reason": reason,
    }


def _uint(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_U64:
        raise ValueError(f"{label}: expected unsigned 64-bit integer")
    return value


def _bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{label}: expected boolean")
    return value


def _fixed_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label}: malformed fields")
    return value


def _stamp(event: dict[str, Any], label: str) -> tuple[int, int, int, int]:
    begin_wall = _uint(event["begin_time_ns"], f"{label}.begin_time_ns")
    begin_cpu = _uint(event["begin_cpu_time_ns"], f"{label}.begin_cpu_time_ns")
    end_wall = _uint(event["end_time_ns"], f"{label}.end_time_ns")
    end_cpu = _uint(event["end_cpu_time_ns"], f"{label}.end_cpu_time_ns")
    if end_wall < begin_wall or end_cpu < begin_cpu:
        raise ValueError(f"{label}: clock interval regresses")
    if _bool(event["clock_valid"], f"{label}.clock_valid") is not True:
        raise ValueError(f"{label}: invalid clock sample")
    return begin_wall, begin_cpu, end_wall, end_cpu


def _work_fields(event: dict[str, Any], label: str, trials: int) -> None:
    for field in (
        "pump_drive_calls", "send_attempts", "send_accepted", "send_would_block",
        "send_interrupted", "receive_calls", "receive_batches", "receive_datagrams",
        "receive_empty", "receive_would_block", "retained_gro_segments_delivered", "events_drained",
    ):
        _uint(event[field], f"{label}.{field}")
    _bool(event["overflow"], f"{label}.overflow")
    if event["overflow"]:
        raise ValueError(f"{label}: counter overflow")
    _bool(event["timer_due"], f"{label}.timer_due")
    _bool(event["application_ready"], f"{label}.application_ready")
    pump = _fixed_object(event["pump"], _PUMP_FIELDS, f"{label}.pump")
    for field in _PUMP_FIELDS - {"overflow"}:
        _uint(pump[field], f"{label}.pump.{field}")
    _bool(pump["overflow"], f"{label}.pump.overflow")
    if pump["overflow"]:
        raise ValueError(f"{label}: pump counter overflow")
    result = _fixed_object(event["result"], _RESULT_FIELDS, f"{label}.result")
    if _uint(result["work"], f"{label}.result.work") > 64:
        raise ValueError(f"{label}.result.work exceeds bounded turn budget")
    _bool(result["exhausted"], f"{label}.result.exhausted")
    _bool(result["write_blocked"], f"{label}.result.write_blocked")
    # A sequence is retained only while input is outstanding.  This check is
    # kept here as a contract reminder; range validation happens at the row.
    _uint(event["sequence"], f"{label}.sequence")
    if event["sequence"] > trials:
        raise ValueError(f"{label}: sequence outside outstanding range")


def _step_summary(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase": event["phase"],
        "duration_ns": {"wall": event["end_wall"] - event["begin_wall"],
                        "thread_cpu": event["end_cpu"] - event["begin_cpu"]},
        "sequence": event["sequence"],
        "timer_due": event["timer_due"],
        "pump_drive_calls": event["pump_drive_calls"],
        "send_attempts": event["send_attempts"],
        "send_accepted": event["send_accepted"],
        "send_would_block": event["send_would_block"],
        "send_interrupted": event["send_interrupted"],
        "receive_calls": event["receive_calls"],
        "receive_batches": event["receive_batches"],
        "receive_datagrams": event["receive_datagrams"],
        "receive_empty": event["receive_empty"],
        "receive_would_block": event["receive_would_block"],
        "retained_gro_segments_delivered": event["retained_gro_segments_delivered"],
        "events_drained": event["events_drained"],
        "application_ready": event["application_ready"],
        "pump": dict(event["pump"]),
        "result": dict(event["result"]),
    }


def analyze(result: dict[str, Any], trace: dict[str, Any]) -> dict[str, Any]:
    """Validate a trace and report bounded initial-offer/loop-top pairs."""
    try:
        trials, boundaries = _validated_boundaries(result)
        _sample_check(result, boundaries)
        trace = _fixed_object(trace, _TOP_FIELDS, "trace")
        if trace["schema_version"] != 1 or type(trace["schema_version"]) is not int:
            raise ValueError("unsupported reactor trace schema")
        if trace["protocol"] != _PROTOCOL:
            raise ValueError("unsupported reactor trace protocol")
        if trace["diagnostic_only"] is not True or type(trace["diagnostic_only"]) is not bool:
            raise ValueError("trace is not diagnostic-only")
        if trace["wall_clock"] != "CLOCK_MONOTONIC" or trace["cpu_clock"] != "CLOCK_THREAD_CPUTIME_ID":
            raise ValueError("trace clock labels are invalid")
        if trace["sample_order"] != "wall_then_cpu_not_simultaneous":
            raise ValueError("trace sample order is invalid")
        if trace["run_succeeded"] is not True or trace["valid"] is not True:
            raise ValueError("trace is invalid or incomplete")
        if trace["overflow"] is not False or type(trace["overflow"]) is not bool:
            raise ValueError("trace reports overflow")
        capacity = _uint(trace["capacity"], "trace.capacity")
        if not 0 < capacity <= 8192:
            raise ValueError("trace capacity outside bounded recorder contract")
        calibration = trace["cpu_clock_calibration_ns"]
        if not isinstance(calibration, list) or len(calibration) != 16:
            raise ValueError("trace clock calibration is malformed")
        for index, sample in enumerate(calibration):
            _uint(sample, f"calibration[{index}]")
        identity = _fixed_object(
            trace["identity"],
            {"pid", "tid", "boot_id", "time_namespace_dev", "time_namespace_ino"},
            "trace.identity",
        )
        pid = _uint(identity["pid"], "trace.identity.pid")
        tid = _uint(identity["tid"], "trace.identity.tid")
        if pid == 0 or tid == 0:
            raise ValueError("trace identity pid/tid must be positive")
        public_identity = _identity(result.get("clock_identity"), "public clock")
        trace_identity = _identity(
            {
                "boot_id": identity["boot_id"],
                "time_namespace_dev": identity["time_namespace_dev"],
                "time_namespace_ino": identity["time_namespace_ino"],
            },
            "trace identity",
        )
        if trace_identity != public_identity:
            raise ValueError("trace and public clock identities differ")

        events = trace["events"]
        if not isinstance(events, list) or not events:
            raise ValueError("trace events are missing")
        if len(events) > capacity:
            raise ValueError("trace exceeds recorder capacity")
        normalized: list[dict[str, Any]] = []
        previous_end_wall = previous_end_cpu = -1
        previous_sequence = -1
        for index, raw in enumerate(events):
            label = f"event[{index}]"
            if not isinstance(raw, dict) or "kind" not in raw:
                raise ValueError(f"{label}: malformed event")
            kind = raw["kind"]
            if kind == "anchor":
                event = _fixed_object(raw, _ANCHOR_FIELDS, label)
                if event["anchor"] not in _ANCHORS:
                    raise ValueError(f"{label}: unknown anchor")
                sequence = _uint(event["sequence"], f"{label}.sequence")
                if sequence > trials:
                    raise ValueError(f"{label}: sequence outside outstanding range")
                begin_wall, begin_cpu, end_wall, end_cpu = _stamp(event, label)
                if begin_wall != end_wall or begin_cpu != end_cpu:
                    raise ValueError(f"{label}: anchor must be a single stamp")
                if begin_wall < previous_end_wall or begin_cpu < previous_end_cpu:
                    raise ValueError(f"{label}: global clock ordering regresses")
                normalized.append({"kind": kind, "anchor": event["anchor"], "sequence": sequence,
                                   "begin_wall": begin_wall, "begin_cpu": begin_cpu,
                                   "end_wall": end_wall, "end_cpu": end_cpu})
            elif kind == "step":
                event = _fixed_object(raw, _STEP_FIELDS, label)
                if event["phase"] not in _PHASES:
                    raise ValueError(f"{label}: unknown phase")
                begin_wall, begin_cpu, end_wall, end_cpu = _stamp(event, label)
                _work_fields(event, label, trials)
                sequence = event["sequence"]
                if sequence < previous_sequence:
                    raise ValueError(f"{label}: sequence regresses")
                if begin_wall < previous_end_wall or begin_cpu < previous_end_cpu:
                    raise ValueError(f"{label}: global clock ordering regresses")
                normalized.append({"kind": kind, "phase": event["phase"], "sequence": sequence,
                                   "begin_wall": begin_wall, "begin_cpu": begin_cpu,
                                   "end_wall": end_wall, "end_cpu": end_cpu, **event})
            else:
                raise ValueError(f"{label}: unknown event kind")
            if sequence < previous_sequence:
                raise ValueError(f"{label}: sequence regresses")
            previous_sequence = sequence
            previous_end_wall, previous_end_cpu = end_wall, end_cpu

        groups = {sequence: [] for sequence in range(trials + 1)}
        for event in normalized:
            groups[event["sequence"]].append(event)
        rows: list[dict[str, Any]] = []
        initial_pairs: list[dict[str, Any]] = []
        for sequence in range(trials + 1):
            group = groups[sequence]
            if not group:
                raise ValueError(f"sequence {sequence} has no outstanding observations")
            anchors = [event for event in group if event["kind"] == "anchor"]
            if [event["anchor"] for event in anchors] != ["input_read", "sink_accepted"]:
                raise ValueError(f"sequence {sequence}: expected input_read then sink_accepted")
            input_index = group.index(anchors[0])
            sink_index = group.index(anchors[1])
            if input_index != 0 or sink_index != len(group) - 1:
                raise ValueError(f"sequence {sequence}: anchors do not enclose steps")
            steps = group[1:-1]
            if not steps or steps[-1].get("phase") != "loop_top":
                raise ValueError(f"sequence {sequence}: sink requires a loop_top turn")
            for event in steps:
                if event["kind"] != "step":
                    raise ValueError(f"sequence {sequence}: non-step inside anchor window")
            initial_indices = [
                index for index, event in enumerate(steps)
                if event["phase"] == "initial_post_offer"
            ]
            if len(initial_indices) > 1:
                raise ValueError(f"sequence {sequence}: duplicate initial offer step")
            if initial_indices and initial_indices != [0]:
                raise ValueError(f"sequence {sequence}: initial offer must be first step")
            for index, event in enumerate(steps):
                if event["phase"] == "retry_post_offer" and (
                    index == 0 or steps[index - 1]["phase"] != "loop_top"
                    or index + 1 == len(steps) or steps[index + 1]["phase"] != "loop_top"
                ):
                    raise ValueError(f"sequence {sequence}: retry must be between loop_top turns")
            sequence_pairs = []
            for index in initial_indices:
                if index + 1 >= len(steps):
                    raise ValueError(f"sequence {sequence}: initial offer lacks immediate loop_top")
                event = steps[index]
                following = steps[index + 1]
                if following["phase"] != "loop_top":
                    raise ValueError(f"sequence {sequence}: initial offer lacks immediate loop_top")
                sequence_pairs.append({
                    "sequence": sequence,
                    "wall_ns": following["begin_wall"] - event["end_wall"],
                    "thread_cpu_ns": following["begin_cpu"] - event["end_cpu"],
                    "initial_post_offer": _step_summary(event),
                    "following_loop_top": _step_summary(following),
                })
            if sequence == 0:
                continue
            boundary = boundaries[sequence - 1]
            outside = any(
                event["begin_wall"] < boundary["send_ns"]
                or event["end_wall"] > boundary["accepted_ns"]
                for event in group
            )
            row = {
                "trial": sequence - 1,
                "sequence": sequence,
                "window_ns": [boundary["send_ns"], boundary["accepted_ns"]],
                "steps": len(steps),
                "initial_post_offer_pairs": sum(
                    pair["sequence"] == sequence for pair in sequence_pairs
                ),
            }
            if outside:
                row.update(status="excluded", exclusion="event_outside_public_window")
            elif not sequence_pairs:
                row.update(status="excluded", exclusion="initial_offer_blocked")
            else:
                row["status"] = "included"
                initial_pairs.extend(sequence_pairs)
            rows.append(row)
        return {
            "status": "DIAGNOSTIC",
            "qualification": "NOT_APPLICABLE",
            "integration_authorized": False,
            "target_pid": pid,
            "target_tid": tid,
            "rows": rows,
            "initial_post_offer_pairs": initial_pairs,
            "included_sequences": sum(row["status"] == "included" for row in rows),
            "limitation": "Step durations include event draining. Sequential wall/CPU samples and work counters do not prove a turn can be skipped or establish causal savings. Warmup and excluded pairs are not aggregated.",
        }
    except (ValueError, KeyError, TypeError, IndexError) as error:
        return _bad(str(error))
