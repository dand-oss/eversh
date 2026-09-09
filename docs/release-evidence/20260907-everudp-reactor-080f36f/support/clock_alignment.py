"""Fail-closed alignment of diagnostic Rust and benchmark clocks.

This module is deliberately separate from the qualification analyzer.  It
only aligns the two process-relative ``CLOCK_MONOTONIC`` domains when both
exports carry a matching host/time-namespace identity and bounded clock
anchors.  The resulting handoff intervals are syscall-observed local-edge
intervals; they are not a measurement of an exclusive kernel or network
segment.
"""

from __future__ import annotations

from typing import Any
import re


_PUBLIC_CLOCK = "CLOCK_MONOTONIC; local host and time namespace only"
_ANCHOR_CLOCK = "CLOCK_MONOTONIC"
_MAX_U64 = (1 << 64) - 1
_MAX_BRACKET_NS = 10_000
_BOOT_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= _MAX_U64:
        raise ValueError(f"{label}: expected unsigned 64-bit integer")
    return value


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label}: expected object")
    return value


def _identity(value: Any, label: str) -> dict[str, Any]:
    value = _object(value, label)
    if set(value) != {"boot_id", "time_namespace_dev", "time_namespace_ino"}:
        raise ValueError(f"{label}: malformed identity fields")
    boot_id = value["boot_id"]
    if not isinstance(boot_id, str) or _BOOT_ID.fullmatch(boot_id) is None:
        raise ValueError(f"{label}: invalid boot_id")
    return {
        "boot_id": boot_id,
        "time_namespace_dev": _int(value["time_namespace_dev"], f"{label}.time_namespace_dev"),
        "time_namespace_ino": _int(value["time_namespace_ino"], f"{label}.time_namespace_ino"),
    }


def _anchor(value: Any, label: str) -> tuple[int, int, int]:
    value = _object(value, label)
    if set(value) != {"elapsed_ns", "lower_ns", "upper_ns"}:
        raise ValueError(f"{label}: malformed anchor fields")
    elapsed = _int(value["elapsed_ns"], f"{label}.elapsed_ns")
    lower = _int(value["lower_ns"], f"{label}.lower_ns")
    upper = _int(value["upper_ns"], f"{label}.upper_ns")
    if lower > upper:
        raise ValueError(f"{label}: anchor interval regresses")
    if upper - lower > _MAX_BRACKET_NS:
        raise ValueError(f"{label}: anchor bracket is wider than {_MAX_BRACKET_NS}ns")
    return elapsed, lower, upper


def _unavailable(reason: str) -> dict[str, Any]:
    return {
        "status": "UNAVAILABLE",
        "qualification": "NOT_APPLICABLE",
        "rows": [],
        "reason": reason,
    }


def _validated_boundaries(result: dict[str, Any]) -> tuple[int, list[dict[str, int]]]:
    if result.get("public_clock") != _PUBLIC_CLOCK:
        raise ValueError("result: unsupported public clock")
    trials = result.get("trials")
    if not isinstance(trials, int) or isinstance(trials, bool) or trials <= 0:
        raise ValueError("result: invalid trials")
    boundaries = result.get("public_boundaries")
    if not isinstance(boundaries, list) or len(boundaries) != trials:
        raise ValueError("result: public_boundaries mismatch")
    normalized: list[dict[str, int]] = []
    previous_accepted = -1
    for index, boundary in enumerate(boundaries):
        boundary = _object(boundary, f"result.public_boundaries[{index}]")
        if set(boundary) != {"trial", "send_ns", "accepted_ns"}:
            raise ValueError(f"result.public_boundaries[{index}]: malformed fields")
        trial = _int(boundary["trial"], f"result.public_boundaries[{index}].trial")
        send = _int(boundary["send_ns"], f"result.public_boundaries[{index}].send_ns")
        accepted = _int(boundary["accepted_ns"], f"result.public_boundaries[{index}].accepted_ns")
        if trial != index or accepted < send or send < previous_accepted or accepted < previous_accepted:
            raise ValueError(f"result.public_boundaries[{index}]: non-monotonic boundary")
        previous_accepted = accepted
        normalized.append({"trial": trial, "send_ns": send, "accepted_ns": accepted})
    return trials, normalized


def analyze_handoffs(result: Any, validated_client: Any) -> dict[str, Any]:
    """Return bounded local handoff intervals or an unavailable report.

    ``validated_client`` is the normalized result of ``validate_trace`` from
    ``analyze_floor_attribution``.  Historical traces have no alignment or
    benchmark identity and are intentionally reported as unavailable.  A
    present but malformed diagnostic field is evidence corruption and raises
    ``ValueError`` so the caller can classify it as ``TraceInvalid``.
    """
    result = _object(result, "result")
    client = _object(validated_client, "client trace")

    alignment = client.get("clock_alignment")
    benchmark_identity = result.get("clock_identity")
    if alignment is None or benchmark_identity is None:
        return _unavailable("clock alignment or benchmark identity is absent (historical trace)")
    if not isinstance(alignment, dict):
        raise ValueError("client.clock_alignment: expected object")

    if set(alignment) != {"valid", "clock", "identity", "start", "end"}:
        raise ValueError("client.clock_alignment: malformed fields")
    if alignment["valid"] is not True or not isinstance(alignment["valid"], bool):
        raise ValueError("client.clock_alignment: anchor is not valid")
    if alignment["clock"] != _ANCHOR_CLOCK:
        raise ValueError("client.clock_alignment: unsupported clock")
    trace_identity = _identity(alignment["identity"], "client.clock_alignment.identity")
    public_identity = _identity(benchmark_identity, "result.clock_identity")
    if trace_identity != public_identity:
        raise ValueError("clock identities differ (boot or time namespace)")

    start_elapsed, start_lower, start_upper = _anchor(alignment["start"], "client.clock_alignment.start")
    end_elapsed, end_lower, end_upper = _anchor(alignment["end"], "client.clock_alignment.end")
    if start_elapsed != 0:
        raise ValueError("client.clock_alignment.start.elapsed_ns must be zero")
    if end_elapsed == 0:
        raise ValueError("client.clock_alignment.end.elapsed_ns must be positive")
    # The relationship between Rust's opaque Instant origin and the absolute
    # CLOCK_MONOTONIC value is an offset that may be signed.  Do not perform
    # u64 subtraction here; Python's signed arithmetic preserves that offset.
    end_offset = (end_lower - end_elapsed, end_upper - end_elapsed)
    offset_lower = max(start_lower, end_offset[0])
    offset_upper = min(start_upper, end_offset[1])
    if offset_lower > offset_upper:
        raise ValueError("clock anchor offset intervals do not overlap (drift)")

    trials, boundaries = _validated_boundaries(result)
    events = client.get("events")
    if not isinstance(events, list):
        raise ValueError("client.events: expected normalized event list")
    for index, event in enumerate(events):
        event = _object(event, f"client.events[{index}]")
        elapsed = _int(event.get("elapsed_ns"), f"client.events[{index}].elapsed_ns")
        if elapsed > end_elapsed:
            raise ValueError(f"client.events[{index}]: event lies outside clock anchor")

    by_sequence: dict[int, dict[str, list[dict[str, Any]]]] = {
        sequence: {"terminal_read": [], "sink_accepted": []}
        for sequence in range(1, trials + 1)
    }
    for event in events:
        stage = event.get("stage")
        sequence = event.get("sequence")
        if (stage not in ("terminal_read", "sink_accepted")
                or not isinstance(sequence, int) or isinstance(sequence, bool)
                or sequence not in by_sequence):
            continue
        by_sequence[sequence][stage].append(event)

    rows: list[dict[str, Any]] = []
    for index, boundary in enumerate(boundaries):
        sequence = index + 1
        read_events = by_sequence[sequence]["terminal_read"]
        sink_events = by_sequence[sequence]["sink_accepted"]
        if len(read_events) != 1 or len(sink_events) != 1:
            raise ValueError(f"client: sequence {sequence} needs one terminal_read and sink_accepted")
        read, sink = read_events[0], sink_events[0]
        if read.get("thread") != sink.get("thread"):
            raise ValueError(f"client: sequence {sequence} handoff markers use different threads")
        read_elapsed = _int(read.get("elapsed_ns"), f"client sequence {sequence} terminal_read")
        sink_elapsed = _int(sink.get("elapsed_ns"), f"client sequence {sequence} sink_accepted")
        if sink_elapsed < read_elapsed:
            raise ValueError(f"client: sequence {sequence} terminal_read follows sink_accepted")

        input_lower = read_elapsed + offset_lower - boundary["send_ns"]
        input_upper = read_elapsed + offset_upper - boundary["send_ns"]
        output_lower = boundary["accepted_ns"] - sink_elapsed - offset_upper
        output_upper = boundary["accepted_ns"] - sink_elapsed - offset_lower
        if input_lower < 0 or output_lower < 0:
            raise ValueError(f"client: sequence {sequence} handoff interval crosses zero")
        rows.append({
            "trial": index,
            "sequence": sequence,
            "input_handoff_ns": {"lower": input_lower, "upper": input_upper},
            "output_handoff_ns": {"lower": output_lower, "upper": output_upper},
        })

    return {
        "status": "DIAGNOSTIC",
        "qualification": "NOT_APPLICABLE",
        "integration_authorized": False,
        "clock_identity": trace_identity,
        "clock_alignment": {
            "clock": _ANCHOR_CLOCK,
            "offset_ns": {"lower": offset_lower, "upper": offset_upper},
            "uncertainty_ns": offset_upper - offset_lower,
            "start_bracket_ns": start_upper - start_lower,
            "end_bracket_ns": end_upper - end_lower,
        },
        "handoff_semantics": "Syscall-observed local terminal handoffs; intervals are not kernel/network-exclusive latency.",
        "rows": rows,
    }
