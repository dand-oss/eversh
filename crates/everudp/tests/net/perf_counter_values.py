"""Fail-closed decoding of perf stat JSON counter values.

This parser normalizes only the counters used by the hardware-counter
preflight.  It reports counts and arithmetic ratios; it does not infer CPU
time, stalls, causality, or scheduler behavior from the counters.
"""

from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any


_EVENTS = ("cycles:u", "instructions:u", "cache-misses:u")
_FIELDS = {"counter-value", "unit", "event", "event-runtime", "pcnt-running"}
_COUNT_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
_MAX_U64 = (1 << 64) - 1
_MAX_BYTES = 64 * 1024


def _count(value: Any, label: str) -> int:
    if not isinstance(value, str) or not _COUNT_RE.fullmatch(value):
        raise ValueError(f"{label}: expected a nonnegative decimal count")
    try:
        decimal = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"{label}: invalid decimal count") from exc
    if not decimal.is_finite() or not decimal == decimal.to_integral_value():
        raise ValueError(f"{label}: count is not an integer")
    count = int(decimal)
    if count > _MAX_U64:
        raise ValueError(f"{label}: count exceeds unsigned 64-bit bound")
    return count


def _runtime(value: Any, label: str) -> int:
    if type(value) is not int or not 0 < value <= _MAX_U64:
        raise ValueError(f"{label}: expected a positive unsigned integer")
    return value


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    record = {}
    for key, value in pairs:
        if key in record:
            raise ValueError(f"duplicate JSON field: {key}")
        record[key] = value
    return record


def parse_counter_values(text: str, *, grouped: bool = False) -> dict[str, Any]:
    """Parse the exact three-event perf preflight export.

    Every line must be one JSON object with exactly the five fields emitted by
    the verified perf invocation. Each event must have a positive runtime and
    complete multiplexing coverage; runtimes are reported individually because
    ungrouped perf events can differ slightly. Derived values are plain ratios
    only; no timing or causal interpretation is made. Grouped captures must
    additionally report identical runtimes for all events.
    """
    if not isinstance(text, str) or not text or len(text.encode("utf-8")) > _MAX_BYTES:
        raise ValueError("counter export is empty, non-text, or exceeds the bound")

    records: list[dict[str, Any]] = []
    for index, line in enumerate(text.splitlines()):
        if not line.strip():
            raise ValueError(f"record {index}: blank line")
        try:
            record = json.loads(line, object_pairs_hook=_unique_fields)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"record {index}: malformed JSON") from exc
        if not isinstance(record, dict) or set(record) != _FIELDS:
            raise ValueError(f"record {index}: unexpected perf fields")
        records.append(record)
    if len(records) != len(_EVENTS):
        raise ValueError("counter export must contain exactly three records")

    counts: dict[str, int] = {}
    runtimes: dict[str, int] = {}
    for index, record in enumerate(records):
        event = record["event"]
        if not isinstance(event, str) or event not in _EVENTS or event in counts:
            raise ValueError(f"record {index}: missing, unknown, or duplicate event")
        if record["unit"] != "" or not isinstance(record["unit"], str):
            raise ValueError(f"record {index}: unsupported counter unit")
        count = _count(record["counter-value"], f"record {index}.counter-value")
        record_runtime = _runtime(record["event-runtime"], f"record {index}.event-runtime")
        running = record["pcnt-running"]
        if type(running) is not float or running != 100.0:
            raise ValueError(f"record {index}: counter was not fully counted")
        counts[event] = count
        runtimes[event] = record_runtime

    if set(counts) != set(_EVENTS):
        raise ValueError("counter export is missing a required event")
    if grouped and len(set(runtimes.values())) != 1:
        raise ValueError("grouped counters have different runtimes")
    cycles = counts["cycles:u"]
    instructions = counts["instructions:u"]
    if cycles == 0 or instructions == 0:
        raise ValueError("cannot derive ratios with a zero denominator")
    return {
        "events": list(_EVENTS),
        "counts": {event: counts[event] for event in _EVENTS},
        "runtime": {event: runtimes[event] for event in _EVENTS},
        "ipc": instructions / cycles,
        "cache_misses_per_instruction": counts["cache-misses:u"] / instructions,
    }
