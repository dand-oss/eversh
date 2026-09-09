#!/usr/bin/env python3
"""Diagnostic attribution of scheduler wake-up chains.

The scheduler trace is an aid for explaining a local handoff interval.  It is
not a qualification input and it cannot establish an exclusive kernel,
runtime, or network latency.  In particular, callers must independently
verify the perf clock id, tracing time namespace, and lost-event count.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any

from analyze_floor_attribution import TraceInvalid, analyze as analyze_floor, validate_trace
from clock_alignment import analyze_handoffs


_LINE = re.compile(r"^(?P<seconds>[0-9]+)\.(?P<fraction>[0-9]{9}): sched:(?P<kind>sched_waking|sched_wakeup|sched_switch): (?P<body>.*)$")
_WAKE = re.compile(
    r"^comm=(?P<comm>[^\n]{1,16}?) pid=(?P<pid>[0-9]+) prio=(?P<prio>-?[0-9]+) target_cpu=(?P<cpu>[0-9]+)$"
)
_SWITCH = re.compile(
    r"^prev_comm=(?P<prev_comm>[^\n]{1,16}?) prev_pid=(?P<prev_pid>[0-9]+) "
    r"prev_prio=(?P<prev_prio>-?[0-9]+) prev_state=(?P<prev_state>[^ ]+) ==> "
    r"next_comm=(?P<next_comm>[^\n]{1,16}?) next_pid=(?P<next_pid>[0-9]+) "
    r"next_prio=(?P<next_prio>-?[0-9]+)$"
)


def _parse_scheduler(text: str, target_pid: int) -> list[dict[str, Any]]:
    if not isinstance(text, str):
        raise TraceInvalid("scheduler: text must be a string")
    if not isinstance(target_pid, int) or isinstance(target_pid, bool) or target_pid <= 0:
        raise TraceInvalid("scheduler: target_pid must be a positive integer")
    records: list[dict[str, Any]] = []
    previous = -1
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = _LINE.fullmatch(line)
        if match is None:
            raise TraceInvalid(f"scheduler line {line_number}: malformed record")
        timestamp = int(match["seconds"]) * 1_000_000_000 + int(match["fraction"])
        if timestamp > (1 << 64) - 1 or timestamp <= previous:
            raise TraceInvalid(f"scheduler line {line_number}: timestamp regresses")
        previous = timestamp
        kind = match["kind"]
        body = match["body"]
        if kind in ("sched_waking", "sched_wakeup"):
            fields = _WAKE.fullmatch(body)
            if fields is None or int(fields["pid"]) != target_pid:
                raise TraceInvalid(f"scheduler line {line_number}: wake record targets another pid")
            records.append({
                "timestamp_ns": timestamp,
                "kind": "waking" if kind == "sched_waking" else "wakeup",
                "pid": target_pid,
                "cpu": int(fields["cpu"]),
            })
            continue
        fields = _SWITCH.fullmatch(body)
        if fields is None:
            raise TraceInvalid(f"scheduler line {line_number}: malformed switch record")
        previous_pid = int(fields["prev_pid"])
        next_pid = int(fields["next_pid"])
        if target_pid not in (previous_pid, next_pid):
            raise TraceInvalid(f"scheduler line {line_number}: switch does not involve target pid")
        if previous_pid == next_pid:
            raise TraceInvalid(f"scheduler line {line_number}: switch does not change tasks")
        if next_pid == target_pid:
            switch_kind = "switch_in"
        else:
            switch_kind = "switch_out"
        records.append({
            "timestamp_ns": timestamp,
            "kind": switch_kind,
            "pid": target_pid,
            "prev_pid": previous_pid,
            "next_pid": next_pid,
        })
    if not records:
        raise TraceInvalid("scheduler: no records")
    return records


def _invalid(reason: str) -> dict[str, Any]:
    return {
        "status": "UNKNOWN",
        "qualification": "NOT_APPLICABLE",
        "integration_authorized": False,
        "independently_verified": False,
        "rows": [],
        "errors": [reason],
    }


def analyze(
    result: Any,
    client: Any,
    server: Any,
    scheduler_text: str,
    target_pid: int,
) -> dict[str, Any]:
    """Analyze scheduler chains for every public trial, retaining exclusions."""
    try:
        if not isinstance(result, dict):
            raise TraceInvalid("result: object required")
        normalized_client = validate_trace(client, "client")
        # Validate the server even though its timestamps are not used here;
        # accepting a corrupt companion trace would make this diagnostic
        # evidence appear stronger than it is.
        validate_trace(server, "server")
        floor_report = analyze_floor(result, client, server)
        if floor_report.get("status") != "DIAGNOSTIC":
            raise TraceInvalid("existing floor analyzer did not validate capture")
        handoffs = analyze_handoffs(result, normalized_client)
        if handoffs["status"] != "DIAGNOSTIC":
            raise TraceInvalid("local clock alignment is unavailable")
        if normalized_client["pid"] != target_pid:
            raise TraceInvalid("target_pid does not match client trace pid")
        records = _parse_scheduler(scheduler_text, target_pid)
        boundaries = result.get("public_boundaries")
        if not isinstance(boundaries, list):
            raise TraceInvalid("result: public_boundaries are unavailable")
        offset = handoffs["clock_alignment"]["offset_ns"]
        by_sequence: dict[int, dict[str, Any]] = {}
        for event in normalized_client["events"]:
            if event["stage"] == "terminal_read" and event["sequence"] is not None:
                if event["sequence"] in by_sequence:
                    raise TraceInvalid("client: duplicate terminal_read sequence")
                by_sequence[event["sequence"]] = event

        first = records[0]["timestamp_ns"]
        last = records[-1]["timestamp_ns"]
        rows: list[dict[str, Any]] = []
        for index, boundary in enumerate(boundaries):
            sequence = index + 1
            read = by_sequence.get(sequence)
            if read is None:
                raise TraceInvalid(f"client: missing terminal_read sequence {sequence}")
            send_ns = boundary["send_ns"]
            read_lower = read["elapsed_ns"] + offset["lower"]
            read_upper = read["elapsed_ns"] + offset["upper"]
            window = [record for record in records if send_ns <= record["timestamp_ns"] <= read_lower]
            kinds = [record["kind"] for record in window]
            row: dict[str, Any] = {
                "trial": index,
                "sequence": sequence,
                "send_ns": send_ns,
                "read_bounds_ns": {"lower": read_lower, "upper": read_upper},
            }
            if send_ns < first or read_upper > last:
                row.update({"status": "excluded", "exclusion": "outside_coverage"})
                rows.append(row)
                continue
            boundary_events = [record for record in records
                               if read_lower < record["timestamp_ns"] <= read_upper]
            if boundary_events:
                row.update({
                    "status": "excluded",
                    "exclusion": "ambiguous_chain",
                    "scheduler_kinds": [record["kind"] for record in boundary_events],
                    "boundary_events": boundary_events,
                })
                rows.append(row)
                continue
            if not window:
                row.update({"status": "excluded", "exclusion": "ambiguous_chain", "scheduler_kinds": []})
                rows.append(row)
                continue
            if kinds != ["waking", "wakeup", "switch_in"]:
                row.update({
                    "status": "excluded",
                    "exclusion": "ambiguous_chain",
                    "scheduler_kinds": kinds,
                })
                rows.append(row)
                continue
            waking, wakeup, switch_in = window
            if switch_in["timestamp_ns"] > read_lower:
                row.update({"status": "excluded", "exclusion": "ambiguous_chain", "scheduler_kinds": kinds})
                rows.append(row)
                continue
            switch_ns = switch_in["timestamp_ns"]
            row.update({
                "status": "included",
                "scheduler_kinds": kinds,
                "intervals_ns": {
                    "send_to_waking": waking["timestamp_ns"] - send_ns,
                    "waking_to_wakeup": wakeup["timestamp_ns"] - waking["timestamp_ns"],
                    "wakeup_to_switchin": switch_ns - wakeup["timestamp_ns"],
                    "switchin_to_read": {
                        "lower": read_lower - switch_ns,
                        "upper": read_upper - switch_ns,
                    },
                    "send_to_switchin": switch_ns - send_ns,
                },
            })
            rows.append(row)
        included = sum(row["status"] == "included" for row in rows)
        return {
            "status": "DIAGNOSTIC",
            "qualification": "NOT_APPLICABLE",
            "integration_authorized": False,
            "independently_verified": False,
            "target_pid": target_pid,
            "scheduler_coverage_ns": {"first": first, "last": last},
            "scheduler_record_count": len(records),
            "covered_rows": included,
            "excluded_rows": len(rows) - included,
            "scheduler_semantics": "Observed sched_waking/sched_wakeup/sched_switch chain; not an exclusive kernel, runtime, or network measurement.",
            "verification_requirements": ["perf clock id", "time namespace identity", "lost-event count"],
            "rows": rows,
        }
    except (TraceInvalid, KeyError, TypeError, ValueError) as exc:
        return _invalid(str(exc))


def analyze_paths(result_path: str | pathlib.Path, client_path: str | pathlib.Path,
                  server_path: str | pathlib.Path, scheduler_path: str | pathlib.Path,
                  target_pid: int) -> dict[str, Any]:
    try:
        result = json.loads(pathlib.Path(result_path).read_text(encoding="utf-8"))
        client = json.loads(pathlib.Path(client_path).read_text(encoding="utf-8"))
        server = json.loads(pathlib.Path(server_path).read_text(encoding="utf-8"))
        scheduler = pathlib.Path(scheduler_path).read_text(encoding="utf-8")
        return analyze(result, client, server, scheduler, target_pid)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return _invalid(str(exc))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result")
    parser.add_argument("client_trace")
    parser.add_argument("server_trace")
    parser.add_argument("scheduler")
    parser.add_argument("target_pid", type=int)
    parser.add_argument("-o", "--output", type=pathlib.Path)
    args = parser.parse_args(argv)
    report = analyze_paths(args.result, args.client_trace, args.server_trace, args.scheduler, args.target_pid)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    return 0 if report["status"] == "DIAGNOSTIC" else 2


if __name__ == "__main__":
    raise SystemExit(main())
