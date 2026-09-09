"""Elapsed I/O call coverage, not packet identity, CPU cost or qualification."""

import argparse
import json
from pathlib import Path
import statistics

from analyze_path_trace import analyze
from validate_io_trace import load, validate

STARTS = {"protocol_transmit_start": "protocol", "transmit_poll": "send"}
ENDS = {"protocol_transmit_ready": "protocol", "protocol_transmit_idle": "protocol",
        "transmit_accepted": "send", "transmit_blocked": "send", "transmit_error": "send"}


def pair(events):
    """Input schema is validated by validate(); reject ambiguous call nesting."""
    active = None
    spans = []
    previous = -1
    for event in events:
        stage, timestamp = event["stage"], event["time_ns"]
        if timestamp < previous:
            raise ValueError("timestamp regression")
        previous = timestamp
        if stage in STARTS:
            if active is not None:
                raise ValueError("overlapping I/O calls")
            active = event
        elif stage in ENDS:
            if active is None or STARTS[active["stage"]] != ENDS[stage]:
                raise ValueError("unmatched I/O completion")
            if event["connection"] != active["connection"]:
                raise ValueError("I/O connection mismatch")
            spans.append((active["time_ns"], timestamp, ENDS[stage]))
            active = None
    if active is not None:
        raise ValueError("unfinished I/O call")
    return spans


def coverage(spans, start, end):
    if end < start:
        raise ValueError("reversed window")
    result = {"window_ns": end - start, "protocol_ns": 0, "send_ns": 0,
              "clipped_calls": 0}
    previous = -1
    for left, right, kind in spans:
        if left < previous or right < left or kind not in ("protocol", "send"):
            raise ValueError("invalid or overlapping spans")
        previous = right
        overlap = max(0, min(right, end) - max(left, start))
        if overlap:
            result[kind + "_ns"] += overlap
            result["clipped_calls"] += int(left < start or right > end)
    result["residual_ns"] = end - start - result["protocol_ns"] - result["send_ns"]
    return result


def analyze_directory(directory):
    paths = {role: load(directory / f"{role}-path-trace.json")
             for role in ("client", "gateway")}
    report = analyze(paths["client"], paths["gateway"], load(directory / "result.json"))
    events, spans = {}, {}
    for role in paths:
        sidecar = load(directory / f"{role}-path-trace.json.io.json")
        validate(sidecar, paths[role], role)
        events[role] = sidecar["events"]
        spans[role] = pair(events[role])
    rows = []
    for trial, row in enumerate(report["rows"]):
        input_row = row["input"]
        start = input_row["queued_ns"]
        written, prepared = input_row["written_ns"], input_row["prepared_ns"]
        result = {"trial": trial}
        rows.append(result)
        if len(written) != 1 or len(prepared) != 1:
            result["excluded"] = "ambiguous input attempt"
            continue
        written, prepared = written[0], prepared[0]
        reads = [e["time_ns"] for e in events["gateway"]
                 if e["stage"] == "stream_readable" and e["stream"] == 2
                 and start <= e["time_ns"] <= prepared]
        if len(reads) != 1:
            result["excluded"] = "ambiguous input readability"
            continue
        ready = reads[0]
        sends = [e["time_ns"] for e in events["client"]
                 if e["stage"] == "transmit_accepted" and written <= e["time_ns"] <= ready]
        receives = [e["time_ns"] for e in events["gateway"]
                    if e["stage"] == "udp_receive" and start <= e["time_ns"] <= ready]
        if not sends or not receives:
            result["excluded"] = "missing send or receive boundary"
            continue
        # These selections do not identify the packet carrying the input.
        for role, left, right in (("client", written, sends[0]),
                                  ("gateway", receives[-1], ready)):
            result[role] = {"start_ns": left, "end_ns": right,
                            **coverage(spans[role], left, right)}
    included = [row for row in rows if "excluded" not in row]
    medians = {role: {key: statistics.median(row[role][key] for row in included)
                     for key in ("window_ns", "protocol_ns", "send_ns", "residual_ns")}
               for role in paths} if included else {}
    return {"status": "DIAGNOSTIC", "qualification": False,
            "included": len(included), "excluded": len(rows) - len(included),
            "elapsed_medians_ns": medians, "rows": rows}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="one candidate's validated trace directory")
    args = parser.parse_args()
    print(json.dumps(analyze_directory(args.directory), sort_keys=True))
