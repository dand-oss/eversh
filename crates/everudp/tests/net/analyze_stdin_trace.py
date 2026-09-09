"""Split public-send to input-queue timing; no CPU or qualification claims.

This bounded one-byte fixture requires one unambiguous read per trial. Retried
or coalesced reads reject the entire analysis, never silently discard a trial.
"""
import argparse
import json
from pathlib import Path

from analyze_path_trace import analyze
from validate_io_trace import load, validate

STAGES = ("stdin_ready", "stdin_read_start", "stdin_read_end", "stdin_data", "stdin_dispatch")


def split_window(events, start, end):
    if end < start:
        raise ValueError("reversed public input window")
    markers = [e for e in events if e["stage"] in STAGES and start <= e["time_ns"] <= end]
    if tuple(e["stage"] for e in markers) != STAGES:
        raise ValueError("missing or ambiguous stdin read/dispatch window")
    times = [start, *(e["time_ns"] for e in markers), end]
    if any(right < left for left, right in zip(times, times[1:])):
        raise ValueError("reversed stdin marker chronology")
    labels = ("public_send_to_ready", "ready_to_read", "read_call", "read_end_to_data",
              "data_to_dispatch", "dispatch_to_queue")
    durations = dict(zip(labels, (right - left for left, right in zip(times, times[1:]))))
    durations["public_send_to_queue"] = end - start
    return {"markers_ns": dict(zip(("public_send", *STAGES, "input_queued"), times)),
            "durations_ns": durations}


def analyze_directory(directory):
    client = load(directory / "client-path-trace.json")
    gateway = load(directory / "gateway-path-trace.json")
    result = load(directory / "result.json")
    path = analyze(client, gateway, result)
    sidecar = load(directory / "client-path-trace.json.io.json")
    validate(sidecar, client, "client")
    rows = []
    for row in path["rows"]:
        trial = row["trial"]
        window = split_window(sidecar["events"], result["public_boundaries"][trial]["send_ns"],
                              row["input"]["queued_ns"])
        rows.append({"trial": trial, **window})
    return {"status": "DIAGNOSTIC", "qualification": False, "rows": rows,
            "scope": "terminal readiness/read/dispatch wall-clock spans, not exclusive CPU"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze_directory(args.directory), sort_keys=True))
