"""Split exact packet-to-application windows using validated I/O markers.

Call coverage is wall-clock overlap, not CPU cost or proof that moving a call
will save that duration. Missing or ambiguous readability invalidates analysis.
"""
import argparse
import json
from pathlib import Path

from analyze_packet_trace import analyze
from analyze_io_spans import pair, coverage
from validate_io_trace import validate
from validate_packet_trace import load


def split_window(packet, packet_events, io_events, spans):
    start, end = packet["stream_received_ns"], packet["receiver_boundary_ns"]
    anchors = [e for e in packet_events if e["event"] == "stream_received"
               and e["time_ns"] == start and e["values"][2:5] ==
               [packet["packet_number"], packet["number_space"], packet["stream"]]]
    if len(anchors) != 1:
        raise ValueError("missing or ambiguous packet receipt anchor")
    connection = anchors[0]["values"][0]
    markers = [e for e in io_events if e["stage"] == "stream_readable"
               and e["connection"] == connection and e["stream"] == packet["stream"]
               and start <= e["time_ns"] <= end]
    if len(markers) != 1:
        raise ValueError("missing or ambiguous stream readability")
    ready = markers[0]["time_ns"]
    return {"stream_received_ns": start, "stream_readable_ns": ready,
            "application_ns": end,
            "before_notification": coverage(spans, start, ready),
            "after_notification": coverage(spans, ready, end)}


def analyze_directory(directory):
    paths = {r: load(directory / f"{r}-path-trace.json") for r in ("client", "gateway")}
    packets = {r: load(directory / f"{r}-path-trace.json.packets.json") for r in paths}
    report = analyze(paths["client"], paths["gateway"], load(directory / "result.json"),
                     packets["client"], packets["gateway"])
    io, spans = {}, {}
    for role in paths:
        sidecar = load(directory / f"{role}-path-trace.json.io.json")
        validate(sidecar, paths[role], role)
        io[role] = sidecar["events"]
        spans[role] = pair(io[role])
    rows = [{"trial": row["trial"], **{
        direction: split_window(row[direction], packets[role]["events"], io[role], spans[role])
        for direction, role in (("input", "gateway"), ("output", "client"))}}
        for row in report["rows"]]
    return {"status": "DIAGNOSTIC", "qualification": False, "rows": rows,
            "scope": "packet-bounded wall-clock I/O coverage; not exclusive CPU cost"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze_directory(args.directory), sort_keys=True))
