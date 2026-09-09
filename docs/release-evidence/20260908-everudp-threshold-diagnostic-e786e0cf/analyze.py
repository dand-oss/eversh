"""Reproduce diagnostic attribution; run with the repository root as argument."""
import json
from pathlib import Path
import statistics
import sys
from collections import Counter

sys.path.insert(0, str(Path(sys.argv[1]) / "crates/everudp/tests/net"))
from stream_floor_evidence import sealed
from analyze_packet_trace import analyze as packets
from analyze_path_trace import analyze as paths
from analyze_stdin_trace import analyze_directory as stdin
from analyze_packet_protection import analyze_directory as protection
from validate_packet_trace import load

root = Path(__file__).resolve().parent / "capture"
sealed(root)
directory = root / "everudp"
c, g, result, cp, gp = [load(directory / name) for name in (
    "client-path-trace.json", "gateway-path-trace.json", "result.json",
    "client-path-trace.json.packets.json", "gateway-path-trace.json.packets.json")]
assert result["trials"] == 200 and result["transcript_failures"] == 0
path = paths(c, g, result)
packet = packets(c, g, result, cp, gp)
terminal = stdin(directory)
crypto = protection(directory)
assert all(len(report["rows"]) == 200 for report in (path, packet, terminal, crypto))


def medians(rows):
    return {key: statistics.median(row[key] for row in rows) / 1000
            for key in rows[0]}


summary = {"status": "DIAGNOSTIC", "qualification": False, "trials": 200}
summary["stdin_us"] = medians([r["durations_ns"] for r in terminal["rows"]])
summary["packets_us"] = {direction: medians([r[direction]["durations_ns"]
    for r in packet["rows"]]) for direction in ("input", "output")}
summary["protection_us"] = {direction: medians([r[direction]
    for r in crypto["rows"]]) for direction in ("input", "output")}
summary["edges_us"] = medians([{
    "input_prepared_to_committed": r["input"]["accepted_ns"] - min(r["input"]["prepared_ns"]),
    "input_committed_to_output_queued": r["output"]["gateway_queued_ns"] - r["input"]["accepted_ns"],
    "output_staged_to_stdout_committed": r["output"]["accepted_ns"] - r["output"]["staged_ns"],
} for r in path["rows"]])
summary["full_intertrial_windows"] = {}
boundaries = result["public_boundaries"]
assert len(boundaries) == 200
for side, trace in (("client", cp), ("gateway", gp)):
    windows, shapes = Counter(), Counter()
    for left, right in zip(boundaries, boundaries[1:]):
        events = [e for e in trace["events"]
                  if left["send_ns"] <= e["time_ns"] < right["send_ns"]]
        counts = Counter(e["event"] for e in events)
        assert counts["packet_transmit_accepted"] > 0
        windows[(counts["packet_transmit_accepted"], counts["packet_built"],
                 sum(e["event"] == "stream_sent" and e["values"][4] == 0 for e in events))] += 1
        for event in events:
            if event["event"] != "packet_built":
                continue
            streams = tuple(sorted(e["values"][4] for e in events
                if e["event"] == "stream_sent" and e["values"][:4] == event["values"][:4]))
            shapes[streams] += 1
    assert sum(windows.values()) == 199
    summary["full_intertrial_windows"][side] = {
        "tx_built_control_counts": {str(k): v for k, v in sorted(windows.items())},
        "packet_stream_ids": {str(k): v for k, v in sorted(shapes.items())}}
print(json.dumps(summary, indent=2, sort_keys=True))
