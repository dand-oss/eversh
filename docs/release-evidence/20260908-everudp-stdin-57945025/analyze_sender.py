"""Reproduce sender asymmetry from the sealed capture; never qualification."""
import collections
import json
from pathlib import Path
import statistics
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root.parents[2] / "crates/everudp/tests/net"))
from analyze_io_spans import pair, coverage
from analyze_packet_trace import analyze
from stream_floor_evidence import sealed
from validate_io_trace import validate
from validate_packet_trace import load

sealed(root / "capture")
p = root / "capture/everudp"
c, g, result, cp, gp = [load(p / name) for name in (
    "client-path-trace.json", "gateway-path-trace.json", "result.json",
    "client-path-trace.json.packets.json", "gateway-path-trace.json.packets.json")]
report = analyze(c, g, result, cp, gp)
assert len(report["rows"]) == 200
summary = {}
for direction, role, path, trace, kind in (
    ("input", "client", c, cp, 0x20), ("output", "gateway", g, gp, 0x40)
):
    io = load(p / f"{role}-path-trace.json.io.json")
    validate(io, path, role)
    spans = pair(io["events"])
    rows, sizes, frames, blocked = [], collections.Counter(), collections.Counter(), 0
    phases = []
    for row in report["rows"]:
        packet = row[direction]
        builds = [e for e in trace["events"] if e["event"] == "packet_built"
                  and e["values"][2:4] == [packet["packet_number"], packet["number_space"]]]
        assert len(builds) == 1
        identity = builds[0]["values"]
        sizes[identity[5]] += 1
        frames[sum(e["event"] == "stream_sent" and e["values"][1:4] == identity[1:4]
                   for e in trace["events"])] += 1
        operations = [e for e in trace["events"] if e["event"] == "operation"
                      and e["values"][1] == packet["stream"]
                      and e["values"][4] == kind
                      and e["values"][5] == packet["operation_start"]]
        assert len(operations) == 1
        reserved, built = operations[0]["time_ns"], packet["built_ns"]
        rows.append(coverage(spans, reserved, built))
        markers = [e for e in io["events"] if reserved <= e["time_ns"] <= built
                   and e["stage"] in ("driver_poll", "driver_service", "protocol_transmit_start")]
        assert [e["stage"] for e in markers] == [
            "driver_poll", "driver_service", "protocol_transmit_start"], "ambiguous driver chain"
        assert all(e["connection"] == identity[0] for e in markers[1:])
        times = [reserved, *(e["time_ns"] for e in markers), built]
        assert all(a <= b for a, b in zip(times, times[1:]))
        phases.append(dict(zip(("reservation_to_driver_poll", "driver_poll_to_lock_acquired",
                               "driver_service_to_protocol_start", "protocol_start_to_built"),
                              (b - a for a, b in zip(times, times[1:])))))
        blocked += sum(e["event"] == "packet_transmit_blocked"
                       and e["values"][1] == identity[1] for e in trace["events"])
    summary[direction] = {
        "rows": len(rows), "packet_lengths": dict(sizes), "stream_frames": dict(frames),
        "blocked_polls": blocked,
        "driver_phase_median_us": {
            key: statistics.median(row[key] for row in phases) / 1000 for key in phases[0]},
        "reservation_to_build_median_us": {
            key: statistics.median(row[key] for row in rows) / 1000
            for key in ("window_ns", "protocol_ns", "send_ns", "residual_ns")},
    }
print(json.dumps({"status": "DIAGNOSTIC", "qualification": False,
                  "scope": "wall-clock call coverage; no exclusive CPU attribution",
                  "summary": summary}, indent=2, sort_keys=True))
