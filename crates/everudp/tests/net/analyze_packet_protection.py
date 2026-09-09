"""Exact completion-packet protection intervals; not CPU or qualification."""
import argparse
import json
from pathlib import Path

from analyze_packet_trace import analyze
from validate_packet_trace import load


def split_protection(events, identity, reserved, built):
    markers = [e for e in events if e["event"] in
               ("packet_protection_start", "packet_protection_end")
               and e["values"][:4] == identity]
    if [e["event"] for e in markers] != ["packet_protection_start", "packet_protection_end"]:
        raise ValueError("missing or ambiguous protection pair")
    if any(e["values"] != [*identity, 1] for e in markers):
        raise ValueError("invalid protection direction or arity")
    start, end = (e["time_ns"] for e in markers)
    if not reserved <= start <= end <= built:
        raise ValueError("protection chronology outside packet construction")
    return {"reservation_to_protection_ns": start - reserved,
            "protection_ns": end - start, "protection_to_built_ns": built - end}


def split_assembly(events, identity, reserved, built):
    """Partition one exact completion packet; includes recorder overhead.

    Reservation-to-frames also includes driver scheduling and packet selection;
    it is not exclusively header construction. Old traces fail closed when
    assembly analysis is requested, rather than substituting absent markers.
    """
    names = ("packet_frames_start", "packet_frames_end",
             "packet_protection_start", "packet_protection_end")
    markers = [event for event in events if event["event"] in names
               and event["values"][:4] == identity]
    if [event["event"] for event in markers] != list(names):
        raise ValueError("missing, duplicate or reordered packet assembly markers")
    if any(event["values"] != [*identity, 1] for event in markers):
        raise ValueError("invalid assembly direction or arity")
    start, end, protection_start, protection_end = (event["time_ns"] for event in markers)
    if not reserved <= start <= end <= protection_start <= protection_end <= built:
        raise ValueError("packet assembly chronology outside construction")
    return {"reservation_to_frames_ns": start - reserved,
            "frame_population_ns": end - start,
            "frames_to_protection_ns": protection_start - end,
            "protection_ns": protection_end - protection_start,
            "protection_to_built_ns": built - protection_end}


def analyze_directory(directory, *, assembly=False):
    c, g, result, cp, gp = [load(directory / name) for name in (
        "client-path-trace.json", "gateway-path-trace.json", "result.json",
        "client-path-trace.json.packets.json", "gateway-path-trace.json.packets.json")]
    report = analyze(c, g, result, cp, gp)
    rows = []
    for row in report["rows"]:
        joined = {"trial": row["trial"]}
        for direction, trace, kind in (("input", cp, 0x20), ("output", gp, 0x40)):
            packet = row[direction]
            builds = [e for e in trace["events"] if e["event"] == "packet_built"
                      and e["values"][2:4] == [packet["packet_number"], packet["number_space"]]]
            if len(builds) != 1:
                raise ValueError("ambiguous built packet identity")
            operations = [e for e in trace["events"] if e["event"] == "operation"
                          and e["values"][1] == packet["stream"]
                          and e["values"][4] == kind
                          and e["values"][5] == packet["operation_start"]]
            if len(operations) != 1:
                raise ValueError("ambiguous operation reservation")
            split = split_assembly if assembly else split_protection
            joined[direction] = split(trace["events"], builds[0]["values"][:4],
                                      operations[0]["time_ns"], packet["built_ns"])
        rows.append(joined)
    return {"status": "DIAGNOSTIC", "qualification": False, "rows": rows,
            "scope": "protection wall-clock interval includes instrumentation; not exclusive CPU"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--assembly", action="store_true", help="require exact frame-population markers")
    args = parser.parse_args()
    print(json.dumps(analyze_directory(args.directory, assembly=args.assembly), sort_keys=True))
