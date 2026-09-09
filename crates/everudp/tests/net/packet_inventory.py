"""Inventory accepted QUIC packets by STREAM IDs, without decoding payloads.

No-STREAM is not synonymous with ACK-only. Control-stream packets are not
decoded into application kinds. Packet counts do not measure removable CPU
time, and QUIC packets are not necessarily individual UDP/GSO transmissions.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

from stream_floor_blocks import public_samples
from validate_packet_trace import validate, load


def inventory(trace, base, role, begin, end):
    validate(trace, base, role)
    if type(begin) is not int or type(end) is not int or not 0 <= begin < end:
        raise ValueError("invalid half-open measurement interval")
    built, accepted = {}, {}
    streams = defaultdict(set)
    for event in trace["events"]:
        values = event["values"]
        key = tuple(values[:4])
        if event["event"] == "packet_built":
            if key in built:
                raise ValueError("duplicate packet identity")
            built[key] = event
        elif event["event"] == "stream_sent":
            if key not in built:
                raise ValueError("STREAM has no preceding built packet")
            streams[key].add(values[4])
        elif event["event"] == "packet_transmit_accepted":
            tx = tuple(values[:2])
            if tx in accepted:
                raise ValueError("duplicate accepted transmit cookie")
            accepted[tx] = event
    counts = Counter()
    unsent = 0
    for key, event in built.items():
        sent = accepted.get(key[:2])
        if sent is None:
            unsent += 1
            continue
        values = event["values"]
        if (sent["time_ns"] < event["time_ns"] or
                values[4] + values[5] > sent["values"][2]):
            raise ValueError("packet falls outside its accepted transmit")
        if begin <= sent["time_ns"] < end:
            label = "+".join(str(stream) for stream in sorted(streams[key])) or "no_stream"
            counts[label] += 1
    return {"qualification": False, "packets_by_streams": dict(sorted(counts.items())),
            "built_without_accepted_transmit": unsent}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate_directory", type=Path)
    args = parser.parse_args()
    root = args.candidate_directory
    result = load(root / "result.json")
    public_samples(result)
    begin = result["public_boundaries"][0]["send_ns"]
    end = result["public_boundaries"][-1]["accepted_ns"]
    output = {"qualification": False, "trials": result["trials"], "begin_ns": begin, "end_ns": end}
    for role in ("client", "gateway"):
        trace = load(root / f"{role}-path-trace.json.packets.json")
        clock = result["clock_identity"]
        if ((trace["boot_id"], trace["namespace_dev"], trace["namespace_ino"]) !=
                (clock["boot_id"], clock["time_namespace_dev"], clock["time_namespace_ino"])):
            raise ValueError("public and packet clocks differ")
        output[role] = inventory(trace, load(root / f"{role}-path-trace.json"), role, begin, end)
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
