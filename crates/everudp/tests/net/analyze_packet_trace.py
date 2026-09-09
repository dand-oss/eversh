"""Join packet diagnostics to public trial boundaries, never qualification.

Durations describe the packet that completes each operation. Earlier fragments
can overlap other work. Send-poll to userspace receive includes socket work,
kernel/network transit and receiver scheduling; it is NOT pure network time.
"""
import argparse
import json

from analyze_path_trace import analyze as analyze_path
from packet_join import correlate_operation
from validate_packet_trace import load, validate


def analyze(client, gateway, result, client_packets, gateway_packets):
    validate(client_packets, client, "client")
    validate(gateway_packets, gateway, "gateway")
    path = analyze_path(client, gateway, result)
    rows = []
    for row in path["rows"]:
        joined = {"trial": row["trial"]}
        for direction, sender, receiver, kind, boundary in (
            ("input", client_packets, gateway_packets, 0x20,
             min(row["input"]["prepared_ns"])),
            ("output", gateway_packets, client_packets, 0x40,
             row["output"]["staged_ns"]),
        ):
            anchor = row[direction]
            operations = [e for e in sender["events"] if e["event"] == "operation"
                          and e["values"][2:5] == [anchor["epoch"], anchor["sequence"], kind]]
            if len(operations) != 1:
                raise ValueError(f"trial {row['trial']} {direction}: ambiguous operation anchor")
            completion = correlate_operation(sender["events"], receiver["events"],
                                             operations[0], boundary)
            completion["durations_ns"] = {
                "operation_to_completion_packet_build": completion["built_ns"] - operations[0]["time_ns"],
                "build_to_successful_send_poll": completion["poll_ns"] - completion["built_ns"],
                "send_poll_to_userspace_receive": completion["received_ns"] - completion["poll_ns"],
                "send_poll_duration": completion["accepted_ns"] - completion["poll_ns"],
                "receive_to_authenticated": completion["authenticated_ns"] - completion["received_ns"],
                "authenticated_to_stream_received": completion["stream_received_ns"] - completion["authenticated_ns"],
                "stream_received_to_application": boundary - completion["stream_received_ns"],
            }
            joined[direction] = completion
        rows.append(joined)
    return {"status": "DIAGNOSTIC", "qualification": False,
            "scope": "single-connection completion-packet paths; not exclusive CPU or wire time",
            "rows": rows}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("client", "gateway", "result", "client_packets", "gateway_packets"):
        parser.add_argument(name)
    args = parser.parse_args()
    print(json.dumps(analyze(*(load(getattr(args, name)) for name in
                               ("client", "gateway", "result", "client_packets", "gateway_packets"))),
                     sort_keys=True))
