"""Strict attribution of the interval before QUIC frame population.

This is diagnostic evidence only.  It joins a packet's exact operation and
completion identities first, then accepts one protocol transmit call and one
driver-service marker around that packet.  It never selects markers by nearest
timestamp and it keeps every public row in the returned report.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from analyze_packet_protection import split_assembly
from analyze_packet_trace import analyze as analyze_packets
from validate_io_trace import CONTEXTUAL, STAGES, load as load_io, validate as validate_io
from validate_packet_trace import load as load_packets


def _u64(value: Any, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 1 << 64:
        raise ValueError(f"{label}: expected u64")
    return value


def _validate_events(events: Any) -> list[dict[str, Any]]:
    """Validate the event shape needed when split_preframes is called directly."""
    if not isinstance(events, list) or not events:
        raise ValueError("I/O events: expected non-empty list")
    previous = -1
    for index, event in enumerate(events):
        if not isinstance(event, dict) or set(event) != {"stage", "time_ns", "connection", "stream"}:
            raise ValueError(f"I/O event {index}: malformed fields")
        stage = event["stage"]
        if not isinstance(stage, str) or stage not in STAGES:
            raise ValueError(f"I/O event {index}: invalid stage")
        timestamp = _u64(event["time_ns"], f"I/O event {index}.time_ns")
        if timestamp < previous:
            raise ValueError("I/O timestamps regress")
        previous = timestamp
        contextual = stage in CONTEXTUAL
        connection = event["connection"]
        if contextual:
            _u64(connection, f"I/O event {index}.connection")
        elif connection is not None:
            raise ValueError(f"I/O event {index}: unexpected connection")
        if stage == "stream_readable":
            _u64(event["stream"], f"I/O event {index}.stream")
        elif event["stream"] is not None:
            raise ValueError(f"I/O event {index}: unexpected stream")
    return events


def split_preframes(
    io_events: list[dict[str, Any]],
    connection: int,
    reserved: int,
    frames_start: int,
    built: int,
) -> dict[str, Any]:
    """Partition reservation, driver service, protocol, and frame-population.

    Every protocol call in the trace is paired globally.  A pair ending in
    ``idle`` is valid evidence of a call but cannot satisfy this packet's
    enclosing ``ready`` requirement.  A mismatched connection, nesting, or
    incomplete pair invalidates the entire analysis.
    """
    events = _validate_events(io_events)
    connection = _u64(connection, "connection")
    reserved = _u64(reserved, "reserved")
    frames_start = _u64(frames_start, "frames_start")
    built = _u64(built, "built")
    if not reserved <= frames_start <= built:
        raise ValueError("packet chronology is invalid")

    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    active: dict[str, Any] | None = None
    for event in events:
        stage = event["stage"]
        if stage == "protocol_transmit_start":
            if active is not None:
                raise ValueError("nested protocol transmit calls")
            active = event
        elif stage in {"protocol_transmit_ready", "protocol_transmit_idle"}:
            if active is None:
                raise ValueError("unmatched protocol transmit completion")
            if event["connection"] != active["connection"]:
                raise ValueError("protocol transmit connection mismatch")
            if event["time_ns"] < active["time_ns"]:
                raise ValueError("protocol transmit chronology is invalid")
            pairs.append((active, event))
            active = None
    if active is not None:
        raise ValueError("unfinished protocol transmit call")

    candidates = [
        (start, end)
        for start, end in pairs
        if start["connection"] == connection
        and end["stage"] == "protocol_transmit_ready"
        and start["time_ns"] <= frames_start <= built <= end["time_ns"]
    ]
    if len(candidates) != 1:
        raise ValueError("missing or ambiguous enclosing protocol transmit call")
    protocol_start, protocol_ready = candidates[0]

    services = [
        event for event in events
        if event["stage"] == "driver_service"
        and event["connection"] == connection
        and reserved <= event["time_ns"] <= protocol_start["time_ns"]
    ]
    if len(services) != 1:
        raise ValueError("missing or ambiguous driver service marker")
    service = services[0]
    if not reserved <= service["time_ns"] <= protocol_start["time_ns"] <= frames_start <= built <= protocol_ready["time_ns"]:
        raise ValueError("pre-frame chronology is invalid")

    return {
        "reservation_to_service_ns": service["time_ns"] - reserved,
        "service_to_protocol_ns": protocol_start["time_ns"] - service["time_ns"],
        "protocol_to_frames_ns": frames_start - protocol_start["time_ns"],
        "reservation_ns": reserved,
        "driver_service_ns": service["time_ns"],
        "protocol_start_ns": protocol_start["time_ns"],
        "frames_start_ns": frames_start,
        "built_ns": built,
        "protocol_ready_ns": protocol_ready["time_ns"],
    }


def _packet_preframes(packet_trace: dict[str, Any], io_events: list[dict[str, Any]],
                      packet: dict[str, Any], kind: int) -> dict[str, Any]:
    builds = [event for event in packet_trace["events"]
              if event["event"] == "packet_built"
              and event["values"][2:4] == [packet["packet_number"], packet["number_space"]]]
    if len(builds) != 1:
        raise ValueError("ambiguous built packet identity")
    build = builds[0]
    identity = build["values"][:4]
    operations = [event for event in packet_trace["events"]
                  if event["event"] == "operation"
                  and event["values"][0] == identity[0]
                  and event["values"][1] == packet["stream"]
                  and event["values"][4] == kind
                  and event["values"][5] == packet["operation_start"]]
    if len(operations) != 1:
        raise ValueError("ambiguous operation reservation")
    assembly = split_assembly(packet_trace["events"], identity,
                              operations[0]["time_ns"], packet["built_ns"])
    preframes = split_preframes(io_events, identity[0], operations[0]["time_ns"],
                                next(event["time_ns"] for event in packet_trace["events"]
                                     if event["event"] == "packet_frames_start"
                                     and event["values"] == [*identity, 1]),
                                packet["built_ns"])
    return {"packet": packet, "assembly": assembly, "preframes": preframes}


def analyze_directory(directory: str | Path) -> dict[str, Any]:
    """Analyze every exact input/output completion in one capture directory."""
    directory = Path(directory)
    client, gateway, result, client_packets, gateway_packets = [load_packets(directory / name)
        for name in ("client-path-trace.json", "gateway-path-trace.json", "result.json",
                     "client-path-trace.json.packets.json", "gateway-path-trace.json.packets.json")]
    packet_report = analyze_packets(client, gateway, result, client_packets, gateway_packets)
    io_values = {}
    for role, path_trace in (("client", client), ("gateway", gateway)):
        sidecar = load_io(directory / f"{role}-path-trace.json.io.json")
        validate_io(sidecar, path_trace, role)
        io_values[role] = sidecar["events"]

    rows = []
    for row in packet_report["rows"]:
        joined = {"trial": row["trial"]}
        joined["input"] = _packet_preframes(client_packets, io_values["client"], row["input"], 0x20)
        joined["output"] = _packet_preframes(gateway_packets, io_values["gateway"], row["output"], 0x40)
        rows.append(joined)
    return {"status": "DIAGNOSTIC", "qualification": False,
            "rows": rows, "scope": "exact completion packets; pre-frame wall-clock attribution"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze_directory(args.directory), sort_keys=True))
