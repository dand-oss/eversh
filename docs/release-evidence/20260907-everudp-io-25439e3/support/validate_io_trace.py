"""Validate QUIC I/O diagnostics against their owning path trace, not packets."""

import argparse
from collections import Counter
import json
from pathlib import Path

from analyze_path_trace import _identity, _trace, _u64

CAPACITY = 65_536  # crates/everudp/src/io_trace.rs
MAX_JSON_BYTES = 16 * 1024 * 1024
CONTEXTUAL = {"driver_service", "protocol_transmit_start", "protocol_transmit_ready",
              "protocol_transmit_idle", "stream_readable"}
STAGES = CONTEXTUAL | {"udp_receive", "receive_copy", "driver_poll", "transmit_poll",
                      "transmit_accepted", "transmit_blocked", "transmit_error"}


def validate(sidecar, base, role):
    if role not in ("client", "gateway"):
        raise ValueError("invalid path trace role")
    base_identity, _ = _trace(base, role)
    required = {"schema_version", "trace_kind", "diagnostic_only", "clock", "valid",
                "overflow", "pid", "boot_id", "namespace_dev", "namespace_ino", "events"}
    if not isinstance(sidecar, dict) or set(sidecar) != required:
        raise ValueError("malformed I/O trace fields")
    if (type(sidecar["schema_version"]) is not int or sidecar["schema_version"] != 1
            or sidecar["trace_kind"] != "quic_io" or sidecar["diagnostic_only"] is not True
            or sidecar["clock"] != "CLOCK_MONOTONIC" or sidecar["valid"] is not True
            or sidecar["overflow"] is not False):
        raise ValueError("invalid I/O trace status")
    identity = _identity({"boot_id": sidecar["boot_id"],
                          "time_namespace_dev": sidecar["namespace_dev"],
                          "time_namespace_ino": sidecar["namespace_ino"]}, "I/O trace")
    pid = _u64(sidecar["pid"], "I/O pid")
    if pid == 0 or pid != base["pid"] or identity != base_identity:
        raise ValueError("I/O trace process or clock identity mismatch")
    events = sidecar["events"]
    if not isinstance(events, list) or not 0 < len(events) <= CAPACITY:
        raise ValueError("invalid I/O event count")
    counts = Counter()
    previous = -1
    for event in events:
        if not isinstance(event, dict) or set(event) != {"stage", "time_ns", "connection", "stream"}:
            raise ValueError("malformed I/O event fields")
        stage = event["stage"]
        if not isinstance(stage, str) or stage not in STAGES:
            raise ValueError("invalid I/O stage")
        timestamp = _u64(event["time_ns"], "I/O timestamp")
        if timestamp < previous:
            raise ValueError("I/O timestamp regression")
        previous = timestamp
        for field, required_id in (("connection", stage in CONTEXTUAL),
                                   ("stream", stage == "stream_readable")):
            if required_id:
                _u64(event[field], f"I/O {field}")
            elif event[field] is not None:
                raise ValueError(f"unexpected I/O {field}")
        counts[stage] += 1
    return {"status": "DIAGNOSTIC", "qualification": False, "event_count": len(events),
            "stage_counts": dict(counts), "first_ns": events[0]["time_ns"],
            "last_ns": events[-1]["time_ns"]}


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    with Path(path).open("rb") as source:
        data = source.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ValueError("JSON exceeds bounded size")
    return json.loads(data, object_pairs_hook=unique)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sidecar", type=Path)
    parser.add_argument("base", type=Path)
    parser.add_argument("role", choices=("client", "gateway"))
    args = parser.parse_args()
    print(json.dumps(validate(load(args.sidecar), load(args.base), args.role), sort_keys=True))
