"""Validate bounded QUIC packet diagnostics against their owning path trace.

Packet diagnostics are evidence only.  This module validates identity, shape,
and the packet/stream field contract; it deliberately does not infer packet
causality or turn the result into a qualification measurement.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from typing import Any

from analyze_path_trace import _trace

CAPACITY = 65_536
MAX_JSON_BYTES = 32 * 1024 * 1024
UINT64_MAX = (1 << 64) - 1
VARINT62_MAX = (1 << 62) - 1

ARITIES = {
    "packet_transmit_poll": 4,
    "packet_transmit_blocked": 4,
    "packet_transmit_error": 4,
    "packet_transmit_accepted": 4,
    "datagram_received": 2,
    "packet_built": 7,
    "packet_authenticated": 7,
    "packet_protection_start": 5,
    "packet_protection_end": 5,
    "packet_frames_start": 5,
    "packet_frames_end": 5,
    "unsupported_path": 3,
    "stream_sent": 8,
    "stream_received": 8,
    "operation": 7,
    "packet_trace_invalid": 0,
}
EVENTS = frozenset(ARITIES)
INPUT_KINDS = frozenset((0x20, 0x21, 0x22, 0x23))
OUTPUT_KINDS = frozenset((0x40, 0x41, 0x42))


def _u64(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= UINT64_MAX:
        raise ValueError(f"{label}: expected u64")
    return value


def _varint62(value: Any, label: str) -> int:
    value = _u64(value, label)
    if value > VARINT62_MAX:
        raise ValueError(f"{label}: exceeds QUIC varint")
    return value


def _status(sidecar: Any) -> None:
    required = {
        "schema_version", "trace_kind", "diagnostic_only", "clock", "valid",
        "overflow", "pid", "boot_id", "namespace_dev", "namespace_ino", "events",
    }
    if not isinstance(sidecar, dict) or set(sidecar) != required:
        raise ValueError("malformed packet trace fields")
    if (type(sidecar["schema_version"]) is not int or sidecar["schema_version"] != 1
            or sidecar["trace_kind"] != "quic_packets"
            or sidecar["diagnostic_only"] is not True
            or sidecar["clock"] != "CLOCK_MONOTONIC"
            or sidecar["valid"] is not True or sidecar["overflow"] is not False):
        raise ValueError("invalid packet trace status")


def _check_values(name: str, values: Any, role: str) -> None:
    if not isinstance(values, list) or len(values) != ARITIES[name]:
        raise ValueError(f"{name}: invalid value arity")
    for index, value in enumerate(values):
        _u64(value, f"{name}.values[{index}]")
    if name == "packet_trace_invalid" or name == "unsupported_path":
        raise ValueError(f"{name}: invalid marker in a valid trace")
    if name in {"packet_transmit_poll", "packet_transmit_blocked",
                "packet_transmit_error", "packet_transmit_accepted"}:
        if values[1] == 0 or values[2] == 0:
            raise ValueError(f"{name}: cookie and bytes must be nonzero")
        # A zero segment size is the explicit no-GSO encoding.
    elif name == "datagram_received":
        if values[0] == 0 or values[1] == 0:
            raise ValueError("datagram_received: cookie and bytes must be nonzero")
    elif name in {"packet_built", "packet_authenticated"}:
        if values[1] == 0 or values[5] == 0:
            raise ValueError(f"{name}: cookie and packet length must be nonzero")
        if values[3] not in (1, 2, 3):
            raise ValueError(f"{name}: invalid packet number space")
        _varint62(values[2], f"{name}.packet_number")
        expected_direction = 1 if name == "packet_built" else 2
        if values[6] != expected_direction:
            raise ValueError(f"{name}: invalid direction")
        packet_offset = _varint62(values[4], f"{name}.packet_offset")
        if packet_offset + values[5] > VARINT62_MAX:
            raise ValueError(f"{name}: packet range exceeds QUIC varint")
    elif name in {"packet_protection_start", "packet_protection_end",
                  "packet_frames_start", "packet_frames_end"}:
        if values[1] == 0:
            raise ValueError(f"{name}: cookie must be nonzero")
        if values[3] not in (1, 2, 3):
            raise ValueError(f"{name}: invalid packet number space")
        _varint62(values[2], f"{name}.packet_number")
        # Assembly diagnostics are emitted only around locally-sent packets.
        if values[4] != 1:
            raise ValueError(f"{name}: invalid direction")
    elif name in {"stream_sent", "stream_received"}:
        if values[1] == 0:
            raise ValueError(f"{name}: cookie must be nonzero")
        if values[3] not in (1, 2, 3):
            raise ValueError(f"{name}: invalid packet number space")
        _varint62(values[2], f"{name}.packet_number")
        _varint62(values[4], f"{name}.stream")
        offset = _varint62(values[5], f"{name}.offset")
        if offset + values[6] > VARINT62_MAX:
            raise ValueError(f"{name}: stream range exceeds QUIC varint")
        if values[6] == 0 and values[7] != 1:
            raise ValueError(f"{name}: zero length requires FIN")
        if values[7] not in (0, 1):
            raise ValueError(f"{name}: invalid FIN")
    elif name == "operation":
        # noQ's local connection handle is a slab index, so zero is valid.
        stream = _varint62(values[1], "operation.stream")
        if values[6] < 14:
            raise ValueError("operation: length must include the 14-byte wire header")
        if values[4] not in (INPUT_KINDS | OUTPUT_KINDS):
            raise ValueError("operation: unknown wire kind")
        expected = INPUT_KINDS if role == "client" else OUTPUT_KINDS
        if values[4] not in expected:
            raise ValueError("operation: kind does not belong to trace role")
        # Client-initiated unidirectional streams are 2 mod 4; server ones
        # are 3 mod 4.  Control streams are not operation anchors.
        expected_mod = 2 if role == "client" else 3
        if stream % 4 != expected_mod:
            raise ValueError("operation: stream direction does not match role")
        _varint62(values[5], "operation.offset")
        if values[5] + values[6] > VARINT62_MAX:
            raise ValueError("operation: stream range exceeds QUIC varint")


def validate(sidecar: Any, base_path_trace: Any, role: str) -> dict[str, Any]:
    """Validate one packet sidecar against its owning client/gateway trace."""
    if role not in ("client", "gateway"):
        raise ValueError("invalid packet trace role")
    _status(sidecar)
    base_identity, _ = _trace(base_path_trace, role)
    pid = _u64(sidecar["pid"], "packet trace pid")
    base_pid = _u64(base_path_trace["pid"], f"{role}.pid")
    if not 0 < pid <= (1 << 32) - 1 or pid != base_pid:
        raise ValueError("packet trace process identity mismatch")
    if not isinstance(sidecar["boot_id"], str):
        raise ValueError("packet trace boot identity malformed")
    identity = (sidecar["boot_id"], _u64(sidecar["namespace_dev"], "packet trace namespace_dev"),
                _u64(sidecar["namespace_ino"], "packet trace namespace_ino"))
    if identity != base_identity:
        raise ValueError("packet trace clock identity mismatch")
    events = sidecar["events"]
    if not isinstance(events, list) or not 0 < len(events) <= CAPACITY:
        raise ValueError("invalid packet event count")
    counts: Counter[str] = Counter()
    previous = -1
    for index, event in enumerate(events):
        if not isinstance(event, dict) or set(event) != {"event", "time_ns", "values"}:
            raise ValueError(f"malformed packet event {index}")
        name = event["event"]
        if not isinstance(name, str) or name not in EVENTS:
            raise ValueError(f"unknown packet event {index}")
        timestamp = _u64(event["time_ns"], f"packet event {index}.time_ns")
        if timestamp < previous:
            raise ValueError("packet timestamp regression")
        previous = timestamp
        _check_values(name, event["values"], role)
        counts[name] += 1
    return {"status": "DIAGNOSTIC", "qualification": False,
            "event_count": len(events), "stage_counts": dict(counts),
            "first_ns": events[0]["time_ns"], "last_ns": events[-1]["time_ns"]}


def load(path: str | Path) -> Any:
    """Load at most 32 MiB of JSON while rejecting duplicate object keys."""
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
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
