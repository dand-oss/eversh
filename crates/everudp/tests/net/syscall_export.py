"""Strict, pointer-free export of selected syscall perf-script records."""

from __future__ import annotations

import argparse
import json
import re
from typing import Any


class ExportError(ValueError):
    """The trace is not safe to export."""


_LINE = re.compile(r"^\s*(?P<seconds>[0-9]+)\.(?P<frac>[0-9]{9}):\s+(?P<event>syscalls:sys_(?:enter|exit)_[a-z0-9]+):(?:\s+(?P<body>.*?))?\s*$")
_HEX = re.compile(r"^0x[0-9a-fA-F]+$")
_DEC = re.compile(r"^-?[0-9]+$")
_RAW_WRITE = re.compile(
    r"^\s*([0-9]+)\.([0-9]{9}):\s+raw_syscalls:sys_(enter|exit):\s+NR 1 (.*?)\s*$")
_RAW_ARGS = re.compile(r"\(([0-9a-fA-F]+), ([0-9a-fA-F]+), ([0-9a-fA-F]+), "
                       r"([0-9a-fA-F]+), ([0-9a-fA-F]+), ([0-9a-fA-F]+)\)")
_EVENTS = {
    "poll": {"ufds", "nfds", "timeout_msecs"},
    "read": {"fd", "buf", "count"},
    "write": {"fd", "buf", "count"},
    "sendmsg": {"fd", "msg", "flags"},
    "sendmmsg": {"fd", "mmsg", "vlen", "flags"},
    "recvmsg": {"fd", "msg", "flags"},
    "recvmmsg": {"fd", "mmsg", "vlen", "flags", "timeout"},
    "sendto": {"fd", "buff", "len", "flags", "addr", "addr_len"},
    "recvfrom": {"fd", "ubuf", "size", "flags", "addr", "addr_len"},
}
_POINTERS = {
    "poll": {"ufds"}, "read": {"buf"}, "write": {"buf"},
    "sendmsg": {"msg"}, "sendmmsg": {"mmsg"}, "recvmsg": {"msg"},
    "recvmmsg": {"mmsg", "timeout"}, "sendto": {"buff", "addr"},
    "recvfrom": {"ubuf", "addr", "addr_len"},
}


def _number(raw: str, *, signed: bool = False, width: int = 64) -> int:
    """Parse perf's scalar spelling without retaining the source text."""
    if _HEX.fullmatch(raw):
        value = int(raw, 16)
        if value > (1 << 64) - 1:
            raise ExportError("scalar outside 64-bit range")
        if signed:
            if width == 32:
                if value <= (1 << 32) - 1:
                    if value & (1 << 31):
                        value -= 1 << 32
                elif value >= (1 << 64) - (1 << 31):
                    value -= 1 << 64
                else:
                    raise ExportError("scalar outside signed 32-bit range")
            elif value & (1 << 63):
                value -= 1 << 64
    elif _DEC.fullmatch(raw):
        value = int(raw, 10)
    else:
        raise ExportError("malformed scalar")
    lower = -(1 << (width - 1)) if signed else 0
    upper = (1 << (width - 1)) - 1 if signed else (1 << 64) - 1
    if value < lower or value > upper:
        raise ExportError("scalar outside permitted range")
    return value


def _fields(body: str, event: str) -> dict[str, int]:
    if not body:
        raise ExportError(f"{event}: missing fields")
    values: dict[str, int] = {}
    for item in body.split(","):
        item = item.strip()
        if not item or ":" not in item:
            raise ExportError(f"{event}: malformed field")
        key, raw = (part.strip() for part in item.split(":", 1))
        allowed = _EVENTS[event]
        if key not in allowed or key in values:
            raise ExportError(f"{event}: unknown or duplicate field")
        values[key] = _number(
            raw,
            signed=key == "timeout_msecs",
            width=32 if key == "timeout_msecs" else 64,
        )
    if set(values) != _EVENTS[event]:
        raise ExportError(f"{event}: missing or extra fields")
    return {key: value for key, value in values.items() if key not in _POINTERS[event]}


def parse(text: str) -> dict[str, Any]:
    if not isinstance(text, str) or not text:
        raise ExportError("trace is empty")
    events: list[dict[str, Any]] = []
    previous = -1
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if "LOST" in line.upper():
            raise ExportError(f"line {line_number}: lost events")
        raw = _RAW_WRITE.fullmatch(line)
        if raw is not None:
            # Linux x86_64 write(2). The producer verifies the architecture and
            # filters NR=1. Never use augmented typed write tracepoints: some
            # kernels record buffer contents in them.
            seconds, fraction, edge, body = raw.groups()
            if edge == "enter":
                arguments = _RAW_ARGS.fullmatch(body)
                if arguments is None:
                    raise ExportError("malformed raw write arguments")
                values = [_number("0x" + value) for value in arguments.groups()]
                fields = {"fd": values[0], "count": values[2]}
            else:
                if not body.startswith("= "):
                    raise ExportError("malformed raw write return")
                fields = {"ret": _number(body[2:], signed=True)}
            timestamp = int(seconds) * 1_000_000_000 + int(fraction)
            if timestamp <= previous or timestamp > (1 << 64) - 1:
                raise ExportError("raw write timestamp regression")
            previous = timestamp
            events.append({"time_ns": timestamp, "event": f"syscalls:sys_{edge}_write", "fields": fields})
            continue
        match = _LINE.fullmatch(line)
        if match is None:
            raise ExportError(f"line {line_number}: malformed event")
        timestamp = int(match["seconds"]) * 1_000_000_000 + int(match["frac"])
        if timestamp <= previous or timestamp > (1 << 64) - 1:
            raise ExportError(f"line {line_number}: timestamp regression")
        previous = timestamp
        name = match["event"]
        suffix = name.removeprefix("syscalls:sys_")
        edge, event = suffix.split("_", 1)
        if event not in _EVENTS:
            raise ExportError(f"line {line_number}: unsupported syscall {event}")
        if edge == "exit":
            body = match["body"] or ""
            if "," in body or not body.strip():
                raise ExportError(f"line {line_number}: malformed exit")
            fields = {"ret": _number(body.strip(), signed=True)}
        else:
            fields = _fields(match["body"] or "", event)
        events.append({"time_ns": timestamp, "event": name, "fields": fields})
    if not events:
        raise ExportError("trace has no events")
    return {"schema_version": 1, "events": events}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args()
    exported = parse(open(args.input, encoding="utf-8").read())
    with open(args.output, "x", encoding="utf-8") as stream:
        json.dump(exported, stream, separators=(",", ":"), sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
