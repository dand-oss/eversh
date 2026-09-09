"""Strict decoding for the instruction samples emitted by ``perf script``.

This parser intentionally accepts only the requested ``instructions:u`` event
and a fully formed ``pid/tid time event ip symbol (dso)`` sample row.  It does
not infer CPU time or causal latency, and it drops the address and DSO from the
returned records so callers cannot accidentally treat those fields as scope
identity.
"""
import re


_LINE = re.compile(
    r"\s*(\d+)/(\d+)\s+(\d+)\.(\d{9}):\s+"
    r"(instructions:u):\s+([0-9a-fA-F]+)\s+(.+)\s+\((.*)\)\s*"
)
MAX_BYTES = 16 * 1024 * 1024
MAX_SAMPLES = 100_000
_MAX_U64 = (1 << 64) - 1


def _validate_scope(targets):
    if (not isinstance(targets, dict) or not targets or
            any(type(pid) is not int or pid <= 0 or not tids or
                any(type(tid) is not int or tid <= 0 for tid in tids)
                for pid, tids in targets.items())):
        raise ValueError("invalid instruction sample scope")


def parse(text, targets):
    """Return scoped, monotonic instruction samples from a perf-script export.

    ``targets`` maps each verified process ID to its verified thread IDs.  Any
    record outside that identity, any lost/non-sample record, and any event
    other than ``instructions:u`` fails closed.
    """
    _validate_scope(targets)
    if not isinstance(text, str):
        raise ValueError("instruction sample export must be text")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ValueError("instruction sample export exceeds bound")

    samples = []
    previous = -1
    for line in text.splitlines():
        if not line.strip():
            continue
        match = _LINE.fullmatch(line)
        if match is None:
            raise ValueError("non-sample or malformed perf record")
        pid, tid, seconds, fraction, _event, _ip, symbol, _dso = match.groups()
        pid, tid = int(pid), int(tid)
        if pid not in targets or tid not in targets[pid]:
            raise ValueError("sample outside verified process scope")
        timestamp = int(seconds) * 1_000_000_000 + int(fraction)
        if not previous <= timestamp <= _MAX_U64:
            raise ValueError("instruction sample timestamp regressed or overflowed")
        previous = timestamp
        samples.append({
            "pid": pid,
            "tid": tid,
            "time_ns": timestamp,
            "event": "instructions:u",
            "symbol": symbol.rstrip(),
        })
        if len(samples) > MAX_SAMPLES:
            raise ValueError("instruction sample count exceeds bound")
    if not samples:
        raise ValueError("no instruction samples")
    return samples
