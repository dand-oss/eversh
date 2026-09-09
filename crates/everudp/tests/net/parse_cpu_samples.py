"""Strict perf leaf-sample decoding; symbol names are not loss notifications.

Accept only `perf script --ns -F pid,tid,time,event,ip,sym,dso` sample rows.
Lost records and every other unrecognized record fail closed. Callers must
separately validate event attributes, capture identity, and clock alignment.
"""
import re
from bisect import bisect_right
from collections import Counter

_LINE = re.compile(
    r"\s*(\d+)/(\d+)\s+(\d+)\.(\d{9}):\s+(cpu-clock:[uk]):"
    r"\s+([0-9a-f]+)\s+(.+)\s+\((.*)\)\s*")
MAX_BYTES = 16 * 1024 * 1024
MAX_SAMPLES = 100_000


def parse(text, targets):
    """targets maps each recorded process ID to its verified thread IDs."""
    if not targets or any(type(pid) is not int or pid <= 0 or not tids
                          or any(type(tid) is not int or tid <= 0 for tid in tids)
                          for pid, tids in targets.items()):
        raise ValueError("invalid CPU sample scope")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ValueError("CPU sample export exceeds bound")
    samples = []
    previous = -1
    for line in text.splitlines():
        if not line.strip():
            continue
        match = _LINE.fullmatch(line)
        if match is None:
            raise ValueError("non-sample or malformed perf record")
        pid, tid, seconds, fraction, event, _ip, symbol, _dso = match.groups()
        pid, tid = int(pid), int(tid)
        if pid not in targets or tid not in targets[pid]:
            raise ValueError("sample outside verified process scope")
        timestamp = int(seconds) * 1_000_000_000 + int(fraction)
        if not previous <= timestamp <= (1 << 64) - 1:
            raise ValueError("CPU sample timestamp regressed or overflowed")
        previous = timestamp
        samples.append({"pid": pid, "tid": tid, "time_ns": timestamp,
                        "event": event, "symbol": symbol.rstrip()})
        if len(samples) > MAX_SAMPLES:
            raise ValueError("CPU sample count exceeds bound")
    if not samples:
        raise ValueError("no CPU samples")
    return samples


def correlate(samples, boundaries, roles):
    """Count leaf samples in complete public windows, never estimate CPU time.

    Callers validate boundaries with clock_alignment._validated_boundaries and
    verify clock identity, perf attributes and absence of lost records first.
    The common first/last sample interval conservatively excludes edge trials.
    """
    if not roles or len(set(roles.values())) != len(roles):
        raise ValueError("invalid role mapping")
    by_pid = {pid: [] for pid in roles}
    for sample in samples:
        if sample["pid"] not in by_pid:
            raise ValueError("unscoped correlation sample")
        by_pid[sample["pid"]].append(sample["time_ns"])
    if any(not times or times != sorted(times) for times in by_pid.values()):
        raise ValueError("missing or regressing process samples")
    low = max(times[0] for times in by_pid.values())
    high = min(times[-1] for times in by_pid.values())
    if high < low:
        raise ValueError("no common sample coverage")
    rows, starts = [], []
    previous = -1
    for i, boundary in enumerate(boundaries):
        start, end = boundary["send_ns"], boundary["accepted_ns"]
        if boundary["trial"] != i or not previous < start < end:
            raise ValueError("invalid public window")
        previous = end
        starts.append(start)
        row = {"trial": i, "samples": 0}
        if start < low or end > high:
            row["excluded"] = "outside common sample coverage"
        rows.append(row)
    histograms = {role: {kind: Counter() for kind in ("cpu-clock:u", "cpu-clock:k")}
                  for role in roles.values()}
    outside = 0
    for sample in samples:
        i = bisect_right(starts, sample["time_ns"]) - 1
        if (i < 0 or sample["time_ns"] > boundaries[i]["accepted_ns"]
                or "excluded" in rows[i]):
            outside += 1
            continue
        rows[i]["samples"] += 1
        histograms[roles[sample["pid"]]][sample["event"]][sample["symbol"]] += 1
    return {"status": "DIAGNOSTIC", "qualification": False,
            "coverage_ns": [low, high], "outside_samples": outside, "rows": rows,
            "leaf_sample_counts": {role: {kind: dict(counts) for kind, counts in kinds.items()}
                                   for role, kinds in histograms.items()}}
