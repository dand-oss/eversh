#!/usr/bin/env python3
"""Correlate timed keystrokes with pcap-derived authoritative echo arrival."""
import json
import math
import subprocess
import sys
from datetime import datetime, timezone


def tcpdump_lines(pcap):
    # The ambient pyenv LD_LIBRARY_PATH breaks libz mapping in tcpdump; use
    # a sanitized environment.
    proc = subprocess.run(
        ["/usr/bin/env", "-i", "/usr/bin/tcpdump", "-nn", "-r", pcap],
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.splitlines()


def parse_packet(line):
    # Live captures include a date; replaying today's file omits it.
    parts = line.split()
    if len(parts) >= 6 and parts[2] == "IP":
        stamp = f"{parts[0]} {parts[1]}"
        src, dst = parts[3], parts[5].rstrip(":")
    elif len(parts) >= 5 and parts[1] == "IP":
        stamp = parts[0]
        src, dst = parts[2], parts[4].rstrip(":")
    else:
        return None
    try:
        parsed = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        try:
            parsed = datetime.strptime(stamp, "%H:%M:%S.%f")
        except ValueError:
            return None
        today = datetime.now()
        parsed = parsed.replace(
            year=today.year, month=today.month, day=today.day
        )
    when = parsed.timestamp()
    return when, src, dst


def main() -> int:
    pcap, events_path, output, server_port = sys.argv[1:5]
    server_suffix = f".{server_port}"
    packets = []
    for line in tcpdump_lines(pcap):
        parsed = parse_packet(line)
        if parsed:
            packets.append(parsed)
    with open(events_path, encoding="utf-8") as handle:
        events = json.load(handle)
    results = []
    for event in events:
        key_wall = event["t"] / 1_000_000_000
        request = min(
            (
                p
                for p in packets
                if p[0] + 1e-4 >= key_wall and not p[1].endswith(server_suffix)
            ),
            key=lambda p: p[0],
            default=None,
        )
        if request is None:
            results.append(0)
            continue
        reply = min(
            (p for p in packets if p[0] >= request[0] and p[1].endswith(server_suffix)),
            key=lambda p: p[0],
            default=None,
        )
        results.append(int((reply[0] - key_wall) * 1_000_000) if reply else 0)
    ordered = sorted(value for value in results if value > 0)

    def pick(fraction):
        if not ordered:
            return 0
        index = max(0, math.ceil(len(ordered) * fraction) - 1)
        return ordered[index]

    summary = {
        "trials": len(results),
        "nonzero": len(ordered),
        "median_us": pick(0.50),
        "p95_us": pick(0.95),
        "max_us": ordered[-1] if ordered else 0,
    }
    with open(output, "w", encoding="utf-8") as handle:
        json.dump({"summary": summary, "samples": results}, handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
